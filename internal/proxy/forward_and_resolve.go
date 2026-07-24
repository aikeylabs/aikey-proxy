// forward_and_resolve.go — credential resolution + ReverseProxy forwarding.
//
// The "inner" half of the request path, shared by every pipeline handler
// in pipelines.go:
//
//   - ResolveBindingCredential: vault lookup that turns a (provider, binding)
//     tuple into a concrete (BaseURL, RealKey, VirtualKeyID, KeyAlias).
//     Used by the App and Probe pipelines to figure out which upstream key
//     to inject before forwarding.
//
//   - serveRouteWithObserver: thin wrapper around serveRoute that fires
//     observer.NotifyStart / NotifyEnd hooks for the plugin observer
//     registry (see pkg/observer/registry.go).
//
//   - serveRoute: the actual httputil.ReverseProxy forwarding loop —
//     streaming detection, transport selection, response rewriting,
//     usage-event emission. Called by handleAppPipeline,
//     handleProbePipeline, handlePathPrefixRoute via
//     serveRouteWithObserver.
//
// Split out of proxy.go on 2026-05-26 — see
// workflow/CI/refactor/2026-05-26-proxy-go-split.md for the file map.
package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/apppipe"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// serveRouteWithObserver wraps p.serveRoute with NotifyStart/End for the
// given SPEC §1.4.1 stream. Used by user_chat callers (Handle's legacy
// /v1/ branch + handlePathPrefixRoute's 4 sub-branches) so the
// observer wiring lives in one place rather than 5 copy-pastes.
//
// Why not also use this from handleAppPipeline / handleProbePipeline:
// those handlers build a richer RequestContext (AppKeyID / AppSlug /
// AppMode for the App pipeline, alias_kind logging for Probe) inline
// at call site. Funneling them through here would either lose those
// fields or balloon the helper's signature. Two-handler-specific +
// one-shared-helper is the right granularity — DRY where the pipelines
// agree, explicit where they diverge.
//
// requestedModel intentionally empty for user_chat — extracting body.model
// here would require parsing + restoring r.Body, with risk of breaking
// the byte-identical forward semantics path-prefix routing relies on.
// Event.Model has json:omitempty so the downstream NDJSON consumer
// survives the absence.
//
// stream taxonomy (today only user_chat reaches here; future agent_chat /
// agent_event branches will reuse this wrapper). Inlining the constant
// would make adding the next stream branch a re-plumb across 5 call sites.
//
//nolint:unparam // `stream` kept parameterized for the SPEC §1.4.1
func (p *Proxy) serveRouteWithObserver(
	w http.ResponseWriter, r *http.Request,
	route *vkeys.ResolvedRoute, prov provider.Provider,
	realKey, inboundBearer string,
	startTime time.Time, logger *slog.Logger,
	stream string, traceID string,
) {
	// P1d (R-C, design D-10): normalize provider ATTRIBUTION to the truthful
	// upstream vendor BEFORE building obsReqCtx below. obsReqCtx.ProviderID and
	// SessionID (resolveSessionID keys on ProviderCode) are stamped from
	// route.ProviderCode here; without this hoist the observer / rhythm-audit
	// stream recorded the DECLARED provider (anthropic) while the usage ledger —
	// normalized later inside serveRoute — recorded the real vendor (zhipu for a
	// GLM /api/anthropic binding declared anthropic), a two-source split. serveRoute
	// re-applies the SAME normalization idempotently (LookupByBaseURL on the
	// already-truthful code returns it unchanged), which also covers the direct
	// (app / probe) serveRoute callers that don't funnel through here.
	if route != nil {
		route.ProviderCode = truthfulProviderCode(route.BaseURL, route.ProviderCode)
	}

	var obsReqCtx *observer.RequestContext
	if p.observerRegistry != nil && p.observerRegistry.Active() > 0 {
		// User_chat-side ProtocolFamily fallback (2026-05-23): the legacy
		// /v1/... route resolution doesn't fill `route.ProtocolFamily`
		// (it's only populated in handleAppPipeline — see
		// ResolvedRoute.ProtocolFamily doc-comment). Without this, the
		// rhythm observer's protocol gate trips on every user_chat event
		// (`unknown_protocol` WARN) and D-rule scoring never runs. We
		// re-derive from the same provider_fingerprint yaml the app
		// pipeline uses so user_chat observers see the same shape app
		// observers do. No change for paths that already filled the
		// field (route.ProtocolFamily != "" wins).
		// P1d (design D-10, safe slice): prefer the path-aware route row keyed
		// on the resolved base_url so multi-endpoint hosts (GLM /api/anthropic
		// vs /api/paas) get the right wire family; fall back to the path-blind
		// ByProvider when the base_url host isn't in the table. Audit-only.
		pf := route.ProtocolFamily
		if pf == "" {
			if pr, ok := provider.Routes().LookupByBaseURL(route.BaseURL); ok {
				pf = pr.Protocol
			} else if route.ProviderCode != "" {
				pf, _ = provider.ProtocolFamily(route.ProviderCode, route.ProtocolType)
			}
		}
		obsReqCtx = &observer.RequestContext{
			KeyAlias:       route.KeyAlias,
			ProviderID:     route.ProviderCode,
			ProtocolFamily: pf,
			SessionID:      resolveSessionID(r, route.ProtocolType, route.ProviderCode),
			TraceID:        traceID,
			StartedAt:      startTime,
			// Multi-tenant attribution — mirror the usage path's single-source
			// rule (events/reportable.go) so the conversation-audit observer and
			// usage events agree on who a turn belongs to.
			OrgID: route.OrgID,
			OwnerAccountID: func() string {
				if route.AccountID != "" {
					return route.AccountID
				}
				return p.loggedInAccountID // personal-key fallback, as in usage
			}(),
			// Same field usage events stamp (reportable.go SeatID) — the seat
			// dimension is what keeps shared-pool-VK turns attributed to the
			// employee, not the VK owner (2026-07-07 audit misattribution).
			SeatID: route.SeatID,
		}
		// payload_level=full (enterprise conversation audit): when some active
		// observer wants the raw request body, buffer+restore it here so the
		// observer sees the prompt in OnRequestStart. Gated by WantsFullPayload
		// → the common case (no audit observer, or audit off) pays nothing and
		// r.Body is never touched. Body capture is best-effort; see
		// bufferRequestBodyForObserver for the main-link safety guards.
		if p.observerRegistry.WantsFullPayload() {
			obsReqCtx.RequestBody = bufferRequestBodyForObserver(r)
		}
		route.ObserverContext = obsReqCtx
		route.ObserverRegistry = p.observerRegistry
		// Probe traffic (X-Aikey-Probe header — e.g. the CLI connectivity self-test
		// in aikey-cli/src/connectivity, which POSTs "hi" max_tokens=1 to the normal
		// /v1/messages URL) is surfaced to observers as StreamProbe, mirroring the
		// usage path's isAikeyProbe bypass (events_and_helpers.go). Without this it
		// arrives as StreamUserChat (it uses the chat URL, not /probe/), so the
		// conversation-audit observer would record every self-test as an empty "hi"
		// turn — inflating a seat's session/turn counts with non-conversations.
		if isAikeyProbe(r) {
			stream = observer.StreamProbe
		}
		p.observerRegistry.NotifyStart(r.Context(), stream, obsReqCtx)
	}

	p.serveRoute(w, r, route, prov, realKey, inboundBearer, startTime, logger)

	if obsReqCtx != nil {
		latency := int(time.Since(startTime).Milliseconds())
		p.observerRegistry.NotifyEnd(r.Context(), obsReqCtx, latency)
	}
}

// ResolveBindingCredential resolves the upstream credential for the
// given `binding`. Behavior depends on `binding.KeySourceType`:
//
//   - "personal_oauth_account" → broker.EnsureFresh + ResolveCredential,
//     mutate `r` headers via oauthInject, apply Codex BaseURL override
//     for canonicalCode=openai. On broker failure (broker nil, refresh
//     failed, resolve failed) returns *BindingResolveError that the
//     caller passes to writeJSONError.
//
//   - "team" → activeReader.GetTeamKeyByID; populates ManagedKey,
//     KeyAlias (LocalAlias), BaseURL (ProviderBaseURLs lookup with
//     canonicalCode → providerCode → mk.BaseURL fallback). Soft-fails
//     (logger.Warn + empty RealKey) so caller falls back to legacy.
//
//   - default (personal) → activeReader.GetPersonalKeyByAlias;
//     populates RealKey, KeyAlias (== binding.KeySourceRef), BaseURL
//     (entry-specified or providerDefaultBaseURL). Soft-fails like team.
//
// Refactored from the inline code at handlePathPrefixRoute's binding
// branch (AKL-207, 2026-05-20). Fence tests in oauth_binding_fence_test.go
// pin the OAuth path's exact pre-refactor behavior.
func (p *Proxy) ResolveBindingCredential(
	r *http.Request,
	binding *vault.ProviderBinding,
	providerCode, canonicalCode string,
	logger *slog.Logger,
) (*apppipe.BindingCredential, *apppipe.BindingResolveError) {
	out := &apppipe.BindingCredential{}

	switch binding.KeySourceType {
	case "personal_oauth_account":
		// OAuth account — resolve via broker, not vault.
		if p.broker == nil {
			return nil, &apppipe.BindingResolveError{
				StatusCode: http.StatusServiceUnavailable,
				ErrorType:  "server_error",
				ErrorCode:  "OAUTH_NOT_AVAILABLE",
				Message:    "OAuth is not configured. Restart proxy or use API Key instead.",
			}
		}

		// EnsureFresh: broker handles token refresh internally.
		if err := p.broker.EnsureFresh(r.Context(), binding.KeySourceRef); err != nil {
			logger.Warn("oauth: EnsureFresh failed", "account_id", binding.KeySourceRef, "error", err)
			return nil, &apppipe.BindingResolveError{
				StatusCode: http.StatusUnauthorized,
				ErrorType:  "auth_error",
				ErrorCode:  "OAUTH_TOKEN_EXPIRED",
				Message:    err.Error() + "\n  Run: aikey auth login " + providerCode,
			}
		}

		// Resolve decrypted credential.
		cred, err := p.broker.ResolveCredential(r.Context(), binding.KeySourceRef)
		if err != nil {
			logger.Error("oauth: ResolveCredential failed", "account_id", binding.KeySourceRef, "error", err)
			return nil, &apppipe.BindingResolveError{
				StatusCode: http.StatusServiceUnavailable,
				ErrorType:  "server_error",
				ErrorCode:  "OAUTH_RESOLVE_FAILED",
				Message:    err.Error(),
			}
		}

		// Dialect gate (2026-07-13): codex OAuth serves ONLY the Responses API.
		// Without this, a /chat/completions client's path got appended to
		// chatgpt.com/backend-api/codex and ChatGPT's edge answered with a
		// misleading "invalid x-api-key" — users debugged the key for hours.
		// Same predicate the group lane uses (single source of truth).
		if reason := oauthUpstreamRejectsPath(canonicalCode, r.URL.Path); reason != "" {
			logger.Warn("oauth: upstream does not serve this endpoint",
				"event.name", observability.EventProxyRequestDialectUnsupported,
				"error.code", observability.ErrCodeOAuthResponsesOnly,
				"error.message", reason,
				"url.path", r.URL.Path,
				"provider", canonicalCode,
			)
			return nil, &apppipe.BindingResolveError{
				StatusCode: http.StatusBadRequest,
				ErrorType:  "invalid_request_error",
				ErrorCode:  observability.ErrCodeOAuthResponsesOnly,
				Message:    reason,
			}
		}

		// Per-provider OAuth upstream (base URL + any provider setup) via the shared
		// resolver — same source as the group route. Codex's chatgpt.com override +
		// deferred model capture live in resolveOAuthUpstream; pinned by
		// TestFence_OAuthBinding_OpenAICodexBaseURLOverride.
		out.BaseURL, r = resolveOAuthUpstream(canonicalCode, binding.ProtocolType, r)
		oauthInject(r, cred, canonicalCode)

		identityTag := cred.Identity
		if identityTag == "" {
			identityTag = binding.KeySourceRef
		}
		logger.Info("oauth: forwarding request",
			"provider", canonicalCode,
			"identity", identityTag,
			"account_id", binding.KeySourceRef,
		)

		out.RealKey = "__oauth__" // sentinel — not used for header injection (injector did it)
		out.VirtualKeyID = "oauth:" + binding.KeySourceRef
		out.OAuthIdentity = identityTag
		out.OAuthAccountID = binding.KeySourceRef
		return out, nil

	case "team", "managed_virtual_key":
		// P1e (D-11): pass the resolved upstream provider so a multi-binding VK
		// (e.g. GLM + official on one VK) picks THIS request's binding + its own
		// key. canonicalCode is the truthful upstream vendor; empty/unmatched
		// falls back to the VK's primary binding (legacy single-binding behavior).
		mk, err := p.activeReader.GetTeamKeyByID(binding.KeySourceRef, canonicalCode, binding.ProtocolType)
		if err != nil {
			logger.Warn("vault: team key lookup via binding failed", "vk_id", binding.KeySourceRef, "error", err)
			return out, nil // soft fail — caller will try legacy fallback
		}
		if mk == nil {
			return out, nil // not found, soft fail
		}
		out.ManagedKey = mk
		out.RealKey = mk.PlaintextKey
		out.VirtualKeyID = mk.VirtualKeyID
		// 2026-05-09: surface the team key's user-facing alias so the
		// receipt / WAL `key_label` shows e.g. `key-335923591-0011-1`
		// instead of the vk_id tail.
		out.KeyAlias = mk.LocalAlias
		if url, ok := mk.ProviderBaseURLs[canonicalCode]; ok && url != "" {
			out.BaseURL = url
		} else if url, ok := mk.ProviderBaseURLs[providerCode]; ok && url != "" {
			out.BaseURL = url
		} else {
			out.BaseURL = mk.BaseURL
		}
		return out, nil

	default:
		// Personal key path. binding.KeySourceType is typically "personal"
		// (legacy) or "personal_api_key" (canonical post-CredentialType
		// enum). Both are accepted via the default branch — strict-match
		// would have been a regression if the writer side ever emits the
		// other.
		plaintext, _, entryBaseURL, err := p.activeReader.GetPersonalKeyByAlias(binding.KeySourceRef)
		if err != nil {
			logger.Warn("vault: personal key lookup via binding failed", "alias", binding.KeySourceRef, "error", err)
			return out, nil // soft fail
		}
		out.RealKey = plaintext
		out.VirtualKeyID = "personal:" + binding.KeySourceRef
		out.KeyAlias = binding.KeySourceRef
		if entryBaseURL != "" {
			out.BaseURL = entryBaseURL
		} else {
			out.BaseURL = providerBaseURLForProtocol(canonicalCode, binding.ProtocolType)
		}
		return out, nil
	}
}

// serveRoute executes the forwarding pipeline (streaming detection, transport
// selection, reverse proxy) shared by token-based and path-prefix routing.
func (p *Proxy) serveRoute(w http.ResponseWriter, r *http.Request, route *vkeys.ResolvedRoute, prov provider.Provider, realKey, bearerToken string, startTime time.Time, logger *slog.Logger) {
	// P1d (R-C, design D-10 refined): normalize provider ATTRIBUTION to the
	// truthful upstream vendor resolved from the binding's base_url. A binding
	// declared as anthropic but pointing at GLM's .../api/anthropic endpoint
	// then attributes usage/pricing to zhipu (the real vendor), fixing "metadata
	// shows anthropic instead of glm". No-op for the overwhelming majority whose
	// declared provider already matches their endpoint (LookupByBaseURL returns
	// the same code) and for third-party gateways absent from the table (!ok).
	// Adapter selection is unchanged — it's driven by the path's wire protocol,
	// which is correct (the client speaks that wire). This is the single funnel
	// every pipeline passes through, so one fix covers all. IDEMPOTENT: the
	// observer path (serveRouteWithObserver) already applied this before building
	// obsReqCtx so the audit stream sees the real vendor too; re-applying here is
	// a no-op for it (LookupByBaseURL on the truthful code returns it unchanged)
	// and still covers the direct app / probe callers that skip the observer wrap.
	if route != nil {
		route.ProviderCode = truthfulProviderCode(route.BaseURL, route.ProviderCode)
	}

	// Base-URL fault fence (2026-07-24). OAuth routes forward through
	// applyOAuthUpstreamURL, a literal prepend that cannot repair a base URL
	// which already carries the version segment — the result is /v1/v1/messages
	// and a bare upstream 404 on EVERY model, attributed to the provider rather
	// than to us. Fail loud with the fix instead, BEFORE the quota gate: a
	// request we cannot forward must not consume the seat's quota.
	//
	// Excluded: the mock provider (joins via StitchForProviderProtocol, which is
	// version-aware) and every API-key route (joins via providerroutes.Stitch,
	// likewise version-aware). See oauthBaseURLFault's scope note.
	if route != nil && realKey == oauthSentinelKey && route.ProviderCode != "mock" {
		if reason := oauthBaseURLFault(route.BaseURL, r.URL.Path); reason != "" {
			p.errors.Add(1)
			logger.Error("oauth upstream base URL misconfigured — refusing to forward",
				"event.name", "proxy.route.base_url_misconfigured",
				"base_url", route.BaseURL,
				"request_path", r.URL.Path,
				"provider_code", route.ProviderCode,
				"protocol_type", route.ProtocolType,
			)
			writeJSONError(w, http.StatusBadGateway, "server_error", "BASE_URL_MISCONFIGURED", reason)
			return
		}
	}

	// Phase 2 quota gate — UNIVERSAL chokepoint (Stage 3 + D-U8/P7). serveRoute is
	// the single funnel EVERY real route passes through (Tier1 token, OAuth,
	// active-sentinel, app pipeline, default binding; serveRouteWithObserver
	// delegates here). Enforcing here — rather than per-branch in the dispatchers —
	// guarantees no real-traffic path can accrue usage (accrueQuotaUsage runs in
	// this same forward flow) without ALSO being blocked when over-limit. This
	// closes the gap where path-prefix traffic (aikey use → /<provider>/v1/...)
	// counted usd/tokens but never enforced. Probes are exempt: they must pass for
	// health checks and are likewise excluded from accrual (isAikeyProbe). The gate
	// is in-memory + flag-gated — a no-op when quota is off or the seat has no quota.
	if !isAikeyProbe(r) && p.enforceQuota(w, route, logger) {
		return
	}

	// Why: extractModel also stashes the parsed model into the `x-aikey-model`
	// request header, which buildBaseEvent later reads to populate ev.Model.
	// Historically this was only called inside the allowlist check (`len(route.AllowedModels) > 0`),
	// so OAuth / personal routes without an allowlist left `ev.Model` empty
	// and the UI showed `model: null`. Call unconditionally — it's cheap
	// (single JSON decode of an already-buffered body).
	_ = extractModel(r)

	// 6. Detect streaming.
	streaming := isStreamingRequest(r)

	// 6b. Optional: stash raw request body for the 4xx debug-capture path
	// (gated by AIKEY_PROXY_DEBUG_4XX_BODIES). No-op when flag is off, so
	// hot path stays untouched. Must run AFTER extractModel — extractModel
	// has already re-buffered r.Body once, our stash reads from the buffer
	// and re-buffers again.
	stashRequestBodyForDebug(r)

	// 6a. Inject stream_options.include_usage=true for /chat/completions only.
	// Why: OpenAI-compatible streaming responses only include token usage in the
	// final SSE chunk when this option is set. Without it, all token counts are 0.
	// Only /chat/completions supports this; newer endpoints like /responses
	// (used by Codex) reject it as unknown_parameter.
	if streaming && prov.Name() != "anthropic" && strings.HasSuffix(r.URL.Path, "/chat/completions") {
		injectStreamUsageOption(r)
	}

	// 6c. P4 filter dispatch: inbound compliance/DLP check on the request body
	// BEFORE forwarding to the LLM. No-op when no filter hook is installed
	// (zero hot-path cost behind the nil check inside applyInboundFilter).
	// On Block, applyInboundFilter writes the 403 and we return without
	// forwarding. On Mask, r.Body is rewritten to the redacted version so the
	// upstream LLM never sees the raw sensitive prompt. Fail-open on degraded.
	if !p.applyInboundFilter(w, r, extractModel(r), route.RouteSource, route.OrgID, route.VirtualKeyID, route.SeatID, resolveSessionID(r, route.ProtocolType, route.ProviderCode), logger) {
		return
	}

	// 6d. P2 model mapping (design D-1/D-2): rewrite the outbound body.model to
	// the upstream model name for providers with a model_map (GLM). Independent
	// layer, run after route resolution + client-model allowlist (D-4) and
	// before the adapter RewriteRequest. Inert for non-mapped providers (body
	// byte-identical), so blast radius is scoped to GLM traffic. On an unmatched
	// reject it answers MODEL_MAPPING_NOT_FOUND and we stop.
	if !p.applyModelMappingToRequest(w, r, route, logger) {
		return
	}

	// 7. Store metadata in context for post-processing.
	// For streaming requests, bridge the HTTP/1.1 close-notifier to a context
	// so the streamDrainer can abort the upstream call when the client
	// disconnects mid-stream (HTTP/1.1 does not cancel r.Context() until
	// ServeHTTP returns, which is too late to interrupt upstream.Read).
	reqBase := r.Context()
	if streaming {
		//nolint:staticcheck // CloseNotifier is the only reliable HTTP/1.1 disconnect signal
		if cn, ok := w.(http.CloseNotifier); ok {
			cancelCtx, cancel := context.WithCancel(reqBase)
			defer cancel()
			// Isolated: per-request disconnect watcher. A panic here only
			// breaks one streaming request's mid-stream cancel behavior.
			observability.GoSafe("proxy.request.close_notifier", observability.Isolated, func() {
				select {
				case <-cn.CloseNotify(): //nolint:staticcheck // CloseNotifier deprecated but the reliable HTTP/1.1 mid-stream disconnect signal
					cancel()
				case <-cancelCtx.Done():
				}
			})
			reqBase = cancelCtx
		}
	}
	ctx := context.WithValue(reqBase, ctxKeyRoute, route)
	ctx = context.WithValue(ctx, ctxKeyStartTime, startTime)
	ctx = context.WithValue(ctx, ctxKeyIsStreaming, streaming)
	r = r.WithContext(ctx)

	// 8. Build inner transport.
	// Non-streaming: detach from the client context so the upstream call
	// completes even if the client disconnects — the provider has already
	// started generating and will charge for it regardless.
	// Streaming: keep the client context. When the client disconnects the
	// upstream TCP connection is released so the provider stops generation
	// and stops billing. Partial token usage is still recorded by the drainer.
	inner := p.currentTransport()
	if inner == nil {
		inner = http.DefaultTransport
		logger.Debug("using default transport (no custom transport set)")
	} else {
		logger.Debug("using custom transport (upstream proxy)")
	}
	// Per-account egress proxy (§11.7, P7): when the resolved oauth-group account
	// pins an egress_proxy_url, THIS request leaves through it, chained through the
	// node socks5 front proxy when present (2-hop). Only group routes ever set this;
	// the default hot path skips this block entirely (byte-unchanged). A build error
	// (e.g. non-socks5 node front cannot chain a socks5 account) fails the request
	// loudly rather than silently leaking traffic out the wrong (node) IP.
	//
	// Coexistence (2026-07-18, reversed the 2026-07-16 L1 override): per-account
	// egress is an ACCOUNT-level attribute — it applies whenever the resolved account
	// has one, INDEPENDENT of any node-level upstream. A node upstream set via
	// /user/settings only serves traffic WITHOUT a per-account egress (api_key / VK /
	// OAuth accounts without one) — it no longer overrides an account's egress. This
	// keeps single-IP-per-account防封 intact while letting the user proxy their
	// non-egress traffic.
	//
	// Escape hatch (2026-07-19, OPT-IN — update/20260719-oauth-egress-override-逃生舱.md):
	// `oauthEgressOverride` re-adds a GATED override for self-rescue. Default OFF →
	// the condition is byte-identical to the 2026-07-18 coexist behavior (a
	// per-account egress applies unconditionally). When a member deliberately flips
	// it ON (Settings → Upstream proxy), an OAuth account's egress is SKIPPED and its
	// traffic falls to the node chain (`inner`, unchanged below) — the same transport
	// non-egress traffic already uses — so a member whose admin egress line is down
	// can route out their own upstream instead of eating a 503. Node-local; the cost
	// (all OAuth accounts then share this node's exit IP) is surfaced in the UI.
	// Trade-off when OFF: if the admin's per-account proxy is down, the account's
	// request fails loudly (ErrCodeAccountEgressEngine/ErrCodeAccountEgressProxy
	// 503) — the escape hatch is the deliberate opt-out of that fail-loud.
	// Per-request egress attribution (2026-07-19): derive ONCE from the resolved
	// account egress + node override, then (A) log it at Info for live trace_id
	// grep and (B) let recordEvent stamp the same onto the usage event's ext_json.
	// egApplied is byte-identical to the old gate below. Logged for BOTH cases
	// (applied per-account egress, or fell to node/direct) so any request is
	// traceable, not just the egress ones. Never logs the spec verbatim — only
	// its fingerprint (a mihomo fragment carries socks5 credentials).
	egApplied, egEngine, egFingerprint := egressAttribution(route.EgressProxyURL, p.oauthEgressOverride.Load())
	logger.Info("egress attribution",
		"event.name", observability.EventProxyEgressRequestAttribution,
		"account_id", route.AccountID,
		"oauth_identity", route.OAuthIdentity,
		"egress_applied", egApplied,
		"egress_engine", egEngine,
		"egress_fingerprint", egFingerprint,
	)
	if egApplied && route.EgressProxyURL != "" {
		egT, egErr := p.accountEgressTransport(route.EgressProxyURL)
		if egErr != nil {
			p.errors.Add(1)
			logger.Error("per-account egress proxy unavailable",
				"event.name", observability.EventProxyRequestUpstreamError,
				"error.code", observability.ErrCodeAccountEgressEngine,
				"error.message", egErr.Error(),
				"account_id", route.AccountID,
			)
			writeJSONError(w, http.StatusServiceUnavailable, "server_error", observability.ErrCodeAccountEgressEngine,
				accountEgressErrorMessage(route,
					"its configured egress could not be started. Traffic was not sent without the required egress. Check the account egress setting and whether the required egress engine is installed."))
			return
		}
		inner = egT
	}
	var transport http.RoundTripper = inner
	if !streaming {
		transport = &detachedTransport{
			inner:      inner,
			proxyCtx:   p.proxyCtx,
			maxTimeout: p.UpstreamTimeout,
		}
	}

	logger.Debug("forwarding request", "base_url", route.BaseURL, "path", r.URL.Path, "provider_code", route.ProviderCode)

	// P1j (design D-17, 禁止 #32): the stitch fallback (literal-prepend for a
	// host absent from provider_routes) is the degraded path — third-party
	// gateways with an explicit base_url still flow, but it must NOT be silent.
	// WARN so "UI shows one upstream, proxy forwards another" is observable.
	if route.BaseURL != "" && realKey != "__oauth__" {
		if _, known := provider.Routes().LookupByBaseURL(route.BaseURL); !known {
			logger.Warn("upstream host not in provider_routes — using degraded literal-prepend stitch",
				"event.name", "proxy.route.not_found", "base_url", route.BaseURL, "provider_code", route.ProviderCode)
		}
	}

	// 9. Build and execute reverse proxy.
	rp := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			if realKey == "__oauth__" {
				// OAuth: headers already injected by oauthInject() — only set upstream URL.
				// BaseURL may contain a path prefix (e.g. https://api.kimi.com/coding)
				// that must be prepended to the request path.
				if route.ProviderCode == "mock" {
					// The resident Mock Provider uses deployment-specific host/cluster
					// addresses, so host lookup cannot identify its fingerprint row.
					// Use the two explicit axes to attach the canonical version while
					// preserving the runtime rail and its /mock-provider prefix.
					if err := provider.Routes().StitchForProviderProtocol(req, route.BaseURL, route.ProviderCode, route.ProtocolType); err != nil {
						logger.Error("rewrite Mock OAuth request failed", "error", err)
					}
				} else {
					applyOAuthUpstreamURL(req, route.BaseURL)
				}
			} else {
				if err := prov.RewriteRequest(req, realKey, route.BaseURL); err != nil {
					logger.Error("rewrite request failed", "error", err)
				}
			}
			// Remove hop-by-hop headers the proxy shouldn't forward.
			req.Header.Del("X-Forwarded-For")

			// Propagate the proxy's logical request id to every upstream attempt.
			// Group failover clones the same inbound request for A→B retries; the
			// TraceContext is inherited by every clone, so this produces one stable
			// correlation key for the whole logical request instead of letting each
			// provider attempt invent an unrelated id. Preserve a caller-supplied
			// X-Request-Id (ExtractOrCreate already adopted it as the trace request
			// id); only synthesize the missing header.
			if req.Header.Get("X-Request-Id") == "" {
				if tc := traceFromContext(req.Context()); tc.RequestID != "" {
					req.Header.Set("X-Request-Id", tc.RequestID)
				}
			}

			// Strip AiKey-internal annotations before forwarding. These are
			// stashed onto the incoming request by extractModel() /
			// stashExtractedFields() for downstream usage-event recording
			// (see stashExtractedFields, proxy.go:1436). They must NOT
			// reach the upstream provider — Anthropic's OAuth WAF, in
			// particular, treats unrecognized headers as a persona signal
			// that the request isn't a real Claude Code session, returning
			// 429 with no X-RateLimit-Reset (business rejection signature).
			// Strip the whole `x-aikey-*` namespace so future internal
			// annotations don't repeat this leak. Floor invariant (§6): no
			// X-Aikey-* ever reaches the upstream — fenced by
			// TestStripAikeyRequestHeaders.
			stripAikeyRequestHeaders(req.Header)
			// Fence I13 second half (2026-07-21): the namespace strip above is a
			// NAME rule and cannot see an identity value parked under a header
			// that simply doesn't start with X-Aikey- (e.g. a future
			// `X-Member-Union-Id`). This is the VALUE rule — see
			// member_identity_guard.go for what it does and does not promise.
			// Fail-loud: a hit means some code above learned a member's provider
			// identity, so it WARNs rather than scrubbing silently.
			if scrubbed := scrubMemberIdentityHeaders(req.Header); len(scrubbed) > 0 {
				logger.Warn("member identity scrubbed from upstream request headers",
					"event.name", observability.EventProxyRequestIdentityScrubbed,
					"headers", scrubbed,
				)
			}
			// Why: tell upstream we only accept identity (uncompressed) so the
			// drainer and non-streaming token extractor can parse the body
			// directly. Anthropic's OAuth endpoint in particular returns
			// Content-Encoding: gzip for SSE streams, which made
			// ExtractTokens see gzip magic bytes (1f8b08...) and return 0/0.
			// Trade-off: slightly more bandwidth on the proxy-upstream hop,
			// but we're usually local loopback or a fast VPC so this is fine,
			// and unambiguous token counting is more valuable than saving a
			// few KB per request.
			req.Header.Set("Accept-Encoding", "identity")

			// Optional upstream-headers diagnostic capture. The toggle is
			// resolved through three layers (API > env > compile); see
			// debug_upstream.go for semantics. Logs the final method, URL,
			// and headers — the snapshot AFTER all rewrites (path strip,
			// OAuth Bearer + persona, Accept-Encoding override), so what
			// you see is what goes on the wire. Authorization / x-api-key
			// are masked.
			if debugUpstreamHeadersEnabled() {
				logger.Info("upstream request snapshot",
					"event.name", "proxy.request.upstream_headers",
					"method", req.Method,
					"url", req.URL.String(),
					"headers", maskAuthHeaders(req.Header),
					"request_body", truncateBodyForLog(debugRequestBodyFromContext(r.Context())),
				)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			// P1 error-origin (20260719): tag relayed error responses so a client
			// can tell WHO produced the error. First-writer-wins: if a deeper aikey
			// hop (worker/ingress) already set X-Aikey-Error-Origin, keep it (that's
			// the root cause); only when it's UNTAGGED and ≥400 do we attribute it to
			// the provider we forwarded to (upstream:<provider>) — the body is left
			// byte-identical (protocol transparency). Every hop appends itself to the
			// path. RESPONSE direction only — never touches the upstream request.
			if resp.StatusCode >= 400 {
				if resp.Header.Get(HeaderAikeyErrorOrigin) == "" {
					resp.Header.Set(HeaderAikeyErrorOrigin, "upstream:"+route.ProviderCode)
				}
				resp.Header.Add(HeaderAikeyErrorPath, errorOriginComponent)
			}
			// P3 correlation (20260719): re-expose the provider's own request id
			// under the ONE consistent aikey key so a user can JOIN it across the
			// log / usage store / provider support — no request-header propagation
			// (RESPONSE direction only). Set whenever the provider returned one.
			if id := upstreamRequestIDFromHeader(resp.Header); id != "" {
				resp.Header.Set(HeaderAikeyUpstreamRequestID, id)
			}

			// Codex OAuth model capture — only persist on 2xx so a bad
			// `model: gpt-4o` request (rejected by ChatGPT-account
			// Codex) can't poison the state file the connectivity probe
			// reads. See codex_model_capture.go §2026-06-09 deferred-
			// persist redesign. No-op for non-Codex paths because
			// ctxKeyCodexCandidateModel is only stashed inside the
			// canonicalCode == "openai" OAuth branch above.
			persistCodexLastModelIfSuccessful(resp.Request, resp.StatusCode)

			// N8c reactive fallback: if a pool account's upstream says it is
			// broken (401) or its window is exhausted (rate-limit-signal 429),
			// cool it down so the resolver routes subsequent requests around it.
			// This request still returns its status to the client; in-request
			// retry (no client-visible failure) is N9. Non-group routes
			// (route.OauthGroupID == "") skip this entirely.
			if route.OauthGroupID != "" && route.AccountID != "" {
				// Path Z (通道3 §14): record the observed window-reset epoch so the
				// next N7c pull piggybacks it to master, which re-rolls this
				// account's window_max_util_pct when a new window starts. Present on
				// 200s too. Observability-only side effect; never blocks the request.
				if resets, ok := observedWindowResetEpochs(resp.Header); ok {
					p.poolObservedResets.record(route.AccountID, resets)
				}
				// P1-C tier-first guard (2026-07-19, sub2api "must not fall through"):
				// a 429 whose SOLE trigger is a premium-model window (Fable 7d_oi)
				// cools (account, tier) only — the aggregate unified headers mirror
				// the representative claim, so without this guard the generic
				// evidence path below would cool the WHOLE account and block every
				// other model's traffic too (pool-wide, via in-request failover).
				nowT := time.Now()
				tierUntil, tierKey, tierOnly := time.Time{}, "", false
				if resp.StatusCode == http.StatusTooManyRequests {
					tierUntil, tierKey, tierOnly = anthropicTierOnlyLimit(resp.Header, nowT)
					// self-surfacing tier-table gap detection (Phase 0 folded into
					// post-deploy log verification): an exhausted window id we don't
					// map yet is loudly visible instead of silently misclassified.
					if wins := unknownExhaustedWindows(resp.Header); len(wins) > 0 {
						logger.Warn("pool 429 carries unmapped exhausted rate-limit window(s)",
							"event.name", observability.EventProxyGroupModelTierCooldown,
							"account_id", route.AccountID,
							"window_ids", strings.Join(wins, ","))
					}
				}
				if tierOnly {
					p.poolCooldown.markTier(route.AccountID, tierKey, tierUntil)
					logger.Warn("pool account model-tier cooled down (other models keep serving)",
						"event.name", observability.EventProxyGroupModelTierCooldown,
						"oauth_group_id", route.OauthGroupID,
						"account_id", route.AccountID,
						"tier", tierKey,
						"until", tierUntil.Unix())
				} else if until, ok := cooldownDecision(resp, nowT); ok {
					p.poolCooldown.markWithState(route.AccountID, until, cooldownRouteState(resp, nowT, until))
					logger.Warn("pool account cooled down after upstream failure",
						"event.name", observability.EventProxyGroupAccountCooldown,
						"oauth_group_id", route.OauthGroupID,
						"account_id", route.AccountID,
						"status", resp.StatusCode)
				} else if resp.StatusCode >= 500 {
					// P0-B (2026-07-19): generic 5xx cools only after CONSECUTIVE
					// repeats — a single transient 502/503 must not pull a good
					// account, but a persistently-broken one must stop eating one
					// wasted in-request-failover attempt per request (N9 hides the
					// failure from the CLIENT; this stops the WASTE).
					if _, cooled := p.poolCooldown.noteServerError(route.AccountID); cooled {
						// noteServerError marked the cooldown itself (atomic with the
						// streak reset) — this is the observability side only.
						logger.Warn("pool account cooled down after repeated server errors",
							"event.name", observability.EventProxyGroupAccountCooldown,
							"oauth_group_id", route.OauthGroupID,
							"account_id", route.AccountID,
							"status", resp.StatusCode,
							"streak_threshold", serverErrStreakThreshold)
					}
				} else if resp.StatusCode < 400 {
					// success proves the account serves → reset its 5xx streak.
					p.poolCooldown.noteSuccess(route.AccountID)
				}
				// N10 防封 pre-cut: on a successful response, if the account's utilization
				// crossed its randomized cap, cool it down for this window so it
				// never hits 100% (which looks like abuse upstream). Error responses
				// are owned by the reactive classifier above; an exhaustion 429 often
				// carries the same 100%-used headers and must retain its precise state.
				if caps, ok := windowCapsFromContext(resp.Request); ok {
					if until, hit := successfulDualWindowPreCutDecision(resp, caps, time.Now()); hit {
						retryAt := until.Unix()
						p.poolCooldown.markWithState(route.AccountID, until, PoolAccountRouteState{
							Status: poolRouteWindowProtected, RetryAt: retryAt,
						})
						logger.Warn("pool account pre-cut at window cap",
							"event.name", observability.EventProxyGroupWindowPrecut,
							"oauth_group_id", route.OauthGroupID,
							"account_id", route.AccountID,
							"cap_5h_pct", caps.FiveHour,
							"cap_7d_pct", caps.SevenDay)
					}
				}
			}

			// Upstream-headers debug toggle: log a "response snapshot" with
			// status + body + selected response headers (rate-limit + retry
			// hints) for ANY status code. Why every status, not just 4xx:
			// the user-facing failure mode "opencode shows error" can be
			// 200-with-empty-content, 200-with-error-body, 4xx, or 5xx; a
			// snapshot scoped to 4xx misses the first two. Truncated to
			// debug4xxBodyCap so log lines stay bounded.
			if debugUpstreamHeadersEnabled() {
				respBody, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				resp.Body = io.NopCloser(bytes.NewReader(respBody))
				resp.ContentLength = int64(len(respBody))
				rateLimitHeaders := map[string]string{}
				for k, v := range resp.Header {
					kl := strings.ToLower(k)
					if strings.Contains(kl, "ratelimit") || kl == "x-should-retry" || kl == "retry-after" || kl == "request-id" || kl == "anthropic-organization-id" {
						rateLimitHeaders[k] = strings.Join(v, ", ")
					}
				}
				logger.Info("upstream response snapshot",
					"event.name", "proxy.response.upstream_snapshot",
					"status_code", resp.StatusCode,
					"upstream_request_id", extractUpstreamRequestID(resp),
					"response_signal_headers", rateLimitHeaders,
					"response_body", truncateBodyForLog(respBody),
				)
			}
			if resp.StatusCode >= 400 {
				// 2026-05-25 — default-on app-pipeline 4xx/5xx forensic
				// WARN log. Symptom that motivated this: a third-party
				// APP's OAuth call returned 8 × 404 from Anthropic, and
				// neither the WAL nor the proxy log captured the
				// outbound URL or upstream error envelope — we couldn't
				// distinguish "wrong URL" / "wrong model" / "WAF body
				// rejection" without that data. The opt-in
				// AIKEY_PROXY_DEBUG_4XX_BODIES capture below is verbose
				// (full request/response body), but that's gated
				// because bodies contain user prompts (PII). This new
				// log stays default-on by limiting to non-PII fields:
				// status + outbound URL + response envelope error
				// metadata + route shape. No body contents.
				//
				// Scoped to RouteSource == "app" because the legacy
				// /v1/... and provider-prefix paths already have their
				// own observability surfaces; this fills the third-
				// party app gap specifically.
				if route.RouteSource == "app" {
					p.logAppUpstreamErrorForensic(logger, r, resp, route, realKey)
				}
				// Optional debug capture: when AIKEY_PROXY_DEBUG_4XX_BODIES
				// is set, drain the upstream body, log it together with the
				// stashed request body, and re-buffer so the client still
				// gets the original payload. Truncated to debug4xxBodyCap
				// to keep the jsonl line bounded.
				//
				// Why log only for 4xx (not 5xx): 5xx is usually upstream
				// infrastructure (timeouts, gateway errors); the response
				// body is rarely informative. 4xx is where provider-side
				// validation rejects something specific in the request,
				// which is exactly what this capture exists to inspect.
				if debug4xxEnabled() && resp.StatusCode < 500 {
					respBody, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					resp.Body = io.NopCloser(bytes.NewReader(respBody))
					resp.ContentLength = int64(len(respBody))
					reqBody := debugRequestBodyFromContext(r.Context())
					logger.Warn("upstream 4xx body capture",
						"event.name", "proxy.request.4xx_body_capture",
						"status_code", resp.StatusCode,
						"upstream_request_id", extractUpstreamRequestID(resp),
						"provider", route.ProviderCode,
						"request_path", r.URL.Path,
						"request_content_type", r.Header.Get("Content-Type"),
						"response_content_type", resp.Header.Get("Content-Type"),
						"request_body", truncateBodyForLog(reqBody),
						"response_body", truncateBodyForLog(respBody),
					)
				}
				// Error response: record immediately without token counts.
				p.recordEvent(r, resp, startTime, route, bearerToken, streaming)
				return nil
			}
			// Reverse tool-name rewrite — runs only when forward (in oauth_inject)
			// stored a mapping on the request context. Real Claude CLI traffic
			// has no mapping → no-op. See oauth_tool_rewrite.go.
			toolNameRevMapping := toolNameMappingFrom(r.Context())

			if !streaming {
				// Non-streaming success: read body, extract tokens, re-buffer.
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					return nil
				}
				body = rewriteToolNamesReverseJSON(body, toolNameRevMapping)

				// Token extraction runs on the upstream-NATIVE body shape
				// (e.g. Anthropic for an App pipeline binding pointed at
				// Claude). The optional ResponseTransform below runs AFTER
				// this so the translation step doesn't affect usage events.
				breakdown := prov.ExtractTokenBreakdown(body, false, logger)

				// Phase 2 (App pipeline only): if a ResponseTransform is
				// armed on the ResolvedRoute, translate the upstream body
				// to the inbound protocol shape (e.g. Anthropic → OpenAI).
				// Tier 1 / Tier 2 routes leave this field nil → block is
				// a single nil-check no-op. On failure: rewrite status to
				// 502 + emit a synthetic OpenAI-style error envelope so
				// the client gets a precise, structured error instead of
				// the upstream's body or a generic httputil 502.
				if route.ResponseTransform != nil {
					translated, terr := route.ResponseTransform(r.Context(), body)
					if terr != nil {
						logger.Error("app pipeline response translation failed",
							"event.name", "proxy.response.translation_failed",
							"error", terr,
							"provider", route.ProviderCode,
							"app_slug", route.AppSlug,
						)
						resp.StatusCode = http.StatusBadGateway
						resp.Status = "502 Bad Gateway"
						// Drop transfer/content encoding headers that
						// referred to the upstream body we're discarding.
						resp.Header.Del("Content-Length")
						resp.Header.Del("Content-Encoding")
						resp.Header.Del("Transfer-Encoding")
						resp.Header.Set("Content-Type", "application/json")
						errBody := []byte(`{"error":{"type":"server_error","code":"RESPONSE_TRANSLATION_FAILED","message":"Upstream response could not be translated back to the inbound protocol shape: ` +
							jsonEscapeForError(terr.Error()) + `"}}`)
						resp.Body = io.NopCloser(bytes.NewReader(errBody))
						resp.ContentLength = int64(len(errBody))
						// Still record the event with the upstream-native
						// breakdown so usage isn't lost on translation
						// failures.
						p.recordEvent(r, resp, startTime, route, bearerToken, streaming)
						return nil
					}
					body = translated
					// Translator changed the body size — drop the upstream's
					// Content-Length header so Go's net/http server recomputes
					// it from the new body length. Without this, the client
					// sees `transfer closed with N bytes remaining` because
					// the header still advertises the upstream-side size.
					resp.Header.Del("Content-Length")
					resp.Header.Del("Content-Encoding")
					resp.Header.Del("Transfer-Encoding")
				}

				// P3 (design D-5): restore the response model name to the
				// client's original when the request leg mapped it, so the
				// client recognizes its own model (N2). No-op unless mapping
				// happened. This is the non-streaming leg; the streaming leg's
				// SSE restoration is IMPLEMENTED via newSSEModelRewriter (P3.3),
				// wired in the streaming branch below.
				body = restoreResponseModel(r.Context(), body)

				// Rebuffer with the FINAL body (post-translation if engaged,
				// otherwise unchanged from upstream).
				resp.Body = io.NopCloser(bytes.NewReader(body))
				resp.ContentLength = int64(len(body))

				// Caller-side double defense per principles/logging-conventions.md:
				// extractor may have logged a WARN for a known shape mismatch, but if
				// it returned (0, 0) on a non-empty 2xx body without WARN'ing (new
				// wire format the extractor wasn't updated for), this catches it.
				// Note: `body` may be post-translation here, but breakdown was
				// computed from the upstream-native body above so the WARN
				// condition is unchanged in semantics.
				if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
					len(body) > 100 &&
					breakdown.InputTokens == 0 && breakdown.OutputTokens == 0 {
					logger.Warn("non-streaming: 2xx response with non-empty body but extractor produced zero tokens",
						"event.name", observability.EventProxyExtractionEmpty,
						"error.code", observability.ErrCodeUsageExtractionFailed,
						"provider", route.ProviderCode,
						"path", r.URL.Path,
						"body_len", len(body),
					)
				}
				ev := p.buildBaseEvent(r, resp, startTime, route, false)
				ev.InputTokens = breakdown.InputTokens
				ev.OutputTokens = breakdown.OutputTokens
				// 2026-05-09 response-first model: prefer the
				// upstream-resolved model id from the JSON response
				// (often a dated pin like claude-opus-4-7-20251015)
				// over the request-body model (alias the client sent)
				// captured by extractModel(). Fall back to the
				// request-side value when the body was malformed or
				// the extractor returned an empty Model.
				if breakdown.Model != "" {
					ev.Model = breakdown.Model
				}
				// Probe traffic is forwarded normally so the CLI gets a truthful
				// status code, but must not inflate usage counters or trigger
				// reporter uploads (it'd be double-counting our own self-tests).
				if !isAikeyProbe(r) {
					p.collector.Record(&ev)
					// Non-streaming always terminates atomically — the response is
					// either the full JSON or it's an error we surface elsewhere.
					sessionID := resolveSessionID(r, route.ProtocolType, route.ProviderCode)
					upstreamReqID := extractUpstreamRequestID(resp)
					p.reportUsage(route, bearerToken, ev.Model, startTime, resp.StatusCode, breakdown, "", "", realKey, sessionID, "complete", upstreamReqID, r.URL.Path)
					// Phase 2: accrue token + local usd quota for this completed request.
					// Backfill the model for local usd pricing when the adapter left it
					// empty (mirrors the streaming path) so codex/others aren't unpriced.
					if breakdown.Model == "" {
						breakdown.Model = ev.Model
					}
					p.accrueQuotaUsage(route, breakdown, logger)
				}
			} else {
				// Streaming success: wrap body — background goroutine drains the
				// full SSE stream and records token usage when it ends, regardless
				// of whether the client stays connected.
				baseEvent := p.buildBaseEvent(r, resp, startTime, route, true)
				// Capture probe flag + session_id from the request now; by
				// callback time the request's header map may have been recycled.
				probe := isAikeyProbe(r)
				sessionID := resolveSessionID(r, route.ProtocolType, route.ProviderCode)
				// Capture the path now too — same request-recycling caveat.
				requestPath := r.URL.Path
				// Capture upstreamReqID NOW (response headers are stable from
				// here onward; the streaming body keeps draining in a goroutine
				// but headers are already finalized by upstream).
				upstreamReqID := extractUpstreamRequestID(resp)
				var cb reporterCallback
				// Fire the completion callback for all non-probe streams (not just
				// when a reporter is configured): Phase 2 Stage 3 quota accrual must
				// count on stream completion even in offline/no-reporter mode. The
				// usage upload stays reporter-gated inside.
				if !probe {
					cb = func(br provider.TokenBreakdown, completion string) {
						// 2026-05-09 response-first: prefer the upstream-resolved
						// model id from the SSE first frame (br.Model) over the
						// request-body model captured into baseEvent. Same logic
						// as in stream_drainer.go where ev.Model gets overridden
						// for the SQLite collector path. Without this fix, the
						// JSONL WAL written via reportUsage would carry the
						// request-side undated alias even when extractor saw a
						// dated upstream response — observed via DEBUG log
						// "DEBUG response-first".
						model := baseEvent.Model
						if br.Model != "" {
							model = br.Model
						}
						if p.reporter != nil {
							p.reportUsage(route, bearerToken, model, startTime, resp.StatusCode, br, "", "", realKey, sessionID, completion, upstreamReqID, requestPath)
						}
						// Phase 2: accrue token + local usd quota on stream completion,
						// independent of the reporter.
						// Local usd pricing keys on br.Model, but some providers' usage
						// frame omits it (Codex /responses SSE) → the request would be
						// left unpriced (usd=0) even though reportUsage recorded the
						// correct `model`. Backfill so the edge price lookup matches the
						// model this request actually ran (2026-07-06 codex-into-pool).
						if br.Model == "" {
							br.Model = model
						}
						p.accrueQuotaUsage(route, br, logger)
					}
				}
				// For probe traffic skip the collector entirely by passing nil.
				collector := p.collector
				if probe {
					collector = nil
				}
				// Wrap upstream BEFORE streamDrainer so SSE chunks are line-
				// buffered + tool_use.name rewritten before the drainer reads
				// them. newSSEToolNameRewriter is a no-op pass-through when
				// the mapping is empty (real CLI traffic).
				upstream := newSSEToolNameRewriter(resp.Body, toolNameRevMapping)
				// P3.3 (design D-5/D-6): restore the streaming response model to
				// the client's original name in the first message_start event.
				// No-op (returns upstream unchanged) unless the request was mapped.
				if clientModel, ok := r.Context().Value(ctxKeyMappedClientModel).(string); ok {
					upstream = newSSEModelRewriter(upstream, clientModel)
				}
				// Phase 4 M2 plugin observer dispatch: pluck the observer
				// context + registry that handleAppPipeline stashed on the
				// route (App pipeline branch only — legacy /v1/... routes
				// leave both nil, the drainer short-circuits). Type-assert
				// here because vkeys/types.go declares both fields as `any`
				// to keep vkeys at the bottom of the dep graph.
				var obsRegistry *observer.Registry
				var obsReqCtx *observer.RequestContext
				if route.ObserverRegistry != nil {
					obsRegistry, _ = route.ObserverRegistry.(*observer.Registry)
				}
				if route.ObserverContext != nil {
					obsReqCtx, _ = route.ObserverContext.(*observer.RequestContext)
				}
				resp.Body = newStreamDrainer(upstream, &baseEvent, prov, collector, p.proxyCtx, r.Context(), logger, cb, obsRegistry, obsReqCtx)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.errors.Add(1)
			latencyMs := time.Since(startTime).Milliseconds()
			// P0-B (2026-07-19): transport-level failures (dial refused, TLS
			// failure, pre-response timeout, egress hop down) never reach
			// ModifyResponse, so they were invisible to the pool health path —
			// sticky binding kept sending every next request into the dead lane.
			// Count them toward the account's CONSECUTIVE server-error streak
			// (same threshold as generic 5xx; one blip cools nobody). The 502/503
			// written below flows through N9's first-byte gate, so group routes
			// ALSO retry this request on another account. context.Canceled is the
			// CLIENT hanging up (streaming keeps the client context) — not the
			// account's fault, never counted.
			if route.OauthGroupID != "" && route.AccountID != "" && !errors.Is(err, context.Canceled) {
				if _, cooled := p.poolCooldown.noteServerError(route.AccountID); cooled {
					logger.Warn("pool account cooled down after repeated transport errors",
						"event.name", observability.EventProxyGroupAccountCooldown,
						"oauth_group_id", route.OauthGroupID,
						"account_id", route.AccountID,
						"error.message", err.Error(),
						"streak_threshold", serverErrStreakThreshold)
				}
			}
			// Per-account egress dial failure (a socks5 hop refused, or a
			// fallback/url-test group has NO reachable member): surface it plainly
			// so the user knows it's THEIR egress, not the provider, and NEVER fall
			// through to a direct dial (the engine already failed rather than leak).
			var egErr *EgressDialError
			if errors.As(err, &egErr) {
				logger.Error("per-account egress connect failed",
					"event.name", observability.EventProxyRequestUpstreamError,
					"error.code", observability.ErrCodeAccountEgressProxy,
					"error.message", err.Error(),
					"latency_ms", latencyMs,
					"account_id", route.AccountID,
				)
				writeJSONError(w, http.StatusServiceUnavailable, "server_error", observability.ErrCodeAccountEgressProxy,
					accountEgressErrorMessage(route,
						"its configured egress upstream is unreachable. Run `aikey doctor` and check this account's egress setting."))
				return
			}
			logger.Error("upstream error",
				"event.name", observability.EventProxyRequestUpstreamError,
				"error.code", observability.ErrCodeUpstreamError,
				"error.message", err.Error(),
				"latency_ms", latencyMs,
			)
			writeJSONError(w, http.StatusBadGateway, "server_error", "UPSTREAM_ERROR",
				"Failed to connect to upstream provider.")
		},
		FlushInterval: -1, // Flush immediately for SSE streaming.
	}

	// ConcurrencyPeak signal (best-effort, main-link-safe): count this credential
	// as in-flight for the upstream forward, release on completion. defer
	// guarantees the decrement even if ServeHTTP panics, so the live counter can't
	// leak. trackInflight returns a no-op closure for a nil reporter / empty
	// CredentialID, so this stays a single cheap map-lock with no extra branching.
	// Placed AFTER the quota gate + inbound-filter early-returns above, so only
	// requests that actually reach the upstream are counted (blocked ones never
	// inc). ponytail: scoped to the synchronous ServeHTTP window — for streaming
	// that blocks until the SSE copy to the client finishes, a good-enough
	// concurrency proxy; chasing the detached non-streaming token-drain goroutine
	// would need cross-goroutine lifetime tracking for marginal accuracy.
	defer p.signalReporter.trackInflight(route.CredentialID)()
	rp.ServeHTTP(w, r)

	// 10. Slow request detection (after the full response is sent).
	latencyMs := time.Since(startTime).Milliseconds()
	if latencyMs >= p.VerySlowRequestMs {
		logger.Warn("very slow request",
			"event.name", observability.EventProxyRequestSlow,
			"latency_ms", latencyMs,
			"threshold_ms", p.VerySlowRequestMs,
		)
	} else if latencyMs >= p.SlowRequestMs {
		logger.Info("slow request",
			"event.name", observability.EventProxyRequestSlow,
			"latency_ms", latencyMs,
			"threshold_ms", p.SlowRequestMs,
		)
	}
}

// accountEgressErrorMessage names the selected shared account when that identity
// is available. Members can see the same identity on /user/team-oauth, so this
// is actionable context rather than a secret; omitting it made failover errors
// look like an unrelated account/login problem.
func accountEgressErrorMessage(route *vkeys.ResolvedRoute, detail string) string {
	subject := "The selected shared account"
	if route != nil && strings.TrimSpace(route.OAuthIdentity) != "" {
		subject += " (" + strings.TrimSpace(route.OAuthIdentity) + ")"
	}
	return "AiKey: " + subject + " is signed in, but " + detail
}
