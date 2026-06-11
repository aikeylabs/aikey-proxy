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
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
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
//nolint:unparam // `stream` kept parameterized for the SPEC §1.4.1
// stream taxonomy (today only user_chat reaches here; future agent_chat /
// agent_event branches will reuse this wrapper). Inlining the constant
// would make adding the next stream branch a re-plumb across 5 call sites.
func (p *Proxy) serveRouteWithObserver(
	w http.ResponseWriter, r *http.Request,
	route *vkeys.ResolvedRoute, prov provider.Provider,
	realKey, inboundBearer string,
	startTime time.Time, logger *slog.Logger,
	stream string, traceID string,
) {
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
		pf := route.ProtocolFamily
		if pf == "" && route.ProviderCode != "" {
			if pr, ok := provider.Routes().ByProvider(route.ProviderCode); ok {
				pf = pr.Protocol
			}
		}
		obsReqCtx = &observer.RequestContext{
			KeyAlias:       route.KeyAlias,
			ProviderID:     route.ProviderCode,
			ProtocolFamily: pf,
			SessionID:      resolveSessionID(r, route.ProtocolType, route.ProviderCode),
			TraceID:        traceID,
			StartedAt:      startTime,
		}
		route.ObserverContext = obsReqCtx
		route.ObserverRegistry = p.observerRegistry
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

		// Codex BaseURL override pinned by TestFence_OAuthBinding_OpenAICodexBaseURLOverride.
		// Why: Codex OAuth uses chatgpt.com/backend-api/codex (Responses API),
		// NOT api.openai.com/v1 (Chat Completions API). API key users hit
		// api.openai.com; OAuth users hit chatgpt.com.
		// Ref: workflow/CI/research/oauth-codex-test/main.go
		if canonicalCode == "openai" {
			out.BaseURL = "https://chatgpt.com/backend-api/codex"
			// Stage the `model` field into request context. Actual
			// persistence is deferred to ModifyResponse, which only
			// writes the file when upstream returned 2xx — see
			// codex_model_capture.go for the bug-2026-06-09 rationale.
			// `captureCodexModel` returns a NEW request with the value
			// in context; reassign to propagate downstream.
			r = captureCodexModel(r)
		} else {
			out.BaseURL = providerDefaultBaseURL(canonicalCode)
		}
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

	case "team":
		mk, err := p.activeReader.GetTeamKeyByID(binding.KeySourceRef)
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
			out.BaseURL = providerDefaultBaseURL(canonicalCode)
		}
		return out, nil
	}
}

// serveRoute executes the forwarding pipeline (streaming detection, transport
// selection, reverse proxy) shared by token-based and path-prefix routing.
func (p *Proxy) serveRoute(w http.ResponseWriter, r *http.Request, route *vkeys.ResolvedRoute, prov provider.Provider, realKey string, bearerToken string, startTime time.Time, logger *slog.Logger) {
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
	if !p.applyInboundFilter(w, r, extractModel(r), route.RouteSource, route.OrgID, route.VirtualKeyID, logger) {
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
				case <-cn.CloseNotify(): //nolint:staticcheck
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
	inner := p.transport
	if inner == nil {
		inner = http.DefaultTransport
		logger.Debug("using default transport (no custom transport set)")
	} else {
		logger.Debug("using custom transport (upstream proxy)")
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

	// 9. Build and execute reverse proxy.
	rp := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			if realKey == "__oauth__" {
				// OAuth: headers already injected by oauthInject() — only set upstream URL.
				// BaseURL may contain a path prefix (e.g. https://api.kimi.com/coding)
				// that must be prepended to the request path.
				if u, err := url.Parse(route.BaseURL); err == nil {
					req.URL.Scheme = u.Scheme
					req.URL.Host = u.Host
					req.Host = u.Host
					if u.Path != "" && u.Path != "/" {
						req.URL.Path = strings.TrimRight(u.Path, "/") + req.URL.Path
					}
				}
			} else {
				if err := prov.RewriteRequest(req, realKey, route.BaseURL); err != nil {
					logger.Error("rewrite request failed", "error", err)
				}
			}
			// Remove hop-by-hop headers the proxy shouldn't forward.
			req.Header.Del("X-Forwarded-For")

			// Strip AiKey-internal annotations before forwarding. These are
			// stashed onto the incoming request by extractModel() /
			// stashExtractedFields() for downstream usage-event recording
			// (see stashExtractedFields, proxy.go:1436). They must NOT
			// reach the upstream provider — Anthropic's OAuth WAF, in
			// particular, treats unrecognized headers as a persona signal
			// that the request isn't a real Claude Code session, returning
			// 429 with no X-RateLimit-Reset (business rejection signature).
			// Strip the whole `x-aikey-*` namespace so future internal
			// annotations don't repeat this leak.
			for k := range req.Header {
				if len(k) >= 8 && strings.EqualFold(k[:8], "X-Aikey-") {
					req.Header.Del(k)
				}
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
			// Codex OAuth model capture — only persist on 2xx so a bad
			// `model: gpt-4o` request (rejected by ChatGPT-account
			// Codex) can't poison the state file the connectivity probe
			// reads. See codex_model_capture.go §2026-06-09 deferred-
			// persist redesign. No-op for non-Codex paths because
			// ctxKeyCodexCandidateModel is only stashed inside the
			// canonicalCode == "openai" OAuth branch above.
			persistCodexLastModelIfSuccessful(resp.Request, resp.StatusCode)

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
					p.collector.Record(ev)
					// Non-streaming always terminates atomically — the response is
					// either the full JSON or it's an error we surface elsewhere.
					sessionID := resolveSessionID(r, route.ProtocolType, route.ProviderCode)
					upstreamReqID := extractUpstreamRequestID(resp)
					p.reportUsage(route, bearerToken, ev.Model, startTime, resp.StatusCode, breakdown, "", "", realKey, sessionID, "complete", upstreamReqID)
					// Phase 2: accrue token + local usd quota for this completed request.
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
							p.reportUsage(route, bearerToken, model, startTime, resp.StatusCode, br, "", "", realKey, sessionID, completion, upstreamReqID)
						}
						// Phase 2: accrue token + local usd quota on stream completion,
						// independent of the reporter.
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
				resp.Body = newStreamDrainer(upstream, baseEvent, prov, collector, p.proxyCtx, r.Context(), logger, cb, obsRegistry, obsReqCtx)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.errors.Add(1)
			latencyMs := time.Since(startTime).Milliseconds()
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
