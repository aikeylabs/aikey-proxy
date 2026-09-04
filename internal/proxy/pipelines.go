// pipelines.go — the three pipeline-entry handlers + their shared
// response-writer wrapper.
//
//   - handleAppPipeline      — /apps/<slug>/v1/...   (Phase 4 App pipeline)
//   - handleProbePipeline    — /probe/<alias>/v1/... (Probe / mode C)
//   - handlePathPrefixRoute  — /v1/... and /<provider>/v1/... (legacy)
//
// Each handler stages: parse → authn → resolve binding → translate
// (App only) → forward → record. Forwarding itself is delegated to
// serveRoute / serveRouteWithObserver in forward_and_resolve.go.
//
// Also holds appPipelineStatusWriter — a thin http.ResponseWriter
// wrapper that captures the final status code on every exit path so
// the in-memory AppHealthCache (see apppipe/health.go) can record
// each app's last-call health for the Web "Connected Apps" Health
// column.
//
// Split out of proxy.go on 2026-05-26 — see
// workflow/CI/refactor/2026-05-26-proxy-go-split.md for the file map.
package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/apppipe"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/probepipe"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/uaattribution"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// oauthSentinelKey is the placeholder value stored in the "real key" slot for
// OAuth routes. It is NOT a credential: the actual bearer token is injected
// into the upstream request headers by oauthInject. Keeping it as a named
// constant gives a single source of truth and avoids the literal being
// (mis)read as a hardcoded secret.
const oauthSentinelKey = "__oauth__"

// appPipelineStatusWriter wraps an http.ResponseWriter so handleAppPipeline
// can observe the final HTTP status (and optional proxy-side error
// category) on every exit path — early proxy-synthesized 4xx as well as
// the ReverseProxy success path that copies the upstream status through.
//
// Why not net/http/httptest.ResponseRecorder: that one buffers the entire
// body in memory. We need a transparent passthrough so streaming SSE
// responses (the common app-pipeline success shape) aren't buffered.
//
// Why a custom field for errorType: we want the per-slug HealthCache to
// optionally carry a proxy-side category string (e.g. "base_url_misconfigured")
// that callers set explicitly when they synthesize a 4xx. The HTTP wire
// has no header for this, so we thread it via a method on the wrapper.
//
// Concurrency: a single handler goroutine owns the wrapper for the duration
// of the request — no mutex needed.
type appPipelineStatusWriter struct {
	http.ResponseWriter
	errorType  string
	statusCode int
	written    bool
}

func (s *appPipelineStatusWriter) WriteHeader(code int) {
	if !s.written {
		s.statusCode = code
		s.written = true
	}
	s.ResponseWriter.WriteHeader(code)
}

// Write captures the implicit "200 OK because the handler wrote a body
// without calling WriteHeader" case (net/http's own contract). statusCode
// was pre-seeded to 200 in the wrapper constructor so we don't need to
// overwrite here — but we do need to flip the written flag so a later
// WriteHeader call (which net/http would log as "superfluous") doesn't
// overwrite the observed-as-200 code.
func (s *appPipelineStatusWriter) Write(b []byte) (int, error) {
	if !s.written {
		s.written = true
	}
	return s.ResponseWriter.Write(b)
}

// Flush forwards to the underlying writer's Flush if it implements
// http.Flusher — required so SSE streams (which the App pipeline often
// produces) aren't buffered behind the wrapper. Without this method the
// wrapper would silently break streaming responses.
func (s *appPipelineStatusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// handleAppPipeline is the entry into the Phase 4 App pipeline for requests
// matching /apps/<slug>/v1/... (Tier 0a in proxy.Handle's
// routing order). Today it's a structural stub returning 501 with the
// parsed AppContext for diagnosability — Sprint 2 remaining tasks
// (AKL-204 authn, AKL-205 resolve, AKL-206 egress sanitizer, AKL-207
// pipeline editorial) replace this body with the full pipeline.
//
// Until those land, this handler proves the wiring works end-to-end:
//  1. Tier 0a routing fires (URL parsing — AKL-203)
//  2. The user sees confirmation that slug + protocol parsed correctly
//  3. Counters + logger context include app_slug + app_protocol for
//     operator visibility while the pipeline is being filled in
//
// The 501 is intentional vs 503: per RFC 9110, 501 says "the server does
// not support the functionality required to fulfill the request" which
// matches "this endpoint exists in routing but its handler is not yet
// wired", whereas 503 implies temporary unavailability of a working
// service. Clients (test scripts, integration probes) can distinguish
// "deploy in progress" (501) from "transient downstream failure" (503).
func (p *Proxy) handleAppPipeline(w http.ResponseWriter, r *http.Request, appCtx *apppipe.AppContext, startTime time.Time, logger *slog.Logger, traceID string) {
	_ = startTime
	logger = logger.With("app_slug", appCtx.Slug)

	// Wrap the response writer so we observe the final status code on
	// EVERY exit path — proxy-side early errors (BASE_URL_MISCONFIGURED,
	// authn fail, resolve fail) AND the ReverseProxy success path
	// (upstream status passed through). The captured value drives the
	// per-slug HealthCache update below, which the Web "Connected Apps"
	// list reads to populate the Health column.
	//
	// Default 200 mirrors net/http's own behavior: if a handler writes a
	// body without calling WriteHeader, Go implicitly uses 200. Capturing
	// "actually called WriteHeader yet?" via the bool gives us a cheap
	// way to distinguish "explicit 200" from "implicit 200 because the
	// handler wrote no header and no body" — useful when the early-exit
	// path forgets WriteHeader (we'd see 200, which is the bug, but at
	// least we record the actual on-wire status).
	sw := &appPipelineStatusWriter{ResponseWriter: w, statusCode: http.StatusOK}
	w = sw
	defer func() {
		// `errorType` left empty for now — the UI's 4-bucket classification
		// (OK / Warn / Error / Never) only needs status_code. Future work
		// can thread a proxy-side error code (e.g. "base_url_misconfigured")
		// through via sw.errorType for richer tooltip detail without
		// changing the cache shape.
		p.recordAppHealth(appCtx.Slug, sw.statusCode, sw.errorType)
	}()

	// 2026-05-25 防呆 (double-v1 base_url misconfiguration):
	//
	// Real-world bug seen with Anthropic Python SDK + claude-mem-style
	// plugin: the SDK appends "/v1/messages" to the configured base_url
	// unconditionally. If the user set base_url to
	// "http://127.0.0.1:27200/apps/<slug>/v1" (the form that works for
	// openai-python, which appends "/chat/completions" without "/v1"),
	// the Anthropic SDK produces
	// "http://127.0.0.1:27200/apps/<slug>/v1/v1/messages" — double v1.
	//
	// ExtractAppPath happily parses this as
	// {Slug:<slug>, StrippedPath:"/v1/messages"}, then the handler
	// prepends "/v1" again on line 921 → outbound URL becomes
	// "https://api.anthropic.com/v1/v1/messages" which Anthropic 404s
	// with "Not Found". The user sees an opaque 404 with no clue that
	// it's a base_url config error on their side.
	//
	// Detection: strippedPath starting with "/v1/" means the inbound URL
	// was /apps/<slug>/v1/v1/... (only the second v1 ends up in
	// strippedPath after the first one was stripped). No legitimate
	// upstream path starts with /v1 (Anthropic uses /messages,
	// /complete; OpenAI uses /chat/completions, /embeddings; none start
	// with another "v1" segment). Safe to reject.
	//
	// Emit a precise, actionable error so the user fixes it in their
	// SDK config rather than blaming AiKey for "404 from upstream".
	if strings.HasPrefix(appCtx.StrippedPath, "/v1/") || appCtx.StrippedPath == "/v1" {
		p.errors.Add(1)
		logger.Warn("app pipeline base_url misconfigured (double /v1)",
			"event.name", "proxy.app.base_url_misconfigured",
			"inbound_path", r.URL.Path,
			"stripped_path", appCtx.StrippedPath,
			"hint", "client base_url likely ends with /v1 AND SDK appends another /v1/<endpoint>",
		)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "BASE_URL_MISCONFIGURED",
			fmt.Sprintf(
				"Your client's base_url has a double /v1/ — received URL %q after stripping "+
					"the app prefix becomes %q, which means the original URL was "+
					"/apps/%s/v1/v1/... — that 'second v1' was added by your SDK on top of the /v1 "+
					"already in your base_url. Fix: drop /v1 from base_url. "+
					"For Anthropic SDK: base_url=\"http://127.0.0.1:27200/apps/%s\" (no trailing /v1). "+
					"For OpenAI SDK: base_url=\"http://127.0.0.1:27200/apps/%s/v1\" (keep /v1 — OpenAI SDK appends /chat/completions without /v1).",
				r.URL.Path, appCtx.StrippedPath, appCtx.Slug, appCtx.Slug, appCtx.Slug,
			))
		return
	}

	// Stage 1: authn — extract bearer, verify Registry membership, check
	// the URL slug matches the token's vault-recorded AppSlug.
	route, authErr := apppipe.Authenticate(r.Header, p.registry, appCtx)
	if authErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline authn failed",
			"error.code", authErr.ErrorCode,
			"event.name", observability.EventProxyRequestAuthFailed,
		)
		writeJSONError(w, authErr.StatusCode, "authentication_error", authErr.ErrorCode, authErr.Message)
		return
	}

	// Stage 2: resolve metadata-only — pick profile scope + load app_records.
	// Binding lookup is deferred to Stage 4 (after body sanitize + model
	// inference); the inferred upstream is the lookup key.
	resolved, resolveErr := apppipe.Resolve(p.appVault, route, appCtx)
	if resolveErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline resolve failed",
			"error.code", resolveErr.ErrorCode,
			"app_key_id", route.AppKeyID,
			"app_kind", route.AppKind,
		)
		writeJSONError(w, resolveErr.StatusCode, "server_error", resolveErr.ErrorCode, resolveErr.Message)
		return
	}

	// Stage 3: sanitize — strip aikey/metadata fields, reject n>1, silent-drop
	// logprobs/seed with warnings. response_format is passed through to the
	// protocol translator (Phase 2 Day 5).
	//
	// Capture the genuine inbound User-Agent BEFORE Stage 5 (which calls
	// oauthInject → forces UA to "claude-cli/2.1.22 (external, cli)" for
	// non-CLI clients). The post-translation WAF re-rewrite below needs
	// to know if the original client was real Claude CLI (skip rewrite)
	// vs a third-party SDK (apply rewrite). Without this snapshot the
	// post-translation check always sees the masked UA.
	inboundUAWasClaudeCode := clientIsClaudeCode(r)

	bodyBytes, bodyErr := io.ReadAll(r.Body)
	if bodyErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline body read failed", "error", bodyErr)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "BODY_READ_FAILED",
			"Could not read request body: "+bodyErr.Error())
		return
	}
	_ = r.Body.Close()

	sanitized, sanitizeCtx, sanitizeErr := apppipe.SanitizeRequestBody(bodyBytes)
	if sanitizeErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline body sanitize failed",
			"error.code", sanitizeErr.ErrorCode,
			"app_key_id", route.AppKeyID,
		)
		writeJSONError(w, sanitizeErr.StatusCode, "invalid_request_error", sanitizeErr.ErrorCode, sanitizeErr.Message)
		return
	}
	for _, w := range sanitizeCtx.Warnings {
		logger.Warn("app pipeline field degraded", "degradation", w, "app_key_id", route.AppKeyID)
	}

	// Stage 4 (Phase 2 Day 7): infer upstream from body.model and look up
	// the binding for (profile, upstream). This replaces the URL-protocol-
	// based binding lookup of Phase 1. The Agent's body.model field is the
	// single routing signal — LangChain-aligned per industry consensus.
	inboundModel := extractModelLazy(sanitized)
	inferredUpstream := provider.InferUpstreamFromModel(inboundModel)
	binding, bindResolveErr := apppipe.ResolveUpstreamBinding(p.appVault, resolved, inferredUpstream)
	if bindResolveErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline upstream-binding resolve failed",
			"error.code", bindResolveErr.ErrorCode,
			"app_key_id", route.AppKeyID,
			"model", inboundModel,
			"inferred_upstream", inferredUpstream,
		)
		writeJSONError(w, bindResolveErr.StatusCode, "invalid_request_error",
			bindResolveErr.ErrorCode, bindResolveErr.Message)
		return
	}

	// Preserve the independent client-route, physical-provider and protocol
	// axes. Bound aliases have no stored ClientRoute, so this request supplies
	// it; the credential's ProviderCode is never overwritten with that route.
	normalizedBinding, axesErr := normalizeBindingForClientRoute(binding, inferredUpstream)
	if axesErr != nil {
		p.errors.Add(1)
		errorCode := "BINDING_ROUTE_MISMATCH"
		message := "App \"" + appCtx.Slug + "\" has an invalid binding for body.model route \"" +
			inferredUpstream + "\": " + axesErr.Error()
		if resolved.AppRecord != nil && resolved.AppRecord.BoundAlias != "" {
			errorCode = "BOUND_ALIAS_PROVIDER_MISMATCH"
			message += ". Re-bind with `aikey app update " + appCtx.Slug + " --bound-alias <name>`."
		}
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", errorCode, message)
		return
	}
	binding = normalizedBinding

	// Capture inbound bearer BEFORE Stage 5 — ResolveBindingCredential calls
	// oauthInject which overwrites r.Header.Authorization with the upstream
	// OAuth access token. If we read it AFTER, `extractRawAuthValue(r)` returns
	// the upstream secret instead of the client-presented token, breaking the
	// audit anchor (virtual_key_hash) AND the first-party probe attribution
	// branch in BuildReportableEvent (BR-rc.5-60 fix relies on the client
	// bearer to reverse-lookup the app slug). Bug surfaced via BR-rc.5-60
	// follow-up 2026-05-25 when manual Trust Check probes kept landing in ODS
	// with app_slug=NULL despite the attribution code being in place.
	inboundBearer := extractRawAuthValue(r)

	// Stage 5: resolve credential from binding (shared with legacy path).
	// p.ResolveBindingCredential walks the same OAuth/team/personal branches
	// used by handlePathPrefixRoute — pinned by oauth_binding_fence_test.go.
	// Provider setup is path/body-aware, so present the upstream-facing path and
	// a replayable sanitized body before entering it. This ordering is part of
	// the contract: Codex normalizes /v1/responses and captures body.model here.
	r.URL.Path = "/v1" + appCtx.StrippedPath
	if r.URL.RawPath != "" {
		r.URL.RawPath = r.URL.Path
	}
	r.Body = io.NopCloser(bytes.NewReader(sanitized))
	r.ContentLength = int64(len(sanitized))
	cred, resolvedReq, bindErr := p.ResolveBindingCredential(r, binding, logger)
	if bindErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline credential resolution failed",
			"error.code", bindErr.ErrorCode,
			"app_key_id", route.AppKeyID,
		)
		writeJSONError(w, bindErr.StatusCode, bindErr.ErrorType, bindErr.ErrorCode, bindErr.Message)
		return
	}
	r = resolvedReq
	if cred.RealKey == "" {
		p.errors.Add(1)
		writeJSONError(w, http.StatusServiceUnavailable, "server_error", "BINDING_CREDENTIAL_UNRESOLVED",
			"App's binding (profile=\""+resolved.ProfileID+"\", upstream=\""+inferredUpstream+
				"\", source="+binding.KeySourceType+":"+binding.KeySourceRef+
				") could not be resolved to a usable credential. The referenced "+
				"alias or virtual-key may have been deleted. Re-run `aikey app route "+appCtx.Slug+
				"` to repair.")
		return
	}

	// Stage 6: build the ResolvedRoute without collapsing its axes.
	// ProviderCode is the physical upstream vendor; ProtocolType is the wire
	// adapter selected by the binding. ProtocolFamily prefers the path-aware
	// base_url row (important for GLM's multiple endpoints) and otherwise uses
	// the exact Provider+Protocol compatibility row.
	protocolType := binding.ProtocolType
	if protocolType == "" && cred.ManagedKey != nil && cred.ManagedKey.ProtocolType != "" {
		protocolType = cred.ManagedKey.ProtocolType
	}
	protocolFamily := ""
	if pr, ok := provider.Routes().LookupByBaseURL(cred.BaseURL); ok {
		protocolFamily = pr.Protocol
	} else if pf, ok := provider.ProtocolFamily(binding.ProviderCode, protocolType); ok {
		protocolFamily = pf
	}
	if protocolType == "" {
		protocolType = protocolFamily
	}
	appResolvedRoute := &vkeys.ResolvedRoute{
		VirtualKeyID:     route.VirtualKeyID, // "app:<slug>"
		Provider:         binding.ProviderCode,
		BaseURL:          cred.BaseURL,
		KeyAlias:         cred.KeyAlias,
		PlaintextKey:     cred.RealKey,
		OAuthIdentity:    cred.OAuthIdentity,
		AccountID:        cred.OAuthAccountID,
		ProviderCode:     binding.ProviderCode,
		ProtocolType:     protocolType,
		ProtocolFamily:   protocolFamily,
		RouteSource:      "app",
		AppSlug:          route.AppSlug,
		AppKind:          route.AppKind,
		AppKeyID:         route.AppKeyID,
		FollowUserActive: route.FollowUserActive,
	}
	if cred.ManagedKey != nil {
		appResolvedRoute.OrgID = cred.ManagedKey.OrgID
		appResolvedRoute.SeatID = cred.ManagedKey.SeatID
		appResolvedRoute.CredentialID = cred.ManagedKey.CredentialID
		appResolvedRoute.CredentialRevision = cred.ManagedKey.CredentialRevision
		appResolvedRoute.VirtualKeyRevision = cred.ManagedKey.VirtualKeyRevision
	}

	// Stage 7: provider adapter selected by the BINDING's upstream protocol.
	prov, err := p.providers.Get(protocolType)
	if err != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
			"Unknown upstream provider protocol: "+protocolType)
		return
	}

	// Stage 8 (Phase 2 protocol translation, optional): if inbound wire
	// differs from upstream wire (binding.ProtocolType), translate the
	// request body + arm a response-side closure on the ResolvedRoute.
	// No-op when from == to. Phase 2 中方案 (2026-05-21): inbound wire
	// is inferred from URL path — `/v1/messages` ≡ Anthropic, else
	// OpenAI (see apppipe.InferInboundWire).
	inboundFmt := apppipe.InferInboundWire(appCtx.StrippedPath)
	translateOut, translateErr := apppipe.MaybeTranslateRequest(
		r.Context(),
		p.translatorRegistry,
		appResolvedRoute,
		binding,
		inboundFmt,
		r,
		sanitized,
		inboundModel,
	)
	if translateErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline protocol translation failed",
			"error.code", translateErr.ErrorCode,
			"app_key_id", route.AppKeyID,
			"upstream", binding.ProviderCode,
		)
		writeJSONError(w, translateErr.StatusCode, "invalid_request_error", translateErr.ErrorCode, translateErr.Message)
		return
	}
	if translateOut.Engaged {
		logger.Info("app pipeline translation engaged",
			"upstream_format", string(translateOut.UpstreamFormat),
			"app_key_id", route.AppKeyID,
		)
		// Rewrite the upstream path for the target format (e.g.
		// /v1/chat/completions → /v1/messages for Anthropic).
		if canonical := apppipe.CanonicalUpstreamPath(translateOut.UpstreamFormat); canonical != "" {
			r.URL.Path = canonical
			if r.URL.RawPath != "" {
				r.URL.RawPath = canonical
			}
		}
	}

	// Replace request body with the post-translation bytes (or sanitized
	// if no translation engaged — TranslateOutcome.Body is always the
	// final bytes to forward).
	r.Body = io.NopCloser(bytes.NewReader(translateOut.Body))
	r.ContentLength = int64(len(translateOut.Body))

	// Phase 4 fix (2026-05-22, Stage 7 smoke): when OAuth → Anthropic, the
	// WAF body fingerprint must be present in body.system[0]. Stage 5 runs
	// oauthInject against a replay copy, but translation below deliberately
	// rebuilds the final body from the sanitized source. Re-run the WAF rewrite
	// on that final body so translation cannot discard the fingerprint.
	// Without this, Anthropic returns 429 "rate_limit_error" with no
	// anthropic-ratelimit-* headers (business rejection signature, ref
	// workflow/CI/research/oauth-token-response-identity/2026-04-15-oauth-token-response-identity.md).
	oauthCode, _ := oauthInjectionProvider(binding.ProviderCode, protocolType)
	if binding.KeySourceType == "personal_oauth_account" &&
		oauthCode == "anthropic" &&
		!inboundUAWasClaudeCode {
		injectClaudeWAFFingerprintFull(r)
		// injectClaudeWAFFingerprintFull may have rewritten r.Body; sync
		// ContentLength so the reverse proxy reports the correct length
		// to the upstream.
		if r.Body != nil {
			if newBytes, err := io.ReadAll(r.Body); err == nil {
				r.Body = io.NopCloser(bytes.NewReader(newBytes))
				r.ContentLength = int64(len(newBytes))
			}
		}
	}

	// inboundBearer is captured pre-Stage-5 above (moved 2026-05-25 to
	// survive oauthInject's Authorization rewrite — see comment near
	// Stage 5).

	// app_mode tags the credential-resolution path so log readers can tell
	// A vs B mode without re-deriving from follow_user_active + bound_alias
	// fields. SPEC §1.1 / §6.1 anti-example "label deception" was rooted in
	// log fields that didn't distinguish modes; this is the explicit fix.
	appMode := "a"
	if resolved.AppRecord != nil && resolved.AppRecord.BoundAlias != "" {
		appMode = "b"
	}
	logger.Info("app pipeline forwarding upstream",
		"app_key_id", route.AppKeyID,
		"app_kind", route.AppKind,
		"app_mode", appMode,
		"bound_alias", resolved.AppRecord.BoundAlias, // empty in A mode
		"profile_id", resolved.ProfileID,
		"binding_source_type", binding.KeySourceType,
		"upstream_base", cred.BaseURL,
		"upstream", binding.ProviderCode,
		"protocol_family", appResolvedRoute.ProtocolFamily,
	)

	// Phase 4 M2 plugin observer — NotifyStart at App pipeline entry +
	// NotifyEnd at exit. The per-frame NotifySSEEvent dispatch lives
	// inside streamDrainer (gated on the observer registry being
	// attached + ProtocolFamily known) so it sees the byte-identical
	// upstream SSE before ResponseTransform reshapes the chunks.
	//
	// Why we build the RequestContext here (not inside serveRoute):
	// app-specific fields (AppSlug / AppKeyID / AppMode / ProviderID /
	// ProtocolFamily) are only meaningful for the App pipeline branch.
	// serveRoute is shared with the legacy /v1/... + /<provider>/v1/...
	// paths which never need a RequestContext. Wiring here keeps the
	// observer surface contained to the App pipeline by construction.
	//
	// nil observerRegistry ⇒ the Notify* helpers below short-circuit;
	// see Proxy.observerRegistry doc-comment for zero-cost rationale.
	var obsReqCtx *observer.RequestContext
	if p.observerRegistry != nil && p.observerRegistry.Active() > 0 {
		appMode := "isolated"
		if route.FollowUserActive {
			appMode = "follow-active"
		}
		obsReqCtx = &observer.RequestContext{
			AppKeyID: route.AppKeyID,
			AppSlug:  route.AppSlug,
			AppMode:  appMode,
			// KeyAlias is the vault-side credential alias resolved at this
			// step (e.g. user's "claude" for follow-user-active). trust-local
			// uses it as the alias_name primary aggregation key — without it
			// the report falls back to a synthetic "app:<slug>:<keyid>"
			// alias and PerAliasTrust queries can't surface real-user trust
			// per provider key.
			KeyAlias:       appResolvedRoute.KeyAlias,
			ProviderID:     binding.ProviderCode,
			ProtocolFamily: appResolvedRoute.ProtocolFamily,
			RequestedModel: inboundModel,
			SessionID:      resolveSessionID(r, appResolvedRoute.ProtocolType, binding.ProviderCode),
			TraceID:        traceID,
			StartedAt:      startTime,
		}
		// Stash on the route so streamDrainer can pull it out without
		// needing a parallel parameter channel. Tier 1 / Tier 2 routes
		// never set ObserverContext, so the drainer's nil-check
		// short-circuits for legacy paths.
		appResolvedRoute.ObserverContext = obsReqCtx
		appResolvedRoute.ObserverRegistry = p.observerRegistry
		// SPEC §1.4.1: this handler serves the /apps/<slug>/v1/... pipeline
		// so emit under the StreamAppPipeline name. Observers that didn't
		// declare interest in this stream are filtered at Registry level.
		p.observerRegistry.NotifyStart(r.Context(), observer.StreamAppPipeline, obsReqCtx)
	}

	// 🔴 Task 2.0b / F-19 · D-5: the candidate loop hangs HERE for the App
	// pipeline. An App-routed team VK with a route group configured would
	// otherwise show 「配了但没生效」 on the App surface — a chain the administrator
	// can see in the console and that never runs — which is the precise failure
	// this whole change exists to remove.
	//
	// appChain returns nil for every request that has no chain (a personal alias,
	// an OAuth account whose failover the ACCOUNT axis already owns, a team VK
	// with no group, or an app pinned to one member). Those fall through to the
	// single-shot call below, byte for byte as before. See chain_app.go for why
	// the app's own pin row — not the default profile's — is the one consulted.
	if chain := p.appChain(appResolvedRoute, binding, protocolType, logger); chain != nil &&
		(chain.canFailover() || (chain.grouped && len(chain.candidates) == 1)) {
		p.serveManagedChain(w, r, chain, inboundBearer, startTime, logger, traceID, observer.StreamAppPipeline)
		if obsReqCtx != nil {
			latency := int(time.Since(startTime).Milliseconds())
			p.observerRegistry.NotifyEnd(r.Context(), obsReqCtx, latency)
		}
		return
	}

	p.serveRoute(w, r, appResolvedRoute, prov, cred.RealKey, inboundBearer, startTime, logger)

	if obsReqCtx != nil {
		latency := int(time.Since(startTime).Milliseconds())
		p.observerRegistry.NotifyEnd(r.Context(), obsReqCtx, latency)
	}
}

// handleProbePipeline is the entry into the Probe pipeline (mode C) for
// requests matching /probe/<alias>/v1/... See SPEC
// `workflow/CI/requirements/2026-05-23-credential-mode-architecture.md` §1.3.
//
// Pipeline stages (parallel to handleAppPipeline but simpler — no
// app_records / follow_user_active / provider-binding indirection):
//
//  1. authn          — first-party constant Bearer check (probepipe.Authenticate)
//  2. resolve alias  — vault.GetAliasCredential → synthetic ProviderBinding
//  3. sanitize body  — strip aikey/* fields, reject n>1 (reuses apppipe)
//  4. infer upstream — body.model → provider; sanity-check matches alias's provider
//  5. resolve cred   — reuses ResolveBindingCredential (shared with App pipeline)
//  6. build route    — synthesize ResolvedRoute with RouteSource="probe"
//  7. translate      — reuses apppipe.MaybeTranslateRequest (no-op when wire matches)
//  8. forward        — same serveRoute as App / legacy pipelines
//
// Why we reuse so much from apppipe: sanitize / translate / ResolveBindingCredential
// don't depend on app concepts (slug / follow_user_active); they operate on
// (ProviderBinding, request) inputs. Sharing them avoids divergence on the
// shared upstream-injection paths (OAuth WAF fingerprint, model translation,
// SSE drain). Probe-specific differences live entirely in stages 1-2 + 6.
func (p *Proxy) handleProbePipeline(w http.ResponseWriter, r *http.Request, probeCtx *probepipe.ProbeContext, startTime time.Time, logger *slog.Logger, traceID string) {
	_ = traceID
	logger = logger.With("probe_alias", probeCtx.AliasName, "routing", "probe")

	// Stage 1: authn — first-party constant Bearer.
	if authErr := probepipe.Authenticate(r.Header); authErr != nil {
		p.errors.Add(1)
		logger.Warn("probe pipeline authn failed",
			"error.code", authErr.ErrorCode,
			"event.name", observability.EventProxyRequestAuthFailed,
		)
		writeJSONError(w, authErr.StatusCode, "authentication_error", authErr.ErrorCode, authErr.Message)
		return
	}

	// Stage 2: resolve alias → synthetic ProviderBinding.
	aliasCred, resolveErr := probepipe.Resolve(p.probeVault, probeCtx)
	if resolveErr != nil {
		p.errors.Add(1)
		logger.Warn("probe pipeline alias resolve failed",
			"error.code", resolveErr.ErrorCode,
		)
		writeJSONError(w, resolveErr.StatusCode, "server_error", resolveErr.ErrorCode, resolveErr.Message)
		return
	}
	binding := aliasCred.Binding

	// Stage 2b: model discovery (GET /probe/<alias>/v1/models).
	//
	// 🔴 Branches HERE, before stage 3, because stages 3 and 4 both assume a
	// chat request: the sanitizer rejects an empty body with
	// MALFORMED_REQUEST_BODY, and stage 4 infers the upstream from
	// `body.model` — the very thing a discovery call exists to find out. See
	// probe_models.go for why this capability lives in the proxy at all.
	if isProbeModelsRequest(r, probeCtx) {
		p.handleProbeModelsDiscovery(w, r, probeCtx, binding, logger)
		return
	}

	// Capture the genuine inbound User-Agent BEFORE the credential resolve
	// step (which may call oauthInject and mask the UA). Mirrors the
	// handleAppPipeline pattern; needed for the post-translation WAF rewrite
	// decision below.
	inboundUAWasClaudeCode := clientIsClaudeCode(r)

	// Stage 3: sanitize body (reuses apppipe — same egress rules apply).
	bodyBytes, bodyErr := io.ReadAll(r.Body)
	if bodyErr != nil {
		p.errors.Add(1)
		logger.Warn("probe pipeline body read failed", "error", bodyErr)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "BODY_READ_FAILED",
			"Could not read request body: "+bodyErr.Error())
		return
	}
	_ = r.Body.Close()

	sanitized, sanitizeCtx, sanitizeErr := apppipe.SanitizeRequestBody(bodyBytes)
	if sanitizeErr != nil {
		p.errors.Add(1)
		logger.Warn("probe pipeline body sanitize failed",
			"error.code", sanitizeErr.ErrorCode,
		)
		writeJSONError(w, sanitizeErr.StatusCode, "invalid_request_error", sanitizeErr.ErrorCode, sanitizeErr.Message)
		return
	}
	for _, warning := range sanitizeCtx.Warnings {
		logger.Warn("probe pipeline field degraded", "degradation", warning)
	}

	// Stage 4: infer the client route from body.model and validate that the
	// alias's protocol can serve it. The physical provider may deliberately
	// differ (Mock or GLM), so Provider equality is not a valid gate.
	inboundModel := extractModelLazy(sanitized)
	inferredUpstream := provider.InferUpstreamFromModel(inboundModel)
	if inferredUpstream == "" {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "UPSTREAM_UNINFERRABLE",
			"Could not infer upstream provider from body.model. Expected a "+
				"recognized model id (claude-*, gpt-*, kimi-*, ...) so AiKey "+
				"can confirm the alias's provider matches the request.")
		return
	}
	normalizedBinding, axesErr := normalizeBindingForClientRoute(binding, inferredUpstream)
	if axesErr != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "PROBE_PROVIDER_MISMATCH",
			"Alias \""+probeCtx.AliasName+"\" cannot serve body.model route \""+inferredUpstream+
				"\": "+axesErr.Error()+". Use a model matching the alias's protocol.")
		return
	}
	binding = normalizedBinding

	// Capture inbound bearer BEFORE Stage 5 — same reason as handleAppPipeline:
	// ResolveBindingCredential → oauthInject overwrites r.Header.Authorization
	// with the upstream OAuth access token. Reading AFTER returns the upstream
	// secret instead of the client's constant first-party bearer, breaking
	// BR-rc.5-60's probe → app_slug attribution (firstPartyAppSlugForBearer
	// lookup fails because the bearer is no longer the whitelisted constant).
	inboundBearer := extractRawAuthValue(r)

	// Stage 5: resolve credential via the shared App/legacy machinery.
	// As in the App pipeline, provider setup must see the upstream-facing path
	// and a replayable sanitized body before it runs.
	r.URL.Path = "/v1" + probeCtx.StrippedPath
	if r.URL.RawPath != "" {
		r.URL.RawPath = r.URL.Path
	}
	r.Body = io.NopCloser(bytes.NewReader(sanitized))
	r.ContentLength = int64(len(sanitized))
	cred, resolvedReq, bindErr := p.ResolveBindingCredential(r, binding, logger)
	if bindErr != nil {
		p.errors.Add(1)
		logger.Warn("probe pipeline credential resolution failed",
			"error.code", bindErr.ErrorCode,
			"binding_source_type", binding.KeySourceType,
		)
		writeJSONError(w, bindErr.StatusCode, bindErr.ErrorType, bindErr.ErrorCode, bindErr.Message)
		return
	}
	r = resolvedReq
	if cred.RealKey == "" {
		p.errors.Add(1)
		writeJSONError(w, http.StatusServiceUnavailable, "server_error", "BINDING_CREDENTIAL_UNRESOLVED",
			"Alias \""+probeCtx.AliasName+"\" (source="+binding.KeySourceType+":"+
				binding.KeySourceRef+") could not be resolved to a usable credential. "+
				"The referenced personal entry or OAuth account may have been deleted.")
		return
	}

	// Stage 6: build the ResolvedRoute for serveRoute. RouteSource=routeSourceProbe
	// distinguishes probe traffic from app/legacy in usage_event records;
	// trust-local reads this to attribute probe events to the right pipeline.
	// It is ALSO the compliance exclusion key — serveRoute's applyInboundFilter
	// skips the whole chain for it (see isProbePipelineRoute). Renaming or
	// dropping this value silently re-enables masking of the fixed probe prompt.
	// P1d (design D-10, safe slice): path-aware protocol-family resolution
	// (see the App-pipeline sibling comment above). Audit-only blast radius.
	protocolType := binding.ProtocolType
	if protocolType == "" && cred.ManagedKey != nil && cred.ManagedKey.ProtocolType != "" {
		protocolType = cred.ManagedKey.ProtocolType
	}
	protocolFamily := ""
	if pr, ok := provider.Routes().LookupByBaseURL(cred.BaseURL); ok {
		protocolFamily = pr.Protocol
	} else if pf, ok := provider.ProtocolFamily(binding.ProviderCode, protocolType); ok {
		protocolFamily = pf
	}
	if protocolType == "" {
		protocolType = protocolFamily
	}
	probeResolvedRoute := &vkeys.ResolvedRoute{
		VirtualKeyID:     "probe:" + probeCtx.AliasName,
		Provider:         binding.ProviderCode,
		BaseURL:          cred.BaseURL,
		KeyAlias:         cred.KeyAlias,
		PlaintextKey:     cred.RealKey,
		OAuthIdentity:    cred.OAuthIdentity,
		AccountID:        cred.OAuthAccountID,
		ProviderCode:     binding.ProviderCode,
		ProtocolType:     protocolType,
		ProtocolFamily:   protocolFamily,
		RouteSource:      routeSourceProbe,
		FollowUserActive: false, // Probe NEVER follows active — that's the whole point of mode C.
	}
	if cred.ManagedKey != nil {
		probeResolvedRoute.OrgID = cred.ManagedKey.OrgID
		probeResolvedRoute.SeatID = cred.ManagedKey.SeatID
		probeResolvedRoute.CredentialID = cred.ManagedKey.CredentialID
		probeResolvedRoute.CredentialRevision = cred.ManagedKey.CredentialRevision
		probeResolvedRoute.VirtualKeyRevision = cred.ManagedKey.VirtualKeyRevision
	}

	// Stage 7: provider adapter.
	prov, err := p.providers.Get(protocolType)
	if err != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
			"Unknown upstream provider protocol: "+protocolType)
		return
	}

	// Stage 8: protocol translation (reuses apppipe — no-op when inbound and
	// upstream wire formats already match, which is the common case for
	// first-party degrade-detector calling Anthropic /messages).
	inboundFmt := apppipe.InferInboundWire(probeCtx.StrippedPath)
	translateOut, translateErr := apppipe.MaybeTranslateRequest(
		r.Context(),
		p.translatorRegistry,
		probeResolvedRoute,
		binding,
		inboundFmt,
		r,
		sanitized,
		inboundModel,
	)
	if translateErr != nil {
		p.errors.Add(1)
		logger.Warn("probe pipeline protocol translation failed",
			"error.code", translateErr.ErrorCode,
			"upstream", binding.ProviderCode,
		)
		writeJSONError(w, translateErr.StatusCode, "invalid_request_error", translateErr.ErrorCode, translateErr.Message)
		return
	}
	if translateOut.Engaged {
		logger.Info("probe pipeline translation engaged",
			"upstream_format", string(translateOut.UpstreamFormat),
		)
		if canonical := apppipe.CanonicalUpstreamPath(translateOut.UpstreamFormat); canonical != "" {
			r.URL.Path = canonical
			if r.URL.RawPath != "" {
				r.URL.RawPath = canonical
			}
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(translateOut.Body))
	r.ContentLength = int64(len(translateOut.Body))

	// OAuth → Anthropic WAF fingerprint rewrite (same rationale as App pipeline:
	// translation rebuilds the body after the Stage-5 replay copy, so apply the
	// fingerprint to the final post-translation bytes).
	oauthCode, _ := oauthInjectionProvider(binding.ProviderCode, protocolType)
	if binding.KeySourceType == "personal_oauth_account" &&
		oauthCode == "anthropic" &&
		!inboundUAWasClaudeCode {
		injectClaudeWAFFingerprintFull(r)
		if r.Body != nil {
			if newBytes, err := io.ReadAll(r.Body); err == nil {
				r.Body = io.NopCloser(bytes.NewReader(newBytes))
				r.ContentLength = int64(len(newBytes))
			}
		}
	}

	// inboundBearer captured pre-Stage-5 above (must precede oauthInject).

	logger.Info("probe pipeline forwarding upstream",
		"binding_source_type", binding.KeySourceType,
		"upstream_base", cred.BaseURL,
		"upstream", binding.ProviderCode,
		"protocol_family", probeResolvedRoute.ProtocolFamily,
		"alias_kind", aliasCred.AliasKind,
	)

	// Observer wiring (SPEC §1.4 stream = probe). Same pattern as
	// handleAppPipeline — Registry filters per-observer by Streams
	// declaration, so observers that didn't subscribe to probe (e.g.
	// rhythm with Streams=[app_pipeline]) get nothing; ndjson-fanout
	// (Streams=AllStreams()) writes the event to subscribers' files.
	var obsReqCtx *observer.RequestContext
	if p.observerRegistry != nil && p.observerRegistry.Active() > 0 {
		obsReqCtx = &observer.RequestContext{
			KeyAlias:       probeResolvedRoute.KeyAlias,
			ProviderID:     binding.ProviderCode,
			ProtocolFamily: probeResolvedRoute.ProtocolFamily,
			RequestedModel: inboundModel,
			SessionID:      resolveSessionID(r, probeResolvedRoute.ProtocolType, binding.ProviderCode),
			TraceID:        traceID,
			StartedAt:      startTime,
		}
		probeResolvedRoute.ObserverContext = obsReqCtx
		probeResolvedRoute.ObserverRegistry = p.observerRegistry
		p.observerRegistry.NotifyStart(r.Context(), observer.StreamProbe, obsReqCtx)
	}

	p.serveRoute(w, r, probeResolvedRoute, prov, cred.RealKey, inboundBearer, startTime, logger)

	if obsReqCtx != nil {
		latency := int(time.Since(startTime).Milliseconds())
		p.observerRegistry.NotifyEnd(r.Context(), obsReqCtx, latency)
	}
}

// uaWarnLogger is the logger handed to the UA matcher's MatchOrLog WARN hook,
// suppressed (nil) for probe traffic. aikey's own connectivity probes
// (`X-Aikey-Probe: 1`, UA `ureq/...`) carry an unrecognized UA by design and are
// NOT counted as usage (the isAikeyProbe guards in forward_and_resolve skip
// Record/reportUsage), so a WARN on every probe is pure noise — the hook exists
// to surface unrecognized *real* clients (e.g. a drifted codex / Cursor UA).
func uaWarnLogger(logger *slog.Logger, r *http.Request) *slog.Logger {
	if isAikeyProbe(r) {
		return nil
	}
	return logger
}

// handlePathPrefixRoute resolves the active key for providerCode and forwards
// the request with the provider prefix stripped from the path.
// Called when the request path starts with a known provider prefix
// (e.g., /anthropic/v1/messages → strip /anthropic → forward to Anthropic API).
func (p *Proxy) handlePathPrefixRoute(w http.ResponseWriter, r *http.Request, providerCode, strippedPath string, startTime time.Time, logger *slog.Logger, traceID string) {
	logger = logger.With("provider", providerCode, "routing", "path-prefix")

	// Snapshot the inbound User-Agent BEFORE any downstream stage can
	// mutate it. oauthInject (called inside both the OAuth-probe branch
	// below and ResolveBindingCredential's OAuth branch) overwrites UA to
	// "claude-cli/2.1.22 (external, cli)" to defeat upstream WAF rules
	// that key off the original client UA. We need the original here to
	// derive app_slug for OAuth events — see
	// workflow/CI/requirements/2026-05-26-usage-by-key-app-attribution.md
	// and the route construction sites below for how this is consumed.
	// Personal / team / path-prefix-non-OAuth callers don't read this
	// snapshot; leaving it set is harmless (no event field is populated).
	inboundClientUA := r.Header.Get("User-Agent")

	// 🔴 CLUSTER NODE: this branch requires a virtual key.
	//
	// The fall-through below resolves a request that names no aikey token from
	// the DEFAULT BINDING. On a developer's own machine that is the whole point
	// — Claude CLI / Cursor send their own credential to a loopback proxy and it
	// is substituted. On a cluster NODE the same code is an unauthenticated
	// relay over the organisation's virtual keys, reachable from wherever the
	// node is reachable, because config.validate() lifts the loopback rail for
	// cluster.enabled and cluster-install.sh binds 0.0.0.0.
	//
	// Measured 2026-09-02 on a real node, from the public internet with no
	// credential at all: 200, served by a member's virtual key, and recorded in
	// usage_fact_dwd against that member's SEAT. Not "unmetered forwarding" —
	// metered to the wrong person, spending their quota, in their audit trail.
	//
	// 🔴 Tier3Native covers BOTH "no Authorization/x-api-key at all" and "a
	// native provider token", and both must be refused here: the observed
	// request that succeeded carried a syntactically fine but entirely made-up
	// `x-api-key`. Tier3ActiveSentinel is refused for the same reason in a
	// different dress — "use whatever is active" names no key, and a node has no
	// single user whose active key that could mean.
	//
	// 🚫 It is NOT a general "path-prefix routing is off in cluster mode". A
	// request carrying a real aikey_team_* / aikey_personal_* key falls straight
	// through to the Tier1 handling below and is served exactly as before —
	// which is how every legitimate cluster client reaches this proxy. Turning
	// the route off instead would break them, and a fence that only asserted the
	// refusal would not notice.
	//
	// The refusal is byte-identical to the one Handle's step 1 gives a
	// token-less request on any other URL shape, because from the caller's side
	// it is the same mistake.
	//
	// bugfix: workflow/CI/bugfix/2026-09-02-集群节点代理是一个公网开放中继.md
	if p.clusterNode {
		switch ClassifyToken(extractRawAuthValue(r)) { //nolint:exhaustive // only the two Tier3 (no-VK) shapes are refused here; every other class names a virtual key and is resolved below
		case Tier3Native, Tier3ActiveSentinel:
			p.errors.Add(1)
			logger.Warn("authentication failed: missing virtual key on a cluster node",
				"event.name", observability.EventProxyRequestAuthFailed,
			)
			writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_MISSING",
				"Missing virtual key. Expected token with 'aikey_team_' or 'aikey_personal_' "+
					"prefix in Authorization or x-api-key header.")
			return
		}
	}

	// 2026-04-29 namespace-authority early hard-fail. Run BEFORE the
	// activeReader nil check so malformed `aikey_*` tokens always fail
	// loud with TOKEN_INVALID — independent of vault wiring state. This
	// also keeps the proxy's behavior consistent across editions (Personal
	// without active vault still rejects clearly-bad aikey tokens).
	if rawAuth := extractRawAuthValue(r); rawAuth != "" {
		// Only two early-reject cases here: malformed aikey_ tokens
		// (TokenInvalid) and provider-prefix-misrouted App bearers
		// (Tier1App). Tier3 / Tier2 / Tier1Team / Tier1Personal cases
		// fall through intentionally — they're resolved by the
		// activeReader-driven code below.
		switch ClassifyToken(rawAuth) { //nolint:exhaustive // only Invalid + Tier1App rejected here; rest handled below
		case TokenInvalid:
			p.errors.Add(1)
			logger.Warn("aikey_* token form invalid (namespace authority)",
				"event.name", observability.EventProxyRequestAuthFailed,
			)
			writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
				"Token is in the aikey_ namespace but doesn't match any recognized form. "+
					"Run 'aikey route' to see valid tokens.")
			return
		case Tier1App:
			// 2026-05-20 AKL-208: App bearer at provider-prefix URL is the
			// wrong path. Reject precisely BEFORE the activeReader nil check
			// so the user-actionable hint surfaces consistently across
			// editions (including Personal without active vault). The
			// downstream Tier1App branch in this function would otherwise
			// be unreachable in editions without activeReader.
			p.errors.Add(1)
			writeJSONError(w, http.StatusUnauthorized, "authentication_error", "APP_TOKEN_WRONG_PATH",
				"App bearer tokens must be sent to /apps/<slug>/v1/... URLs, "+
					"not /"+providerCode+"/v1/... Use the OPENAI_BASE_URL value printed "+
					"by `aikey app authorize <slug>` for the correct URL.")
			return
		}
	}

	if p.activeReader == nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusServiceUnavailable, "server_error", "ACTIVE_KEY_NOT_SUPPORTED",
			"Path-prefix routing is not available (vault does not support active key config).")
		return
	}

	var realKey, baseURL, protocolType, virtualKeyID string
	var mk *vault.ManagedKey                 // populated when resolved via team key (for org metadata)
	var oauthIdentity, oauthAccountID string // populated when resolved via OAuth account
	// keyAlias carries the vault-entry alias for personal / BYOK routes so the
	// reporter's deriveKeyLabel shows "my-kimi-key" instead of a truncated
	// virtual_key_id like "personal:my-…". Team keys have no per-binary alias
	// (ManagedKey stores VK id, not label); OAuth uses OAuthIdentity instead.
	var keyAlias string

	// Normalise brand aliases ("claude" → "anthropic") before vault lookup so
	// the query matches the provider_code stored by the server.
	canonicalCode := providerCanonicalCode(providerCode)

	// Protocol comes from the request dialect first. Endpoints such as /models
	// do not identify a dialect, so legacy client routes may use the routing
	// table only when that route name has exactly one supported protocol.
	// Never infer a multi-protocol Provider's protocol from its identity.
	protocolType = requestProtocolFromPath(strippedPath)
	if protocolType == "" {
		protocolType, _ = provider.ProtocolFamily(canonicalCode, "")
	}

	// ── 2026-04-29 prefix rename: namespace-authority dispatch ─────────────
	// `aikey_*` tokens are AiKey's routing namespace; proxy is the
	// authoritative decision point. Only specific subforms (team, personal,
	// probe, active) are valid; anything else in the namespace returns
	// TOKEN_INVALID immediately. Non-`aikey_*` tokens (native provider
	// tokens from Claude CLI / Cursor) fall through to the default binding.
	// See dispatch.go ClassifyToken for the full namespace rules.
	rawAuthValue := extractRawAuthValue(r)
	dispatchAction := ClassifyToken(rawAuthValue)

	// Hard-fail any `aikey_*` token whose subform we don't recognize. This
	// catches: aikey_route_* (reserved namespace, not implemented), unknown
	// aikey_* prefixes (typos / future-extension residue), legacy aikey_vk_*
	// (fully removed post-migration), malformed aikey_personal_<non-64-hex>.
	// Falling through silently would mask config bugs — exactly what the
	// namespace-authority principle forbids.
	if dispatchAction == TokenInvalid {
		p.errors.Add(1)
		logger.Warn("aikey_* token form invalid (namespace authority)",
			"event.name", observability.EventProxyRequestAuthFailed,
		)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Token is in the aikey_ namespace but doesn't match any recognized form. "+
				"Run 'aikey route' to see valid tokens.")
		return
	}

	// Tier2ProbeRaw — pre-save proxy probe (2026-05-26, see probe_raw.go +
	// roadmap20260320/技术实现/update/20260526-pre-save-proxy-probe-raw.md).
	// MUST be dispatched BEFORE Tier1 / Tier3 paths because handleProbeRaw
	// short-circuits all vault binding lookups — caller's plaintext bearer
	// in X-Aikey-Probe-Bearer is the auth source. Self-contained pipeline:
	// no reporter / WAL / GetProviderBinding involvement (audit-able as one
	// file in probe_raw.go).
	if dispatchAction == Tier2ProbeRaw {
		// Strip provider prefix so handleProbeRaw forwards using the path
		// the caller actually requested (e.g. /anthropic/v1/messages →
		// /v1/messages joined onto upstream base URL).
		p.handleProbeRaw(w, r, canonicalCode, strippedPath, logger)
		return
	}

	// Tier 1: aikey_team_<vk_id> or aikey_personal_<64-hex> — resolve via Registry.
	// (Tier1App was handled early-fail above per AKL-208 for edition consistency.)
	if dispatchAction == Tier1Team || dispatchAction == Tier1Personal {
		route := p.registry.Resolve(rawAuthValue)
		if route == nil {
			p.errors.Add(1)
			logger.Warn("tier-1 bearer not in registry",
				"event.name", observability.EventProxyRequestAuthFailed,
			)
			writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
				"Route token not found in registry. Run 'aikey route' to see available tokens.")
			return
		}
		// 🔴 Task 2.0b / 2.28. This entry serves the SAME thing as the legacy
		// `/v1/...` dispatch — a team VK's direct-bind credential — and only
		// differs in the URL shape the client used. Wiring the chain into one and
		// not the other would make failover depend on whether a client sends
		// `/v1/messages` or `/anthropic/v1/messages`, and nobody debugging "it
		// failed over for them but not for me" would think to suspect that.
		chain, selectErr := p.selectTokenChain(route, canonicalCode, protocolType, logger)
		if selectErr != nil {
			p.errors.Add(1)
			writeJSONError(w, http.StatusConflict, "invalid_request_error", "PROVIDER_ROUTE_AMBIGUOUS", selectErr.Error())
			return
		}
		route = chain.primary()
		if route.ProtocolType != "" {
			protocolType = route.ProtocolType
		}

		// Oauth-group VK: serve via the group handler — the path-prefix entry must
		// wire this exactly like the legacy /v1 dispatch (handle_dispatch.go:235).
		// A group VK carries NO VK-level provider (it's per-account in the group
		// runtime), so without this branch it falls through to the provider-
		// compatibility check below and 403s PROVIDER_MISMATCH on the empty
		// ProviderCode. The connectivity-test probe targets /<provider>/... (the
		// path-prefix entry), so ONLY this entry was affected — real Claude Code
		// uses the /v1 entry which already had the branch. Same empty-provider
		// root cause as 2026-06-25-group-vk-empty-provider-code-502. group VKs are
		// only registered when the oauth-group flag is on, so OauthGroupID is empty
		// in flag-off builds and the direct-bind path stays byte-identical.
		if route.OauthGroupID != "" {
			// Strip the provider prefix BEFORE handing off to the group handler.
			// The path-prefix entry normally defers the strip to below (after the
			// provider-compat check: `r.URL.Path = strippedPath`), but
			// handleOauthGroupRoute forwards r.URL.Path VERBATIM to the upstream —
			// so an unstripped `/anthropic/v1/models` would hit
			// `api.anthropic.com/anthropic/v1/models` → 404 (verified: Cf-Ray 404
			// from api.anthropic.com). The legacy /v1 entry (handle_dispatch.go) is
			// unaffected: its path is already `/v1/...` with no provider prefix.
			// Bugfix: 2026-06-26-group-vk-pathprefix-unstripped-404.
			r.URL.Path = strippedPath
			if r.URL.RawPath != "" {
				r.URL.RawPath = strippedPath
			}
			p.handleOauthGroupRoute(w, r, route, rawAuthValue, startTime, logger, traceID)
			return
		}

		// Provider compatibility check: token's provider must match path's provider.
		if !isProviderCompatible(route, canonicalCode, protocolType) {
			p.errors.Add(1)
			writeJSONError(w, http.StatusForbidden, "permission_error", "PROVIDER_MISMATCH",
				"Route token is bound to provider '"+route.ProviderCode+
					"', but request path indicates '"+canonicalCode+
					"'. Use the correct path prefix or a different token.")
			return
		}

		// Strip provider prefix from path.
		r.URL.Path = strippedPath
		if r.URL.RawPath != "" {
			r.URL.RawPath = strippedPath
		}

		// Resolve real key.
		var tokenRealKey string
		switch {
		case route.PlaintextKey != "":
			tokenRealKey = route.PlaintextKey
		case route.KeyAlias == oauthSentinelKey:
			// OAuth route token — broker handles credential injection in serveRoute.
			tokenRealKey = oauthSentinelKey
			oauthIdentity = route.OAuthIdentity
			oauthAccountID = route.AccountID
		default:
			var err error
			tokenRealKey, err = p.vault.GetSecret(route.KeyAlias)
			if err != nil {
				p.errors.Add(1)
				// Distinguish "key truly missing" from a transient vault infra
				// error (SQLITE_BUSY / IO / decrypt). A momentary lock — on
				// Trial cli+proxy+server share one SQLite — must not tell the
				// user to re-add an existing key (GAP 5, 2026-06-09 proxy
				// architecture review). Both remain 503 (soft-fail contract).
				if errors.Is(err, vault.ErrSecretNotFound) {
					writeJSONError(w, http.StatusServiceUnavailable, "server_error", "SECRET_NOT_CONFIGURED",
						"Provider API Key '"+route.KeyAlias+"' is not in the vault. Run: aikey add "+route.KeyAlias)
					return
				}
				writeJSONError(w, http.StatusServiceUnavailable, "server_error", "VAULT_UNAVAILABLE",
					"Vault temporarily unavailable, please retry.")
				return
			}
		}

		// Override baseURL from path's provider default if route doesn't specify one.
		tokenBaseURL := route.BaseURL
		if tokenBaseURL == "" {
			tokenBaseURL = providerBaseURLForProtocol(route.ProviderCode, protocolType)
		}
		// P1j (design D-17): fail-loud instead of forwarding to an empty base_url.
		// providerDefaultBaseURL returns "" for a provider it doesn't know; with
		// no vault base_url either, there is no upstream to reach — surface it as
		// PROVIDER_ROUTE_NOT_FOUND rather than silently building a broken URL
		// (禁止 #32: no silent fallback).
		if tokenBaseURL == "" {
			p.errors.Add(1)
			logger.Warn("no upstream base_url resolved for provider",
				"event.name", "proxy.route.not_found", "provider", canonicalCode)
			writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ROUTE_NOT_FOUND",
				"No upstream endpoint is configured for provider '"+canonicalCode+"'. "+
					"Set a base URL on the key, or use a supported provider.")
			return
		}

		prov, err := p.providers.Get(protocolType)
		if err != nil {
			p.errors.Add(1)
			writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
				"Unknown provider protocol: "+protocolType)
			return
		}

		tokenRoute := &vkeys.ResolvedRoute{
			VirtualKeyID:       route.VirtualKeyID,
			Provider:           providerCode,
			BaseURL:            tokenBaseURL,
			PlaintextKey:       tokenRealKey,
			ProviderCode:       route.ProviderCode,
			ProtocolType:       protocolType,
			CredentialID:       route.CredentialID,
			CredentialRevision: route.CredentialRevision,
			VirtualKeyRevision: route.VirtualKeyRevision,
			OrgID:              route.OrgID,
			AccountID:          route.AccountID,
			SeatID:             route.SeatID,
			OAuthIdentity:      oauthIdentity,
			AllowedModels:      route.AllowedModels, // Why: serveRoute checks this field for model allowlist enforcement
			// Why: KeyAlias is the user-facing label for team/personal/BYOK
			// routes (see deriveKeyLabel in reportable.go). Without copying
			// it through, path-prefix receipts degrade to a truncated
			// virtual_key_id like `vk_abc…` instead of the key's alias.
			// OAuth uses OAuthIdentity instead so we skip KeyAlias for the
			// sentinel __oauth__ value.
			KeyAlias: func() string {
				if route.KeyAlias == oauthSentinelKey {
					return ""
				}
				return route.KeyAlias
			}(),
			// Why: route_source drives deriveKeyLabel's classification — OAuth
			// routes pick OAuthIdentity (user's email), personal/team pick
			// KeyAlias. Without this copy, reportable.go's OrgID-based fallback
			// mis-classifies OAuth as "personal" and the UI shows a truncated
			// VK id like `oauth:sessio` instead of the user's email.
			RouteSource: route.RouteSource,
		}
		// UA-derived app attribution for the Tier-1 OAuth path (aikey_personal_*
		// wrapper tokens whose registry-resolved route has RouteSource="oauth").
		// This is the MOST COMMON OAuth invocation route — `aikey use <oauth-alias>`
		// hands the user an `aikey_personal_<64hex>` token, the registry maps it
		// to a vault.OAuthRouteToken at startup, and every request lands here.
		// tokenRoute is a per-request copy so mutating it is safe (no race with
		// concurrent requests hitting the same OAuth account); the cached
		// registry route is left untouched. inboundClientUA was snapshotted at
		// handler entry before oauthInject below scrubbed the header. See spec
		// at workflow/CI/requirements/2026-05-26-usage-by-key-app-attribution.md.
		if tokenRoute.RouteSource == "oauth" {
			tokenRoute.AppSlug = uaattribution.Default().MatchOrLog(inboundClientUA, uaWarnLogger(logger, r))
		}

		// Handle OAuth credential injection if this is an OAuth route token.
		if tokenRealKey == oauthSentinelKey && oauthAccountID != "" && p.broker != nil {
			if reason := oauthUpstreamRejectsPath(canonicalCode, r.URL.Path); reason != "" {
				p.errors.Add(1)
				writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
					observability.ErrCodeOAuthResponsesOnly, reason)
				return
			}
			if err := p.broker.EnsureFresh(r.Context(), oauthAccountID); err != nil {
				p.errors.Add(1)
				writeJSONError(w, http.StatusUnauthorized, "auth_error", "OAUTH_TOKEN_EXPIRED",
					err.Error()+"\n  Run: aikey auth login "+providerCode)
				return
			}
			cred, err := p.broker.ResolveCredential(r.Context(), oauthAccountID)
			if err != nil {
				p.errors.Add(1)
				writeJSONError(w, http.StatusServiceUnavailable, "server_error", "OAUTH_RESOLVE_FAILED", err.Error())
				return
			}
			tokenRoute.BaseURL, r = resolveOAuthUpstream(
				canonicalCode, protocolType, tokenRoute.BaseURL, r)
			oauthInject(r, cred, canonicalCode)
		}

		// 🔴 Task 2.0b: the candidate loop hangs HERE, not at the end of this
		// function — the Tier-1 branch returns on its own. This entry serves the
		// same thing as the legacy `/v1/...` dispatch (a team VK's direct-bind
		// credential) and differs only in the URL shape the client used, so wiring
		// one and not the other would make failover depend on whether a client
		// sends `/v1/messages` or `/anthropic/v1/messages`.
		//
		// A chain that cannot fail over falls straight through to the single-shot
		// call below, byte-identical to before.
		if chain.canFailover() || (chain.grouped && len(chain.candidates) == 1) {
			p.serveManagedChain(w, r, chain, rawAuthValue, startTime, logger, traceID, observer.StreamUserChat)
			return
		}

		// SPEC §1.4.1 user_chat — see serveRouteWithObserver docstring.
		p.serveRouteWithObserver(w, r, tokenRoute, prov, tokenRealKey, rawAuthValue, startTime, logger,
			observer.StreamUserChat, traceID)
		return
	}

	// ── aikey_probe_<alias> sentinel ────────────────────────────────────
	//
	// Introduced 2026-04-22 (Stage 3 of connectivity-probe-through-proxy).
	// Renamed in the 2026-04-29 prefix rename refactor — was previously a
	// dedicated `_alias_` suffix form, now `aikey_probe_<alias>`.
	//
	// Why: `aikey test <alias>` and the shell wrapper preflight (called
	// before every `claude` / `codex`) must probe a specific personal API
	// key without the CLI touching the vault. The CLI cannot ask for the
	// master password on every invocation — that's terrible UX for a
	// wrapper that runs on every command. Proxy already holds the vault
	// derived key in memory from its own startup password prompt, so it
	// can decrypt any personal alias on demand.
	//
	// Unlike the no-bearer fallback below — which resolves whichever
	// personal/team/OAuth binding is ACTIVE for canonicalCode — this
	// sentinel tests EXACTLY the alias the caller named. That fixes the
	// 2026-04-22 caveat where probing an inactive personal key silently
	// exercised the active one.
	//
	// Security: proxy is bound to 127.0.0.1, so any caller already has
	// local-host equivalence — this is the same trust boundary that lets
	// `claude` runtime hit `127.0.0.1:<port>/anthropic/v1/...` without
	// presenting credentials. No new attack surface.
	if dispatchAction == Tier2Probe {
		alias := strings.TrimPrefix(rawAuthValue, "aikey_probe_")
		if alias == "" {
			p.errors.Add(1)
			writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
				"aikey_probe_ sentinel missing alias suffix")
			return
		}

		// ── OAuth probe path (2026-04-29 fix A — bugfix/2026-04-29-oauth-probe-tier2-503.md) ──
		//
		// CLI sends `aikey_probe_<account_id>` for OAuth credentials too
		// (connectivity/mod.rs:243 oauth_target builds bearer this way).
		// account_id looks like `session_*`. Without this branch the code
		// below tries GetPersonalKeyByAlias("session_xxx"), fails, returns
		// 503 — the user-facing "claude → ... 503" red row in `aikey doctor`.
		//
		// Try OAuth account lookup first (cheap status check via broker);
		// only fall through to personal-key lookup if it's not a known
		// OAuth account. This preserves Tier3 active-OAuth's documented
		// flow (proxy refreshes token, attaches persona headers, forwards)
		// for the probe path too — connectivity/mod.rs:84 explicitly
		// promises this behavior.
		if p.broker != nil {
			if _, statusErr := p.broker.GetAccountStatus(r.Context(), alias); statusErr == nil {
				// OAuth account recognized — refresh + forward
				if err := p.broker.EnsureFresh(r.Context(), alias); err != nil {
					p.errors.Add(1)
					logger.Warn("oauth probe: EnsureFresh failed",
						"account_id", alias, "error", err,
						"event.name", observability.EventProxyRequestVaultFailed,
					)
					writeJSONError(w, http.StatusUnauthorized, "auth_error", "OAUTH_TOKEN_EXPIRED",
						err.Error()+"\n  Run: aikey auth login "+providerCode)
					return
				}
				cred, err := p.broker.ResolveCredential(r.Context(), alias)
				if err != nil {
					p.errors.Add(1)
					logger.Error("oauth probe: ResolveCredential failed",
						"account_id", alias, "error", err)
					writeJSONError(w, http.StatusServiceUnavailable, "server_error",
						"OAUTH_RESOLVE_FAILED", err.Error())
					return
				}

				// Remove the client-facing provider namespace before provider-specific
				// OAuth setup. Codex normalization intentionally operates on
				// /v1/responses, not /openai/v1/responses.
				r.URL.Path = strippedPath
				if r.URL.RawPath != "" {
					r.URL.RawPath = strippedPath
				}
				if reason := oauthUpstreamRejectsPath(canonicalCode, r.URL.Path); reason != "" {
					p.errors.Add(1)
					writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
						observability.ErrCodeOAuthResponsesOnly, reason)
					return
				}
				oauthBase, resolvedReq := resolveOAuthUpstream(canonicalCode, protocolType, "", r)
				r = resolvedReq
				oauthInject(r, cred, canonicalCode)

				identityTag := cred.Identity
				if identityTag == "" {
					identityTag = alias
				}
				logger.Info("oauth probe: forwarding request",
					"provider", canonicalCode,
					"identity", identityTag,
					"account_id", alias,
					"routing", "tier2-probe",
				)

				prov, err := p.providers.Get(protocolType)
				if err != nil {
					p.errors.Add(1)
					writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
						"Unknown provider protocol: "+protocolType)
					return
				}

				oauthRoute := &vkeys.ResolvedRoute{
					VirtualKeyID:  "oauth:" + alias,
					Provider:      providerCode,
					BaseURL:       oauthBase,
					PlaintextKey:  oauthSentinelKey, // sentinel — header injection done by oauthInject above
					ProviderCode:  canonicalCode,
					ProtocolType:  protocolType,
					KeyAlias:      "", // OAuth uses Identity, not alias
					RouteSource:   "oauth",
					OAuthIdentity: identityTag,
					AccountID:     alias, // OAuth account_id; correct field name (not OAuthAccountID)
					// UA-derived app attribution. inboundClientUA was captured
					// at handler entry, before oauthInject scrubbed the header.
					// Matcher always returns a non-empty slug (falls back to
					// "unknown-app") so OAuth events never render as empty
					// app_slug in the usage-by-key dashboard.
					AppSlug: uaattribution.Default().MatchOrLog(inboundClientUA, uaWarnLogger(logger, r)),
				}
				// SPEC §1.4.1 user_chat — see serveRouteWithObserver docstring.
				p.serveRouteWithObserver(w, r, oauthRoute, prov, oauthSentinelKey, rawAuthValue, startTime, logger,
					observer.StreamUserChat, traceID)
				return
			}
			// not an OAuth account — fall through to personal-key lookup below
		}

		plaintext, entryProviderCode, entryBaseURL, err := p.activeReader.GetPersonalKeyByAlias(alias)
		if err != nil {
			p.errors.Add(1)
			logger.Warn("personal-alias sentinel: vault lookup failed",
				"alias", alias, "error", err,
				"event.name", observability.EventProxyRequestVaultFailed,
			)
			writeJSONError(w, http.StatusServiceUnavailable, "server_error", "SECRET_NOT_CONFIGURED",
				"Personal key '"+alias+"' not found or could not be decrypted. Run: aikey list")
			return
		}

		// Derive baseURL: entry's custom URL > entry's stored provider default >
		// path-prefix canonical default.
		//
		// 🔴 2026-08-03 — this used to be inline here, which meant the FORWARDING
		// path was the only code that could compute it. The connectivity probe
		// therefore guessed the upstream from the provider code and tested an
		// address this entry never talks to. Sharing one function is what makes
		// 「展示=执行」 (requirements 2026-07-18) checkable rather than aspirational.
		resolvedBase := ResolvePersonalUpstreamBase(entryBaseURL, entryProviderCode, canonicalCode)

		prov, err := p.providers.Get(protocolType)
		if err != nil {
			p.errors.Add(1)
			writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
				"Unknown provider protocol: "+protocolType)
			return
		}

		// Strip provider prefix (e.g. /anthropic/v1/messages → /v1/messages)
		// before forwarding, matching the tier-1 (Registry) branch behavior.
		r.URL.Path = strippedPath
		if r.URL.RawPath != "" {
			r.URL.RawPath = strippedPath
		}

		aliasRoute := &vkeys.ResolvedRoute{
			VirtualKeyID: "personal:" + alias,
			Provider:     providerCode,
			BaseURL:      resolvedBase,
			PlaintextKey: plaintext,
			ProviderCode: canonicalCode,
			ProtocolType: protocolType,
			KeyAlias:     alias,
			// RouteSource = "personal" matches what personalTokenToRoute uses
			// so reportable.go's label classification stays consistent
			// regardless of which path produced the route.
			RouteSource: "personal",
		}
		// SPEC §1.4.1 user_chat — see serveRouteWithObserver docstring.
		p.serveRouteWithObserver(w, r, aliasRoute, prov, plaintext, rawAuthValue, startTime, logger,
			observer.StreamUserChat, traceID)
		return
	}

	// ── No auth header: fall through to default binding ────────────────────
	// Strip the client-facing provider namespace before credential resolution.
	// OAuth provider setup is path-aware (Codex maps /v1/responses to
	// /responses), so doing this afterward both hides the request dialect and
	// overwrites the normalized path with the pre-resolution value.
	r.URL.Path = strippedPath
	if r.URL.RawPath != "" {
		r.URL.RawPath = strippedPath
	}

	// ── v1.0.2: try provider binding first ─────────────────────────────────
	// The new model stores per-provider primary key selection in
	// user_profile_provider_bindings. If a binding exists, resolve directly
	// via the shared resolveBindingCredential helper (AKL-207). The helper
	// also serves the App pipeline so both paths produce identical
	// credential records — see helper docstring for per-KeySourceType semantics.
	binding, _ := p.activeReader.GetProviderBinding(canonicalCode)
	upstreamProviderCode := canonicalCode
	if binding != nil {
		normalizedBinding, axesErr := normalizeBindingForClientRoute(binding, canonicalCode)
		if axesErr != nil {
			p.errors.Add(1)
			writeJSONError(w, http.StatusBadGateway, "server_error", "BINDING_AXES_INVALID",
				"Active binding is invalid: "+axesErr.Error())
			return
		}
		binding = normalizedBinding
		upstreamProviderCode = binding.ProviderCode
		protocolType = binding.ProtocolType
		// ── Group VK on the follow-active path (N8 / bugfix 2026-06-30) ────────
		// A group VK (OAuth account pool) carries NO static PlaintextKey — its
		// per-account material lives in GroupRuntime and must be served via
		// handleOauthGroupRoute (the same path the Tier1 `aikey_team_<vk>` token
		// reaches at line ~989). The follow-active path (Claude Code via
		// `aikey run` injects the `aikey_active_<provider>` sentinel) lands here
		// instead, where ResolveBindingCredential's switch has no oauth_group
		// case → it soft-fails with RealKey="" → the legacy fallback also can't
		// serve a keyless VK → "no active key".
		//
		// The active team binding stores the vk_id (KeySourceRef). The supervisor
		// registers every group VK in the registry under the Tier1 team token
		// `aikey_team_<vk_id>` (supervisor.go:725) WITH the group fields fully
		// populated — so re-resolving that token here yields the same complete
		// group route the Tier1 path serves, without touching GetTeamKeyByID
		// (whose query filters on `provider_key_ciphertext IS NOT NULL` and never
		// reads group columns, so it can't see a keyless group VK at all).
		if binding.KeySourceType == "team" {
			if groute := p.registry.Resolve("aikey_team_" + binding.KeySourceRef); groute != nil &&
				groute.OauthGroupID != "" {
				// Strip the provider prefix BEFORE handing off: handleOauthGroupRoute
				// forwards r.URL.Path VERBATIM upstream, so an unstripped
				// `/anthropic/v1/messages` would 404 (same rationale as the Tier1
				// branch at line ~999; bugfix 2026-06-26-group-vk-pathprefix-unstripped-404).
				r.URL.Path = strippedPath
				if r.URL.RawPath != "" {
					r.URL.RawPath = strippedPath
				}
				p.handleOauthGroupRoute(w, r, groute, rawAuthValue, startTime, logger, traceID)
				return
			}
		}

		cred, resolvedReq, bindErr := p.ResolveBindingCredential(r, binding, logger)
		if bindErr != nil {
			// OAuth path: writeJSONError + return (helper does NOT increment
			// p.errors because the caller's view of "what's an error" may
			// differ — we increment here to keep the metric semantics
			// identical to the pre-refactor inline code).
			p.errors.Add(1)
			writeJSONError(w, bindErr.StatusCode, bindErr.ErrorType, bindErr.ErrorCode, bindErr.Message)
			return
		}
		r = resolvedReq
		// Soft-fail path (team / personal with empty cred): RealKey="" leaves
		// the variables blank below and the legacy fallback block fires.
		// OAuth-success path: cred fields populated, RealKey="__oauth__".
		realKey = cred.RealKey
		virtualKeyID = cred.VirtualKeyID
		keyAlias = cred.KeyAlias
		baseURL = cred.BaseURL
		oauthIdentity = cred.OAuthIdentity
		oauthAccountID = cred.OAuthAccountID
		if cred.ManagedKey != nil {
			mk = cred.ManagedKey
		}
	}

	// ── Legacy fallback: active team key → active personal key ─────────────
	// For backward compatibility with pre-v1.0.2 vaults that don't have the
	// user_profile_provider_bindings table.
	if realKey == "" {
		var err error
		mk, err = p.activeReader.GetActiveTeamKeyByProvider(canonicalCode, protocolType)
		if err != nil {
			p.errors.Add(1)
			logger.Error("vault: active team key lookup failed", "error", err)
			writeJSONError(w, http.StatusServiceUnavailable, "server_error", "VAULT_ERROR", err.Error())
			return
		}

		if mk != nil {
			realKey = mk.PlaintextKey
			virtualKeyID = mk.VirtualKeyID
			// 2026-05-09: same alias surfacing as the binding-driven team
			// branch above, for the legacy fallback (pre-v1.0.2 vaults
			// without user_profile_provider_bindings).
			keyAlias = mk.LocalAlias
			if url, ok := mk.ProviderBaseURLs[canonicalCode]; ok && url != "" {
				baseURL = url
			} else if url, ok := mk.ProviderBaseURLs[providerCode]; ok && url != "" {
				baseURL = url
			} else {
				baseURL = mk.BaseURL
			}
		} else {
			cfg, err := p.activeReader.GetActiveKeyConfig()
			if err != nil {
				p.errors.Add(1)
				logger.Error("vault: active key config read failed", "error", err)
				writeJSONError(w, http.StatusServiceUnavailable, "server_error", "VAULT_ERROR", err.Error())
				return
			}
			if cfg != nil && cfg.KeyType == "personal" {
				supported := len(cfg.Providers) == 0
				for _, code := range cfg.Providers {
					// Dual-axis (bugfix 2026-08-20): canonical equality alone
					// accepted a legacy route-shaped entry as ONE supplier of
					// its family and refused the siblings — a moonshot key
					// served /kimi/v1 and 503'd /moonshot/v1.
					if activeEntryServesProvider(code, canonicalCode) {
						supported = true
						break
					}
				}
				if supported {
					plaintext, pcode, entryBaseURL, err := p.activeReader.GetPersonalKeyByAlias(cfg.KeyRef)
					if err != nil {
						p.errors.Add(1)
						logger.Error("vault: personal key read failed", "alias", cfg.KeyRef, "error", err)
						writeJSONError(w, http.StatusServiceUnavailable, "server_error", "VAULT_ERROR", err.Error())
						return
					}
					realKey = plaintext
					virtualKeyID = "personal:" + cfg.KeyRef
					keyAlias = cfg.KeyRef
					// 🔴 2026-08-03 — was a second, hand-written copy of the same
					// precedence ladder, and the copies had DRIFTED: this switch
					// stopped at `case pcode != ""`, so an entry naming a provider
					// with no route row produced an EMPTY upstream, while the
					// sentinel path fell through to the path-derived provider and
					// resolved fine. Same key, same vault — `aikey test` green,
					// real traffic broken (or the reverse).
					//
					// Found by the 「展示=执行」 fence added with the shared resolver,
					// which is the point of writing that fence as a structural scan
					// rather than a value comparison.
					baseURL = ResolvePersonalUpstreamBase(entryBaseURL, pcode, canonicalCode)
				}
			}
		}
	}

	if realKey == "" {
		p.errors.Add(1)
		// 🔴 Name the REAL cause when we know it (2026-08-26). If the active
		// binding points at a team virtual key the control plane has revoked, the
		// generic NO_ACTIVE_KEY answer is not merely vague, it is WRONG ADVICE:
		// it tells the member to run `aikey use <key>`, which cannot succeed —
		// the key is gone server-side, and no local command brings it back. A
		// suspended employee would follow that hint, fail, and open a support
		// ticket about a proxy bug that does not exist.
		//
		// 503 was also the wrong shape: it reads as "the proxy is unwell, retry",
		// so clients retry a decision that will never change. This is a refusal,
		// so it answers 401.
		//
		// See workflow/CI/bugfix/20260826-proxy-revocation-window-unbounded.md.
		if binding != nil && binding.KeySourceType == "team" &&
			p.activeReader != nil && p.activeReader.IsVirtualKeyRevoked(binding.KeySourceRef) {
			logger.Warn("active binding points at a virtual key revoked by the control plane",
				"event.name", observability.EventProxyKeyRevocationRefused,
				"provider", providerCode, "virtual_key_id", binding.KeySourceRef)
			writeJSONError(w, http.StatusUnauthorized, "authentication_error", "SEAT_OR_KEY_REVOKED",
				"This key is no longer active: your organization administrator has suspended "+
					"the seat or revoked the key. Ask them to restore it — no local command can.")
			return
		}
		logger.Warn("no active key for provider")
		writeJSONError(w, http.StatusServiceUnavailable, "server_error", "NO_ACTIVE_KEY",
			"No active key for '"+providerCode+"'. Run 'aikey use <key>'.")
		return
	}

	// Resolve provider adapter by protocol type (derived from URL path).
	prov, err := p.providers.Get(protocolType)
	if err != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
			"Unknown provider protocol: "+protocolType+" (from path: "+providerCode+")")
		return
	}

	route := &vkeys.ResolvedRoute{
		VirtualKeyID: virtualKeyID,
		Provider:     providerCode,
		BaseURL:      baseURL,
		PlaintextKey: realKey,
		ProviderCode: upstreamProviderCode,
		ProtocolType: protocolType,
		// Why: for personal/BYOK path-prefix routes, keyAlias was captured
		// above at vault-lookup time. Without this field, reportable.go's
		// deriveKeyLabel falls back to truncating VirtualKeyID (e.g.
		// "personal:my-kimi-…" instead of "my-kimi-key"). Team & OAuth
		// paths leave this empty because they label via different fields
		// (ManagedKey has no alias; OAuth uses OAuthIdentity).
		KeyAlias: keyAlias,
	}
	// Populate org/account/seat from managed key so usage events carry the correct org_id.
	if mk != nil {
		route.OrgID = mk.OrgID
		route.AccountID = mk.OwnerAccountID
		route.SeatID = mk.SeatID
	}
	// OAuth: carry identity + account_id so usage events can identify the account.
	if oauthAccountID != "" {
		route.AccountID = oauthAccountID
		route.OAuthIdentity = oauthIdentity
	}
	// Why: classify so reportable.go's deriveKeyLabel picks the right label
	// field (OAuthIdentity for oauth, KeyAlias for team/personal). Without
	// this, the OrgID fallback in reportable.go mis-classifies OAuth personal
	// requests as "personal" and produces truncated labels like `oauth:sessio`
	// instead of the user's email. Order matters: OAuth wins even when a team
	// managed-key lookup happens to side-populate mk for the same account.
	switch {
	case oauthAccountID != "":
		route.RouteSource = "oauth"
		// UA-derived app attribution for the direct OAuth path
		// (/v1/...). inboundClientUA was snapshotted at handler entry
		// before ResolveBindingCredential's oauthInject scrubbed it.
		// Matcher returns a non-empty slug ("unknown-app" fallback) so
		// the usage-by-key dashboard always has a row label. Personal /
		// team branches deliberately leave AppSlug empty per spec R5
		// (workflow/CI/requirements/2026-05-26-usage-by-key-app-attribution.md).
		route.AppSlug = uaattribution.Default().MatchOrLog(inboundClientUA, uaWarnLogger(logger, r))
	case mk != nil:
		route.RouteSource = "team"
	default:
		route.RouteSource = "personal"
	}

	// 2026-04-29 prefix rename: receipt token rebuilt from virtualKeyID for
	// usage reporting only (not auth). At this code path virtualKeyID has
	// already been resolved/normalized upstream (via the registry which
	// itself goes through supervisor.NormalizeTeamToken at load time), so
	// simple concat is safe — the registry guarantees no historical-prefix
	// residue. Avoid importing supervisor here to prevent a package cycle.
	// SPEC §1.4.1 user_chat — see serveRouteWithObserver docstring.
	p.serveRouteWithObserver(w, r, route, prov, realKey, "aikey_team_"+virtualKeyID, startTime, logger,
		observer.StreamUserChat, traceID)
}
