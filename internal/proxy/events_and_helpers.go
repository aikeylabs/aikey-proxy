// events_and_helpers.go — usage-event emission + small request/response
// inspection helpers used across the pipeline handlers.
//
// Event emission:
//   - buildBaseEvent         — initialize a UsageEvent from req/resp metadata
//   - recordEvent            — finalize tokens + dispatch to collector / WAL
//   - reportUsage            — record-then-emit shortcut used by serveRoute
//   - logAppUpstreamErrorForensic — default-on WARN log for app-pipeline 4xx/5xx
//
// Upstream-response inspection:
//   - parseUpstreamErrorEnvelope — extract {type,message} from Anthropic/OpenAI errors
//   - extractUpstreamRequestID   — pull the upstream's request-id header (varies by provider)
//   - truncateBodyForLog         — JSON-safe truncation
//
// Debug-body capture (gated by AIKEY_PROXY_DEBUG_4XX_BODIES env):
//   - debug4xxEnabled / resolvedBodyLogCap
//   - stashRequestBodyForDebug / debugRequestBodyFromContext
//
// Request introspection:
//   - resolveSessionID, extractModel(Lazy), stashExtractedFields, jsonEscapeForError
//
// Split out of proxy.go on 2026-05-26 — see
// workflow/CI/refactor/2026-05-26-proxy-go-split.md for the file map.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/sessionid"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// buildBaseEvent constructs a UsageEvent from the request/response metadata,
// without token counts (filled in by callers that have the response body).
//
// 2026-05-08 Kimi 双平台拆分: Provider 字段优先用 canonical ProviderCode (e.g.
// "kimi_code"),不用 URL-prefix 的 Provider (e.g. "kimi" deprecated alias) ——
// 否则同一 vault entry 经 deprecated /kimi/v1 路径请求时 events.provider 写入
// "kimi",而经 /kimi_code/v1 路径请求时写入 "kimi_code",计费 / 用量聚合时
// 会被算成两个 provider,造成数据分裂。canonical ProviderCode 是 single source。
// route.Provider 仍保留 URL-prefix 形式给其他 (调试 / RequestPath 关联) 用途。
func (p *Proxy) buildBaseEvent(req *http.Request, resp *http.Response, startTime time.Time, route *vkeys.ResolvedRoute, streaming bool) events.UsageEvent {
	provider := route.ProviderCode
	if provider == "" {
		// 极端兜底:ResolvedRoute 没填 ProviderCode 时退回 URL-form,避免空字符串
		provider = route.Provider
	}
	// resp may be nil on an upstream-no-response path (transport error → no
	// response object). Every caller today is inside ModifyResponse (resp non-nil),
	// but the `if resp != nil` guard below (util reporting) proves resp is treated
	// as nilable — so read StatusCode nil-safely too, keeping the two consistent and
	// making buildBaseEvent safe if a future error-path caller passes nil (was a
	// latent panic; staticcheck SA5011). 0 = "no upstream status".
	statusCode := 0
	if resp != nil {
		statusCode = resp.StatusCode
	}
	ev := events.UsageEvent{
		Timestamp:    startTime,
		VirtualKeyID: route.VirtualKeyID,
		// AccountID = the REAL account that served this request. For oauth_group
		// routing group_serve sets route.AccountID to the CHOSEN account (and
		// re-points it on fallback A→B), so local audit attributes to the
		// account that actually sent upstream. VirtualKeyID stays the request's
		// VK regardless of switch (stable user attribution).
		AccountID:   route.AccountID,
		Provider:    provider,
		DurationMs:  time.Since(startTime).Milliseconds(),
		StatusCode:  statusCode,
		IsStreaming: streaming,
		RequestPath: req.URL.Path,
	}
	// Ephemeral trace correlation (not persisted) so the async collector can
	// cite trace/span/request ids if it has to drop this event under backpressure.
	if tc := traceFromContext(req.Context()); tc.TraceID != "" {
		ev.TraceID = tc.TraceID
		ev.SpanID = tc.SpanID
		ev.RequestID = tc.RequestID
	}
	if model := req.Header.Get("x-aikey-model"); model != "" {
		ev.Model = model
		ev.RequestedModel = model // Phase 4 §5.3 — captured at request entry, may differ from upstream `Model` after translator remaps
	}
	// SessionID (v1.0.0-rc.6): populate the local UsageEvent so the
	// offline-retry upload path (events.db → collector ingest) preserves
	// the session dimension even when the live reporter is down. Uses
	// the same yaml-driven extractor as reportUsage's sessionID arg, so
	// local and wire formats stay in lockstep.
	ev.SessionID = resolveSessionID(req, route.ProtocolType, route.ProviderCode)
	// Phase 4 (AKL-207) — App pipeline audit fields. Empty for legacy paths
	// (route.RouteSource != "app").
	if route.RouteSource == "app" {
		ev.AppSlug = route.AppSlug
		ev.AppKeyID = route.AppKeyID
		if route.FollowUserActive {
			ev.AppMode = "follow-active"
			ev.BoundVia = "default" // follow-active path uses the user's default profile binding
		} else {
			ev.AppMode = "isolated"
			ev.BoundVia = "app:" + route.AppSlug
		}
		ev.ResolvedProvider = provider
	} else if route.RouteSource == "oauth" && route.AppSlug != "" {
		// OAuth-direct UA-derived attribution (2026-05-26). Mirror of the
		// same branch in events/reportable.go's BuildReportableEvent —
		// keep them in lockstep so the local UsageEvent and the wire
		// ReportableEvent agree on app_slug. AppKeyID / AppMode /
		// BoundVia are deliberately NOT set: those are App-pipeline
		// authorization fields with no meaning for UA-derived labels.
		// Trust note: spoofable signal, display-only.
		ev.AppSlug = route.AppSlug
	}
	// I5 (best-effort, OFF the hot path): ship the upstream's parsed 5h + 7d
	// utilization to master so the allocation engine can read both (util_7d feeds
	// the weekly-squeeze target). The sample still exists only when the 5h header
	// is present — the two unified headers arrive together upstream — and util_7d
	// just enriches it (0 + omitempty when the 7d header is absent, so util_5h
	// reporting stays byte-identical). enqueue is nil-safe (reporter off → no-op)
	// and non-blocking (full buffer drops the sample, never stalls).
	if resp != nil {
		if util5h, ok := parseUnifiedUtil5h(resp.Header); ok {
			util7d, _ := parseUnifiedUtil7d(resp.Header)
			p.signalReporter.enqueue(route.CredentialID, time.Now().Unix(), util5h, util7d)
		}
	}
	return ev
}

// recordEvent records a usage event for error responses (no token counts).
func (p *Proxy) recordEvent(req *http.Request, resp *http.Response, startTime time.Time, route *vkeys.ResolvedRoute, bearerToken string, streaming bool) {
	ev := p.buildBaseEvent(req, resp, startTime, route, streaming)
	var errMsg, errType string
	if resp.StatusCode >= 400 {
		p.errors.Add(1)
		// Capture the upstream error envelope (re-buffers resp.Body so the client
		// still receives the original payload). Returns the provider's error TYPE +
		// human MESSAGE parsed from the body.
		errType, errMsg = captureUpstreamErrorBody(resp)
		// error_type: prefer the provider's classification (e.g.
		// exceeded_current_quota_error / invalid_request_error) so the usage row
		// tells WHY it failed; fall back to the generic HTTP reason phrase
		// (http.StatusText(429) = "Too Many Requests") when the body isn't a known
		// provider envelope.
		if errType != "" {
			ev.ErrorType = errType
		} else {
			ev.ErrorType = http.StatusText(resp.StatusCode)
		}
	}
	// Probe traffic bypasses all sinks — see isAikeyProbe rationale in
	// middleware.go. Keep p.errors.Add(1) above so the /metrics view still
	// shows "N requests returned 4xx/5xx" even for self-tests. Probes also skip
	// the revoked-feed below: a probe may deliberately send no auth and earn a
	// 401, which is NOT a real revocation.
	if isAikeyProbe(req) {
		return
	}
	// Revoked-feed emit (best-effort, OFF the hot path, mirrors the I5 util
	// enqueue in buildBaseEvent): a hard-revoked OAuth token (401 "OAuth token
	// has been revoked") means this credential can't serve again until re-auth,
	// so flag master to quarantine the account in the allocation engine. We do
	// NOT alter the 401 — it still flows to the client unchanged. enqueueRevoked
	// is nil-safe (reporter off → no-op) and non-blocking (full buffer drops).
	if isHardRevoked(resp.StatusCode, errType, errMsg) {
		p.signalReporter.enqueueRevoked(route.CredentialID, "revoked")
	}
	// Rate-limit-feed emit (best-effort, OFF the hot path, mirrors the revoked
	// hook above): the proxy sees every upstream 429 (rate limit) / 403 (forbidden);
	// counting them per credential lets master normalize a near-window 429/403
	// frequency into the allocation engine's §5.1 w5 "Recent429FreqNorm" risk
	// signal. We do NOT alter the response — it flows to the client unchanged. The
	// status is the one captureUpstreamErrorBody already read; we don't re-read the
	// body. incrRateLimit is nil-safe (reporter off → no-op) and non-blocking (a
	// short map lock, reset every flush bounds it); an empty CredentialID (no route)
	// is dropped inside.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
		p.signalReporter.incrRateLimit(route.CredentialID)
	}
	p.collector.Record(&ev)
	// Error responses are treated as interrupted — the client never got a
	// usable result even though the request finished "fast" from our POV.
	sessionID := resolveSessionID(req, route.ProtocolType, route.ProviderCode)
	upstreamReqID := extractUpstreamRequestID(resp)
	p.reportUsage(route, bearerToken, ev.Model, startTime, resp.StatusCode, provider.TokenBreakdown{}, ev.ErrorType, errMsg, "", sessionID, "interrupted", upstreamReqID)
}

// errorBodyCap bounds the captured upstream error body (ODS error_message + WAL
// stay small). Provider error envelopes are tiny JSON; 2KB is ample.
const errorBodyCap = 2048

// captureUpstreamErrorBody reads the upstream error body, re-buffers it so the
// client still receives the original payload, and returns the provider error
// (type, message) for the event. Mirrors the read+rebuffer pattern used by the
// 4xx debug capture in forward_and_resolve.go.
//
//   - errType: the provider's error classification (Anthropic/OpenAI/Kimi share
//     `error.type`, e.g. exceeded_current_quota_error); "" when unparseable.
//   - errMsg:  the RAW upstream body (trimmed + capped) stored LOSSLESS — the page
//     parses/cleans it for display (so we never drop detail at the storage layer;
//     presentation formatting is the consumer's job).
func captureUpstreamErrorBody(resp *http.Response) (errType, errMsg string) {
	if resp == nil || resp.Body == nil {
		return "", ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", ""
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))

	// error_code gets the parsed provider type (structured/queryable); error_message
	// keeps the RAW body for lossless storage — the page does the human-readable
	// cleaning at render time.
	pType, _ := parseUpstreamErrorEnvelope(body)
	msg := strings.TrimSpace(string(body))
	if len(msg) > errorBodyCap {
		msg = msg[:errorBodyCap] + "…"
	}
	return strings.TrimSpace(pType), msg
}

// debug4xxEnabled reports whether AIKEY_PROXY_DEBUG_4XX_BODIES is set to a
// truthy value. Read on every request — getenv is cheap and lets operators
// flip the flag at runtime via an EnvironmentFile reload (no proxy restart
// required) when chasing a sporadic 4xx in production.
//
// Why opt-in (not always on): the request body for chat completions is
// often a few KB of conversation history; logging it for every 4xx adds
// disk pressure and surfaces user prompts into developer-facing logs. The
// flag scopes that exposure to deliberate diagnostic windows.
func debug4xxEnabled() bool {
	v := os.Getenv("AIKEY_PROXY_DEBUG_4XX_BODIES")
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// debug4xxBodyCap caps how many bytes of each side we log. 4 KB is enough
// for typical provider error envelopes (anthropic Bad Request bodies are
// usually <500 bytes; Claude Code request bodies that trigger them sit
// around 1-3 KB). Larger payloads get a `...<truncated>` marker so the
// reader knows there was more.
//
// AIKEY_PROXY_DEBUG_BODY_CAP_BYTES env override: third-party clients
// (opencode/Cline/Cursor) routinely send 30-80 KB request bodies (tool
// definitions + message history); the default 4 KB cap is too small to
// see metadata.user_id / tools / late messages when chasing identity-
// gating bugs. Setting the env to e.g. 65536 lets a focused diagnostic
// session capture full bodies. Hard-capped at 1 MB so a misconfigured
// value can't OOM the log writer.
const (
	debug4xxBodyCap         = 4 * 1024
	debugBodyCapHardCeil    = 1024 * 1024
	debugBodyCapEnvOverride = "AIKEY_PROXY_DEBUG_BODY_CAP_BYTES"
)

// resolvedBodyLogCap returns the active body-log cap, env override winning
// over the compile-time default. Invalid env values fall back silently.
func resolvedBodyLogCap() int {
	if v := os.Getenv(debugBodyCapEnvOverride); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > debugBodyCapHardCeil {
				return debugBodyCapHardCeil
			}
			return n
		}
	}
	return debug4xxBodyCap
}

// stashRequestBodyForDebug reads r.Body fully, stores the bytes in request
// context for ModifyResponse to retrieve later, and re-buffers r.Body for
// the actual upstream call. No-op when no debug flag is active, the body
// is empty, or the body exceeds extractBodyHardLimit.
//
// Why two flags drive this: AIKEY_PROXY_DEBUG_4XX_BODIES historically gated
// 4xx-only body capture; debugUpstreamHeadersEnabled() also drives request-
// body capture so the broader upstream-snapshot toggle can include body
// alongside headers (otherwise body diagnostics needs a separate restart
// with the legacy env).
//
// Why context (not a header): bodies can be megabytes of conversation; cramming
// them into headers would break upstream forwarding (header size limits,
// inadvertent leaks via mirrored response headers).
func stashRequestBodyForDebug(r *http.Request) {
	if (!debug4xxEnabled() && !debugUpstreamHeadersEnabled()) || r.Body == nil {
		return
	}
	if r.ContentLength > extractBodyHardLimit {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	*r = *r.WithContext(context.WithValue(r.Context(), ctxKeyDebugReqBody, body))
}

// debugRequestBodyFromContext fetches the stashed request body. Returns nil
// when the flag was off or the request was too large to stash.
func debugRequestBodyFromContext(ctx context.Context) []byte {
	b, _ := ctx.Value(ctxKeyDebugReqBody).([]byte)
	return b
}

// bufferRequestBodyForObserver reads and restores the client request body so a
// full-payload observer (enterprise conversation audit) can read the prompt in
// OnRequestStart. Returns the buffered copy, or nil when capture is unsafe or
// undesirable; the observer then degrades to completion-only and never blocks
// the request.
//
// MAIN-LINK SAFETY (why the guards, not just "read it"): the user_chat path
// forwards r.Body byte-identically (path-prefix routing relies on it — see
// serveRouteWithObserver's doc). We therefore ONLY buffer when the length is
// known and within the hard cap. Unknown-length (chunked, ContentLength < 0)
// or oversized bodies are skipped untouched — truncating or partially
// consuming r.Body would corrupt the forward, and a stalled audit feature must
// never degrade the proxy's core job. On a read error (broken connection) we
// restore what we read best-effort and return nil. Mirrors
// stashRequestBodyForDebug's proven buffer+restore, gated by observer appetite
// rather than the debug flag.
func bufferRequestBodyForObserver(r *http.Request) []byte {
	if r.Body == nil || r.ContentLength <= 0 || r.ContentLength > extractBodyHardLimit {
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// Connection already broken mid-read; put back what we got so the
		// forward path sees a consistent (if doomed) body, and skip audit.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return body
}

// logAppUpstreamErrorForensic emits a default-on WARN log whenever an
// app-pipeline request returns 4xx/5xx from the upstream. The goal is
// to make third-party APP integration failures debuggable WITHOUT
// requiring the operator to flip AIKEY_PROXY_DEBUG_4XX_BODIES first —
// that flag dumps full bodies (PII) and is rightly opt-in, but the
// resulting "off by default" leaves users staring at a generic 404 in
// the dashboard with no way to ask "what URL? what error message?
// what model? OAuth or API key?".
//
// PII safety contract:
//   - Logs (PII-safe): status, outbound URL (host + path + query),
//     upstream request_id, route shape (slug / kind / route_source),
//     credential family (oauth vs personal-or-team — never the actual
//     secret), upstream error envelope's `type`.
//   - Logs (residual PII risk, mitigated): upstream error envelope's
//     `message` — capped at errorMessageLogCap chars (300, deliberately
//     tight) because provider error messages CAN occasionally echo
//     user-supplied content (e.g. "Bad request: model 'xxx' contains
//     invalid chars", "Prompt rejected: pattern 'yyy' matched policy").
//     The 300-char cap bounds exposure to short snippets that are
//     unlikely to leak useful prompt content while still surfacing the
//     diagnostic signal (error type + first sentence of the message).
//     Full message capture stays gated behind AIKEY_PROXY_DEBUG_4XX_BODIES.
//   - Does NOT log: Authorization header, x-api-key, OAuth bearer,
//     full request body (may contain user prompts), full response body
//     (may contain provider's PII echo beyond the message field).
//
// Body handling: drains the response body so the envelope parser can
// run, then re-buffers so the client still gets the original payload
// — same pattern as the existing debug4xx capture below. The drain cap
// follows `resolvedBodyLogCap()` (env-override-aware), NOT a separate
// hardcoded 8 KB, so an operator who sets AIKEY_PROXY_DEBUG_BODY_CAP_BYTES
// to e.g. 65536 to chase a verbose 4xx error gets the larger window
// applied to BOTH this default-on log AND the opt-in debug4xx capture.
// Otherwise the debug4xx block (which runs after this one) would see
// the already-truncated body and silently respect 8 KB regardless of
// the env override.
//
// When the body parses as a known provider error envelope (Anthropic /
// OpenAI shape) the parsed `type` + `message` are surfaced as
// dedicated fields so log consumers (jq filters, alert rules) can
// pivot without string-matching the whole envelope.
func (p *Proxy) logAppUpstreamErrorForensic(
	logger *slog.Logger,
	r *http.Request,
	resp *http.Response,
	route *vkeys.ResolvedRoute,
	realKey string,
) {
	// Drain the response body — capped at the env-aware body log size
	// so AIKEY_PROXY_DEBUG_BODY_CAP_BYTES applies to this default-on
	// log too (not just the opt-in debug4xx capture below). Re-buffer
	// immediately so the downstream client still gets the original
	// payload byte-for-byte.
	//
	// Note: the parser itself only needs the first ~500 bytes of a
	// well-formed envelope, so most of the read budget is "give
	// debug4xx room to see the full body if it's enabled" rather than
	// "the parser needs it". `+1` byte over the cap is the standard
	// LimitReader trick to detect "was the body actually larger than
	// the cap" without an extra Seek.
	bodyCap := resolvedBodyLogCap()
	var bodyBytes []byte
	if resp.Body != nil {
		buf, err := io.ReadAll(io.LimitReader(resp.Body, int64(bodyCap)+1))
		if err == nil {
			bodyBytes = buf
		}
		_ = resp.Body.Close()
		// Re-buffer for the client. If reading hit the cap, we lose
		// the tail — accept that trade-off (the alternative is two
		// passes / a TeeReader, both add complexity without proving
		// useful in practice). The env override above gives operators
		// a knob to raise the cap when they need it.
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		resp.ContentLength = int64(len(bodyBytes))
	}

	// Outbound URL — reconstruct host from route.BaseURL since
	// ReverseProxy.Director set req.URL.Scheme/Host on a different
	// request object (the one passed to Director, not `r`). r.URL.Path
	// + r.URL.RawQuery at this point ARE the outbound versions (the
	// path mutation in handleAppPipeline + the ?beta=true added by
	// oauthInject all happened before the Director ran).
	outboundURL := route.BaseURL + r.URL.Path
	if r.URL.RawQuery != "" {
		outboundURL += "?" + r.URL.RawQuery
	}

	// Credential family — never the secret. realKey is one of:
	//   "__oauth__" sentinel (oauth path; actual token in header set by oauthInject)
	//   personal key plaintext / team virtual key plaintext (set by ResolveBindingCredential)
	// Logging the family alone is enough for diagnosis without leaking
	// the secret. realKey could in theory contain a real key, so the
	// switch is a positive-match-or-redact pattern.
	credFamily := "personal-or-team"
	if realKey == "__oauth__" {
		credFamily = "oauth"
	}

	// Parse the response envelope for provider-side error metadata.
	// Both Anthropic and OpenAI wrap errors in:
	//   {"type":"error","error":{"type":"...","message":"..."}}     (Anthropic)
	//   {"error":{"type":"...","message":"...","code":"..."}}        (OpenAI)
	// A single struct with optional fields covers both shapes.
	errType, errMessage := parseUpstreamErrorEnvelope(bodyBytes)

	const errorMessageLogCap = 300
	if len(errMessage) > errorMessageLogCap {
		errMessage = errMessage[:errorMessageLogCap] + "...<truncated>"
	}

	logger.Warn("app pipeline upstream error",
		"event.name", "proxy.app.upstream_error",
		"status_code", resp.StatusCode,
		"upstream_request_id", extractUpstreamRequestID(resp),
		"outbound_url", outboundURL,
		"outbound_method", r.Method,
		"route_source", route.RouteSource,
		"app_slug", route.AppSlug,
		"app_kind", route.AppKind,
		"provider", route.ProviderCode,
		"credential_family", credFamily,
		"upstream_error_type", errType,
		"upstream_error_message", errMessage,
		// Hint for verbose follow-up — only one place to point operators
		// at when this log isn't sufficient for diagnosis.
		"hint", "set AIKEY_PROXY_DEBUG_4XX_BODIES=1 for full request/response body capture (PII risk: contains user prompts)",
	)
}

// parseUpstreamErrorEnvelope extracts (type, message) from a provider
// error response body. Returns ("", "") when the body isn't parseable
// JSON or doesn't match a known envelope shape — both cases are
// signal-free, not a bug.
//
// Anthropic shape:  {"type":"error","error":{"type":"not_found_error","message":"..."}}
// OpenAI shape:     {"error":{"type":"invalid_request","message":"...","code":"..."}}
// Both share the `error.{type,message}` nested path, so one parse covers them.
func parseUpstreamErrorEnvelope(body []byte) (errType, errMessage string) {
	if len(body) == 0 {
		return "", ""
	}
	var env struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", ""
	}
	return env.Error.Type, env.Error.Message
}

// truncateBodyForLog renders body bytes as a string, capping at the
// resolved body-log cap (env override or compile default) and appending
// an explicit truncation marker so the reader knows the captured snippet
// is incomplete.
func truncateBodyForLog(b []byte) string {
	logCap := resolvedBodyLogCap()
	if len(b) <= logCap {
		return string(b)
	}
	return string(b[:logCap]) + "...<truncated>"
}

// extractUpstreamRequestID pulls the provider's own request id out of the
// response headers. Anthropic uses `request-id` (their docs explicitly call
// it out as the audit-log pivot), OpenAI / Codex / Azure-OpenAI use
// `x-request-id` or the legacy `openai-request-id`, and most other gateways
// follow one of those two conventions. Returns the first non-empty value;
// callers treat empty as "upstream did not surface one".
func extractUpstreamRequestID(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	for _, h := range []string{"request-id", "x-request-id", "openai-request-id"} {
		if v := resp.Header.Get(h); v != "" {
			return v
		}
	}
	return ""
}

// reportUsage builds a ReportableEvent and emits it to whichever sinks are
// configured:
//   - reporter present → Report() handles WAL append + async upload
//   - reporter nil but WAL present → append directly (offline standalone mode)
//   - neither → no-op
//
// sessionID is the value of X-Claude-Code-Session-Id (empty for non-Claude-Code clients).
// completion is the transport-level outcome: "complete" | "partial" | "interrupted".
// breakdown carries the optional cache split (zeroed for providers that don't
// surface it, e.g. OpenAI/Kimi).
// upstreamReqID is the provider-side request id (anthropic `req_xxx` / openai
// `req_xxx`) extracted from response headers; empty when upstream omitted it.
func (p *Proxy) reportUsage(route *vkeys.ResolvedRoute, bearerToken, model string, startTime time.Time, statusCode int, breakdown provider.TokenBreakdown, errorType, errorMessage, realKey, sessionID, completion, upstreamReqID string) {
	if p.reporter == nil && p.wal == nil {
		return
	}

	// Delivery integrity: allocate a per-source, never-reused sequence for this
	// event (design §5.2). Canary events are deliberately excluded — they are
	// synthetic liveness probes, not business usage, and must not create gaps in
	// the real sequence stream. A SeqAllocator error (e.g. reserve fsync failed)
	// degrades to a v1-shaped event (no seq) rather than blocking the report —
	// the reserve-ahead invariant guarantees the failed seq is never reused.
	var sourceID string
	var sourceSeq *int64
	if p.seqAlloc != nil && p.sourceID != "" && route != nil && route.OrgID != "__canary__" {
		if seq, err := p.seqAlloc.Next(); err != nil {
			slog.Warn("reportUsage: seq alloc failed, emitting v1 event",
				"event.name", "usage.seqalloc.next_failed", "error", err)
		} else {
			sourceID = p.sourceID
			s := seq
			sourceSeq = &s
		}
	}

	ev := events.BuildReportableEvent(&events.ReportOpts{
		EventID:                  observability.NewID(),
		ProxyInstanceID:          p.proxyInstanceID,
		SourceID:                 sourceID,
		SourceSeq:                sourceSeq,
		Route:                    route,
		BearerToken:              bearerToken,
		Model:                    model,
		StartTime:                startTime,
		FinishedAt:               time.Now(),
		StatusCode:               statusCode,
		InputTokens:              breakdown.InputTokens,
		OutputTokens:             breakdown.OutputTokens,
		CacheReadInputTokens:     breakdown.CacheReadInputTokens,
		CacheCreationInputTokens: breakdown.CacheCreationInputTokens,
		// Cost-pricing audit (v1.0.0-rc.8): reasoning from the breakdown, region
		// + endpoint derived from the resolved route's upstream URL. Both
		// flowing through this single reportUsage covers streaming + non-streaming.
		ReasoningTokens:    breakdown.ReasoningTokens,
		Region:             regionFromBaseURL(routeBaseURL(route)),
		EndpointURL:        routeBaseURL(route),
		StopReason:         breakdown.StopReason,
		ErrorType:          errorType,
		ErrorMessage:       errorMessage,
		RealKey:            realKey,
		ClientVersion:      p.clientVersion,
		SourceVersion:      p.clientVersion,
		ProxyConfigVersion: p.proxyConfigVersion,
		LoadedControlSeq:   p.loadedControlSeq,
		LoggedInAccountID:  p.loggedInAccountID,
		SessionID:          sessionID,
		Completion:         completion,
		UpstreamRequestID:  upstreamReqID,
	})
	if p.reporter != nil {
		// Reporter writes WAL + enqueues upload; when wal is the shared
		// instance no duplicate append happens.
		p.reporter.Report(&ev)
		return
	}
	// Offline path: no collector_url, but WAL is still desired so local
	// statusline / watch can consume it.
	p.wal.Append(&ev)
}

// routeBaseURL returns the resolved upstream base URL, nil-safe.
func routeBaseURL(route *vkeys.ResolvedRoute) string {
	if route == nil {
		return ""
	}
	return route.BaseURL
}

// regionFromBaseURL extracts the cloud region from a Bedrock or Vertex upstream
// URL for region-aware pricing. Returns "" for direct providers
// (api.anthropic.com, api.openai.com, ...) which are not region-scoped.
//
//	Bedrock: bedrock-runtime.<region>.amazonaws.com
//	Vertex:  <region>-aiplatform.googleapis.com
func regionFromBaseURL(baseURL string) string {
	if baseURL == "" {
		return ""
	}
	host := baseURL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if strings.HasPrefix(host, "bedrock-runtime.") && strings.HasSuffix(host, ".amazonaws.com") {
		return strings.TrimSuffix(strings.TrimPrefix(host, "bedrock-runtime."), ".amazonaws.com")
	}
	if strings.HasSuffix(host, "-aiplatform.googleapis.com") {
		return strings.TrimSuffix(host, "-aiplatform.googleapis.com")
	}
	return ""
}

// resolveSessionID returns the session id to stamp into the WAL event.
//
// Delegates to the sessionid package's config-driven extractor
// (fingerprint.yaml). The dispatch table there encodes which header
// or body field carries the session ID for each (protocol, provider)
// combination — Claude Code's X-Claude-Code-Session-Id, Kimi's
// prompt_cache_key, OpenAI's conversation_id, the cross-protocol
// X-Aikey-Session-Id convention for third-party Agents, plus a
// common fallback. New protocols are added by editing yaml, not Go
// code. See design doc:
//
//	roadmap20260320/技术实现/阶段5-丰富生态/
//	  20260526-Performance页会话维度与下钻设计.md
//
// Pre-rc.6 behavior was a hard-coded ladder: X-Claude-Code-Session-Id
// header, then (only for Kimi) x-aikey-kimi-session header that
// extractModel pre-stashes from the body's prompt_cache_key. The new
// extractor preserves both paths (Kimi yaml rule tries the stashed
// header first as a perf shortcut, then falls back to body parsing
// if the stash isn't populated), so the existing extractModel stash
// mechanism continues to work without changes.
//
// Both args come from the resolved route; protocol is the wire-level
// protocol family (e.g. "anthropic", "openai", "openai_compatible"),
// provider is the canonical code (e.g. "anthropic", "kimi_code",
// "moonshot", "openai"). Empty values are tolerated — the extractor
// falls through to common_fallback.
func resolveSessionID(req *http.Request, protocolType, providerCode string) string {
	return sessionid.Default().Extract(req, protocolType, providerCode)
}

// extractModel reads the request body to find the top-level `model` field
// and Kimi's `prompt_cache_key` (= session id). It stashes both into
// custom x-aikey-* request headers so buildBaseEvent / reportUsage can
// read them later without re-parsing the body.
//
// Why both in one pass: once ReverseProxy forwards the request the body
// stream is consumed — ModifyResponse can't reach back into it. Parsing
// here is the only correct timing.
//
// Memory model (simplified 2026-04-21 from the prior streaming-prefix
// design):
//
//	Body ≤ extractBodyHardLimit (4 MB): full io.ReadAll + json.Unmarshal.
//	  Typical Claude/Kimi/OpenAI text bodies sit at 10 KB – 500 KB, well
//	  within this budget. Concurrency on a single-user local proxy is
//	  low, so the instantaneous memory cost is tiny.
//	Body > extractBodyHardLimit: skip parsing entirely. ev.Model stays
//	  empty (UI handles the empty case via fallback paths). This fence
//	  protects against OOM on multimodal payloads with base64 images
//	  (legitimately 10+ MB).
//
// Earlier a 16 KB streaming-prefix scan was added to reduce memory for
// mid-size bodies, but it turned out to break real Kimi CLI 1.36.0
// traffic: kosong's Python SDK serializes `messages` (huge array) as the
// first top-level key and spreads `prompt_cache_key` via `**kwargs` AFTER
// it. The prefix scan never reached the session id field, so Kimi WAL
// events landed with empty session_id and the receipt hook did not fire.
// The fence alone preserves the OOM protection that review finding #1
// asked for, without the field-order fragility.
const extractBodyHardLimit = 4 * 1024 * 1024 // 4 MB

// jsonEscapeForError escapes a string for safe embedding in a JSON
// error-body literal. Only escapes the JSON-syntax-critical characters
// (`\`, `"`, control bytes); higher-byte sequences pass through, which
// is fine for UTF-8 since none of them collide with structural JSON.
// Used by the App-pipeline ResponseTransform failure path to embed
// an upstream error message into a synthetic error envelope without
// pulling json.Marshal on a known-tiny string.
func jsonEscapeForError(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				// Other control chars get the \u00XX form. Rare in error
				// messages; covered for safety.
				const hex = "0123456789abcdef"
				b.WriteString(`\u00`)
				b.WriteByte(hex[(c>>4)&0xf])
				b.WriteByte(hex[c&0xf])
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

// extractModelLazy parses the `model` field out of an already-buffered
// JSON body without touching the http.Request — used by App pipeline's
// translation step, which has the sanitized bytes in-hand and doesn't
// want to consume/re-buffer r.Body. Returns empty string on parse
// failure or absent field (caller treats empty as "let translator
// decide / pass through").
func extractModelLazy(body []byte) string {
	if len(body) == 0 || len(body) > extractBodyHardLimit {
		return ""
	}
	var partial struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &partial); err != nil {
		return ""
	}
	return partial.Model
}

func extractModel(r *http.Request) string {
	// Parse-once: reuse the model the FIRST extractModel call this request
	// already parsed + cached. Keyed on the context (not the x-aikey-model
	// header) because the header is client-spoofable — see ctxKeyExtractedModel.
	// The cache is set only after a successful real-body parse below, so the
	// allowlist-critical first read is never skipped, and a parse failure
	// (cache not set) keeps the prior re-parse behavior.
	if v, ok := r.Context().Value(ctxKeyExtractedModel).(string); ok {
		return v
	}
	if r.Body == nil {
		return ""
	}
	if r.ContentLength > extractBodyHardLimit {
		return ""
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	var partial struct {
		Model          string `json:"model"`
		PromptCacheKey string `json:"prompt_cache_key"`
	}
	if err := json.Unmarshal(bodyBytes, &partial); err != nil {
		// Body isn't JSON we understand — leave both headers unset.
		return ""
	}

	stashExtractedFields(r, partial.Model, partial.PromptCacheKey)
	// Cache for the repeat calls (overwrites any client-injected header value
	// via stashExtractedFields above, so the cached value is the real model).
	*r = *r.WithContext(context.WithValue(r.Context(), ctxKeyExtractedModel, partial.Model))
	return partial.Model
}

func stashExtractedFields(r *http.Request, model, promptCacheKey string) {
	if model != "" {
		r.Header.Set("x-aikey-model", model)
	}
	if promptCacheKey != "" {
		// Kimi-specific; resolveSessionID gates by provider_code so a
		// non-Kimi client that happens to send prompt_cache_key cannot
		// accidentally inject a session_id into WAL (review finding #3).
		r.Header.Set("x-aikey-kimi-session", promptCacheKey)
	}
}
