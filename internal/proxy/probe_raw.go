package proxy

// Pre-save proxy probe — `aikey_probe_raw_<canonical>` pipeline.
//
// Spec: roadmap20260320/技术实现/update/20260526-pre-save-proxy-probe-raw.md
//
// Purpose: let Web Add Key modal + CLI `aikey add` validate that the
// **key being typed** (not whatever active binding happens to exist) can
// successfully reach the provider through this machine's aikey-proxy.
//
// Differences vs the regular path-prefix / probe pipeline:
//   - No vault lookup (the key isn't in vault yet — that's the whole point)
//   - Bearer comes from X-Aikey-Probe-Bearer HTTP header, not Authorization
//   - Bypasses reporter / WAL (already covered by isAikeyProbe but
//     reinforced by never calling p.recordEvent in this file)
//   - Strict allowlist for outbound headers (Anthropic / OpenAI etc are
//     sensitive to custom headers — X-Aikey-Probe-* MUST NOT leak)
//   - Response: proxy itself returns 200 with body carrying real upstream
//     status (lets caller distinguish "proxy chain ok, key rejected" from
//     "proxy down")
//
// Why a separate file: the whole pipeline is ~150 LOC self-contained, no
// shared state with the main legacy path beyond p.transport. Putting it
// here keeps proxy.go from growing past 2400 lines and makes the security
// surface (allowlist, redactor, no-reporter) audit-able in one read.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// ── Constants ─────────────────────────────────────────────────────────────

const (
	// Header names. Lowercase canonical (Go http.Header normalizes to
	// MIME-style on Get/Set, but match input casing exactly for clarity in
	// allowlist checks below).
	headerProbeRawBearer  = "X-Aikey-Probe-Bearer"
	headerProbeRawBaseURL = "X-Aikey-Probe-BaseURL"

	// Caps. probeBearer max length: provider keys today are ≤ 256 chars (sk-ant
	// long form ~108 chars, OpenAI sk-... ~51 chars). 1024 caps adversarial
	// abuse of the header to push large payloads through probe path. probeBaseURL
	// caps at 512 (typical https://<host>/v1 is ~64 chars).
	probeBearerMaxLen  = 1024
	probeBaseURLMaxLen = 512

	// Upstream call timeout for probe traffic. Tighter than the regular
	// upstream timeout because probe should be fast (no streaming, no large
	// completions) — better to fail loud at 10s than let the modal hang.
	probeRawUpstreamTimeout = 10 * time.Second

	// Fixed User-Agent for outbound probe traffic. Never propagate caller UA
	// (may contain internal hostnames, IPs, or telemetry-identifying strings).
	probeRawUserAgent = "aikey-proxy-probe/1.0"

	// Feature flag env var. Note: DISABLED semantics (default behavior =
	// enabled; flag is a defense rollback switch, not a progressive enabler).
	// Spec §8 — 2026-05-26 user decision to default-on.
	envProbeRawDisabled = "AIKEY_PROBE_RAW_DISABLED"

	// Path probed when the URL is just the provider prefix (e.g. POST
	// /anthropic/) — most providers accept GET /v1/models cheaply for liveness.
	// Caller usually sends a specific path (/anthropic/v1/messages, etc) and
	// we just forward that; this default only kicks in if the path is empty.
	defaultProbePath = "/v1/models"
)

// outboundHeaderAllowlist is the EXHAUSTIVE list of headers permitted to
// reach upstream provider in probe_raw mode.
//
// ⚠️  ALLOWLIST, NOT BLACKLIST — per spec §7.1. Anthropic / OpenAI / etc
// have anti-abuse systems that may flag exotic custom headers as risk
// signals; X-Aikey-Probe-Bearer in particular carries plaintext key + the
// Authorization header was already replaced, so upstream seeing it would
// be a duplicate-key echo (worst-case ban trigger).
//
// New headers must be added explicitly with security review.  Default-deny.
//
// Headers MUST be in HTTP/2 canonical form (Title-Case) — Go's http.Header
// canonicalizes on Get/Set/Add via http.CanonicalHeaderKey. Probe outbound
// uses Header.Set which canonicalizes; comparisons here use the same form.
var outboundHeaderAllowlist = map[string]struct{}{
	// Generic HTTP plumbing — needed for upstream to parse the request.
	"Content-Type":    {},
	"Content-Length":  {},
	"Accept":          {},
	"Accept-Encoding": {},

	// Anthropic-required protocol headers (anthropic-version is part of the
	// Messages API contract; anthropic-beta unlocks specific endpoints).
	"Anthropic-Version": {},
	"Anthropic-Beta":    {},

	// OpenAI-optional org / project scoping. Usually not needed for probes
	// but harmless and may be required for project-scoped keys.
	"Openai-Organization": {},
	"Openai-Project":      {},

	// User-Agent intentionally NOT here — we always overwrite with a fixed
	// value in the handler (probeRawUserAgent). Keeping it in the allowlist
	// would let caller UA leak through.
	//
	// Authorization intentionally NOT here — we always set ourselves from
	// X-Aikey-Probe-Bearer header.
}

// ── Handler ───────────────────────────────────────────────────────────────

// handleProbeRaw services pre-save probe requests classified as
// Tier2ProbeRaw. Called from handlePathPrefixRoute's dispatch switch.
//
// Inputs:
//   - canonicalCode: from URL path (e.g. /anthropic/v1/... → "anthropic"),
//     already canonicalized by providerCanonicalCode at the caller.
//   - strippedPath: URL after the provider prefix is removed (e.g. "/v1/messages").
//
// Pipeline:
//
//	1. flag gate (defense rollback)
//	2. header presence + length validation
//	3. resolve upstream base URL
//	4. construct upstream request with allowlist headers + fixed UA + injected auth
//	5. send + time the upstream call
//	6. emit JSON response with probe_ok + upstream_status + latency_ms
//	7. NEVER call p.recordEvent (no reporter/WAL — isAikeyProbe enforces
//	   for shared paths; we never enter them in the first place)
func (p *Proxy) handleProbeRaw(w http.ResponseWriter, r *http.Request, canonicalCode, strippedPath string, logger *slog.Logger) {
	logger = logger.With(
		"routing", "probe-raw",
		"provider", canonicalCode,
	)

	// 1. Defense rollback gate.
	if probeRawDisabled() {
		logger.Warn("probe_raw blocked by flag", "event.name", observability.EventProxyRequestPolicyDenied)
		writeJSONError(w, http.StatusServiceUnavailable, "server_error", "PROBE_RAW_DISABLED",
			"Pre-save proxy probe disabled by operator. Unset "+envProbeRawDisabled+" to restore.")
		return
	}

	// 2a. Enforce X-Aikey-Probe: 1 header. Without this the path is a
	// reporter-bypass vulnerability (caller could send arbitrary upstream
	// traffic with no billing record). Spec §7.2.
	if !isAikeyProbe(r) {
		logger.Warn("probe_raw missing X-Aikey-Probe: 1 header")
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "PROBE_HEADER_REQUIRED",
			"aikey_probe_raw_* tokens require X-Aikey-Probe: 1 header (defense against reporter-bypass abuse)")
		return
	}

	// 2b. Read + validate probe headers.
	probeBearer := r.Header.Get(headerProbeRawBearer)
	probeBaseURL := r.Header.Get(headerProbeRawBaseURL)
	if len(probeBearer) > probeBearerMaxLen {
		logger.Warn("probe_raw bearer header too long", "len", len(probeBearer), "max", probeBearerMaxLen)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "PROBE_BEARER_TOO_LONG",
			"X-Aikey-Probe-Bearer length exceeds limit")
		return
	}
	if len(probeBaseURL) > probeBaseURLMaxLen {
		logger.Warn("probe_raw base_url header too long", "len", len(probeBaseURL), "max", probeBaseURLMaxLen)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "PROBE_BASEURL_TOO_LONG",
			"X-Aikey-Probe-BaseURL length exceeds limit")
		return
	}

	// 3. Resolve upstream base URL — caller override wins if non-empty,
	// otherwise providerDefaultBaseURL (same source-of-truth as legacy paths).
	baseURL := probeBaseURL
	if baseURL == "" {
		baseURL = providerDefaultBaseURL(canonicalCode)
	}
	if baseURL == "" {
		// canonicalProviderCodes accepted the token but providerDefaultBaseURL
		// returned empty — drift between the two allowlists. Surface loud (this
		// is the cross-language drift fence the spec calls out).
		logger.Error("probe_raw: canonical accepted but no default base URL — drift bug",
			"event.name", observability.EventProxyRequestVaultFailed,
		)
		writeJSONError(w, http.StatusInternalServerError, "server_error", "PROBE_BASEURL_DRIFT",
			"internal: provider "+canonicalCode+" lacks default base URL (config drift)")
		return
	}

	// Strip trailing slash from baseURL so url join is predictable
	// (providerDefaultBaseURL is inconsistent about trailing /v1 vs not, but
	// we mirror the legacy path-prefix behavior which assumes no trailing
	// slash and strippedPath always starts with /).
	baseURL = strings.TrimRight(baseURL, "/")
	upstreamURL := baseURL + strippedPath
	if strippedPath == "" || strippedPath == "/" {
		upstreamURL = baseURL + defaultProbePath
	}

	// 4. Construct upstream request. Use the request's context so caller
	// disconnect cancels upstream (avoids dangling probes).
	upstreamCtx, cancel := contextWithProbeTimeout(r.Context())
	defer cancel()

	upstreamReq, reqErr := http.NewRequestWithContext(upstreamCtx, r.Method, upstreamURL, r.Body)
	if reqErr != nil {
		logger.Warn("probe_raw upstream request build failed", "error", redactBearer(reqErr.Error(), probeBearer))
		writeJSONError(w, http.StatusInternalServerError, "server_error", "PROBE_REQUEST_BUILD_FAILED",
			"failed to build upstream request: "+redactBearer(reqErr.Error(), probeBearer))
		return
	}

	// 4a. Copy allowlisted headers from inbound to outbound.
	// Default-deny: anything not in outboundHeaderAllowlist is dropped.
	copyAllowlistedHeaders(r.Header, upstreamReq.Header)

	// 4b. Set fixed User-Agent — overwrites whatever caller sent
	// (including any UA copied above, since UA is NOT in the allowlist).
	upstreamReq.Header.Set("User-Agent", probeRawUserAgent)

	// 4c. Inject upstream auth.  When probeBearer empty (caller didn't
	// provide it), we send no auth and let upstream return 401 — still a
	// useful signal ("proxy → upstream chain works, just no key was tested").
	if probeBearer != "" {
		injectProbeAuth(upstreamReq, canonicalCode, probeBearer)
	}

	// 4d. Final safety guard — strip any X-Aikey-* headers that might have
	// slipped through (allowlist should already exclude them; double-check
	// invariant per spec §4.3).
	stripAikeyHeaders(upstreamReq.Header)

	// 5. Send + time. Use p.transport so HTTP_PROXY env etc are honored
	// the same way as the regular upstream path.
	transport := p.transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client := &http.Client{Transport: transport, Timeout: probeRawUpstreamTimeout}

	startUp := time.Now()
	resp, doErr := client.Do(upstreamReq)
	latencyMs := time.Since(startUp).Milliseconds()

	// 6. Emit response. Proxy itself returns 200 on success; upstream's real
	// status is in body (lets caller distinguish proxy vs key issues, spec §2.4).
	if doErr != nil {
		logger.Info("probe_raw upstream unreachable",
			"latency_ms", latencyMs,
			"error", redactBearer(doErr.Error(), probeBearer),
			"event.name", observability.EventProxyRequestUpstreamError,
		)
		writeProbeRawJSON(w, http.StatusBadGateway, map[string]any{
			"probe_ok":      false,
			"error_code":    classifyUpstreamErr(doErr),
			"error_message": redactBearer(doErr.Error(), probeBearer),
			"latency_ms":    latencyMs,
			"provider":      canonicalCode,
		})
		return
	}
	defer resp.Body.Close()

	// Consume + discard upstream body. We don't care about content — only
	// status code matters for probe semantics. Discarding (not skipping)
	// keeps the connection reusable in transport's pool.
	_, _ = io.Copy(io.Discard, resp.Body)

	logger.Info("probe_raw upstream returned",
		"upstream_status", resp.StatusCode,
		"latency_ms", latencyMs,
		"event.name", observability.EventProxyRequestCompleted,
	)
	writeProbeRawJSON(w, http.StatusOK, map[string]any{
		"probe_ok":        true,
		"upstream_status": resp.StatusCode,
		"latency_ms":      latencyMs,
		"provider":        canonicalCode,
		"status_hint":     probeRawStatusHint(resp.StatusCode),
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────

// probeRawDisabled reads the feature flag at request time (cheap env lookup).
// Reading per-request rather than caching at startup lets operators flip the
// flag without restarting proxy — important for hotfix rollback. Cost is
// negligible (one syscall per probe; probes are low-frequency by nature).
//
// Truthy values: "1", "true", "yes" (case-insensitive). Anything else =
// enabled (default).
func probeRawDisabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(envProbeRawDisabled)))
	return v == "1" || v == "true" || v == "yes"
}

// copyAllowlistedHeaders copies headers from src → dst where the canonical
// header name is in outboundHeaderAllowlist. Default-deny: anything else
// is silently dropped (per spec §7.1 allowlist model).
//
// http.Header.Get/Set canonicalize via http.CanonicalHeaderKey, so the
// allowlist uses MIME-style Title-Case names and src's casing is normalized
// at access time.
func copyAllowlistedHeaders(src, dst http.Header) {
	for name, values := range src {
		canonical := http.CanonicalHeaderKey(name)
		if _, allowed := outboundHeaderAllowlist[canonical]; !allowed {
			continue
		}
		for _, v := range values {
			dst.Add(canonical, v)
		}
	}
}

// stripAikeyHeaders removes any X-Aikey-* headers from outbound request.
// Defense in depth — outboundHeaderAllowlist should never let them through,
// but a second guard ensures even an allowlist regression doesn't leak
// probe bearer to upstream. Cost: one map iteration on outbound headers
// (typically < 10 entries).
func stripAikeyHeaders(h http.Header) {
	var toDelete []string
	for name := range h {
		canonical := http.CanonicalHeaderKey(name)
		if strings.HasPrefix(canonical, "X-Aikey-") {
			toDelete = append(toDelete, name)
		}
	}
	for _, name := range toDelete {
		h.Del(name)
	}
}

// injectProbeAuth sets the upstream Authorization (or x-api-key) header
// using the caller-provided probeBearer. Header convention matches the
// provider's wire protocol — Anthropic uses x-api-key, others Bearer auth.
//
// Mirrors connectivity/runtime.rs::probe_auth in the Rust client so caller
// and proxy agree on auth shape.
func injectProbeAuth(req *http.Request, canonicalCode, bearer string) {
	switch canonicalCode {
	case "anthropic":
		// Anthropic uses x-api-key. Bearer Authorization also works for
		// some endpoints but x-api-key is the documented contract.
		req.Header.Set("X-Api-Key", bearer)
	default:
		// OpenAI / DeepSeek / Groq / xAI / Kimi / Moonshot / etc all use
		// Bearer Authorization. google (Gemini) accepts x-goog-api-key but
		// also Bearer for generativelanguage API — Bearer is the safe default.
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
}

// classifyUpstreamErr maps a transport-layer error to a stable error_code
// returned to caller. Categorization helps the caller (web modal / CLI)
// render specific user-facing hints instead of dumping raw Go error strings.
func classifyUpstreamErr(err error) string {
	if err == nil {
		return "PROBE_UPSTREAM_OK"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "PROBE_UPSTREAM_TIMEOUT"
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "dns"):
		return "PROBE_UPSTREAM_DNS_FAIL"
	case strings.Contains(msg, "connection refused"):
		return "PROBE_UPSTREAM_CONN_REFUSED"
	case strings.Contains(msg, "tls"), strings.Contains(msg, "x509"):
		return "PROBE_UPSTREAM_TLS_FAIL"
	default:
		return "PROBE_UPSTREAM_UNREACHABLE"
	}
}

// probeRawStatusHint maps upstream HTTP status → short hint string for the
// caller to render. Mirrors connectivity/runtime.rs::proxy_status_hint so
// CLI and web display consistent labels.
func probeRawStatusHint(status int) string {
	switch status {
	case 200:
		return "routing ok, key valid"
	case 201, 204:
		return "routing ok"
	case 400, 404, 405:
		return "routing ok (endpoint returned " + strconv.Itoa(status) + ")"
	case 401, 403:
		return "routing ok, key rejected by upstream"
	case 429:
		return "routing ok, upstream rate-limited"
	case 503:
		return "upstream unavailable"
	default:
		if status >= 500 {
			return "upstream error " + strconv.Itoa(status)
		}
		return "HTTP " + strconv.Itoa(status)
	}
}

// redactBearer replaces all occurrences of `bearer` in `s` with [REDACTED].
// Used on err.Error() and any other free-form text path where the caller-
// provided plaintext key might appear (TLS errors with hostnames OK; transport
// errors with embedded query strings could leak — defense in depth).
//
// No-op when bearer is empty (avoids replacing every char position).
func redactBearer(s, bearer string) string {
	if bearer == "" {
		return s
	}
	return strings.ReplaceAll(s, bearer, "[REDACTED]")
}

// writeProbeRawJSON writes a JSON response with the given status code and
// body. Uses encoding/json (not the inline string-concat path used by
// writeJSONError) because the body has nested numbers/bools that string
// concat would mishandle.
func writeProbeRawJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// contextWithProbeTimeout returns a child context that is canceled when
// either the parent is canceled (caller disconnect) or probeRawUpstreamTimeout
// elapses. Caller is responsible for calling the returned cancel func.
func contextWithProbeTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, probeRawUpstreamTimeout)
}

