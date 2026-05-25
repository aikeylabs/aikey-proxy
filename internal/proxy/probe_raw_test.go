package proxy

// Security fence tests for the pre-save proxy probe (probe_raw.go).
//
// Spec: roadmap20260320/技术实现/update/20260526-pre-save-proxy-probe-raw.md §10.1
//
// Five fences pinned here:
//   1. Flag gate (PROBE_RAW_DISABLED env var disables the path with 503)
//   2. Header gate (missing X-Aikey-Probe: 1 → 401 PROBE_HEADER_REQUIRED)
//   3. Length cap (oversize X-Aikey-Probe-Bearer → 400 PROBE_BEARER_TOO_LONG)
//   4. Outbound header allowlist — NO X-Aikey-* / X-Forwarded-* on the request
//      that actually reaches upstream, AND User-Agent is the fixed
//      "aikey-proxy-probe/1.0", AND injected auth matches the caller's
//      X-Aikey-Probe-Bearer (not whatever Authorization the caller sent).
//   5. Redactor — when upstream call fails with the bearer echoed in the
//      error string, the error_message field in the JSON response has
//      [REDACTED] substituted for the plaintext bearer.
//
// Bonus (covered by happy path):
//   6. Response shape — 200 on proxy success, body has probe_ok + upstream_status
//      + latency_ms + provider + status_hint.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ── Recording upstream: captures the headers AND Authorization the proxy
// actually sends. Distinct from runtime_switching_test.go's recordingUpstream
// (which only captures the key) — we need the full header set to fence #4.

type probeRawRecordingUpstream struct {
	server *httptest.Server
	mu     sync.Mutex
	last   http.Header
	body   []byte
}

func newProbeRawRecordingUpstream(status int, respBody string) *probeRawRecordingUpstream {
	u := &probeRawRecordingUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		// Clone header so we capture the exact map sent by proxy.
		u.last = r.Header.Clone()
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(respBody))
	}))
	return u
}

func (u *probeRawRecordingUpstream) close()             { u.server.Close() }
func (u *probeRawRecordingUpstream) URL() string        { return u.server.URL }
func (u *probeRawRecordingUpstream) capturedHeaders() http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.last.Clone()
}

// sendProbeRaw builds a probe_raw request and dispatches it through the
// proxy's Handle method. Returns the response recorder for assertion.
//
// `bearerHeader` empty → don't set X-Aikey-Probe-Bearer at all (tests the
// "no auth" code path). Setting to "" via Header.Set would still create the
// header with empty value, which is a different test case.
func sendProbeRaw(t *testing.T, p *Proxy, provider, baseURL, bearerHeader string, extraHeaders map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/"+provider+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer aikey_probe_raw_"+provider)
	req.Header.Set("X-Aikey-Probe", "1")
	if baseURL != "" {
		req.Header.Set("X-Aikey-Probe-BaseURL", baseURL)
	}
	if bearerHeader != "" {
		req.Header.Set("X-Aikey-Probe-Bearer", bearerHeader)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	p.Handle(rec, req)
	return rec
}

// minimalProbeRawProxy builds a Proxy with the minimum machinery for
// probe_raw routing — needs an ActiveKeyReader (so handlePathPrefixRoute is
// reachable), but probe_raw itself never consults vault/binding state.
func minimalProbeRawProxy(t *testing.T) *Proxy {
	t.Helper()
	av := &mockActiveVault{}
	return setupTestProxyWithActive(t, av)
}

// decodeProbeRawBody parses the proxy's JSON response body into a map.
// Fail-loud on bad JSON to surface contract drift early.
func decodeProbeRawBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v\nbody: %s", err, rec.Body.String())
	}
	return body
}

// ─────────────────────────────────────────────────────────────────────────
// Fence 1: Flag gate — AIKEY_PROBE_RAW_DISABLED=1 returns 503
// ─────────────────────────────────────────────────────────────────────────

func TestProbeRaw_FlagDisabled(t *testing.T) {
	t.Setenv(envProbeRawDisabled, "1")

	p := minimalProbeRawProxy(t)
	rec := sendProbeRaw(t, p, "anthropic", "" /* default base URL */, "sk-ant-test", nil)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (PROBE_RAW_DISABLED), got %d — body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PROBE_RAW_DISABLED") {
		t.Errorf("expected body to mention PROBE_RAW_DISABLED, got: %s", rec.Body.String())
	}
}

// Defense rollback flag should accept multiple truthy spellings (operator
// might type "true" or "yes" in stress).
func TestProbeRaw_FlagDisabled_TruthyVariants(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "yes", "YES", " 1 "} {
		v := v
		t.Run(v, func(t *testing.T) {
			t.Setenv(envProbeRawDisabled, v)
			p := minimalProbeRawProxy(t)
			rec := sendProbeRaw(t, p, "anthropic", "", "sk-ant-test", nil)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("flag value %q: expected 503, got %d", v, rec.Code)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Fence 2: Header gate — missing X-Aikey-Probe: 1 → 401
// ─────────────────────────────────────────────────────────────────────────

func TestProbeRaw_MissingProbeHeader(t *testing.T) {
	// Direct construction to omit X-Aikey-Probe header that sendProbeRaw always sets.
	upstream := newProbeRawRecordingUpstream(200, `{"ok":true}`)
	defer upstream.close()

	p := minimalProbeRawProxy(t)

	req := httptest.NewRequest(http.MethodGet, "/anthropic/v1/models", nil)
	req.Header.Set("Authorization", "Bearer aikey_probe_raw_anthropic")
	req.Header.Set("X-Aikey-Probe-BaseURL", upstream.URL())
	req.Header.Set("X-Aikey-Probe-Bearer", "sk-ant-test")
	// Intentionally do NOT set X-Aikey-Probe.
	rec := httptest.NewRecorder()
	p.Handle(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (PROBE_HEADER_REQUIRED), got %d — body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PROBE_HEADER_REQUIRED") {
		t.Errorf("expected body to mention PROBE_HEADER_REQUIRED, got: %s", rec.Body.String())
	}
	// Critical: upstream MUST NOT have been called (reporter-bypass defense).
	if h := upstream.capturedHeaders(); h != nil {
		t.Errorf("upstream was reached despite missing probe header — this is the reporter-bypass vulnerability the gate defends against. headers: %v", h)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Fence 3: Length cap — oversize bearer header → 400
// ─────────────────────────────────────────────────────────────────────────

func TestProbeRaw_BearerHeaderTooLong(t *testing.T) {
	upstream := newProbeRawRecordingUpstream(200, `{}`)
	defer upstream.close()

	p := minimalProbeRawProxy(t)
	oversized := strings.Repeat("a", probeBearerMaxLen+1)
	rec := sendProbeRaw(t, p, "anthropic", upstream.URL(), oversized, nil)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (PROBE_BEARER_TOO_LONG), got %d — body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PROBE_BEARER_TOO_LONG") {
		t.Errorf("expected body to mention PROBE_BEARER_TOO_LONG, got: %s", rec.Body.String())
	}
	if h := upstream.capturedHeaders(); h != nil {
		t.Errorf("oversize bearer reached upstream — length cap should be enforced before forward. headers: %v", h)
	}
}

func TestProbeRaw_BaseURLHeaderTooLong(t *testing.T) {
	p := minimalProbeRawProxy(t)
	oversized := strings.Repeat("x", probeBaseURLMaxLen+1)
	rec := sendProbeRaw(t, p, "anthropic", oversized, "sk-ant-test", nil)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (PROBE_BASEURL_TOO_LONG), got %d — body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PROBE_BASEURL_TOO_LONG") {
		t.Errorf("expected body to mention PROBE_BASEURL_TOO_LONG, got: %s", rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Fence 4 (CRITICAL): Outbound headers — allowlist enforces no leakage
// ─────────────────────────────────────────────────────────────────────────
//
// This is the security-critical invariant the user surfaced 2026-05-26:
// upstream provider (Anthropic / OpenAI) reading X-Aikey-Probe-Bearer or
// any X-Aikey-* / X-Forwarded-* / non-allowlisted header may trigger
// reputation / risk-control systems → potential account ban.
//
// Send caller request with MANY headers including X-Aikey-Probe-Bearer
// (plaintext key) + custom X-Internal-Hostname (simulates app sending
// internal telemetry) + Authorization (caller's own bearer that proxy
// must replace). Assert upstream received NONE of these. Only the
// allowlist + fixed UA + injected Authorization.

func TestProbeRaw_OutboundHeadersAllowlistOnly(t *testing.T) {
	upstream := newProbeRawRecordingUpstream(200, `{"data":[]}`)
	defer upstream.close()

	const probeBearer = "sk-ant-api03-PROBE-SECRET-VALUE"
	p := minimalProbeRawProxy(t)

	// Caller smuggles many sensitive / custom headers — none should reach upstream.
	extra := map[string]string{
		"X-Internal-Hostname":       "dev-laptop-jake.local",
		"X-Forwarded-For":           "192.168.1.100",
		"X-Custom-Telemetry":        "session_xxx",
		"X-Trace-Id":                "trace_abc123",
		"User-Agent":                "Mozilla/5.0 (sensitive UA with IP info)",
		"Anthropic-Version":         "2023-06-01",   // ALLOWED — should reach upstream
		"Content-Type":              "application/json", // ALLOWED
	}
	rec := sendProbeRaw(t, p, "anthropic", upstream.URL(), probeBearer, extra)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (proxy success), got %d — body: %s", rec.Code, rec.Body.String())
	}

	// What upstream actually saw.
	got := upstream.capturedHeaders()
	if got == nil {
		t.Fatal("upstream was never called — pipeline broken")
	}

	// (A) NO X-Aikey-* of any kind reached upstream — this is the bearer leak fence.
	for name := range got {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Aikey-") {
			t.Errorf("CRITICAL SECURITY: header %q (value %q) leaked to upstream — allowlist failed",
				name, got.Get(name))
		}
	}

	// (B) NO X-Forwarded-* reached upstream (defense against header smuggling).
	for name := range got {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Forwarded-") {
			t.Errorf("header %q leaked to upstream — allowlist should drop X-Forwarded-*", name)
		}
	}

	// (C) NO unknown custom headers smuggled by caller reached upstream.
	bannedSamples := []string{"X-Internal-Hostname", "X-Custom-Telemetry", "X-Trace-Id"}
	for _, n := range bannedSamples {
		if v := got.Get(n); v != "" {
			t.Errorf("custom header %q smuggled to upstream with value %q", n, v)
		}
	}

	// (D) User-Agent was REWRITTEN to the fixed probe UA — caller's UA never leaked.
	if ua := got.Get("User-Agent"); ua != probeRawUserAgent {
		t.Errorf("User-Agent = %q, want %q (caller UA must be rewritten, not propagated)",
			ua, probeRawUserAgent)
	}

	// (E) Allowlisted protocol header DID reach upstream.
	if av := got.Get("Anthropic-Version"); av != "2023-06-01" {
		t.Errorf("Anthropic-Version header was dropped — allowlist too strict (got %q)", av)
	}

	// (F) Authorization was INJECTED from X-Aikey-Probe-Bearer (not caller's Authorization).
	// For anthropic the auth lives in x-api-key, not Authorization.
	if xapi := got.Get("X-Api-Key"); xapi != probeBearer {
		t.Errorf("anthropic auth header X-Api-Key = %q, want %q (probe bearer not injected)",
			xapi, probeBearer)
	}
	if auth := got.Get("Authorization"); strings.Contains(auth, "aikey_probe_raw_") {
		t.Errorf("upstream Authorization still contains namespace token — proxy didn't replace: %q", auth)
	}
}

// Same fence #4, OpenAI-style provider — auth goes in Authorization Bearer
// instead of X-Api-Key. Pins that injectProbeAuth follows per-provider convention.
func TestProbeRaw_OutboundHeadersAllowlist_OpenAI(t *testing.T) {
	upstream := newProbeRawRecordingUpstream(200, `{"data":[]}`)
	defer upstream.close()

	const probeBearer = "sk-openai-PROBE-SECRET"
	p := minimalProbeRawProxy(t)

	extra := map[string]string{
		"X-Internal-Hostname": "should-not-leak",
		"X-Forwarded-For":     "10.0.0.1",
	}
	rec := sendProbeRaw(t, p, "openai", upstream.URL(), probeBearer, extra)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}

	got := upstream.capturedHeaders()
	if got == nil {
		t.Fatal("upstream not reached")
	}

	// No X-Aikey-* / X-Internal-* / X-Forwarded-*.
	for name := range got {
		canon := http.CanonicalHeaderKey(name)
		if strings.HasPrefix(canon, "X-Aikey-") ||
			strings.HasPrefix(canon, "X-Forwarded-") ||
			strings.HasPrefix(canon, "X-Internal-") {
			t.Errorf("leaked header %q to upstream", name)
		}
	}

	// User-Agent rewritten.
	if ua := got.Get("User-Agent"); ua != probeRawUserAgent {
		t.Errorf("User-Agent = %q, want %q", ua, probeRawUserAgent)
	}

	// OpenAI uses Authorization: Bearer <key>.
	wantAuth := "Bearer " + probeBearer
	if auth := got.Get("Authorization"); auth != wantAuth {
		t.Errorf("Authorization = %q, want %q", auth, wantAuth)
	}
	if xapi := got.Get("X-Api-Key"); xapi != "" {
		t.Errorf("X-Api-Key should be empty for openai, got %q", xapi)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Fence 5: Redactor — bearer never appears in error_message
// ─────────────────────────────────────────────────────────────────────────

func TestProbeRaw_RedactBearerInError(t *testing.T) {
	const probeBearer = "sk-ant-DO-NOT-LEAK-ME"
	// Point baseURL at a closed port to force a connection-refused error
	// that may (in some Go versions) include the URL in the error text.
	// More robust: use a dead IP that gets connect-refused fast.
	const deadBaseURL = "http://127.0.0.1:1"

	p := minimalProbeRawProxy(t)
	rec := sendProbeRaw(t, p, "anthropic", deadBaseURL, probeBearer, nil)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 (upstream unreachable), got %d — body: %s", rec.Code, rec.Body.String())
	}
	body := decodeProbeRawBody(t, rec)

	// The error_message field is free-form text — invariant: bearer must NEVER appear.
	errMsg, _ := body["error_message"].(string)
	if strings.Contains(errMsg, probeBearer) {
		t.Errorf("CRITICAL: bearer %q leaked into error_message: %q", probeBearer, errMsg)
	}

	// Unit-check redactBearer helper directly for completeness.
	got := redactBearer("dial err: refused, bearer "+probeBearer+" used", probeBearer)
	if strings.Contains(got, probeBearer) {
		t.Errorf("redactBearer failed to strip bearer: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("redactBearer did not insert [REDACTED]: %s", got)
	}
}

// redactBearer must no-op when bearer is empty — otherwise it would replace
// every empty string match in the input (effectively a no-op via string ops,
// but worth pinning explicitly to catch a future buggy implementation).
func TestRedactBearer_EmptyBearerIsNoOp(t *testing.T) {
	const input = "an error message"
	got := redactBearer(input, "")
	if got != input {
		t.Errorf("redactBearer with empty bearer mutated input: %q → %q", input, got)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Bonus: happy path response shape
// ─────────────────────────────────────────────────────────────────────────

func TestProbeRaw_HappyPath_ResponseShape(t *testing.T) {
	upstream := newProbeRawRecordingUpstream(200, `{"data":[{"id":"claude-3"}]}`)
	defer upstream.close()

	p := minimalProbeRawProxy(t)
	rec := sendProbeRaw(t, p, "anthropic", upstream.URL(), "sk-ant-test", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	body := decodeProbeRawBody(t, rec)

	if ok, _ := body["probe_ok"].(bool); !ok {
		t.Errorf("probe_ok = %v, want true", body["probe_ok"])
	}
	if status, _ := body["upstream_status"].(float64); status != 200 {
		t.Errorf("upstream_status = %v, want 200", body["upstream_status"])
	}
	if prov, _ := body["provider"].(string); prov != "anthropic" {
		t.Errorf("provider = %v, want anthropic", body["provider"])
	}
	if _, ok := body["latency_ms"].(float64); !ok {
		t.Errorf("latency_ms missing or not number: %v", body["latency_ms"])
	}
	if hint, _ := body["status_hint"].(string); hint == "" {
		t.Errorf("status_hint missing: %v", body["status_hint"])
	}
}

// upstream 401 → proxy still returns 200, body says upstream_status=401.
// This pins spec §2.4 ("proxy总是200,upstream真实status进body").
func TestProbeRaw_UpstreamRejects_ProxyStillSucceeds(t *testing.T) {
	upstream := newProbeRawRecordingUpstream(401, `{"error":"bad key"}`)
	defer upstream.close()

	p := minimalProbeRawProxy(t)
	rec := sendProbeRaw(t, p, "anthropic", upstream.URL(), "sk-ant-bad", nil)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (proxy success even on upstream 401), got %d", rec.Code)
	}
	body := decodeProbeRawBody(t, rec)
	if ok, _ := body["probe_ok"].(bool); !ok {
		t.Errorf("probe_ok should be true (proxy chain worked), got %v", body["probe_ok"])
	}
	if status, _ := body["upstream_status"].(float64); status != 401 {
		t.Errorf("upstream_status = %v, want 401", body["upstream_status"])
	}
}

// Missing X-Aikey-Probe-Bearer (caller wants to test proxy → upstream chain
// without providing a key) — should still call upstream and return whatever
// upstream says (typically 401), proving the chain works.
func TestProbeRaw_EmptyBearer_StillProbes(t *testing.T) {
	upstream := newProbeRawRecordingUpstream(401, `{"error":"missing auth"}`)
	defer upstream.close()

	p := minimalProbeRawProxy(t)
	// No bearer header at all.
	rec := sendProbeRaw(t, p, "anthropic", upstream.URL(), "", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (chain works without bearer), got %d — body: %s", rec.Code, rec.Body.String())
	}
	// No Authorization / X-Api-Key should be sent.
	got := upstream.capturedHeaders()
	if got == nil {
		t.Fatal("upstream not reached")
	}
	if auth := got.Get("Authorization"); auth != "" {
		t.Errorf("Authorization should be empty without bearer header, got %q", auth)
	}
	if xapi := got.Get("X-Api-Key"); xapi != "" {
		t.Errorf("X-Api-Key should be empty without bearer header, got %q", xapi)
	}
}

// Drift sanity: every canonical provider in canonicalProviderCodes MUST
// have a matching providerDefaultBaseURL entry. The handler's PROBE_BASEURL_DRIFT
// internal-error branch should NEVER fire for legitimately accepted suffixes.
func TestProbeRaw_NoCanonicalToBaseURLDrift(t *testing.T) {
	for code := range canonicalProviderCodes {
		base := providerDefaultBaseURL(code)
		if base == "" {
			t.Errorf("canonicalProviderCodes has %q but providerDefaultBaseURL returned empty — drift bug. Either remove from canonical or add to base URL switch.", code)
		}
	}
}

// Aliased / non-canonical token at dispatch → classifier already returns
// TokenInvalid (covered in dispatch_test.go), so handler never runs.
// Add a routing-level integration test as defense: confirm `claude` (alias)
// can't sneak past dispatch and reach the handler.
func TestProbeRaw_AliasTokenRejectedAtDispatch(t *testing.T) {
	p := minimalProbeRawProxy(t)
	// `aikey_probe_raw_claude` → TokenInvalid (alias is not canonical).
	// Use the `/claude/v1/...` path so URL parses, but token dispatch fails.
	req := httptest.NewRequest(http.MethodGet, "/anthropic/v1/models", nil)
	req.Header.Set("Authorization", "Bearer aikey_probe_raw_claude")
	req.Header.Set("X-Aikey-Probe", "1")
	req.Header.Set("X-Aikey-Probe-Bearer", "sk-ant-test")
	rec := httptest.NewRecorder()
	p.Handle(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("alias-suffixed probe_raw token should be TOKEN_INVALID (401), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "TOKEN_INVALID") {
		t.Errorf("expected TOKEN_INVALID error, got: %s", rec.Body.String())
	}
}
