package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWriteJSONError_MarksAikeyOrigin pins the aikey-vs-upstream discriminator:
// every aikey-GENERATED error carries X-Aikey-Error-Source = the error code, so a
// client can tell a quota 429 (ours) from a provider rate-limit 429 (pass-through,
// which never sets this header). The body deliberately mimics a provider error
// shape, so the header — not the body — is the reliable signal.
func TestWriteJSONError_MarksAikeyOrigin(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSONError(rec, 429, "quota_error", "QUOTA_EXCEEDED_USD", "Cost ($) quota exceeded")

	if got := rec.Header().Get(HeaderAikeyErrorSource); got != "QUOTA_EXCEEDED_USD" {
		t.Fatalf("aikey-generated 429 must carry %s=<code>, got %q", HeaderAikeyErrorSource, got)
	}
	if rec.Code != 429 {
		t.Errorf("status: want 429 got %d", rec.Code)
	}
	if b := rec.Body.String(); !strings.Contains(b, `"code":"QUOTA_EXCEEDED_USD"`) || !strings.Contains(b, `"type":"quota_error"`) {
		t.Errorf("body must keep provider-shaped type + aikey code, got %s", b)
	}
}

// TestWriteJSONError_StampsErrorOrigin pins P1 error-origin (2026-07-19): every
// aikey-GENERATED error carries X-Aikey-Error-Origin = <component>.<code> + a
// body top-level `origin`, so a client can tell WHO produced the error (this
// component) without SSH-grepping. RESPONSE direction only. 能红: remove the
// setErrorOrigin call in writeJSONError → the header/body assertions fail.
func TestWriteJSONError_StampsErrorOrigin(t *testing.T) {
	prev := errorOriginComponent
	defer func() { errorOriginComponent = prev }()

	// local-proxy (default) component.
	SetErrorOriginComponent("") // no cluster node id → local-proxy
	rec := httptest.NewRecorder()
	writeJSONError(rec, 503, "server_error", "GROUP_NO_CANDIDATES", "no usable account")
	if got := rec.Header().Get(HeaderAikeyErrorOrigin); got != "local-proxy.GROUP_NO_CANDIDATES" {
		t.Errorf("origin header = %q, want local-proxy.GROUP_NO_CANDIDATES", got)
	}
	if got := rec.Header().Get(HeaderAikeyErrorPath); got != "local-proxy" {
		t.Errorf("path header = %q, want local-proxy", got)
	}
	if b := rec.Body.String(); !strings.Contains(b, `"origin":"local-proxy.GROUP_NO_CANDIDATES"`) {
		t.Errorf("body must mirror origin, got %s", b)
	}

	// worker-proxy component (cluster node id set).
	SetErrorOriginComponent("node-7")
	rec = httptest.NewRecorder()
	writeJSONError(rec, 429, "rate_limit_error", "GROUP_POOL_FULL", "pool full")
	if got := rec.Header().Get(HeaderAikeyErrorOrigin); got != "worker-proxy.GROUP_POOL_FULL" {
		t.Errorf("cluster origin = %q, want worker-proxy.GROUP_POOL_FULL", got)
	}
}

// TestSetErrorOrigin_FirstWriterWins pins the caused-by invariant: a component
// RELAYING a response that ALREADY carries an origin (a deeper hop is the root
// cause) must NOT overwrite it — it only appends itself to the path. 能红: change
// setErrorOrigin to h.Set unconditionally → the deeper origin is clobbered.
func TestSetErrorOrigin_FirstWriterWins(t *testing.T) {
	prev := errorOriginComponent
	defer func() { errorOriginComponent = prev }()
	SetErrorOriginComponent("") // local-proxy relaying

	rec := httptest.NewRecorder()
	rec.Header().Set(HeaderAikeyErrorOrigin, "upstream:openai") // worker already tagged
	setErrorOrigin(rec.Header(), "SOME_LOCAL_CODE")

	if got := rec.Header().Get(HeaderAikeyErrorOrigin); got != "upstream:openai" {
		t.Errorf("origin must stay the deeper root cause upstream:openai, got %q", got)
	}
	// Path still records that this hop was traversed.
	if got := rec.Header().Values(HeaderAikeyErrorPath); len(got) != 1 || got[0] != "local-proxy" {
		t.Errorf("path must append local-proxy, got %v", got)
	}
}

// TestStripAikeyRequestHeaders pins the FLOOR invariant (§6.6, highest priority):
// NO X-Aikey-* header may ever reach the upstream provider — Anthropic's OAuth
// WAF treats unrecognized headers as a non-Claude-Code persona signal and 撞墙s
// (business 429). All error-origin/trace annotations are RESPONSE-direction; this
// asserts the outbound request scrub removes the whole namespace while leaving
// standard headers intact. 能红: drop the strip and the X-Aikey-* survivors fail.
func TestStripAikeyRequestHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Aikey-Error-Origin", "local-proxy.X")
	h.Set("X-Aikey-Trace-Id", "abc")      // a hypothetical future annotation
	h.Set("x-aikey-model", "gpt-5")       // lowercase variant
	h.Set("Authorization", "Bearer real") // standard header — must survive
	h.Set("Content-Type", "application/json")

	stripAikeyRequestHeaders(h)

	for k := range h {
		if len(k) >= 8 && strings.EqualFold(k[:8], "X-Aikey-") {
			t.Errorf("X-Aikey-* header %q survived → would pollute the LLM request (撞墙 risk)", k)
		}
	}
	if h.Get("Authorization") != "Bearer real" || h.Get("Content-Type") != "application/json" {
		t.Errorf("standard headers must survive the scrub, got auth=%q ct=%q",
			h.Get("Authorization"), h.Get("Content-Type"))
	}
}

// TestUpstreamRequestIDFromHeader pins the P3 correlation-key extraction across
// the provider header variants (request-id / x-request-id / openai-request-id).
func TestUpstreamRequestIDFromHeader(t *testing.T) {
	cases := []struct{ header, val, want string }{
		{"openai-request-id", "req_abc", "req_abc"},
		{"x-request-id", "xr_123", "xr_123"},
		{"request-id", "rid_9", "rid_9"},
	}
	for _, c := range cases {
		h := http.Header{}
		h.Set(c.header, c.val)
		if got := upstreamRequestIDFromHeader(h); got != c.want {
			t.Errorf("%s=%q → %q, want %q", c.header, c.val, got, c.want)
		}
	}
	if got := upstreamRequestIDFromHeader(http.Header{}); got != "" {
		t.Errorf("no provider id → empty, got %q", got)
	}
}

// TestTestOnlyBaseURLAllowed pins the AIKEY_PROXY_TEST_* base-url gate: loopback
// and RFC 6761 ".test" hostnames pass (the egress-coexistence E2E needs a
// non-loopback name so the loopback egress bypass doesn't short-circuit it);
// anything routable is REJECTED so a prod misconfig can never reroute real
// traffic. 能红: widen the gate (e.g. drop the ".test" suffix check) and the
// routable-host cases fire.
// TestResolveOAuthUpstream_StripsV1ForCodex pins the version-prefix
// normalization: the codex OAuth upstream (backend-api/codex) serves /responses
// with NO /v1 segment, but the group lane's agent base_url ends in /v1 (ingress
// allowlist requirement) so requests arrive as /v1/responses. Verbatim append
// 404'd at ChatGPT's backend ({"detail":"Not Found"}, live repro 2026-07-19).
// Both shapes must forward as /responses; non-openai providers keep their path.
func TestResolveOAuthUpstream_StripsV1ForCodex(t *testing.T) {
	cases := []struct {
		code     string
		inPath   string
		wantPath string
	}{
		{"openai", "/v1/responses", "/responses"},
		{"openai", "/responses", "/responses"},
		{"anthropic", "/v1/messages", "/v1/messages"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", c.inPath, strings.NewReader(`{"model":"gpt-5"}`))
		_, out := resolveOAuthUpstream(c.code, r)
		if out.URL.Path != c.wantPath {
			t.Errorf("resolveOAuthUpstream(%q, %q): forwarded path = %q, want %q",
				c.code, c.inPath, out.URL.Path, c.wantPath)
		}
	}
}

func TestTestOnlyBaseURLAllowed(t *testing.T) {
	allowed := []string{
		"http://127.0.0.1:8080",
		"http://localhost:9999",
		"http://e2e-oauth.aikey.test:18080", // egress E2E form
		"http://mock.test:1",
	}
	rejected := []string{
		"",
		"https://api.anthropic.com",
		"http://evil.com:80",              // routable host
		"http://test.evil.com:80",         // ".test" only as a LABEL, not the TLD
		"https://e2e-oauth.aikey.test:18", // https not allowed — hook is plain-http mocks only
		"http://10.0.0.9:1080",            // private IP is still routable
		"::not a url::",
	}
	for _, u := range allowed {
		if !testOnlyBaseURLAllowed(u) {
			t.Errorf("must ALLOW %q", u)
		}
	}
	for _, u := range rejected {
		if testOnlyBaseURLAllowed(u) {
			t.Errorf("must REJECT %q (routable → could reroute real traffic)", u)
		}
	}
}
