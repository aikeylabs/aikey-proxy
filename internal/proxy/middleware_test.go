package proxy

import (
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
