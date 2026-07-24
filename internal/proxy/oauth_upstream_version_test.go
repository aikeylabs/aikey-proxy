package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// TestResolveOAuthUpstream_NoDoubleVersionSegment is the regression fence for
// the 2026-07-24 onsite incident: EVERY model 404'd for a team OAuth (anthropic)
// credential, with `aikey doctor --last-errors` showing
// `404 /v1/messages ← upstream:anthropic` and no aikey-side error code.
//
// Root cause: resolveOAuthUpstream's default branch returned
// providerroutes.EffectiveUpstream(route) == base_url + version ==
// "https://api.anthropic.com/v1" whenever the credential carried a
// protocol_type, while applyOAuthUpstreamURL (the OAuth Director's join)
// literal-prepends that path onto a request path that ALREADY carries the
// version — producing https://api.anthropic.com/v1/v1/messages. Anthropic
// answers that path with a bare 404 regardless of model, which is why swapping
// Opus→Sonnet and dropping the [1m] suffix changed nothing.
//
// The protocol_type == "" branch (providerDefaultBaseURL, the root form) was
// unaffected, which is why the pre-existing coverage — every case in
// TestResolveOAuthUpstream_StripsV1ForCodex passes protocolType "" — stayed
// green through the regression.
//
// 能红: revert resolveOAuthUpstream's default branch to
// providerBaseURLForProtocol and the protocol-typed anthropic cases below fail
// with "/v1/v1/messages".
func TestResolveOAuthUpstream_NoDoubleVersionSegment(t *testing.T) {
	cases := []struct {
		name     string
		code     string
		protocol string
		inPath   string
		wantHost string
		wantPath string
	}{
		{
			name:     "anthropic oauth with protocol_type (the onsite repro)",
			code:     "anthropic",
			protocol: "anthropic",
			inPath:   "/v1/messages",
			wantHost: "api.anthropic.com",
			wantPath: "/v1/messages",
		},
		{
			name:     "anthropic oauth without protocol_type (the branch that worked)",
			code:     "anthropic",
			protocol: "",
			inPath:   "/v1/messages",
			wantHost: "api.anthropic.com",
			wantPath: "/v1/messages",
		},
		{
			// "claude" is the brand alias the console stores on some rows;
			// canonicalization must not change the join.
			name:     "claude alias with protocol_type",
			code:     "claude",
			protocol: "anthropic",
			inPath:   "/v1/messages",
			wantHost: "api.anthropic.com",
			wantPath: "/v1/messages",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", c.inPath, strings.NewReader(`{"model":"claude-opus-4-8"}`))
			base, out := resolveOAuthUpstream(c.code, c.protocol, r)
			if base == "" {
				t.Fatalf("resolveOAuthUpstream(%q, %q) returned an empty base URL", c.code, c.protocol)
			}
			applyOAuthUpstreamURL(out, base)

			if out.URL.Host != c.wantHost {
				t.Errorf("outbound host = %q, want %q (base %q)", out.URL.Host, c.wantHost, base)
			}
			if out.URL.Path != c.wantPath {
				t.Errorf("outbound path = %q, want %q (base %q) — a doubled version segment 404s for every model",
					out.URL.Path, c.wantPath, base)
			}
		})
	}
}

// TestFence_OAuthBinding_ProtocolTypedPathNotDoubled is the END-TO-END half of
// the same fence: it drives the real p.Handle → serveRoute → ReverseProxy
// Director and asserts the EXACT outbound path a protocol-typed OAuth binding
// produces.
//
// It is deliberately separate from TestFence_OAuthBinding_HappyPath, which
// carries no ProtocolType (so it exercised only the branch that was never
// broken) and asserts with strings.Contains(url, "/v1/messages") — a substring
// check that "/v1/v1/messages" also satisfies. Both blind spots together are
// why this reached a customer.
//
// 能红: revert resolveOAuthUpstream to providerBaseURLForProtocol → the outbound
// path becomes /v1/v1/messages and this fails.
func TestFence_OAuthBinding_ProtocolTypedPathNotDoubled(t *testing.T) {
	av := &mockActiveVault{
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode: "anthropic",
				// The field the onsite credential carries and the pre-existing
				// fence does not. This is the whole regression.
				ProtocolType:  "anthropic",
				KeySourceType: "personal_oauth_account",
				KeySourceRef:  "session_oauth-acct-1",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)
	p.SetBroker(&mockOAuthBroker{
		resolveCred: &OAuthCredential{
			AccessToken: "oauth-bearer-real",
			AccountID:   "session_oauth-acct-1",
			Provider:    "anthropic",
			ExternalID:  "claude-pro-uuid",
			Identity:    "user@example.com",
		},
	})
	transport := &capturingTransport{}
	p.SetTransport(transport)

	body := `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	p.Handle(httptest.NewRecorder(), req)

	if transport.host != "api.anthropic.com" {
		t.Fatalf("outbound Host = %q, want api.anthropic.com", transport.host)
	}
	// EXACT path, not Contains: "/v1/v1/messages" contains "/v1/messages".
	u, err := url.Parse(transport.url)
	if err != nil {
		t.Fatalf("parse outbound url %q: %v", transport.url, err)
	}
	if u.Path != "/v1/messages" {
		t.Errorf("outbound path = %q, want exactly %q — api.anthropic.com answers a doubled version segment with a bare 404 for EVERY model (2026-07-24 onsite incident)",
			u.Path, "/v1/messages")
	}
}

// TestOAuthBaseURLFault_Detection pins WHICH base URLs the fence rejects. The
// false-positive rows matter as much as the true-positive one: a non-version
// path prefix (kimi's /coding, GLM's /api/anthropic) is legitimate and must
// forward untouched, or the fence would break working credentials.
func TestOAuthBaseURLFault_Detection(t *testing.T) {
	cases := []struct {
		name    string
		base    string
		reqPath string
		wantErr bool
	}{
		{"clean anthropic root", "https://api.anthropic.com", "/v1/messages", false},
		{"trailing slash root", "https://api.anthropic.com/", "/v1/messages", false},
		{"non-version prefix (kimi)", "https://api.kimi.com/coding", "/v1/messages", false},
		{"non-version prefix (GLM)", "https://open.bigmodel.cn/api/anthropic", "/v1/messages", false},
		{"codex backend prefix", "https://chatgpt.com/backend-api/codex", "/responses", false},
		{"version in base but not in path", "https://api.anthropic.com/v1", "/messages", false},

		{"doubled /v1 (the incident)", "https://api.anthropic.com/v1", "/v1/messages", true},
		{"doubled /v1 on a prefixed host", "https://open.bigmodel.cn/api/anthropic/v1", "/v1/messages", true},
		{"doubled /v4", "https://open.bigmodel.cn/api/coding/paas/v4", "/v4/chat/completions", true},
		{"doubled /v1beta", "https://generativelanguage.googleapis.com/v1beta", "/v1beta/models", true},
		{"path equals the version segment", "https://api.anthropic.com/v1", "/v1", true},

		{"missing scheme", "api.anthropic.com", "/v1/messages", true},
		{"missing host", "https://", "/v1/messages", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := oauthBaseURLFault(c.base, c.reqPath)
			if c.wantErr && got == "" {
				t.Errorf("oauthBaseURLFault(%q, %q) = \"\", want a fault reason", c.base, c.reqPath)
			}
			if !c.wantErr && got != "" {
				t.Errorf("oauthBaseURLFault(%q, %q) = %q, want no fault (false positive rejects a working credential)",
					c.base, c.reqPath, got)
			}
		})
	}
}

// TestOAuthBaseURLFault_MessageIsActionable pins that the fault text names the
// offending URL, the segment to delete, and the resulting bad path. The whole
// point of the fence is that the operator does not have to reverse-engineer it
// from a bare upstream 404, so an unhelpful message is a failed fence.
func TestOAuthBaseURLFault_MessageIsActionable(t *testing.T) {
	got := oauthBaseURLFault("https://api.anthropic.com/v1", "/v1/messages")
	if got == "" {
		t.Fatal("expected a fault for the doubled-/v1 case")
	}
	for _, want := range []string{
		"https://api.anthropic.com/v1", // the offending base URL
		`"/v1"`,                        // the segment to remove
		"/v1/v1/messages",              // what would have been requested
		"404",                          // the symptom the operator saw
		"remove",                       // the action
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fault message missing %q\nmessage: %s", want, got)
		}
	}
}

// TestFence_OAuthBaseURLFault_RefusesToForward drives the real proxy and proves
// the fence (a) never reaches the upstream and (b) answers with the
// BASE_URL_MISCONFIGURED code rather than letting the provider's opaque 404
// through. The team key's BaseURL is the misconfigured one; the OAuth binding
// takes precedence, so the fault must come from the OAuth route's own base URL.
//
// 能红: delete the fence block in serveRoute → the request forwards and the
// captured outbound path becomes /v1/v1/messages with a 200 from the mock.
func TestFence_OAuthBaseURLFault_RefusesToForward(t *testing.T) {
	av := &mockActiveVault{
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				ProtocolType:  "anthropic",
				KeySourceType: "personal_oauth_account",
				KeySourceRef:  "session_oauth-acct-1",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)
	p.SetBroker(&mockOAuthBroker{
		resolveCred: &OAuthCredential{
			AccessToken: "oauth-bearer-real",
			AccountID:   "session_oauth-acct-1",
			Provider:    "anthropic",
			ExternalID:  "claude-pro-uuid",
			Identity:    "user@example.com",
		},
	})
	transport := &capturingTransport{}
	p.SetTransport(transport)

	// Point the (loopback/.test-gated) anthropic OAuth upstream at a base URL
	// that carries the version segment — the exact shape the fence exists for.
	t.Setenv("AIKEY_PROXY_TEST_ANTHROPIC_BASE_URL", "http://mock.test:1/v1")

	body := `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if transport.url != "" {
		t.Errorf("request reached the upstream at %q — the fence must refuse BEFORE forwarding", transport.url)
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
	if got := w.Body.String(); !strings.Contains(got, "BASE_URL_MISCONFIGURED") {
		t.Errorf("body = %s, want a BASE_URL_MISCONFIGURED error code", got)
	}
	// The header is what the last-errors ring records, so this is what turns
	// `aikey doctor --last-errors` from "upstream:anthropic — not an aikey
	// fault" into an aikey-attributed, actionable entry.
	if got := w.Header().Get(HeaderAikeyErrorSource); got != "BASE_URL_MISCONFIGURED" {
		t.Errorf("%s = %q, want BASE_URL_MISCONFIGURED so doctor --last-errors attributes it to us",
			HeaderAikeyErrorSource, got)
	}
}

// TestApplyOAuthUpstreamURL_RootContract pins the join's half of the contract
// independently of the table: a base URL carrying a non-version path prefix is
// prepended, a bare-host base URL leaves the path alone. If a future change
// makes the join version-aware instead, this test is the one to revisit — but
// resolveOAuthUpstream must then stop returning the root form in the same
// commit, or the two halves drift apart again.
func TestApplyOAuthUpstreamURL_RootContract(t *testing.T) {
	cases := []struct {
		base     string
		inPath   string
		wantHost string
		wantPath string
	}{
		{"https://api.anthropic.com", "/v1/messages", "api.anthropic.com", "/v1/messages"},
		{"https://api.kimi.com/coding", "/v1/messages", "api.kimi.com", "/coding/v1/messages"},
		{"https://open.bigmodel.cn/api/anthropic", "/v1/messages", "open.bigmodel.cn", "/api/anthropic/v1/messages"},
		{"https://api.anthropic.com/", "/v1/messages", "api.anthropic.com", "/v1/messages"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", c.inPath, strings.NewReader("{}"))
		applyOAuthUpstreamURL(r, c.base)
		if r.URL.Host != c.wantHost || r.URL.Path != c.wantPath {
			t.Errorf("applyOAuthUpstreamURL(%q, %q) → host %q path %q, want host %q path %q",
				c.base, c.inPath, r.URL.Host, r.URL.Path, c.wantHost, c.wantPath)
		}
	}
}
