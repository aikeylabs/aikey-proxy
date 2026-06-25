package proxy

// N8b integration tests: a group VK presented at the legacy /v1 entry is
// resolved (N8a) + injected + forwarded. Uses capturingTransport (defined in
// oauth_binding_fence_test.go) to observe the outbound URL + headers without
// touching the network, and encMat/grKey (group_resolve_test.go) to build the
// encrypted at-rest material.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// fakeGroupKey provides the derived key for at-rest group material decryption.
type fakeGroupKey struct{ k []byte }

func (f fakeGroupKey) DerivedKey() []byte { return f.k }

// outboundCapture records the OUTBOUND (post-Director) request — the clone the
// upstream would see. api_key injection (prov.RewriteRequest) happens in the
// Director on this clone, so the original inbound r.Header would not show it;
// asserting on the outbound request is the correct semantics.
type outboundCapture struct {
	host   string
	auth   string
	apiKey string
}

func (c *outboundCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	c.host = req.URL.Host
	c.auth = req.Header.Get("Authorization")
	c.apiKey = req.Header.Get("x-api-key")
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(
			`{"id":"msg","type":"message","content":[{"type":"text","text":"ok"}],"model":"c","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)),
		Request: req,
	}, nil
}

// setupGroupProxy seeds one group VK route + wires the key provider + the
// outbound-capturing transport, returning the capture for assertions.
func setupGroupProxy(t *testing.T, key []byte, route *vkeys.ResolvedRoute) (*Proxy, *outboundCapture) {
	t.Helper()
	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_grouptest": route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	tr := &outboundCapture{}
	p.SetTransport(tr)
	return p, tr
}

func groupReq(body string) (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_grouptest")
	return req, httptest.NewRecorder()
}

const groupBody = `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`

func TestGroupServe_OAuthAccountInjectsBearer(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-1": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, ExternalID: "uuid-1",
		}, "oauth-tok-live"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", SeatGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("group OAuth route: status=%d body=%s", w.Code, w.Body.String())
	}
	// OAuth → providerDefaultBaseURL(anthropic), Bearer injected, x-api-key gone.
	if tr.host != "api.anthropic.com" {
		t.Fatalf("outbound host=%q want api.anthropic.com", tr.host)
	}
	if tr.auth != "Bearer oauth-tok-live" {
		t.Fatalf("outbound Authorization=%q want decrypted OAuth Bearer (oauthInject must run)", tr.auth)
	}
	if tr.apiKey != "" {
		t.Fatalf("x-api-key must be stripped on OAuth path, got %q", tr.apiKey)
	}
}

func TestGroupServe_APIKeyAccountInjectsKey(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-k", ProviderCode: "anthropic"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-k": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "api_key", BaseURL: "https://key-upstream.example",
		}, "sk-group-key"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", SeatGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p, tr := setupGroupProxy(t, key, route)

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("group api_key route: status=%d body=%s", w.Code, w.Body.String())
	}
	// api_key → upstream is the account's base_url, key injected via adapter.
	if tr.host != "key-upstream.example" {
		t.Fatalf("outbound host=%q want key-upstream.example (api_key base_url)", tr.host)
	}
	if tr.apiKey != "sk-group-key" {
		t.Fatalf("outbound x-api-key=%q want injected group key", tr.apiKey)
	}
}

func TestGroupServe_NoMaterialDegrades503(t *testing.T) {
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: "anthropic"}}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		SeatID: "seat-1", SeatGroupID: "grp-1",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: "", // not pulled yet
	}
	p, tr := setupGroupProxy(t, key, route)

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no material should degrade 503, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "GROUP_NO_MATERIAL") {
		t.Fatalf("degrade body should carry GROUP_NO_MATERIAL code: %s", w.Body.String())
	}
	if tr.host != "" {
		t.Fatalf("degraded request must NOT reach upstream, dialed %q", tr.host)
	}
}

// Byte-unchanged guard: a non-group (direct-bind) team route must NOT enter the
// group path — it forwards via the static-key path exactly as before.
func TestGroupServe_DirectBindUnaffected(t *testing.T) {
	key := grKey()
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-direct", Provider: "anthropic", ProtocolType: "anthropic",
		ProviderCode: "anthropic", RouteSource: "team",
		BaseURL: "https://direct.example", PlaintextKey: "sk-direct-key",
		// SeatGroupID empty → group branch skipped.
	}
	p, tr := setupGroupProxy(t, key, route)

	req, w := groupReq(groupBody)
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("direct-bind team route: status=%d body=%s", w.Code, w.Body.String())
	}
	if tr.host != "direct.example" {
		t.Fatalf("direct-bind must use its own BaseURL, got %q", tr.host)
	}
	if tr.apiKey != "sk-direct-key" {
		t.Fatalf("direct-bind key injection changed: outbound x-api-key=%q", tr.apiKey)
	}
}
