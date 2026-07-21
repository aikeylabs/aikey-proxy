package proxy

// per-account egress + node upstream COEXISTENCE (2026-07-18, reversed the
// 2026-07-16 L1 override — see update/20260718-per-account-egress-与节点上游共存.md).
//
// The node-level upstream (/user/settings) serves ONLY traffic WITHOUT a
// per-account egress (api_key / VK / OAuth accounts without one). Per-account
// egress is account-level and INDEPENDENT — it applies whenever the resolved
// account has one, EVEN WHEN a node upstream is set. This drives the real
// serveRoute funnel (the single place the per-account branch lives) and asserts:
//   - account WITH egress → its per-account socks5 IS traversed, even though a
//     node upstream is set (coexistence — no longer overridden);
//   - account WITHOUT egress → the node upstream transport.
//
// 能红: re-add `&& !p.nodeExplicitEgress.Load()` (the removed override) — or make
// serveRoute skip per-account when a node upstream is set — and assertion (1) fires
// (OAuth wrongly rides the node upstream, account socks5 connects=0).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/egresstest"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func TestServeRoute_PerAccountEgress_CoexistsWithNodeUpstream(t *testing.T) {
	noEgressBypass(t) // hermetic: the account egress dials the loopback upstream THROUGH the socks5
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()
	accountExit := egresstest.NewSocks5Server(t, "", "") // the OAuth account's per-account egress
	node := &recordingNodeTransport{}                    // the /user/settings node upstream

	p := setupTestProxy(t, upstream.URL)
	p.SetTransport(node) // a node upstream IS set — it used to override per-account egress; now it must NOT
	prov, err := p.providers.Get("anthropic")
	if err != nil {
		t.Fatalf("anthropic provider: %v", err)
	}
	body := `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}`

	// (1) Account WITH per-account egress → its socks5, NOT the node upstream — even
	//     though a node upstream is configured (the coexistence guarantee).
	oauthRoute := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-oauth", Provider: "anthropic", BaseURL: upstream.URL,
		ProtocolType: "anthropic", SeatID: "seat-1", AccountID: "acc-oauth",
		EgressProxyURL: "socks5://" + accountExit.Addr(),
	}
	p.serveRoute(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body)),
		oauthRoute, prov, "sk-oauth", "aikey_team_oauth", time.Now(), discardLogger())
	if n, _ := accountExit.Stats(); n == 0 {
		t.Fatalf("account WITH egress must ride its per-account egress even with a node upstream set — account socks5 connects=%d", n)
	}
	if node.hits.Load() != 0 {
		t.Fatalf("account WITH egress must NOT ride the node upstream (coexistence, not override) — node hits=%d", node.hits.Load())
	}

	// (2) Account WITHOUT per-account egress (api_key / VK) → the node upstream.
	before, _ := accountExit.Stats()
	w := httptest.NewRecorder()
	p.serveRoute(w, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body)),
		&vkeys.ResolvedRoute{VirtualKeyID: "vk-key", Provider: "anthropic", BaseURL: upstream.URL, ProtocolType: "anthropic", SeatID: "seat-1", AccountID: "acc-key"},
		prov, "sk-key", "aikey_team_key", time.Now(), discardLogger())
	if w.Code != http.StatusOK {
		t.Fatalf("api_key request failed: %d (%s)", w.Code, w.Body.String())
	}
	if node.hits.Load() == 0 {
		t.Fatalf("account WITHOUT egress must ride the node upstream — node hits=0")
	}
	if after, _ := accountExit.Stats(); after != before {
		t.Fatalf("account WITHOUT egress must NOT touch another account's egress — account socks5 got %d new connects", after-before)
	}
}

// Escape hatch (2026-07-19, update/20260719-oauth-egress-override-逃生舱.md): the
// OPT-IN override makes an OAuth account's per-account egress fall back to the node
// upstream chain — the self-rescue lever when the admin's egress line is down.
// Same harness as coexistence above; the ONLY difference is the flag.
//
// 能红: delete the `&& !p.oauthEgressOverride.Load()` gate in serveRoute and
// assertion (A) fires — the account rides its own egress (account socks5 connects>0,
// node hits=0) instead of the node upstream, i.e. the override is inert.
func TestServeRoute_OAuthEgressOverride_RoutesThroughNodeUpstream(t *testing.T) {
	noEgressBypass(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()
	accountExit := egresstest.NewSocks5Server(t, "", "")
	node := &recordingNodeTransport{}

	p := setupTestProxy(t, upstream.URL)
	p.SetTransport(node)
	prov, err := p.providers.Get("anthropic")
	if err != nil {
		t.Fatalf("anthropic provider: %v", err)
	}
	body := `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}`
	oauthRoute := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-oauth", Provider: "anthropic", BaseURL: upstream.URL,
		ProtocolType: "anthropic", SeatID: "seat-1", AccountID: "acc-oauth",
		EgressProxyURL: "socks5://" + accountExit.Addr(),
	}

	// Default OFF (control): coexist — the account rides its own egress (proves the
	// escape hatch is inert until flipped; the default path is byte-unchanged).
	p.serveRoute(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body)),
		oauthRoute, prov, "sk-oauth", "aikey_team_oauth", time.Now(), discardLogger())
	if n, _ := accountExit.Stats(); n == 0 {
		t.Fatalf("[default OFF] OAuth account must ride its per-account egress (coexist) — account socks5 connects=0")
	}
	if node.hits.Load() != 0 {
		t.Fatalf("[default OFF] OAuth account must NOT ride the node upstream — node hits=%d", node.hits.Load())
	}

	// Flip the escape hatch ON.
	p.SetOAuthEgressOverride(true)
	beforeAcct, _ := accountExit.Stats()

	// (A) With override ON, the SAME OAuth account now routes through the NODE
	//     upstream (self-rescue), NOT its own egress.
	w := httptest.NewRecorder()
	p.serveRoute(w, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body)),
		oauthRoute, prov, "sk-oauth", "aikey_team_oauth", time.Now(), discardLogger())
	if node.hits.Load() == 0 {
		t.Fatalf("[override ON] OAuth account must fall back to the node upstream (self-rescue) — node hits=0")
	}
	if after, _ := accountExit.Stats(); after != beforeAcct {
		t.Fatalf("[override ON] OAuth account must SKIP its per-account egress — account socks5 got %d new connects", after-beforeAcct)
	}

	// (B) Flip back OFF → coexist restored (the toggle is reversible, not sticky).
	p.SetOAuthEgressOverride(false)
	beforeNode := node.hits.Load()
	p.serveRoute(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body)),
		oauthRoute, prov, "sk-oauth", "aikey_team_oauth", time.Now(), discardLogger())
	if node.hits.Load() != beforeNode {
		t.Fatalf("[toggled back OFF] OAuth account must ride its egress again (no new node hits) — node hits grew by %d", node.hits.Load()-beforeNode)
	}
}
