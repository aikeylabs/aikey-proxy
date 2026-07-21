package proxy

// per-account egress (OAuth) + a SEPARATE proxy for api_key traffic — coexistence
// on ONE proxy (2026-07-18). The user's two scenarios:
//
//	情况一: OAuth account has per-account egress, AND the host runs Clash-for-Windows
//	        (mihomo) as the OS System Proxy for api_key traffic. → the system proxy
//	        is the NODE-level transport for non-egress requests; it is layer ④ (below
//	        the explicit-upstream layer, see internal/sysproxy) so it does NOT set
//	        nodeExplicitEgress. Expectation: OAuth rides its per-account egress
//	        (independent socks5, NOT through the system proxy); api_key rides the
//	        node transport (system proxy). Independent — no conflict.
//
//	情况二: OAuth account has per-account egress, AND the user pinned an upstream
//	        proxy in /user/settings (the node upstream, layer ①). 2026-07-18: the
//	        node upstream serves ONLY non-egress traffic — it does NOT override the
//	        per-account egress (reversed the earlier override). Expectation: OAuth
//	        rides its per-account egress (independent), api_key rides the node
//	        upstream. Same coexistence as 情况一 — just a different node-layer source.
//
// Both drive the REAL serveRoute funnel (where the per-account-vs-node branch lives)
// with a real socks5 account exit + a recording node transport standing in for the
// system proxy / user upstream. The node transport is what buildTransport produces
// from the sysproxy layer in production (that layer's own resolution is covered in
// internal/sysproxy); here we pin the PRIORITY/DISPATCH: which transport each
// request type takes. Hermetic — never touches the host system proxy.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/egresstest"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// recordingNodeTransport stands in for the NODE-level transport (SetTransport): the
// OS system proxy (情况一) or the user's /user/settings upstream (情况二). Records
// whether a request rode it; returns a canned Anthropic 200 (it never dials).
type recordingNodeTransport struct{ hits atomic.Int64 }

func (n *recordingNodeTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	n.hits.Add(1)
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`)),
	}, nil
}

func coexistUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	t.Cleanup(s.Close)
	return s
}

const coexistBody = `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}`

// 情况一: per-account egress + system proxy (Clash) for api_key — independent, no conflict.
func TestEgressCoexist_Scenario1_SystemProxyForApiKey_EgressForOAuth(t *testing.T) {
	noEgressBypass(t) // hermetic: the account egress dials the loopback upstream THROUGH the socks5
	upstream := coexistUpstream(t)
	accountExit := egresstest.NewSocks5Server(t, "", "") // the OAuth account's per-account egress
	node := &recordingNodeTransport{}                    // the OS system proxy (Clash)

	p := setupTestProxy(t, upstream.URL)
	p.SetTransport(node) // node-level transport = system proxy for non-egress traffic
	// nodeExplicitEgress stays FALSE — the OS system proxy is layer ④, it does NOT
	// pin an explicit node upstream, so it must NOT override per-account egress.
	prov, err := p.providers.Get("anthropic")
	if err != nil {
		t.Fatalf("anthropic provider: %v", err)
	}

	// (1) OAuth request → its per-account egress socks5, NOT the system proxy.
	oauthRoute := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-oauth", Provider: "anthropic", BaseURL: upstream.URL,
		ProtocolType: "anthropic", SeatID: "seat-1", AccountID: "acc-oauth",
		EgressProxyURL: "socks5://" + accountExit.Addr(),
	}
	p.serveRoute(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/messages", strings.NewReader(coexistBody)),
		oauthRoute, prov, "sk-oauth", "aikey_team_oauth", time.Now(), discardLogger())
	if n, _ := accountExit.Stats(); n == 0 {
		t.Fatalf("[情况一] OAuth must ride its per-account egress — account socks5 connects=%d", n)
	}
	if node.hits.Load() != 0 {
		t.Fatalf("[情况一] OAuth must NOT ride the system proxy (per-account egress is independent) — node hits=%d", node.hits.Load())
	}

	// (2) api_key request (no egress) → the system proxy (node transport).
	before, _ := accountExit.Stats()
	apiRoute := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-key", Provider: "anthropic", BaseURL: upstream.URL,
		ProtocolType: "anthropic", SeatID: "seat-1", AccountID: "acc-key",
		// EgressProxyURL empty → api_key traffic rides the node transport.
	}
	w := httptest.NewRecorder()
	p.serveRoute(w, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(coexistBody)),
		apiRoute, prov, "sk-key", "aikey_team_key", time.Now(), discardLogger())
	if w.Code != http.StatusOK {
		t.Fatalf("[情况一] api_key request failed: %d (%s)", w.Code, w.Body.String())
	}
	if node.hits.Load() == 0 {
		t.Fatalf("[情况一] api_key must ride the system proxy (node transport) — node hits=0")
	}
	if after, _ := accountExit.Stats(); after != before {
		t.Fatalf("[情况一] api_key must NOT touch the OAuth account's egress — account socks5 got %d new connects", after-before)
	}
	t.Logf("✓ 情况一: OAuth → per-account egress (bypassed system proxy); api_key → system proxy. Independent, no conflict.")
}

// 情况二: per-account egress + user-pinned upstream (/user/settings, layer ①) — the
// node upstream (/user/settings) coexists with per-account egress; OAuth keeps its
// egress, api_key rides the upstream (2026-07-18, reversed the override).
func TestEgressCoexist_Scenario2_UserUpstreamCoexistsWithEgress(t *testing.T) {
	noEgressBypass(t)
	upstream := coexistUpstream(t)
	accountExit := egresstest.NewSocks5Server(t, "", "")
	node := &recordingNodeTransport{} // the user's /user/settings upstream proxy

	p := setupTestProxy(t, upstream.URL)
	p.SetTransport(node) // settings upstream set — no longer overrides per-account egress
	prov, err := p.providers.Get("anthropic")
	if err != nil {
		t.Fatalf("anthropic provider: %v", err)
	}

	// (1) OAuth request → its per-account egress socks5, NOT the settings upstream.
	oauthRoute := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-oauth", Provider: "anthropic", BaseURL: upstream.URL,
		ProtocolType: "anthropic", SeatID: "seat-1", AccountID: "acc-oauth",
		EgressProxyURL: "socks5://" + accountExit.Addr(),
	}
	p.serveRoute(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/messages", strings.NewReader(coexistBody)),
		oauthRoute, prov, "sk-oauth", "aikey_team_oauth", time.Now(), discardLogger())
	if n, _ := accountExit.Stats(); n == 0 {
		t.Fatalf("[情况二] OAuth must KEEP its per-account egress even with a settings upstream set — account socks5 connects=%d", n)
	}
	if node.hits.Load() != 0 {
		t.Fatalf("[情况二] settings upstream must NOT override per-account egress — node hits=%d", node.hits.Load())
	}

	// (2) api_key request (no egress) → the settings upstream.
	before, _ := accountExit.Stats()
	w := httptest.NewRecorder()
	p.serveRoute(w, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(coexistBody)),
		&vkeys.ResolvedRoute{VirtualKeyID: "vk-key", Provider: "anthropic", BaseURL: upstream.URL, ProtocolType: "anthropic", SeatID: "seat-1", AccountID: "acc-key"},
		prov, "sk-key", "aikey_team_key", time.Now(), discardLogger())
	if w.Code != http.StatusOK {
		t.Fatalf("[情况二] api_key request failed: %d (%s)", w.Code, w.Body.String())
	}
	if node.hits.Load() == 0 {
		t.Fatalf("[情况二] api_key must ride the settings upstream — node hits=0")
	}
	if after, _ := accountExit.Stats(); after != before {
		t.Fatalf("[情况二] api_key must NOT touch the OAuth account's egress — account socks5 got %d new connects", after-before)
	}
	t.Logf("✓ 情况二: OAuth keeps its per-account egress; api_key rides the /user/settings upstream. Coexist, no override.")
}
