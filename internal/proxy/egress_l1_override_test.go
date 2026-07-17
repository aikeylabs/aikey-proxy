package proxy

// L1 override fence (2026-07-16): a user-pinned node-level explicit upstream
// (/user/settings) must OUTRANK per-account egress for team-oauth routes — the
// escape hatch when the admin's per-account proxy is unavailable. Precedence:
// user-local explicit > per-account. The trade-off (all accounts then share one
// exit IP) is accepted for availability.
//
// This drives the REAL serveRoute funnel (the single place the per-account
// branch lives) with a route that pins an account egress socks5, and asserts:
//   - default (flag off): the account socks5 IS traversed (per-account wins).
//   - flag on: the account socks5 is NOT touched; traffic rides the node-level
//     transport straight to the upstream.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/egresstest"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func TestServeRoute_NodeExplicitEgress_OutranksPerAccount(t *testing.T) {
	noEgressBypass(t) // hermetic: dial loopback stand-in THROUGH the egress
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	// The account's per-account egress socks5 (what an admin set on master).
	accountExit := egresstest.NewSocks5Server(t, "", "")

	body := `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}`
	newRoute := func() *vkeys.ResolvedRoute {
		return &vkeys.ResolvedRoute{
			VirtualKeyID:   "vk", Provider: "anthropic", BaseURL: upstream.URL,
			ProtocolType:   "anthropic", SeatID: "seat-1", AccountID: "acc-1",
			EgressProxyURL: "socks5://" + accountExit.Addr(),
		}
	}

	// (a) Flag OFF (default): per-account egress is honored — the account socks5
	// is traversed on the way to upstream.
	p := setupTestProxy(t, upstream.URL)
	prov, err := p.providers.Get("anthropic")
	if err != nil {
		t.Fatalf("anthropic provider: %v", err)
	}
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	w := httptest.NewRecorder()
	p.serveRoute(w, req, newRoute(), prov, "sk-real", "aikey_team_x", time.Now(), discardLogger())
	if n, _ := accountExit.Stats(); n == 0 {
		t.Fatalf("flag OFF: per-account egress must be used, account socks5 connects=%d", n)
	}

	// (b) Flag ON: the node-level explicit upstream wins — the account socks5 is
	// NOT touched; traffic rides the node transport (default → direct to the
	// loopback upstream here) instead.
	p2 := setupTestProxy(t, upstream.URL)
	p2.SetNodeExplicitEgress(true)
	prov2, _ := p2.providers.Get("anthropic")
	req2 := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	w2 := httptest.NewRecorder()
	before, _ := accountExit.Stats()
	p2.serveRoute(w2, req2, newRoute(), prov2, "sk-real", "aikey_team_x", time.Now(), discardLogger())
	after, _ := accountExit.Stats()
	if after != before {
		t.Fatalf("flag ON: per-account egress must be SKIPPED, account socks5 got %d new connects", after-before)
	}
	if w2.Code != http.StatusOK {
		t.Fatalf("flag ON: request must still succeed via node transport, got %d (%s)", w2.Code, w2.Body.String())
	}
	_ = context.Background
}
