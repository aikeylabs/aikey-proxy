package proxy

// Per-account egress ISOLATION fence (单账号单出口 IP 不变量).
//
// The existing tests prove (a) distinct specs get distinct transports
// (TestAccountEgressTransport_CachedBySpec) and (b) ONE account's delivered
// egress is really dialed through its socks5 (TestEgressDelivery...). This test
// asserts the invariant those compose into but that neither states on its own:
// with TWO accounts each carrying a DIFFERENT egress_proxy_url, account A's
// traffic leaves ONLY through A's exit and account B's ONLY through B's — no
// cross-talk, no accidental sharing of one exit IP.
//
// 能红: a cache-key regression that collapsed two accounts onto one transport
// (both out one IP → anti-ban broken), or a resolver that mismapped account→egress,
// would flip one of the cross-checks below.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/egresstest"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func TestPerAccountEgress_EachAccountExitsItsOwnIP_NoCrossTalk(t *testing.T) {
	noEgressBypass(t) // loopback target is a stand-in for the provider; dial it THROUGH the egress

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()
	targetHP := hostPort(t, target.URL)

	// Two DISTINCT per-account exits (each account's own fixed IP).
	exitA := egresstest.NewSocks5Server(t, "", "")
	exitB := egresstest.NewSocks5Server(t, "", "")
	key := grKey()

	// Two group VKs (two seats), each pinned to a DIFFERENT account carrying a
	// DIFFERENT egress — exactly the pool shape where "one account = one exit IP".
	buildRoute := func(seat, accID, exitAddr string) *vkeys.ResolvedRoute {
		refs := []vkeys.GroupAccountRef{{AccountID: accID, ProviderCode: "anthropic"}}
		mat := map[string]vkeys.GroupRuntimeAccount{
			accID: encMat(t, key, vkeys.GroupRuntimeAccount{
				CredentialType: "oauth_account",
				ExpiresAt:      9_000_000_000,
				EgressProxyURL: "socks5://" + exitAddr,
			}, "tok-"+accID),
		}
		return &vkeys.ResolvedRoute{
			SeatID: seat, OauthGroupID: "grp", KeyAlias: "__oauth__",
			GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
		}
	}
	routeA := buildRoute("seat-a", "acc-1", exitA.Addr())
	routeB := buildRoute("seat-b", "acc-2", exitB.Addr())

	// ONE proxy (shared cache) so the test would catch two accounts colliding on a
	// single cached transport.
	p := &Proxy{}
	dialThrough := func(route *vkeys.ResolvedRoute, wantExit string) {
		res, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
		if err != nil {
			t.Fatalf("resolve %s: %v", route.SeatID, err)
		}
		if res.EgressProxyURL != "socks5://"+wantExit {
			t.Fatalf("%s resolved to egress %q, want socks5://%s", route.SeatID, res.EgressProxyURL, wantExit)
		}
		tr, err := p.accountEgressTransport(res.EgressProxyURL)
		if err != nil {
			t.Fatalf("build egress transport for %s: %v", route.SeatID, err)
		}
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, target.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("dial through %s egress: %v", route.SeatID, err)
		}
		_ = resp.Body.Close()
	}

	// Account 1 → its own exit A.
	dialThrough(routeA, exitA.Addr())
	if n, last := exitA.Stats(); n != 1 || last != targetHP {
		t.Fatalf("account-1 must exit through A exactly once to the target: connects=%d last=%q", n, last)
	}
	if n, _ := exitB.Stats(); n != 0 {
		t.Fatalf("account-1 traffic LEAKED through account-2's exit B: connects=%d (single-account-single-exit broken)", n)
	}

	// Account 2 → its own exit B; A must NOT be touched again.
	dialThrough(routeB, exitB.Addr())
	if n, last := exitB.Stats(); n != 1 || last != targetHP {
		t.Fatalf("account-2 must exit through B exactly once to the target: connects=%d last=%q", n, last)
	}
	if n, _ := exitA.Stats(); n != 1 {
		t.Fatalf("account-2 traffic LEAKED through account-1's exit A: A connects went to %d (want stay 1)", n)
	}
}
