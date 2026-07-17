package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/egresstest"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/egress"

	// Blank import so the built-in socks5 egress engine's init() registers itself
	// in the pkg/egress registry — egress.BuildDialer("socks5://…") below dispatches
	// through that SAME registry the proxy hot path uses (internal/proxy/egress_engine.go).
	_ "github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// TestEgressMemberRail_E2E_DeliveredEgressTakesEffectOnLocalProxy is the member-rail
// (个人/团队成员本地 proxy) end-to-end counterpart of the proxy-package
// TestEgressDelivery_DeliveredMaterialEgressesThroughAccountProxy (which starts from
// vault material). It proves the WHOLE member rail: a per-account egress_proxy_url set
// on master is pulled by THIS proxy over real HTTP (fetchGroupRuntime), survives the
// vault encrypt/decrypt projection (buildGroupRuntimeJSON — the write side we fixed
// 2026-07-16), and then ACTUALLY egresses through that account's proxy — bytes really
// traverse the socks5 exit, not just a string that survived.
//
// Why this test exists (防退化): account-level egress used to ride ONLY the org/cluster
// rail (OrgRuntimeAccount). A personal/team-member proxy pulls the MEMBER rail
// (GET /accounts/me/group-runtime), whose AccountMaterial had no egress field — so a
// per-account egress set in master silently no-op'd on those proxies. This E2E is the
// live guard that the member rail now carries egress from master all the way to the dial.
func TestEgressMemberRail_E2E_DeliveredEgressTakesEffectOnLocalProxy(t *testing.T) {
	// The real upstream ("provider") the routed account would call. A plain TCP
	// listener is enough — we only need a live target the socks5 exit can CONNECT to.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	upstreamAddr := upstream.Addr().String()

	// The account's dedicated egress exit (its own IP, in production terms). A real
	// socks5 recorder so "took effect" means a real CONNECT was served, not a stub.
	exit := egresstest.NewSocks5Server(t, "", "")
	egressSpec := "socks5://" + exit.Addr()

	// Stand up a real master serving GET /accounts/me/group-runtime with ONE OAuth
	// account carrying the per-account egress on the member rail (egress_proxy_url on
	// AccountMaterial — the field added 2026-07-16). This is the exact wire the member
	// proxy pulls; if the member-rail producer dropped egress, it would be absent here.
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/accounts/me/group-runtime" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		resp := fmt.Sprintf(
			`{"groups":[{"oauth_group_id":"grp-1","routing_config":"{}","accounts":[`+
				`{"account_id":"acc-1","credential_id":"cred-1","credential_type":"oauth_account",`+
				`"access_token":"at-live","expires_at":9,"egress_proxy_url":%q}]}]}`, egressSpec)
		_, _ = w.Write([]byte(resp))
	}))
	defer master.Close()

	// (1) Real member-rail pull over HTTP: parses grAccount incl. egress_proxy_url.
	groups, _, err := fetchGroupRuntime(context.Background(), master.URL, "JWT", nil)
	if err != nil || len(groups) != 1 || len(groups[0].Accounts) != 1 {
		t.Fatalf("member-rail pull: err=%v groups=%+v", err, groups)
	}
	if got := groups[0].Accounts[0].EgressProxyURL; got != egressSpec {
		t.Fatalf("egress dropped on the member-rail wire (grAccount): got %q want %q", got, egressSpec)
	}

	// (2) Real vault projection: encrypt the delivered material as the proxy stores it,
	// then read it back the way the resolver does — egress must survive the roundtrip.
	key := testKey()
	js, err := buildGroupRuntimeJSON(key, groups[0].Accounts)
	if err != nil {
		t.Fatalf("buildGroupRuntimeJSON: %v", err)
	}
	var material map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(js), &material); err != nil {
		t.Fatalf("unmarshal group_runtime: %v", err)
	}
	acc, ok := material["acc-1"]
	if !ok {
		t.Fatalf("account absent from projected group_runtime: %s", js)
	}
	deliveredEgress := acc.EgressProxyURL
	if deliveredEgress != egressSpec {
		t.Fatalf("egress lost in vault projection (buildGroupRuntimeMap): got %q want %q", deliveredEgress, egressSpec)
	}

	// (3) It ACTUALLY egresses: build a dialer from the delivered spec through the SAME
	// public registry the hot path uses, dial the upstream, and assert the socks5 exit
	// really served the CONNECT to the upstream — i.e. traffic exits via the account's
	// proxy, not direct.
	dialer, err := egress.BuildDialer(deliveredEgress)
	if err != nil {
		t.Fatalf("BuildDialer(delivered egress): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var conn net.Conn
	if cd, ok := dialer.(interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	}); ok {
		conn, err = cd.DialContext(ctx, "tcp", upstreamAddr)
	} else {
		conn, err = dialer.Dial("tcp", upstreamAddr)
	}
	if err != nil {
		t.Fatalf("dial upstream via delivered egress: %v", err)
	}
	_ = conn.Close()

	n, last := exit.Stats()
	if n == 0 || last != upstreamAddr {
		t.Fatalf("delivered egress did NOT take effect: exit connects=%d last=%q, want a CONNECT to upstream %q", n, last, upstreamAddr)
	}
}
