package app

// Live "能红" fence for the egress self-check (§5.4): the path the endpoint runs —
// enumerate a pool account's egress spec from the registry, then dial it through
// the SHARED egress.TestDial — must report a real exit IP when the egress is up
// and FAIL (not silently pass) when it is down. Hermetic: a local socks5 + a
// local echo, no external network.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/admin"
	"github.com/AiKeyLabs/aikey-proxy/internal/egresstest"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/egress"
)

func TestEgressSelfCheck_LiveDialThroughEnumeratedSpec(t *testing.T) {
	// Neutral echo the self-check dials THROUGH the egress; returns a fixed
	// "exit IP" body (stands in for api.ipify.org).
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.7")
	}))
	defer echo.Close()

	exit := egresstest.NewSocks5Server(t, "", "")

	// A group route pinning this account's egress at the live socks5 — exactly
	// what EgressSelfCheckFn enumerates + dials.
	runtime, _ := json.Marshal(map[string]vkeys.GroupRuntimeAccount{
		"acc-1": {Identity: "pool@x", EgressProxyURL: "socks5://" + exit.Addr()},
	})
	reg := vkeys.NewRegistry()
	reg.Merge(map[string]*vkeys.ResolvedRoute{"t": {GroupRuntime: string(runtime)}})

	specs := reg.EgressSpecs()
	if len(specs) != 1 {
		t.Fatalf("enumerate: want 1 spec, got %d", len(specs))
	}

	// Egress UP → dial succeeds, exit IP surfaced (what `aikey doctor` shows).
	res, err := egress.TestDial(context.Background(), specs[0].Spec, echo.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("live egress dial must succeed: %v", err)
	}
	if res.ExitIP != "203.0.113.7" {
		t.Fatalf("exit IP = %q, want 203.0.113.7", res.ExitIP)
	}

	// Egress DOWN (nothing listening) → the self-check FAILS loudly. This is the
	// "把活的 socks5 关掉 → 该条转 fail" acceptance at the dial layer; the Rust
	// doctor maps an all-fail set to a non-zero exit.
	if _, err := egress.TestDial(context.Background(), "socks5://127.0.0.1:1", echo.URL, 2*time.Second); err == nil {
		t.Fatal("a down egress must fail the self-check, not silently pass")
	}
}

// TestEgressSelfCheck_RealProbeRowsPerSpecShape pins the `aikey doctor` rows for
// each per-account egress shape a pool can deliver to an open-source node,
// produced by the production probe EgressSelfCheckFn uses (egressSelfCheckProbe).
// master-central-oauth-login task 2.0 step 0 (DEC-master-central-login-14):
// changing TestDial must leave these rows as they are. Master saves a pool or
// account egress only as a socks5 hop, a socks5 chain or a fragment, so a
// single http(s):// URL never reaches this chain. Expected values are
// hand-written.
func TestEgressSelfCheck_RealProbeRowsPerSpecShape(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.7")
	}))
	defer echo.Close()
	t.Setenv(egress.EchoURLEnv, echo.URL)
	entry := egresstest.NewSocks5Server(t, "", "")
	exit := egresstest.NewSocks5Server(t, "", "")

	specs := []vkeys.AccountEgressSpec{
		{Label: "a-chain@example.com", Spec: "socks5://" + entry.Addr() + ",socks5://" + exit.Addr()},
		{Label: "b-dead@example.com", Spec: "socks5://127.0.0.1:1"},
		// An enterprise pool's fragment delivered to a node built without the
		// multi-protocol engine.
		{Label: "c-fragment@example.com", Spec: "proxies:\n  - {name: pool-exit, type: ss, server: 198.51.100.3, port: 8388}"},
	}
	rows := runEgressSelfCheck(context.Background(), specs, true, egressSelfCheckProbe)
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3: %+v", len(rows), rows)
	}

	rows[0].LatencyMs = 0 // wall time, not a property of the shape
	if want := (admin.EgressCheckResult{Label: "a-chain@example.com", Dialed: true, OK: true, Engine: "builtin-socks5", ExitIP: "203.0.113.7"}); rows[0] != want {
		t.Fatalf("chain row = %+v, want %+v", rows[0], want)
	}
	if n, last := entry.Stats(); n != 1 || last != exit.Addr() {
		t.Fatalf("entry hop: %d CONNECTs, last %q; want 1 to the exit hop %s", n, last, exit.Addr())
	}
	echoAddr := strings.TrimPrefix(echo.URL, "http://")
	if n, last := exit.Stats(); n != 1 || last != echoAddr {
		t.Fatalf("exit hop: %d CONNECTs, last %q; want 1 to the echo %s", n, last, echoAddr)
	}

	for _, tc := range []struct {
		row   admin.EgressCheckResult
		label string
		words string
	}{
		{rows[1], "b-dead@example.com", "egress unreachable via builtin-socks5"},
		{rows[2], "c-fragment@example.com", "no egress engine handles this proxy spec"},
	} {
		if tc.row.Label != tc.label || !tc.row.Dialed || tc.row.OK || tc.row.Engine != "" || tc.row.ExitIP != "" {
			t.Fatalf("row %+v, want a dialed failure row for %s", tc.row, tc.label)
		}
		if !strings.Contains(tc.row.Reason, tc.words) {
			t.Fatalf("row %s reason %q does not contain %q", tc.label, tc.row.Reason, tc.words)
		}
	}
}
