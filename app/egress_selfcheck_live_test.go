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
	"testing"
	"time"

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
