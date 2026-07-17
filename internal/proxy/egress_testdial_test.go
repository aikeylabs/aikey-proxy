package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/egresstest"
	"github.com/AiKeyLabs/pkg/egress"
)

// egress.TestDial is the shared connectivity probe behind the master console's
// "test" button. This exercises it with a REAL socks5 dial (via the shared test
// rig) so the probe path is proven, plus the failure paths that must surface an
// actionable config error to the admin (the whole point of the button).
func TestEgressTestDial_SuccessAndConfigErrors(t *testing.T) {
	// Echo returns a fixed IP string; extractIP reduces it to ExitIP.
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.7")
	}))
	defer echo.Close()

	proxySrv := egresstest.NewSocks5Server(t, "", "")

	// Success: dial the echo THROUGH the socks5 proxy → exit IP extracted, engine
	// identified, and the proxy really traversed.
	res, err := egress.TestDial(context.Background(), "socks5://"+proxySrv.Addr(), echo.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("probe through live socks5: %v", err)
	}
	if res.ExitIP != "203.0.113.7" {
		t.Errorf("exit ip = %q, want 203.0.113.7 (from echo body)", res.ExitIP)
	}
	if res.Engine != "builtin-socks5" {
		t.Errorf("engine = %q, want builtin-socks5", res.Engine)
	}
	if n, _ := proxySrv.Stats(); n == 0 {
		t.Error("socks5 proxy was not traversed")
	}

	// Config error 1: a well-formed but DEAD socks5 → surfaced error (not a panic,
	// not a silent success).
	if _, err := egress.TestDial(context.Background(), "socks5://127.0.0.1:1", echo.URL, 2*time.Second); err == nil {
		t.Error("a dead socks5 proxy must surface an error for the admin to debug")
	}

	// Config error 2: an unsupported scheme (no engine claims it in this build) →
	// error before any dial, so a typo/unsupported-protocol is reported.
	if _, err := egress.TestDial(context.Background(), "ss://rc4-md5:pw@8.8.8.8:8002", echo.URL, 2*time.Second); err == nil {
		t.Error("an unclaimed spec must surface an error")
	}
}
