package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/admin"
)

// 🔴 WHY (2026-09-01, customer machine + winpc2). Between bind and Serve the
// listener's backlog accepted TCP and nobody answered HTTP, so a slow start
// (3.9s measured warm; slower cold on customer hardware) was indistinguishable
// from a dead process. The CLI's 5s health wait killed almost-ready children —
// "slow machine" became "can never start". These tests pin the replacement:
// the surface answers from the first moment the port is owned, says HONESTLY
// that it is starting (503 + phase), and promotion swaps in the real handlers
// without ever releasing the port.
func TestStartingSurface_AnswersFromBindAndPromotesInPlace(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	phase := NewStartupPhase("supervisor")
	srv := NewStarting(ln, phase.Get)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Shutdown(2 * time.Second) })
	base := fmt.Sprintf("http://%s", ln.Addr())

	get := func(path string) (int, []byte) {
		t.Helper()
		c := http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v — the pre-init surface is the whole point; "+
				"a hang here IS the bug this file fixes", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}

	// 1. /health answers IMMEDIATELY — 503 (still not ready, so every existing
	// consumer that requires a 200 keeps its semantics) with an honest phase.
	code, body := get("/health")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("/health during init = %d, want 503; a 200 would tell the CLI "+
			"the proxy is ready while init is still running", code)
	}
	var health struct {
		Status string `json:"status"`
		Phase  string `json:"phase"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("/health body unparseable: %s", body)
	}
	if health.Status != "starting" || health.Phase != "supervisor" {
		t.Fatalf("expected starting/supervisor, got %+v — without the phase a "+
			"stuck init says nothing about WHERE it is stuck", health)
	}

	// 2. The phase label moves with init.
	phase.Set("egress")
	if _, body := get("/health"); !jsonHasPhase(body, "egress") {
		t.Fatalf("phase did not move: %s", body)
	}

	// 3. A data-plane request mid-start is refused honestly, not hung.
	if code, body := get("/anthropic/v1/messages"); code != http.StatusServiceUnavailable ||
		!jsonHasError(body, "proxy_starting") {
		t.Fatalf("data-plane during init = %d %s, want 503 proxy_starting", code, body)
	}

	// 4. Promote swaps in the real handlers on the SAME listener/port.
	dataHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // distinctive: proves the swap landed
	})
	srv.Promote(dataHandler, &admin.Handler{}, AdminGate{})
	if code, _ := get("/anthropic/v1/messages"); code != http.StatusTeapot {
		t.Fatalf("after Promote the data plane answered %d, want the real handler "+
			"(418) — a proxy stuck on the starting surface serves nobody forever", code)
	}
	if code, _ := get("/health"); code != http.StatusOK {
		t.Fatalf("after Promote /health = %d, want 200 from the real admin handler", code)
	}
}

// Promotion on a classic server is a wiring bug and must be LOUD: a silently
// ignored Promote leaves the proxy answering "starting" forever, which is the
// original silence wearing a new costume.
func TestPromote_PanicsOnAServerWithoutASwitchboard(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	defer ln.Close()
	srv := New(ln, http.NotFoundHandler(), &admin.Handler{}, AdminGate{})
	defer func() {
		if recover() == nil {
			t.Fatal("Promote on a non-starting server did not panic")
		}
	}()
	srv.Promote(http.NotFoundHandler(), &admin.Handler{}, AdminGate{})
}

func jsonHasPhase(b []byte, want string) bool {
	var v struct {
		Phase string `json:"phase"`
	}
	return json.Unmarshal(b, &v) == nil && v.Phase == want
}

func jsonHasError(b []byte, want string) bool {
	var v struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(b, &v) == nil && v.Error == want
}
