package cluster

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeHub serves the hub name-service register/heartbeat endpoints, counting
// calls and letting a test force a 409 on heartbeat. registerIntervalSecs is
// echoed in the register response (0 ⇒ omit, so the Registrar keeps its current
// interval — lets the Run test drive a fast 10ms loop without register override).
func fakeHub(t *testing.T, registerIntervalSecs int, heartbeatStatus *int32, registers, heartbeats *int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/register", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(registers, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"registered":true,"heartbeat_interval_seconds":%d}`, registerIntervalSecs)))
	})
	mux.HandleFunc("/cluster/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(heartbeats, 1)
		w.WriteHeader(int(atomic.LoadInt32(heartbeatStatus)))
	})
	return httptest.NewServer(mux)
}

func TestRegistrar_RegisterAdoptsIntervalAndHeartbeats(t *testing.T) {
	var hbStatus int32 = http.StatusOK
	var registers, heartbeats int32
	srv := fakeHub(t, 1, &hbStatus, &registers, &heartbeats)
	defer srv.Close()

	r := NewRegistrar(srv.URL, "n1", "10.0.0.1:27200", 0, "") // weight 0 → 1
	if r.weight != 1 {
		t.Fatalf("weight 0 should normalize to 1, got %d", r.weight)
	}

	if err := r.register(context.Background()); err != nil {
		t.Fatalf("register: %v", err)
	}
	if registers != 1 {
		t.Fatalf("register count = %d, want 1", registers)
	}
	if r.interval != time.Second {
		t.Fatalf("interval should adopt hub's 1s, got %v", r.interval)
	}

	if err := r.heartbeat(context.Background()); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if heartbeats != 1 {
		t.Fatalf("heartbeat count = %d, want 1", heartbeats)
	}
}

func TestRegistrar_HeartbeatUnknownNodeReturns409Sentinel(t *testing.T) {
	var hbStatus int32 = http.StatusConflict // hub lost the node
	var registers, heartbeats int32
	srv := fakeHub(t, 1, &hbStatus, &registers, &heartbeats)
	defer srv.Close()

	r := NewRegistrar(srv.URL, "n1", "addr", 1, "")
	if err := r.heartbeat(context.Background()); !errors.Is(err, errUnknownNode) {
		t.Fatalf("heartbeat on 409 = %v, want errUnknownNode", err)
	}
}

func TestRegistrar_RunReRegistersAfterHubForgets(t *testing.T) {
	var hbStatus int32 = http.StatusConflict // every heartbeat says "unknown node"
	var registers, heartbeats int32
	// register interval 0 ⇒ Registrar keeps the 10ms set below (no override).
	srv := fakeHub(t, 0, &hbStatus, &registers, &heartbeats)
	defer srv.Close()

	r := NewRegistrar(srv.URL, "n1", "addr", 1, "")
	r.interval = 10 * time.Millisecond // speed up the loop for the test

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	r.Run(ctx) // returns when ctx times out

	// Initial register + at least one re-register triggered by the 409 heartbeats.
	if atomic.LoadInt32(&registers) < 2 {
		t.Fatalf("expected re-registration after 409 heartbeats, registers=%d heartbeats=%d",
			registers, heartbeats)
	}
}
