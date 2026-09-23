package cluster

// register_multihub_test.go — fences for multi-hub fan-out registration.
//
// Why these exist: every aikey-hub instance keeps its own in-memory node table,
// so a node has to register with and heartbeat to EVERY hub or the second hub
// serves an empty table. The supervisor answers that with one Registrar per hub,
// each in its own goroutine (supervisor.startClusterRegistrars). That is only
// correct if the Registrar loops are truly independent — no shared state, no
// shared lock — and if an operator can tell from the log WHICH hub is
// misbehaving. These fences pin exactly those properties; the supervisor's own
// fence pins that the fan-out is wired from the configured list.
//
// update: roadmap20260320/技术实现/update/20260922-集群入口高可用-hub多实例与两台入口机.md
// (DEC-cluster-ingress-ha-2) · deployment design
// workflow/CI/enviroment/tokenhub-gcp/ingress-ha.md §6.3
//nolint:misspell // that directory really is spelled "enviroment"; correcting it here would point at a path that does not exist

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// runConcurrently mirrors the supervisor's wiring: every Registrar runs its own
// loop in its own goroutine on a shared ctx. Returns once every loop has exited.
func runConcurrently(ctx context.Context, regs ...*Registrar) {
	var wg sync.WaitGroup
	for _, r := range regs {
		wg.Add(1)
		go func(r *Registrar) {
			defer wg.Done()
			r.Run(ctx)
		}(r)
	}
	wg.Wait()
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for: %s", timeout, what)
}

// hangingHub accepts connections and never answers — the worst kind of dead hub,
// because the caller only learns about it from its own client timeout (5s). The
// handler returns on client disconnect or test cleanup, so Close never hangs.
func hangingHub(t *testing.T, attempts *int32) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(attempts, 1)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	return srv
}

func TestRegistrar_FanOutRegistersAndHeartbeatsEveryHub(t *testing.T) {
	var okA, okB int32 = http.StatusOK, http.StatusOK
	var regA, hbA, regB, hbB int32
	hubA := fakeHub(t, 0, &okA, &regA, &hbA)
	defer hubA.Close()
	hubB := fakeHub(t, 0, &okB, &regB, &hbB)
	defer hubB.Close()

	a := NewRegistrar(hubA.URL, "n1", "10.0.0.1:27200", 1, "")
	b := NewRegistrar(hubB.URL, "n1", "10.0.0.1:27200", 1, "")
	a.interval, b.interval = 10*time.Millisecond, 10*time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { runConcurrently(ctx, a, b); close(done) }()

	waitFor(t, 2*time.Second, func() bool {
		return atomic.LoadInt32(&regA) >= 1 && atomic.LoadInt32(&hbA) >= 1 &&
			atomic.LoadInt32(&regB) >= 1 && atomic.LoadInt32(&hbB) >= 1
	}, "both hubs to receive POST /cluster/register and at least one POST /cluster/heartbeat")
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("registrar loops did not stop after ctx cancel")
	}
}

func TestRegistrar_OneHubDownDoesNotBlockTheOther(t *testing.T) {
	// Two flavors of "down": a hub that hangs (only the client timeout ends the
	// call) and a hub that refuses connections (fails fast, on every tick).
	t.Run("hub A hangs", func(t *testing.T) {
		var attemptsA int32
		hubA := hangingHub(t, &attemptsA)
		assertHubBUnaffected(t, hubA.URL, func() bool { return atomic.LoadInt32(&attemptsA) >= 1 })
	})
	t.Run("hub A refuses connections", func(t *testing.T) {
		closed := httptest.NewServer(http.NotFoundHandler())
		url := closed.URL
		closed.Close() // the port now refuses connections
		assertHubBUnaffected(t, url, func() bool { return true })
	})
}

// assertHubBUnaffected runs a Registrar against the dead hub A and a healthy hub
// B side by side and proves B keeps its normal rhythm while A is down: register
// + several heartbeats well inside A's 5s client timeout (a serialized fan-out
// would push B behind that timeout), and a prompt wind-down on cancel.
func assertHubBUnaffected(t *testing.T, deadHubURL string, aWasTried func() bool) {
	t.Helper()
	var okB int32 = http.StatusOK
	var regB, hbB int32
	hubB := fakeHub(t, 0, &okB, &regB, &hbB)
	defer hubB.Close()

	a := NewRegistrar(deadHubURL, "n1", "10.0.0.1:27200", 1, "")
	b := NewRegistrar(hubB.URL, "n1", "10.0.0.1:27200", 1, "")
	a.interval, b.interval = 10*time.Millisecond, 10*time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	done := make(chan struct{})
	go func() { runConcurrently(ctx, a, b); close(done) }()

	waitFor(t, 2*time.Second, func() bool {
		return aWasTried() && atomic.LoadInt32(&regB) >= 1 && atomic.LoadInt32(&hbB) >= 3
	}, "hub B to receive register + 3 heartbeats while hub A is down")
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("hub B was served only after %v — hub A's failure leaked into B's loop", elapsed)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("registrar loops did not stop after ctx cancel — a stuck hub call must honor ctx")
	}
	if total := time.Since(start); total > 5*time.Second {
		t.Fatalf("total wall time %v — the dead hub must not stretch the run", total)
	}
}

// syncBuffer serializes writes: the default slog handler is shared by every
// goroutine in the test binary.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestRegistrar_EveryLogLineCarriesHubLabel: with one Registrar per hub, a log
// line that does not say which hub it is about is useless to the operator who
// has to find the broken one. Every branch of Run is driven and every line it
// writes must carry hub=<that hub's URL>.
func TestRegistrar_EveryLogLineCarriesHubLabel(t *testing.T) {
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	// A scripted hub walks Run through every failure branch: register #1 fails
	// (initial register failed), heartbeat #1 answers 409 (hub lost this node →
	// re-register #2, which fails), heartbeat #2 answers 500 (heartbeat failed →
	// re-register #3 succeeds), then everything is healthy.
	var registers, heartbeats int32
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/register", func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&registers, 1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"registered":true}`))
	})
	mux.HandleFunc("/cluster/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		switch atomic.AddInt32(&heartbeats, 1) {
		case 1:
			w.WriteHeader(http.StatusConflict)
		case 2:
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	flaky := httptest.NewServer(mux)
	defer flaky.Close()

	r := NewRegistrar(flaky.URL, "n1", "10.0.0.1:27200", 1, "")
	r.interval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	waitFor(t, 2*time.Second, func() bool { return atomic.LoadInt32(&heartbeats) >= 3 },
		"the scripted hub to see three heartbeats")
	cancel()
	<-done

	// The one success line is written only by the initial register.
	var okReg int32 = http.StatusOK
	var n1, n2 int32
	healthy := fakeHub(t, 0, &okReg, &n1, &n2)
	defer healthy.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	NewRegistrar(healthy.URL, "n1", "10.0.0.1:27200", 1, "").Run(ctx2)

	wantHub := map[string]string{
		"cluster: initial register failed; will retry on next tick": flaky.URL,
		"cluster: hub lost this node; re-registering":               flaky.URL,
		"cluster: re-register failed":                               flaky.URL,
		"cluster: heartbeat failed; attempting re-register":         flaky.URL,
		"cluster: registered with hub":                              healthy.URL,
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unparseable log line %q: %v", line, err)
		}
		msg, _ := rec["msg"].(string)
		if !strings.HasPrefix(msg, "cluster:") {
			continue
		}
		want, known := wantHub[msg]
		if known {
			seen[msg] = true
		}
		hub, _ := rec["hub"].(string)
		if hub == "" {
			t.Errorf("log line %q carries no hub label — with one Registrar per hub the operator cannot tell which hub it is about", msg)
			continue
		}
		if known && hub != want {
			t.Errorf("log line %q labels hub %q, want %q", msg, hub, want)
		}
	}
	for msg := range wantHub {
		if !seen[msg] {
			t.Errorf("the scripted run never produced %q — this fence lost coverage of that branch; check the hub script", msg)
		}
	}
}
