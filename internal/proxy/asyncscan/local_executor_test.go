package asyncscan

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/pkg/deepscan"
)

// countingHook is a stand-in detector child. delay makes it slow enough to
// saturate the executor without a sleep-based race.
type countingHook struct {
	name  string
	delay time.Duration
	calls atomic.Int64
}

func (h *countingHook) Name() string { return h.name }
func (h *countingHook) Detect(ctx context.Context, _ *apphook.Request) *apphook.Response {
	h.calls.Add(1)
	if h.delay > 0 {
		select {
		case <-time.After(h.delay):
		case <-ctx.Done():
			return &apphook.Response{Action: apphook.ActionAllow, Degraded: true}
		}
	}
	return &apphook.Response{Action: apphook.ActionAllow}
}
func (h *countingHook) Status() *apphook.Status { return &apphook.Status{Healthy: true} }

// TestAsyncLocalExecutor_SaturationNeverTouchesRequestPool is the isolation
// fence for the background rule lane.
//
// 🔴 WHAT GOES WRONG WITHOUT IT (design §3.8, DEC-scan-node-deepscan-15): the
// obvious implementation of "scan the tail locally" is to reuse the detector pool
// the request path already has. A single 256 KiB piece is 16 chunks, each taking
// ~11 ms (measured, baseline-forensics §F8 ②) — so one background piece occupies
// that pool for ~180 ms. The request path's detect budget is ONE millisecond:
// every request arriving in that window times out, the hook reports degraded, and
// content is forwarded UNFILTERED. A background nicety would have switched off
// synchronous compliance for a fifth of a second at a time.
//
// So the executor must own a SEPARATE child, and saturating it must leave the
// request pool completely untouched. This test proves both by counting calls on
// two distinct hooks.
func TestAsyncLocalExecutor_SaturationNeverTouchesRequestPool(t *testing.T) {
	requestPool := &countingHook{name: "request-pool"}
	background := &countingHook{name: "background-pool", delay: 300 * time.Millisecond}

	var spawned atomic.Int64
	x := NewLocalExecutor(LocalExecutorConfig{
		QueueMax:   4,
		QueueBytes: 1 << 20,
		// Short so the test does not wait 300s to observe the idle stop.
		IdleStop:      150 * time.Millisecond,
		DetectTimeout: 2 * time.Second,
	}, func() (apphook.Hook, error) {
		spawned.Add(1)
		return background, nil
	})
	defer x.Close(context.Background())

	job := PieceJob{
		JobID: "j", TenantID: "org_a", AuditUnitID: "au_1", ContentSHA256: "sha",
		Source: deepscan.SourceRequest, Text: strings.Repeat("x", 4096),
		Engines: []string{deepscan.EngineRules},
	}

	// Submit far more than the queue holds, from many goroutines, and time every
	// call: Submit is on the request path and must never wait.
	const callers, each = 50, 4
	var wg sync.WaitGroup
	var worst atomic.Int64
	accepted := atomic.Int64{}
	for c := 0; c < callers; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				start := time.Now()
				if x.Submit(job) {
					accepted.Add(1)
				}
				if d := time.Since(start).Microseconds(); d > worst.Load() {
					worst.Store(d)
				}
			}
		}()
	}
	wg.Wait()

	t.Logf("MEASURED %d Submit calls against a 300ms-per-chunk child: accepted=%d worst=%.2fms",
		callers*each, accepted.Load(), float64(worst.Load())/1000)
	if worst.Load() > 20_000 { // 20 ms
		t.Errorf("worst Submit took %.2fms — the request path waited on the background lane", float64(worst.Load())/1000)
	}
	if accepted.Load() >= callers*each {
		t.Error("every job was accepted; the bounded queue did nothing")
	}
	if st := x.Stats(); st.Dropped == 0 {
		t.Error("saturation must produce COUNTED drops, not unbounded buffering")
	}

	if n := requestPool.calls.Load(); n != 0 {
		t.Errorf("the background lane invoked the REQUEST pool %d times — a long piece would then "+
			"stall synchronous detection and force fail-open on real traffic", n)
	}
	if spawned.Load() == 0 {
		t.Error("the executor never spawned its own child; it cannot have been isolated")
	}
	if spawned.Load() > 1 {
		t.Errorf("the executor spawned %d children; design §3.8 says ONE process, on demand", spawned.Load())
	}
}

// TestAsyncLocalExecutor_SpawnsOnDemandAndStopsWhenIdle: the child costs real
// memory on an employee laptop — measured at 163 MB idle / 235 MB while working
// (baseline-forensics §F8 ③, which is 3.6–5.2x what the design assumed). So it
// must not exist until there is work, and must go away when the work stops.
func TestAsyncLocalExecutor_SpawnsOnDemandAndStopsWhenIdle(t *testing.T) {
	hook := &countingHook{name: "background-pool"}
	var spawned, closed atomic.Int64

	x := NewLocalExecutor(LocalExecutorConfig{
		QueueMax: 8, QueueBytes: 1 << 20,
		IdleStop: 80 * time.Millisecond, DetectTimeout: time.Second,
		OnChildStopped: func() { closed.Add(1) },
	}, func() (apphook.Hook, error) {
		spawned.Add(1)
		return hook, nil
	})
	defer x.Close(context.Background())

	if st := x.Stats(); st.Executor != ExecutorAbsent {
		t.Errorf("before any work the executor must report %q, got %q", ExecutorAbsent, st.Executor)
	}
	if spawned.Load() != 0 {
		t.Fatal("a child was spawned before any work arrived — that is 163 MB of an employee's RAM for nothing")
	}

	x.Submit(PieceJob{
		JobID: "j", TenantID: "org_a", ContentSHA256: "sha", Source: deepscan.SourceRequest,
		Text: strings.Repeat("y", 40*1024), Engines: []string{deepscan.EngineRules},
	})
	waitUntil(t, 2*time.Second, func() bool { return spawned.Load() == 1 })
	waitUntil(t, 2*time.Second, func() bool { return closed.Load() == 1 })
	if st := x.Stats(); st.Executor != ExecutorAbsent {
		t.Errorf("after the idle window the executor must be %q again, got %q", ExecutorAbsent, st.Executor)
	}
}

func waitUntil(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", d)
}
