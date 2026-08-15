// filterpool_dispatch_order_test.go — fences for the two things FilterPool
// promises the outside world about its dispatch:
//
//  1. WorkerStatuses()[i] IS dispatch slot i. `/v1/diagnostics/pipeline` and
//     `ak doctor` both let an operator read "worker 1 is down" as a statement
//     about a specific share of traffic; that reading is only valid while the
//     index and the slot are the same thing. It was a prose claim in a comment
//     until 2026-08-14 — machine-checked here.
//
//  2. pick() never hands work to a worker the health surface calls unfit, never
//     returns nil, and never orphans a worker it skipped (review finding B39).
package apphook

import (
	"testing"
	"time"
)

// newPoolForDispatch builds a pool of M ChildHooks with NO child processes.
// Nothing here spawns: these tests are about the dispatcher's arithmetic, and
// the health bit it reads is set directly so every combination (including
// all-dead, which a live harness can only reach destructively) is reachable.
func newPoolForDispatch(t *testing.T, m int) *FilterPool {
	t.Helper()
	workers := make([]*ChildHook, m)
	for i := range workers {
		workers[i] = NewChildHook(&ChildHookConfig{Name: "unit", BinaryPath: "/nonexistent/detector"})
	}
	return NewFilterPool("unit", workers)
}

// setFit forces a worker's dispatch eligibility by writing the SAME Status the
// endpoint publishes — deliberately not a test-only flag, so the fence breaks if
// dispatch ever starts consulting a second, private notion of health.
func setFit(h *ChildHook, fit bool) {
	old := h.status.Load()
	s := *old
	s.Healthy = fit
	s.DegradedReason = ""
	if !fit {
		s.DegradedReason = "read_failed: EOF"
	}
	h.status.Store(&s)
	h.degraded.Store(!fit)
}

// slotOf maps a returned worker back to its WorkerStatuses index.
func slotOf(p *FilterPool, w *ChildHook) int {
	for i, cand := range p.workers {
		if cand == w {
			return i
		}
	}
	return -1
}

// TestFence_WorkerStatusesIndexIsTheDispatchSlot pins the claim both health
// surfaces rest on. With every worker fit, the n-th pick must land on slot
// n mod M — the exact pattern observed live on 2026-08-14, where killing
// workers[1] of a 3-worker pool produced fail-opens at request positions
// 1, 4, 7, 10.
func TestFence_WorkerStatusesIndexIsTheDispatchSlot(t *testing.T) {
	const m = 3
	p := newPoolForDispatch(t, m)
	for _, w := range p.workers {
		setFit(w, true)
	}
	if got := len(p.WorkerStatuses()); got != m {
		t.Fatalf("WorkerStatuses() returned %d entries for a %d-worker pool", got, m)
	}

	var got []int
	for n := 1; n <= 3*m; n++ {
		got = append(got, slotOf(p, p.pick()))
	}
	want := []int{1, 2, 0, 1, 2, 0, 1, 2, 0}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dispatch slot sequence = %v, want %v.\n"+
				"WorkerStatuses()[i] is documented AND rendered as dispatch slot i "+
				"(diagnostics.FilterWorkerHealth.Index, ak doctor's \"worker N\" row). "+
				"If dispatch order changed, every operator reading \"worker 1 is down\" is now "+
				"reading a statement about a different process.", got, want)
		}
	}
}

// TestPick_SkipsUnfitWorkersAndNudgesThem is the B39 unit-level assertion:
// the dead slot receives ZERO dispatches, and is still asked to come back.
func TestPick_SkipsUnfitWorkersAndNudgesThem(t *testing.T) {
	const m, victim = 3, 1
	p := newPoolForDispatch(t, m)
	for _, w := range p.workers {
		setFit(w, true)
	}
	setFit(p.workers[victim], false)
	// Make the victim's recovery observable without spawning anything: a respawn
	// attempt is what moves lastRecoverAt.
	p.workers[victim].lastRecoverAt.Store(0)

	counts := make([]int, m)
	for n := 0; n < 60; n++ {
		counts[slotOf(p, p.pick())]++
	}
	if counts[victim] != 0 {
		t.Errorf("🔴 B39: the unfit worker took %d of 60 dispatches. Live-measured consequence: its "+
			"Detect fails open and that share of user content reaches the upstream LLM "+
			"un-inspected. counts=%v", counts[victim], counts)
	}
	if counts[0] == 0 || counts[2] == 0 {
		t.Errorf("load was not spread across the surviving workers: counts=%v", counts)
	}

	// 🔴 THE SELF-HEAL PARADOX. Skipping must not orphan. lazyRecover is
	// request-triggered, so the worker that stops receiving requests must still be
	// nudged by the dispatcher that skipped it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && p.workers[victim].lastRecoverAt.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if p.workers[victim].lastRecoverAt.Load() == 0 {
		t.Fatal("🔴 the skipped worker was never nudged to recover — pick() turned a transient " +
			"degrade into a permanent amputation, which is a worse bug than the one it fixed")
	}
}

// TestPick_AllUnfitStillServesSomebody pins the whole-pool-loss degradation.
// 不阻塞用户流程 outranks detection: with nobody fit, pick must still return a
// worker so the request travels the existing fail-open path (Allow +
// Degraded=true) instead of being refused or made to wait for a respawn.
func TestPick_AllUnfitStillServesSomebody(t *testing.T) {
	const m = 3
	p := newPoolForDispatch(t, m)
	for _, w := range p.workers {
		setFit(w, false)
	}
	seen := make(map[int]int)
	for n := 0; n < 30; n++ {
		w := p.pick()
		if w == nil {
			t.Fatal("🔴 pick() returned nil with every worker unfit — the caller would panic, " +
				"turning a detector outage into a user-facing outage")
		}
		seen[slotOf(p, w)]++
	}
	if len(seen) != m {
		t.Errorf("the all-dead fallback is not round-robin (slots hit: %v) — respawn attempts would "+
			"pile onto one child instead of being spread", seen)
	}
}

// TestPick_SingleWorkerPoolIsUnchanged guards the M=1 degenerate case that
// Personal and Trial actually run: no scan, no skip, and the one worker keeps
// receiving requests even while degraded (its own roundtrip nudges the recovery
// and fails open — the behavior those editions have always had).
func TestPick_SingleWorkerPoolIsUnchanged(t *testing.T) {
	p := newPoolForDispatch(t, 1)
	setFit(p.workers[0], false)
	for n := 0; n < 5; n++ {
		if p.pick() != p.workers[0] {
			t.Fatal("M=1 pool must always dispatch to its only worker")
		}
	}
}

// BenchmarkFilterPoolPick measures the hot path: pick() runs once per content
// piece per request, so the health check it gained must not be a latency tax.
// Sub-benchmarks separate the best case (a fit worker at the cursor — one atomic
// load) from the worst (every worker unfit — M loads plus the nudge pre-checks).
func BenchmarkFilterPoolPick(b *testing.B) {
	for _, m := range []int{1, 2, 4, 8} {
		p := &FilterPool{name: "bench"}
		for i := 0; i < m; i++ {
			h := NewChildHook(&ChildHookConfig{Name: "bench", BinaryPath: "/nonexistent"})
			p.workers = append(p.workers, h)
		}
		for _, fit := range []bool{true, false} {
			for _, w := range p.workers {
				setFit(w, fit)
			}
			name := "all_healthy"
			if !fit {
				// Keep the nudge from actually spawning goroutines: a fresh
				// lastRecoverAt means the cooldown gate short-circuits, which is also
				// the steady state of a real degraded pool under load.
				for _, w := range p.workers {
					w.lastRecoverAt.Store(time.Now().UnixNano())
				}
				name = "all_unfit"
			}
			b.Run(name+"/M="+itoa(m), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_ = p.pick()
				}
			})
		}
	}
}

// BenchmarkFilterPoolPick_PreFixBaseline reproduces the 2026-08-13 pick()
// arithmetic verbatim (one atomic add + one modulo, no health check) so the cost
// of the B39 fix is a measured delta rather than an assertion. It exists only as
// a reference point — nothing in production calls it.
func BenchmarkFilterPoolPick_PreFixBaseline(b *testing.B) {
	for _, m := range []int{1, 2, 4, 8} {
		p := &FilterPool{name: "bench"}
		for i := 0; i < m; i++ {
			p.workers = append(p.workers, NewChildHook(&ChildHookConfig{Name: "bench", BinaryPath: "/nonexistent"}))
		}
		b.Run("M="+itoa(m), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if len(p.workers) == 1 {
					_ = p.workers[0]
					continue
				}
				idx := p.next.Add(1)
				_ = p.workers[idx%uint64(len(p.workers))]
			}
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
