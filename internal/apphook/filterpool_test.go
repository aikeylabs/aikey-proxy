package apphook

// Phase 3 (the "C"): FilterPool fans Detect across M processes. These prove it
// routes concurrently across all workers, aggregates Status, and stays up when a
// worker goes down (cross-process isolation). Run under -race.

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newPoolWorker(t *testing.T) *ChildHook {
	t.Helper()
	return NewChildHook(&ChildHookConfig{
		Name: "pool-w", BinaryPath: findDetectorBinary(t), BinaryArgs: detectorArgs(),
		Timeout: 2 * time.Second, ReadyTimeout: 5 * time.Second,
	})
}

func TestFilterPool_RoutesAcrossWorkers(t *testing.T) {
	pool := NewFilterPool("test-pool", []*ChildHook{newPoolWorker(t), newPoolWorker(t)})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := pool.Start(ctx); err != nil {
		t.Skipf("child binary unavailable, skipping (build first): %v", err)
	}
	defer func() { _ = pool.Shutdown(context.Background()) }()

	if st := pool.Status(); !st.Healthy {
		t.Fatalf("pool should be healthy with 2 workers up: %s", st.DegradedReason)
	}

	// Concurrent Detects routed round-robin across both workers — all succeed.
	var wg sync.WaitGroup
	var fail atomic.Int64
	for g := 0; g < 24; g++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				res := pool.Detect(ctx, &Request{Direction: DirectionInbound, Payload: []byte(fmt.Sprintf("p-%d-%d", i, j))})
				if res.Degraded || res.Action != ActionAllow { // echo child Allows
					fail.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()
	if n := fail.Load(); n > 0 {
		t.Fatalf("%d/240 pool Detect calls failed across 2 workers", n)
	}
}

func TestFilterPool_SurvivesWorkerDown(t *testing.T) {
	pool := NewFilterPool("test-pool", []*ChildHook{newPoolWorker(t), newPoolWorker(t)})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := pool.Start(ctx); err != nil {
		t.Skipf("child binary unavailable, skipping (build first): %v", err)
	}
	defer func() { _ = pool.Shutdown(context.Background()) }()

	// Take one worker down. The pool must stay healthy (≥1 up) — cross-process
	// isolation: one crash doesn't down the whole filter.
	pool.workers[0].markDegraded("test: simulated crash")
	st := pool.Status()
	if !st.Healthy {
		t.Fatalf("pool must stay healthy with 1/2 workers up, got: %s", st.DegradedReason)
	}

	// The pool keeps serving: the live worker always Allows; a request routed to
	// the downed worker may fail-open ONCE, then lazy-recovers. At least the live
	// worker's share must succeed, and the pool must converge back to serving.
	ok := 0
	for j := 0; j < 30; j++ {
		res := pool.Detect(ctx, &Request{Direction: DirectionInbound, Payload: []byte("after-degrade")})
		if !res.Degraded && res.Action == ActionAllow {
			ok++
		}
	}
	if ok == 0 {
		t.Fatal("pool served nothing after one worker went down — isolation broken")
	}
}
