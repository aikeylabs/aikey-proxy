package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/egress"
)

// Fences for bugfix 2026-07-28 (node egress self-check was serial).
//
// Field failure: staging node had 6 accounts, 4 with a dead egress. Each broken
// one burns the FULL per-account dial timeout, so the endpoint took 24.7s. The
// master console's 拨测 gives it a fixed 20s budget → the console said "node
// admin face unreachable (is the node up?)", which is a misdiagnosis: the node
// was healthy and answering. The tool built to diagnose broken egress became
// least reliable exactly when egress was broken.
//
// The invariant these fences pin is NOT "it is faster" — it is that the
// endpoint's wall clock is bounded by ONE dial, not by the account count, and
// that a budget cutoff still yields readable rows.

func specsForTest(n int) []vkeys.AccountEgressSpec {
	specs := make([]vkeys.AccountEgressSpec, n)
	for i := range specs {
		specs[i] = vkeys.AccountEgressSpec{
			Label: fmt.Sprintf("acct-%02d@example.com", i),
			Spec:  fmt.Sprintf("socks5://10.0.0.%d:1080", i+1),
		}
	}
	return specs
}

// 🔴 THE fence. Every account is a SLOW FAILURE — the exact production shape of
// a dead egress. Serial execution takes n*delay; the fan-out must take ~delay.
//
// 能红: revert runEgressSelfCheck to a sequential `for` loop → 8*300ms = 2.4s,
// blowing the 1.2s ceiling below.
func TestRunEgressSelfCheck_WallClockIndependentOfAccountCount(t *testing.T) {
	const n, delay = 8, 300 * time.Millisecond
	var inFlight, peak int64

	probe := func(ctx context.Context, spec string) (*egress.TestResult, error) {
		cur := atomic.AddInt64(&inFlight, 1)
		for {
			old := atomic.LoadInt64(&peak)
			if cur <= old || atomic.CompareAndSwapInt64(&peak, old, cur) {
				break
			}
		}
		defer atomic.AddInt64(&inFlight, -1)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return nil, errors.New("egress unreachable via mihomo: rejected username/password")
	}

	start := time.Now()
	rows := runEgressSelfCheck(context.Background(), specsForTest(n), true, probe)
	elapsed := time.Since(start)

	if len(rows) != n {
		t.Fatalf("got %d rows, want one per account (%d)", len(rows), n)
	}
	// Serial would be n*delay = 2.4s. Generous ceiling so the fence is about the
	// serial/parallel split, not scheduler jitter.
	if ceiling := 4 * delay; elapsed > ceiling {
		t.Fatalf("self-check took %v for %d slow accounts (ceiling %v) — the dials are running SERIALLY, "+
			"so wall clock still scales with account count and the console's fixed budget will time out again",
			elapsed, n, ceiling)
	}
	if peak < 2 {
		t.Fatalf("peak concurrency was %d — nothing ran in parallel", peak)
	}
	if peak > egressSelfCheckParallel {
		t.Fatalf("peak concurrency %d exceeded the %d cap — an unbounded fan-out can exhaust the node's memory "+
			"building one engine instance per account", peak, egressSelfCheckParallel)
	}
	// A failed dial must still say WHY (失败要显眼), and must not be confused
	// with the budget-cutoff reason.
	for _, r := range rows {
		if r.OK || !r.Dialed {
			t.Fatalf("row %q: want dialed+failed, got dialed=%v ok=%v", r.Label, r.Dialed, r.OK)
		}
		if !strings.Contains(r.Reason, "rejected username/password") {
			t.Fatalf("row %q lost the actionable dial reason: %q", r.Label, r.Reason)
		}
	}
}

// Rows must stay in the registry's (label-sorted) order. The console compares
// exit IPs across nodes row-by-row; a nondeterministic order from the goroutines
// would make that comparison silently wrong rather than obviously broken.
//
// 能红: collect results by appending from each goroutine instead of writing
// out[i] → order follows completion time and this fails.
func TestRunEgressSelfCheck_PreservesInputOrder(t *testing.T) {
	specs := specsForTest(6)
	// Finish in REVERSE order so any append-based collection inverts the list.
	probe := func(ctx context.Context, spec string) (*egress.TestResult, error) {
		var idx int
		_, _ = fmt.Sscanf(spec, "socks5://10.0.0.%d:1080", &idx)
		time.Sleep(time.Duration(len(specs)-idx) * 20 * time.Millisecond)
		return &egress.TestResult{Engine: "mihomo", ExitIP: "69.5.53.60", LatencyMs: 1}, nil
	}
	rows := runEgressSelfCheck(context.Background(), specs, true, probe)
	for i, r := range rows {
		if r.Label != specs[i].Label {
			t.Fatalf("row %d is %q, want %q — result order does not follow input order", i, r.Label, specs[i].Label)
		}
	}
}

// The whole point of the budget: the endpoint ALWAYS answers inside it. Accounts
// that did not get probed must come back as explicit rows carrying the
// budget reason — never dropped (the admin would think the account vanished)
// and never blank-failed (the admin would think its egress is broken).
//
// 能红: drop the pre-fill + budget context and let the fan-out run to
// completion → this test hangs past the ceiling; report an empty slice on
// timeout → the row-count assertion fails.
func TestRunEgressSelfCheck_BudgetCutoffYieldsExplicitRows(t *testing.T) {
	// More accounts than slots, each slower than the budget → the later waves
	// can never get a slot.
	const n = egressSelfCheckParallel * 3
	probe := func(ctx context.Context, spec string) (*egress.TestResult, error) {
		<-ctx.Done() // never completes on its own; only the budget stops it
		return nil, ctx.Err()
	}

	start := time.Now()
	rows := runEgressSelfCheck(context.Background(), specsForTest(n), true, probe)
	elapsed := time.Since(start)

	if elapsed > egressSelfCheckBudget+3*time.Second {
		t.Fatalf("self-check ran %v — it must return within its %v budget so the caller's client never times out",
			elapsed, egressSelfCheckBudget)
	}
	if len(rows) != n {
		t.Fatalf("got %d rows for %d accounts — an unprobed account must still be listed", len(rows), n)
	}
	var cutoff int
	for _, r := range rows {
		if r.OK {
			t.Fatalf("row %q reported OK though nothing completed", r.Label)
		}
		if r.Reason == "" {
			t.Fatalf("row %q has no reason — a silent false reads as 'egress broken' and gets a healthy account retired", r.Label)
		}
		if strings.Contains(r.Reason, "budget") {
			cutoff++
			if r.Dialed {
				t.Fatalf("row %q is marked dialed but was never probed", r.Label)
			}
		}
	}
	if cutoff == 0 {
		t.Fatal("no row carried the budget-exhausted reason — a cut-off account is indistinguishable from a broken one")
	}
}

// Presence mode (`aikey test`, hot path) must not dial at all: §5.4 #2 forbids
// probing the provider egress on a cadence, and it must stay instant.
//
// 能红: make the dial=false branch fall through into the fan-out → probe runs
// and the counter is non-zero.
func TestRunEgressSelfCheck_PresenceModeNeverDials(t *testing.T) {
	var calls int64
	probe := func(ctx context.Context, spec string) (*egress.TestResult, error) {
		atomic.AddInt64(&calls, 1)
		return nil, nil
	}
	specs := specsForTest(4)
	rows := runEgressSelfCheck(context.Background(), specs, false, probe)
	if calls != 0 {
		t.Fatalf("presence mode dialed %d times — the hot path must never touch the network", calls)
	}
	if len(rows) != len(specs) {
		t.Fatalf("got %d rows, want %d", len(rows), len(specs))
	}
	for i, r := range rows {
		if r.Dialed || r.OK || r.Reason != "" {
			t.Fatalf("presence row %d = %+v, want label-only", i, r)
		}
		if r.Label != specs[i].Label {
			t.Fatalf("presence row %d is %q, want %q", i, r.Label, specs[i].Label)
		}
	}
}

// Concurrency safety: the fan-out writes into a shared slice. Run under -race
// with contention to pin that the mutex actually guards it.
//
// 能红: remove the mutex around out[i] and run `go test -race` → data race.
func TestRunEgressSelfCheck_NoDataRace(t *testing.T) {
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runEgressSelfCheck(context.Background(), specsForTest(12), true,
				func(ctx context.Context, spec string) (*egress.TestResult, error) {
					return &egress.TestResult{Engine: "mihomo", ExitIP: "69.5.53.60"}, nil
				})
		}()
	}
	wg.Wait()
}
