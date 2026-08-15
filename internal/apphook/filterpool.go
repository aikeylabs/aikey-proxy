// filterpool.go — the "C" in 双进程+A: fan the compliance filter across M
// independent child processes.
//
// Each ChildHook already multiplexes concurrent Detects to ONE process (the
// "A"). FilterPool puts M of those behind one apphook.Hook so the detector gets
// cross-process fault isolation: a crash/hang in one process takes down only its
// share of in-flight requests (the rest keep serving + the dead one self-heals),
// instead of a single-process all-or-nothing. M× memory (50MB+ models per
// process) is the cost — paid only when M>1 (Production), where servers have RAM.
//
// Total parallelism = M processes × K goroutines-per-process. Personal/Trial run
// M=1 (this pool degenerates to a single ChildHook, behavior unchanged).
package apphook

import (
	"context"
	"fmt"
	"sync/atomic"
)

// FilterTarget is the compliance filter the supervisor installs and the proxy
// dispatches to: a Hook that can also be started, shut down, and queried for its
// effective packs. Both ChildHook (one process) and FilterPool (M processes)
// satisfy it, so the supervisor treats them uniformly.
type FilterTarget interface {
	Hook
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	ListPacks(ctx context.Context) ([]byte, error)
}

// Compile-time proof both implementations satisfy the contract.
var (
	_ FilterTarget = (*ChildHook)(nil)
	_ FilterTarget = (*FilterPool)(nil)
	// The pool is the ONLY multi-unit FilterTarget; ChildHook deliberately does
	// not implement MultiUnit (apphook.WorkerStatuses wraps it as a pool of one).
	_ MultiUnit = (*FilterPool)(nil)
)

// FilterPool dispatches across M ChildHooks round-robin, skipping workers that
// are not currently fit to inspect (see pick). Round-robin (not least-loaded) is
// sufficient because each ChildHook absorbs concurrent Detects internally — the
// pool only needs to spread the steady-state load and provide process isolation.
type FilterPool struct {
	name    string
	workers []*ChildHook
	next    atomic.Uint64
}

// NewFilterPool wraps the given workers. Caller spawns them via Start.
func NewFilterPool(name string, workers []*ChildHook) *FilterPool {
	return &FilterPool{name: name, workers: workers}
}

// Name implements Hook.
func (p *FilterPool) Name() string { return p.name }

// pick returns the worker that serves the next call, skipping workers that are
// currently unfit to inspect anything — and nudging each one it skips to
// self-heal.
//
// 🔴 WHY IT SKIPS (review finding B39, live evidence 2026-08-14). Round-robin
// used to include dead workers. Measured on a live 3-worker pool with worker 1
// killed: 4 of 12 requests were dispatched to the corpse, where Detect fails
// open, and their content was forwarded to the upstream LLM with the PII intact
// — leak positions [1 4 7 10], the period-3 fingerprint of the cursor below.
// The health endpoint reported `partial` correctly; the data plane simply did
// not act on it. A pool at 2/3 must lose 0% of coverage, not 33%.
//
// 🔴 WHY IT ALSO NUDGES — the self-heal paradox. lazyRecover is triggered BY
// REQUESTS (see nudgeRecover). "Just skip the dead ones" would therefore remove
// the only thing that ever woke them: the degrade would stop being transient and
// become permanent, trading a visible bug for a much harder one. The resolution
// is to split the TRIGGER from the PAYLOAD — every request still drives recovery
// for the workers it passes over, but no request's content is spent on a worker
// that cannot inspect it. The scan starts at a rotating offset, so each worker is
// the scan's first element once per M picks and therefore gets nudged within M
// requests of any traffic at all. No timer is involved (定时器挂掉 = 不可用).
//
// 🔴 WHY THE ALL-DEAD CASE STILL RETURNS A WORKER. 不阻塞用户流程 outranks
// detection. With no fit worker the pool falls back to the round-robin choice and
// lets it take the existing fail-open path (ChildHook.Detect → Allow +
// Degraded=true), so the user's request is served, the outage is counted, and
// /v1/diagnostics/pipeline reports `degraded 0/M`. Returning nil, refusing, or
// waiting for a respawn would each turn a detector outage into a user outage.
// (The mandated-org case that genuinely must refuse traffic is enforced far
// upstream by supervisor `declaredButMissing`, not here.)
//
// Cost: one atomic load per candidate. Best case (a healthy worker at the cursor)
// is one load — the same order as the pre-fix version. Worst case is M loads,
// and M is the operator-set worker count.
func (p *FilterPool) pick() *ChildHook {
	n := uint64(len(p.workers))
	if n == 1 {
		// Personal / Trial. Nothing to route around, and ChildHook.roundtrip
		// already nudges its own recovery, so the scan below would be pure cost.
		return p.workers[0]
	}
	start := p.next.Add(1)
	var fallback *ChildHook
	for off := uint64(0); off < n; off++ {
		w := p.workers[(start+off)%n]
		if w.eligibleForDispatch() {
			return w
		}
		if fallback == nil {
			// The worker the cursor actually landed on. Keeping it as the all-dead
			// fallback preserves round-robin fairness in that state, so an
			// all-degraded pool spreads its respawn attempts instead of hammering one
			// child.
			fallback = w
		}
		w.nudgeRecover()
	}
	return fallback
}

// Detect implements Hook — routes to the next worker round-robin.
func (p *FilterPool) Detect(ctx context.Context, req *Request) *Response {
	return p.pick().Detect(ctx, req)
}

// ListPacks answers from any worker — the effective packs (built-in baseline +
// pulled) are identical across workers (same env + pack-puller config). The
// picked worker self-heals if degraded.
func (p *FilterPool) ListPacks(ctx context.Context) ([]byte, error) {
	return p.pick().ListPacks(ctx)
}

// WorkerStatuses implements MultiUnit — one Status per process, in dispatch
// order, so a health surface can name WHICH worker is down and WHY instead of
// reading the pool's collapsed verdict.
//
// 🔴 Dispatch order is load-bearing, not cosmetic: pick() walks this exact slice
// from a rotating cursor, so index i here IS dispatch slot i. An operator
// reading "worker 1 is down" is reading "the slot that would otherwise take
// ≈1/M of the load is out, and the survivors are absorbing its share". Do not
// sort, filter or de-duplicate here.
//
// Machine-checked, not just asserted in prose: TestFence_WorkerStatusesIndexIsTheDispatchSlot
// (filterpool_dispatch_order_test.go) pins index ↔ slot. Live evidence
// 2026-08-14: killing workers[1] of a 3-worker pool produced fail-opens at
// request positions 1, 4, 7, 10 — period 3, phase 1.
func (p *FilterPool) WorkerStatuses() []*Status {
	out := make([]*Status, 0, len(p.workers))
	for _, w := range p.workers {
		out = append(out, w.Status())
	}
	return out
}

// Status implements Hook — healthy iff ≥1 worker is healthy (the pool keeps
// serving while any process survives).
//
// 🔴 THIS VERDICT ANSWERS "should the pool keep serving?", NOT "is the pool
// healthy?". With 1 of 2 workers dead it returns Healthy=true, because the
// dispatcher must keep using the survivor — and that same true is a FALSE GREEN
// for any health surface: the operator provisioned 2 processes, is running on 1,
// and one more failure ends inspection entirely. (Until the 2026-08-14 B39 fix
// it was worse still: dispatch included the dead worker, so half the traffic was
// forwarded un-inspected.) Health surfaces MUST go through apphook.WorkerStatuses
// and grade the per-worker states; the counts embedded in DegradedReason below
// are for human log lines only and must never be parsed.
func (p *FilterPool) Status() *Status {
	healthy := 0
	var sample *Status
	for _, w := range p.workers {
		s := w.Status()
		if sample == nil {
			sample = s
		}
		if s.Healthy {
			healthy++
		}
	}
	if sample == nil {
		return &Status{Healthy: false, DegradedReason: "empty pool"}
	}
	agg := *sample
	agg.Healthy = healthy > 0
	agg.DegradedReason = fmt.Sprintf("%d/%d workers healthy", healthy, len(p.workers))
	return &agg
}

// Start spawns all workers. The pool is usable if AT LEAST ONE starts (the rest
// fail-open and self-heal on demand); returns an error only if ALL fail.
func (p *FilterPool) Start(ctx context.Context) error {
	started := 0
	var lastErr error
	for _, w := range p.workers {
		if err := w.Start(ctx); err != nil {
			lastErr = err
		} else {
			started++
		}
	}
	if started == 0 {
		return lastErr
	}
	return nil
}

// Shutdown closes every worker. Idempotent (each ChildHook.Shutdown is).
func (p *FilterPool) Shutdown(ctx context.Context) error {
	var firstErr error
	for _, w := range p.workers {
		if err := w.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
