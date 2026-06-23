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
)

// FilterPool dispatches across M ChildHooks round-robin. Round-robin (not
// least-loaded) is sufficient because each ChildHook absorbs concurrent Detects
// internally — the pool only needs to spread the steady-state load and provide
// process isolation.
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

func (p *FilterPool) pick() *ChildHook {
	if len(p.workers) == 1 {
		return p.workers[0]
	}
	i := p.next.Add(1)
	return p.workers[i%uint64(len(p.workers))]
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

// Status implements Hook — healthy iff ≥1 worker is healthy (the pool keeps
// serving while any process survives).
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
