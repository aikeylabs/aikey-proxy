// Package heartbeat is a reusable server-reachability probe: a periodic,
// failure-tolerant loop that pings an upstream and records WHEN it was last
// confirmed reachable.
//
// Why this exists (the bug it was extracted from): a "server reachable?" signal
// derived from REQUEST-DRIVEN work (e.g. the usage reporter's last successful
// upload) goes stale whenever there is simply no traffic — even though the
// server is perfectly up. Wiring that into a fail-closed gate makes an idle node
// block itself, and a blocked request produces no traffic to refresh the signal,
// so it deadlocks. A heartbeat fixes this by being TRAFFIC-INDEPENDENT: the
// ticker fires on its own cadence, so "last reachable" reflects the SERVER, not
// local activity, and recovery (server comes back → next probe succeeds) needs
// no request to drive it.
//
// It is the shared primitive behind any reachability signal in the proxy. First
// consumer: budget-mode quota staleness (D-U7/P9). The cluster registrar,
// canary probe, and degrade-detector rhythm poller all reimplement the same
// ticker+retry+track shape and can converge onto this over time.
//
// Contract:
//   - NEVER blocks or kills the host: a probe error only bumps a counter. Run it
//     under an isolated (not fatal) goroutine — a probe panic must not take down
//     the data path.
//   - Reads are cheap and lock-guarded; safe for a hot path to call LastOKAt.
//   - The clock is injectable for deterministic tests.
package heartbeat

import (
	"context"
	"sync"
	"time"
)

// Probe periodically runs ProbeFunc and tracks the last success + consecutive
// failures. A nil *Probe is a no-op (LastOKAt returns zero), so callers that
// only create it under a feature flag can pass nil around freely.
type Probe struct {
	lastOKAt            time.Time
	probe               func(ctx context.Context) error
	now                 func() time.Time
	interval            time.Duration
	consecutiveFailures int
	mu                  sync.RWMutex
}

// New builds a Probe that runs probe every interval. A non-positive interval is
// clamped to a sane minimum so a misconfig can't busy-loop. probe should return
// nil on a reachable server and an error otherwise; it must respect ctx.
func New(interval time.Duration, probe func(ctx context.Context) error) *Probe {
	if interval < time.Second {
		interval = time.Second
	}
	return &Probe{interval: interval, probe: probe, now: time.Now}
}

// withClock swaps the clock (test seam). Returns the receiver for chaining.
func (p *Probe) withClock(now func() time.Time) *Probe {
	if p != nil && now != nil {
		p.now = now
	}
	return p
}

// Run probes once immediately (so a fresh node gets a reachability timestamp
// without waiting a full interval) then on every tick until ctx is done. It
// blocks — launch it on its own goroutine. Safe to call on a non-nil Probe only.
func (p *Probe) Run(ctx context.Context) {
	p.runOnce(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.runOnce(ctx)
		}
	}
}

func (p *Probe) runOnce(ctx context.Context) {
	err := p.probe(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil {
		p.lastOKAt = p.now()
		p.consecutiveFailures = 0
		return
	}
	p.consecutiveFailures++
}

// LastOKAt returns the time of the last successful probe, or the zero time if
// none has succeeded yet (or on a nil Probe). Zero means "never confirmed
// reachable" — a caller MUST treat it as "no staleness evidence" (do not
// fail-closed on a signal that never started), not as "infinitely stale".
func (p *Probe) LastOKAt() time.Time {
	if p == nil {
		return time.Time{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastOKAt
}

// ConsecutiveFailures returns the number of probe failures since the last
// success (0 on a nil Probe).
func (p *Probe) ConsecutiveFailures() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.consecutiveFailures
}
