package observer

import (
	"sync"
	"time"
)

// tokenLimiter is the rate-limiter the observer framework uses to gate
// per-observer panic dumps + auto-disable decisions (P1-2 invariant).
//
// Why a custom limiter (instead of "golang.org/x/time/rate"): the
// external x/time/rate package would introduce an additional module
// dependency on a code path that runs from a panic recover; keeping the
// limiter self-contained lets us audit the full implementation in one
// file. The semantics here are also slightly different from x/rate's
// classic token bucket — we just need "max N events per sliding
// window", which is a few lines to write directly.
type tokenLimiter struct {
	nowFunc func() time.Time
	stamps  []time.Time // event timestamps inside the current window
	budget  int
	window  time.Duration
	mu      sync.Mutex
}

func newTokenLimiter(budget int, window time.Duration) *tokenLimiter {
	return &tokenLimiter{
		budget:  budget,
		window:  window,
		nowFunc: time.Now,
	}
}

// allow returns true if a new event fits inside the sliding window,
// false otherwise. When it returns true the event is recorded; when
// false the event is not (so consumers should treat false as "deny + do
// not retry").
func (t *tokenLimiter) allow() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.nowFunc()
	cutoff := now.Add(-t.window)

	// Drop stamps that fell out of the window. The expected stamp
	// count is small (budget ~10-60), so a linear scan + shift is
	// faster than any ring-buffer scheme would be.
	i := 0
	for i < len(t.stamps) && t.stamps[i].Before(cutoff) {
		i++
	}
	if i > 0 {
		t.stamps = t.stamps[i:]
	}

	if len(t.stamps) >= t.budget {
		return false
	}
	t.stamps = append(t.stamps, now)
	return true
}
