// oauth_pool_cooldown.go — N8c: reactive pool-account fallback.
//
// N8a already does PRE-request avoidance (skips accounts the delivered material
// marks exhausted). N8c adds the REACTIVE layer: when a chosen account's UPSTREAM
// response says the account is broken (401) or its window is used up (a real
// exhaustion 429), cool it down so the resolver's `skip` set routes subsequent
// requests around it. The failing request still returns its status to the client
// — in-request retry (no client-visible failure) is the heavier N9 work.
//
// 429 discrimination (minimal, research-backed; full 三分类 is N9): a 429 WITH a
// rate-limit signal (anthropic-ratelimit-* / Retry-After) is a real quota/limit
// → cool down. A 429 WITHOUT those headers is Anthropic's WAF business-rejection
// (the request persona is wrong, NOT the account's fault) → do NOT cool down,
// or we'd waste a good account. Same signature the OAuth-inject research uses.
package proxy

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// poolCooldownDefault is used when the upstream gives no Retry-After hint.
	// Short enough to recover soon after a 5h window resets, long enough to not
	// hammer a broken account every few seconds.
	poolCooldownDefault = 5 * time.Minute
	// poolCooldownMax caps a server-provided Retry-After so a hostile/huge value
	// can't lock an account out for an unreasonable time.
	poolCooldownMax = 1 * time.Hour
)

// poolCooldownStore holds a per-account "avoid until" time. Concurrency-safe.
// Bounded by the number of distinct pool accounts; lapsed entries are dropped
// lazily on read.
type poolCooldownStore struct {
	mu  sync.Mutex
	m   map[string]time.Time // accountID → avoid-until
	now func() time.Time     // injectable clock (tests)
}

func newPoolCooldownStore() *poolCooldownStore {
	return &poolCooldownStore{m: make(map[string]time.Time), now: time.Now}
}

// mark cools an account down until `until`. A no-op for an empty id or a time
// already in the past.
func (s *poolCooldownStore) mark(accountID string, until time.Time) {
	if accountID == "" {
		return
	}
	s.mu.Lock()
	if cur, ok := s.m[accountID]; !ok || until.After(cur) {
		s.m[accountID] = until
	}
	s.mu.Unlock()
}

// skipSet returns the accounts currently cooling down, for the resolver's `skip`
// argument. Lapsed entries are dropped. Returns nil when nothing is cooling
// (so the resolver's `skip[id]` lookups stay cheap).
func (s *poolCooldownStore) skipSet() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out map[string]bool
	for id, until := range s.m {
		if now.Before(until) {
			if out == nil {
				out = make(map[string]bool)
			}
			out[id] = true
		} else {
			delete(s.m, id)
		}
	}
	return out
}

// snapshot returns the accounts currently cooling down → seconds remaining, for
// the admin health surface (N9 组路由健康). Lapsed entries are pruned (same as
// skipSet). Returns nil when nothing is cooling.
func (s *poolCooldownStore) snapshot() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out map[string]int
	for id, until := range s.m {
		if now.Before(until) {
			if out == nil {
				out = make(map[string]int)
			}
			out[id] = int(until.Sub(now).Seconds())
		} else {
			delete(s.m, id)
		}
	}
	return out
}

// cooldownDecision classifies an upstream response: when the chosen pool account
// should be cooled down, returns (avoid-until, true). 401 → broken account.
// Exhaustion-429 (rate-limit signal present) → honor Retry-After if given, else
// default. WAF-business-429 (no signal) and everything else → (_, false).
func cooldownDecision(resp *http.Response, now time.Time) (time.Time, bool) {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return now.Add(poolCooldownDefault), true
	case http.StatusTooManyRequests:
		if !hasRateLimitSignal(resp.Header) {
			return time.Time{}, false // WAF business rejection — not the account's fault
		}
		d := poolCooldownDefault
		if ra := retryAfterDuration(resp.Header); ra > 0 {
			d = ra
		}
		if d > poolCooldownMax {
			d = poolCooldownMax
		}
		return now.Add(d), true
	default:
		return time.Time{}, false
	}
}

// hasRateLimitSignal reports whether the response carries a real rate-limit /
// exhaustion marker (vs a WAF business rejection that omits them).
func hasRateLimitSignal(h http.Header) bool {
	if h.Get("Retry-After") != "" {
		return true
	}
	for k := range h {
		if strings.Contains(strings.ToLower(k), "ratelimit") {
			return true
		}
	}
	return false
}

// retryAfterDuration parses the Retry-After header's delta-seconds form. The
// HTTP-date form is ignored (returns 0 → caller uses the default).
func retryAfterDuration(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}
