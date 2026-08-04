package proxy

// binding_cooldown.go — cross-request isolation of a failing upstream
// (openspec change `aliyun-aigw-p0-upstream-fallback`, tasks 2.13 / 2.14 / 2.15 /
// 2.16, contract freeze §8).
//
// # 🔴 Why in-request exclusion alone is not enough
//
// Without this, a primary upstream that is down for forty minutes gets tried —
// and waited on — by EVERY request for forty minutes before the chain moves to
// the fallback. The user does not experience "the system is broken", they
// experience "why is everything so slow today", and the slowness is ours. Adding
// failover without cooling can therefore make the product feel WORSE than before
// it existed: one failure becomes one failure plus one success.
//
// # 🔴 Two axes, two stores, never one map
//
// The account axis (`poolCooldownStore`) keys on account id; this one keys on
// binding id. They must not share a map: the id spaces are unrelated, so a
// binding id that happens to equal an account id would cross-contaminate two
// completely different decisions — and the symptom (an upstream mysteriously
// skipped) would point nowhere near the cause.
//
// What IS shared is the JUDGEMENT: `cooldownDecision` / `hasRateLimitSignal`
// decide whether an upstream response is the upstream's fault, and the
// Retry-After ceiling protects against an absurd value. Those three details were
// paid for once on the account axis (429 three-way classification, ceiling
// protection); re-deriving them here would be paying twice for the same lesson.
//
// # 🔴 Deliberately NOT persisted (rev4 overturned rev3)
//
// Purely in memory; a restart clears it. A cooldown records a JUDGEMENT THAT
// EXPIRES. A restart usually means time has passed, so reading an old judgement
// back can route around an upstream that has already recovered — a stale cooldown
// is more dangerous than none.
//
// 🔴 Why this differs from the account axis, written down so nobody "fixes" the
// omission later: account cooldowns usually come from a quota WINDOW (five hours,
// a weekly cap) whose validity far outlives a restart. Upstream outages are much
// shorter-lived. Same mechanism, different half-life, different answer.
//
// # 🔴 Cooling is a preference, not a ban (I14)
//
// `orderCandidates` moves cooled hops to the BACK of the try list, it does not
// remove them. When every candidate is cooling, the request still walks the whole
// chain in the administrator's order. A cooled upstream that has quietly
// recovered is then found by the next real request, at the cost of one attempt —
// whereas refusing to serve would be an outage we invented ourselves.

import (
	"net/http"
	"sync"
	"time"

	"github.com/AiKeyLabs/pkg/fallbackpolicy"
)

// bindingCooldownStore tracks, per binding id, the absolute time after which the
// upstream may be preferred again.
//
// 🚫 No file, no control-plane report, no persistence hook. See the file doc; a
// future "wouldn't it be nice to keep this across restarts" is the change this
// comment exists to stop.
type bindingCooldownStore struct {
	mu    sync.RWMutex
	until map[string]time.Time
}

func newBindingCooldownStore() *bindingCooldownStore {
	return &bindingCooldownStore{until: make(map[string]time.Time)}
}

// note records a failed attempt and returns the cooldown expiry, if any.
//
// The `eligible` gate is `failoverEligibleResponse` — the SAME predicate that
// decides whether to switch at all. Keeping them identical is what makes 2.14
// true by construction: an evidence-less 429 (a content-policy or WAF rejection
// caused by THIS request) neither switches nor cools, because punishing a healthy
// upstream for one user's prompt would push the whole organization onto the
// fallback for minutes.
func (s *bindingCooldownStore) note(bindingID string, status int, header http.Header, cfg fallbackpolicy.Resolved, now time.Time) (time.Time, bool) {
	if bindingID == "" {
		return time.Time{}, false
	}
	if !failoverEligibleResponse(status, header) {
		return time.Time{}, false
	}
	// 🔴 An explicit 0 means "never cool down" and is a legal administrator
	// choice (contract §11). It must NOT be read as "unconfigured" — the whole
	// three-state rule exists for this line.
	if cfg.Value == 0 {
		return time.Time{}, false
	}
	maxCool := time.Duration(cfg.Value) * time.Millisecond

	// Reuse the account axis's evidence-based duration when the upstream supplied
	// one (Retry-After, a reset epoch). It is better information than our default
	// — but it is bounded by the administrator's configured maximum, which is the
	// ceiling protection the account axis already found it needed.
	d := maxCool
	// Binding failover has its own administrator-configured ceiling and is not an
	// OAuth account-pool policy. Preserve its historical 30-second fallback while
	// still reusing provider Retry-After and concrete reset evidence.
	if until, ok := cooldownDecisionWithTemporaryFallback(
		&http.Response{StatusCode: status, Header: header}, now, 30*time.Second,
	); ok {
		if evidence := until.Sub(now); evidence > 0 && evidence < maxCool {
			d = evidence
		}
	}
	deadline := now.Add(d)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.until[bindingID] = deadline
	return deadline, true
}

// noteSuccess clears the cooldown.
//
// 🚫 No "N consecutive successes" hysteresis. It would slow recovery and add a
// second number to tune, and the cost of being wrong is one extra attempt.
func (s *bindingCooldownStore) noteSuccess(bindingID string) {
	if bindingID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.until, bindingID)
}

// cooling reports whether this binding is currently cooled.
//
// It deliberately does NOT return the deadline: no caller ever used it, and
// `snapshot` already exposes remaining seconds for the surfaces that display
// one. An unused second result is a standing invitation to start trusting it.
//
// 🔴 The empty-id guard is load-bearing. A hop whose identity is unknown must
// read as NOT cooling — treating it as cooled would put every such hop in the
// same bucket, which is exactly how cooldown became a silent no-op before
// hopKey existed.
func (s *bindingCooldownStore) cooling(bindingID string, now time.Time) bool {
	if bindingID == "" {
		return false
	}
	s.mu.RLock()
	until, ok := s.until[bindingID]
	s.mu.RUnlock()
	return ok && until.After(now)
}

// snapshot returns the currently-cooling bindings with their remaining seconds,
// for the health endpoint. Expired entries are dropped as they are observed —
// cheap, and it keeps a long-lived process from accumulating dead keys.
func (s *bindingCooldownStore) snapshot(now time.Time) map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int)
	for id, until := range s.until {
		remaining := int(until.Sub(now).Seconds())
		if remaining <= 0 {
			delete(s.until, id)
			continue
		}
		out[id] = remaining
	}
	return out
}
