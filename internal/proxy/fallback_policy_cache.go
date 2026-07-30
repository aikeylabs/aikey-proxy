package proxy

// fallback_policy_cache.go — the proxy's in-memory view of the five
// upstream-fallback thresholds (openspec change `aliyun-aigw-p0-upstream-fallback`,
// tasks 1b.3 / 1b.6 / 1b.7 / 1b.8 / 1b.9).
//
// The policy rail writes here; the request path reads. Three rules shape it:
//
//	1b.6  ONE SNAPSHOT PER REQUEST, shared by every hop of the chain.
//	1b.7  Every value reports {value, source}.
//	1b.8  Judgement STATE (activity, cooldown) never leaves this machine.
//
// # 🔴 1b.6 — why a snapshot instead of reading the cache per hop
//
// Reading per hop lets the policy change mid-chain and produce "hops 1-2 used the
// old timeout, hop 3 used the new one". That is not a rounding error, it is an
// unreproducible one: the timing depends on when a 10-second poll happened to
// land relative to a request, so the same inputs give different behavior and no
// log explains why. Snapshot::Effective is therefore taken once, at the top of a
// request, and passed down.
//
// # 🔴 1b.8 — what may leave this machine, and what may not
//
//	✅ allowed to leave: DERIVED NUMBERS. "this request came N seconds after the
//	   previous one" on a usage event; aggregate P50/P90 in the console. That is
//	   the only source of data for calibrating the thresholds (F-9b), so refusing
//	   it would leave the defaults permanently guessed.
//	🚫 not allowed to leave: LIVE STATE. `last_request_at` per key, the cooldown
//	   table, "who was active at 14:03". None of it is reported, and the control
//	   plane takes no part in the decision.
//
// One sentence: derived numbers may travel; living state may not. This file holds
// only the CONFIGURATION half — the activity and cooldown tables live beside the
// candidate loop (P2) and are likewise process-local.

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/pkg/fallbackpolicy"
)

// FallbackPolicyCache holds the last policy successfully pulled from the control
// plane, plus the local-yaml layer, and resolves the two into effective values.
//
// 🔴 Keep-last-known is deliberate (1b.4): losing contact with the control plane
// must not change the data path. A rail failure leaves this cache exactly as it
// was, and the health endpoint says so — the alternative (reverting to defaults
// on a failed poll) would silently re-time every request in the fleet the moment
// a network blip happened.
type FallbackPolicyCache struct {
	mu sync.RWMutex
	// policy is the org-configured layer. nil means "never successfully pulled",
	// which is NOT the same as "pulled and empty": the former resolves to builtin
	// defaults and reports itself as never-synced, the latter is a real answer.
	policy *fallbackpolicy.Policy
	local  fallbackpolicy.LocalOverrides
	// version is the control plane's counter, used for the conditional request.
	version int64
	// synced marks that at least one pull has succeeded, so /status can say
	// "using builtin defaults because we have never reached the control plane"
	// rather than showing defaults with no explanation.
	synced        bool
	lastSuccessAt int64
}

// NewFallbackPolicyCache builds a cache seeded with the local-yaml layer.
//
// 🔴 Only the per-attempt timeout has a local layer, and that is a decision
// rather than an omission: it already existed as `providers.<name>.timeout`.
// Adding local knobs for the other four would recreate the four-source base_url
// drift this project has already paid for, and B8 records the reason it was
// declined — machines in one group would disagree, producing contradictory
// symptoms nobody thinks to blame on configuration.
func NewFallbackPolicyCache(localAttemptTimeoutMs *int64) *FallbackPolicyCache {
	return &FallbackPolicyCache{
		local: fallbackpolicy.LocalOverrides{UpstreamAttemptTimeoutMs: localAttemptTimeoutMs},
	}
}

// Store records a successfully pulled policy. Called only by the rail.
func (c *FallbackPolicyCache) Store(p *fallbackpolicy.Policy, version int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policy = p
	c.version = version
	c.synced = true
	c.lastSuccessAt = time.Now().Unix()
}

// TouchSuccess records a successful revalidation that changed nothing (a 304).
//
// It matters that this is distinct from Store: a 304 proves the control plane is
// reachable, so `last_success_at` must advance even though no value moved.
// Without it, a fleet whose policy is simply stable would look increasingly
// stale, and an operator would go hunting for a sync failure that is not
// happening.
func (c *FallbackPolicyCache) TouchSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.synced = true
	c.lastSuccessAt = time.Now().Unix()
}

// Version returns the last known version, for the conditional request.
func (c *FallbackPolicyCache) Version() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version
}

// Synced reports whether the control plane has ever been reached.
func (c *FallbackPolicyCache) Synced() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.synced
}

// LastSuccessAt is the unix time of the last successful pull or revalidation.
func (c *FallbackPolicyCache) LastSuccessAt() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastSuccessAt
}

// Snapshot resolves the effective thresholds ONCE (task 1b.6).
//
// 🚫 Callers must not re-Snapshot per hop. Take it at the top of a request and
// thread it through, so every hop of one chain is governed by the same numbers.
func (c *FallbackPolicyCache) Snapshot() fallbackpolicy.Effective {
	c.mu.RLock()
	policy := c.policy
	local := c.local
	c.mu.RUnlock()
	// 🔴 A nil policy FALLS THROUGH to local-yaml then builtin — it never becomes
	// a zero. That is I22, and it is why this function delegates to
	// fallbackpolicy.Resolve instead of unpacking the pointers here: one
	// implementation of the precedence, shared with the control plane.
	return fallbackpolicy.Resolve(policy, local)
}

// PolicyRailHealth is the /status block for the rail (task 1b.9).
type PolicyRailHealth struct {
	Thresholds fallbackpolicy.Effective `json:"thresholds"`
	// Synced is false when the control plane has never been reached. Reporting
	// this alongside the values is what stops "we are using defaults" from being
	// indistinguishable from "the admin configured these numbers to equal the
	// defaults" (task 1b.7's whole point, applied to the health surface).
	Synced        bool  `json:"synced"`
	LastSuccessAt int64 `json:"last_success_at,omitempty"`
	Version       int64 `json:"version"`
	// CoolingBindings maps a cooling binding id to its remaining seconds (task
	// 3.4 / 4.5b).
	//
	// 🔴 Visible is not optional. Without it, an administrator who sees the bill
	// suddenly land on the fallback vendor has no way to tell "the primary is
	// cooling" from "somebody changed the configuration", and will go looking in
	// the wrong place. 🚫 There is deliberately no way to CLEAR a cooldown from
	// outside: cooldowns last minutes, and an entry point would need permissions,
	// auditing and concurrency handling for almost no benefit.
	CoolingBindings map[string]int `json:"cooling_bindings,omitempty"`
	// SessionGapSamples / SessionGapMeanMs are DERIVED aggregates over the
	// inter-arrival gaps used for switch-back (task 2.24).
	//
	// 🔴 An aggregate may travel; the timestamps behind it may not (I23). "Requests
	// on this host arrive about four minutes apart" is calibration data; "this
	// person was working at 14:03" is surveillance, and the second must not be
	// reconstructible from what we publish.
	SessionGapSamples int64 `json:"session_gap_samples,omitempty"`
	SessionGapMeanMs  int64 `json:"session_gap_mean_ms,omitempty"`
}

// Health renders the cache for the health endpoint.
func (c *FallbackPolicyCache) Health() PolicyRailHealth {
	samples, meanMs := SessionGapStats()
	return PolicyRailHealth{
		Thresholds:        c.Snapshot(),
		Synced:            c.Synced(),
		LastSuccessAt:     c.LastSuccessAt(),
		Version:           c.Version(),
		SessionGapSamples: samples,
		SessionGapMeanMs:  meanMs,
	}
}

// HealthWithCooling is Health plus the live cooldown view, which lives on the
// Proxy rather than on this cache (configuration and judgement state are
// deliberately separate — see the file doc).
func (c *FallbackPolicyCache) HealthWithCooling(cooling map[string]int) PolicyRailHealth {
	h := c.Health()
	if len(cooling) > 0 {
		h.CoolingBindings = cooling
	}
	return h
}

// sessionGapObserved counts how many inter-arrival gaps have been derived, and
// sessionGapTotalMs sums them. Two counters, not a timeline.
//
// 🔴 Task 2.24 / 1b.8. The gap is a DERIVED number and may travel; the
// `last_request_at` it was computed from is LIVE STATE and may not. The
// difference is not pedantry — an aggregate says "requests on this host arrive
// about four minutes apart", while the timestamps would say "this person was
// working at 14:03", and only one of those is something a developer's employer
// should be able to read off a dashboard.
//
// 🚫 Deliberately a SUM and a COUNT rather than a list. A list is a timeline
// wearing a different hat: with enough entries the individual arrival times are
// recoverable, so the shape itself has to refuse.
var (
	sessionGapObserved atomic.Int64
	sessionGapTotalMs  atomic.Int64
)

// ObserveSessionGap records one derived inter-arrival gap.
//
// This is the ONLY calibration data that will ever exist for F-9b's five
// defaults, which the code labels as placeholders — refusing to emit it would
// leave them guessed forever. So the line is drawn at derived-versus-live rather
// than at emit-versus-don't.
func ObserveSessionGap(gap time.Duration) {
	sessionGapObserved.Add(1)
	if ms := gap.Milliseconds(); ms > 0 {
		sessionGapTotalMs.Add(ms)
	}
}

// SessionGapObservations is test-only introspection.
func SessionGapObservations() int64 { return sessionGapObserved.Load() }

// SessionGapStats returns (count, mean milliseconds) for the health surface.
// Mean is 0 until at least one gap has been observed.
func SessionGapStats() (int64, int64) {
	n := sessionGapObserved.Load()
	if n == 0 {
		return 0, 0
	}
	return n, sessionGapTotalMs.Load() / n
}
