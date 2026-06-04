package quota

import "time"

// Phase 2 enforcement. BOTH metrics use the same baseline + local-increment model:
//   - TOKEN: increment = the proxy's raw token count per request (Add path).
//   - USD (D-U8/P7): increment = the proxy prices each request LOCALLY from the
//     server-delivered edge price summary (PriceSummary.Cost). usd "used" = server
//     baseline + locally-priced increment, read via UsdUsedSource (counterUsdSource
//     = counter.Get(usd)). The server's full price table stays the billing
//     authority (D-U1 refined: the proxy uses only the tiny server-pushed summary,
//     never the full table), and the proxy total is overwritten by the server's
//     exact value on reconnect (P8). Unknown model → no usd increment, the token
//     quota floor backstops it.

// TokenBucket is a deduped applicable token-quota limit for a seat: which
// subject's counter, which window, and the limit. Computed once at check time
// and reused at increment time so both hit the same buckets even if the request
// spans a period boundary (the request is accounted to the window it started in).
type TokenBucket struct {
	SubjectID string
	Period    string // "daily" | "monthly" — for reset-time computation
	PeriodKey string
	Limit     float64
}

// Violation describes the bucket that caused a block (取最严格 — the first
// at-or-over-limit bucket found across the seat's own + group subjects).
type Violation struct {
	Metric    string // MetricTokens | MetricUSD — drives the 429 error code/message
	SubjectID string
	Period    string
	PeriodKey string
	Limit     float64
	Used      float64
	// FailClosedStale is set when the block is NOT an at/over-limit hit but a
	// budget-mode fail-closed: a usd-quota'd seat whose baseline is too stale to
	// trust (server unreachable past max_staleness). Drives the QUOTA_DEGRADED_BLOCK
	// error code/message instead of QUOTA_EXCEEDED_*. Only ever set under budget
	// enforce_mode (D-U7/P9); availability mode never fails closed.
	FailClosedStale bool
}

// UsdUsedSource resolves a subject's current usd usage for enforcement. The proxy
// never computes cost itself (D-U1) — it reads a server-computed number. P3 wires
// counterUsdSource (= the master usd baseline seeded into the counter); P4 will
// wire max(local collector, master baseline).
type UsdUsedSource interface {
	UsdUsed(subjectID, periodKey string) float64
}

// counterUsdSource reads usd usage straight from the counter = baseline (seeded by
// the snapshot) + locally-priced increment accrued by AccrueUsdForSeat (D-U8/P7).
// The default usd source.
type counterUsdSource struct{ counter *Counter }

func (c counterUsdSource) UsdUsed(subjectID, periodKey string) float64 {
	return c.counter.Get(subjectID, MetricUSD, periodKey)
}

// Enforcer is the proxy-side token+usd quota gate. Holds the live snapshot +
// counter + usd source + the feature flag. nil-safe and flag-gated so it is a
// pure no-op (pass through) when quota is disabled or unwired — the request main
// path is never blocked by quota machinery, only by an actual confirmed
// over-limit (design §8 / 不变量 6: "无规则=放行").
type Enforcer struct {
	snapshot  *Snapshot
	counter   *Counter
	usdSource UsdUsedSource
	enabled   bool
	// budgetMode + maxStaleness implement enforce_mode=budget (D-U7/P9, residual
	// after D-U8): a deployment-level "strict" policy that fail-closes a usd-quota'd
	// seat when its baseline can't be freshly verified (server unreachable past
	// maxStaleness). Default (availability) leaves budgetMode=false → never fails
	// closed (offline-first). Set from env via SetBudgetMode.
	budgetMode   bool
	maxStaleness time.Duration
}

// NewEnforcer wires the gate. A nil snapshot/counter or enabled=false yields a
// no-op enforcer. usd defaults to counterUsdSource (baseline + locally-priced
// increment, D-U8/P7); SetUsdSource remains a seam for alternate sources.
func NewEnforcer(snapshot *Snapshot, counter *Counter, enabled bool) *Enforcer {
	var src UsdUsedSource
	if counter != nil {
		src = counterUsdSource{counter}
	}
	return &Enforcer{snapshot: snapshot, counter: counter, usdSource: src, enabled: enabled}
}

// SetUsdSource overrides the usd used-source (seam for alternate / cluster
// sources). No-op on nil so the default (counterUsdSource) stays.
func (e *Enforcer) SetUsdSource(src UsdUsedSource) {
	if e != nil && src != nil {
		e.usdSource = src
	}
}

// SetBudgetMode enables enforce_mode=budget with the given staleness threshold
// (D-U7/P9). When on, Check fail-closes a usd-quota'd seat whose baseline is older
// than maxStaleness. A non-positive maxStaleness or e==nil is a no-op (stays in
// the default availability mode). Deployment-level; per-subject override deferred.
func (e *Enforcer) SetBudgetMode(maxStaleness time.Duration) {
	if e == nil || maxStaleness <= 0 {
		return
	}
	e.budgetMode = true
	e.maxStaleness = maxStaleness
}

func (e *Enforcer) usdUsed(subjectID, periodKey string) float64 {
	if e == nil || e.usdSource == nil {
		return 0
	}
	return e.usdSource.UsdUsed(subjectID, periodKey)
}

// Enabled reports whether enforcement is active (cheap guard for the hot path).
func (e *Enforcer) Enabled() bool { return e != nil && e.enabled }

// bucketsForSeat returns the deduped quota buckets of one metric applicable to a
// seat at time now (the seat's own subject + its groups). Dedup by (subject,
// period_key) keeping the strictest (lowest) limit, so a duplicate/overlapping
// rule can only tighten, never double-count. The struct is named TokenBucket for
// history; it is metric-agnostic (also used for usd).
func (s *Snapshot) bucketsForSeat(seatID string, now time.Time, metric string) []TokenBucket {
	subs := s.SubjectsForSeat(seatID)
	if len(subs) == 0 {
		return nil
	}
	type key struct{ sid, pk string }
	idx := map[key]int{}
	var out []TokenBucket
	for _, sub := range subs {
		for _, rule := range sub.Rules {
			if rule.Metric != metric || rule.LimitAmount <= 0 {
				continue
			}
			pk := PeriodKey(rule.Period, now)
			k := key{sub.SubjectID, pk}
			if i, ok := idx[k]; ok {
				if rule.LimitAmount < out[i].Limit {
					out[i].Limit = rule.LimitAmount
				}
				continue
			}
			idx[k] = len(out)
			out = append(out, TokenBucket{
				SubjectID: sub.SubjectID,
				Period:    rule.Period,
				PeriodKey: pk,
				Limit:     rule.LimitAmount,
			})
		}
	}
	return out
}

// tokenBucketsForSeat / usdBucketsForSeat: per-metric views. tokens feeds both
// Check and the Add accrual path; usd feeds Check only (no proxy usd increment).
func (s *Snapshot) tokenBucketsForSeat(seatID string, now time.Time) []TokenBucket {
	return s.bucketsForSeat(seatID, now, MetricTokens)
}

func (s *Snapshot) usdBucketsForSeat(seatID string, now time.Time) []TokenBucket {
	return s.bucketsForSeat(seatID, now, MetricUSD)
}

// Check evaluates a seat's token + usd quota at time now. Returns the applicable
// TOKEN buckets (to reuse at increment) and a non-nil Violation if any token OR
// usd bucket is at/over its limit (取最严格 — token checked first). Returns
// (nil/[], nil) = allow when quota is disabled / unwired / the seat has no quota.
// Pure in-memory (no I/O) — it adds no failure mode to the request path.
//
// The crossing request itself is allowed (check runs before the response-time
// increment); the limit is a soft ceiling that blocks the NEXT request once
// used >= limit (design §5.3/§5.6: hard_block marks, next request is denied).
func (e *Enforcer) Check(seatID string, now time.Time) ([]TokenBucket, *Violation) {
	if e == nil || !e.enabled || e.snapshot == nil || e.counter == nil || seatID == "" {
		return nil, nil
	}
	// tokens: used = baseline + local increment (the proxy counts tokens itself).
	tokenBuckets := e.snapshot.tokenBucketsForSeat(seatID, now)
	for _, b := range tokenBuckets {
		used := e.counter.Get(b.SubjectID, MetricTokens, b.PeriodKey)
		if used >= b.Limit {
			return tokenBuckets, &Violation{
				Metric: MetricTokens, SubjectID: b.SubjectID, Period: b.Period,
				PeriodKey: b.PeriodKey, Limit: b.Limit, Used: used,
			}
		}
	}
	// usd: used = baseline + locally-priced increment, via the usd source (D-U8/P7).
	// usd buckets are NOT returned here — usd accrual goes through AccrueUsdForSeat
	// (priced from the edge summary), not the token Add path.
	for _, b := range e.snapshot.usdBucketsForSeat(seatID, now) {
		used := e.usdUsed(b.SubjectID, b.PeriodKey)
		if used >= b.Limit {
			return tokenBuckets, &Violation{
				Metric: MetricUSD, SubjectID: b.SubjectID, Period: b.Period,
				PeriodKey: b.PeriodKey, Limit: b.Limit, Used: used,
			}
		}
		// D-U7/P9 budget mode: this seat HAS a usd quota but we can't freshly
		// verify it (baseline stale past maxStaleness — server unreachable), so a
		// strict deployment fail-closes rather than risk silent over-budget.
		// availability mode (budgetMode=false) skips this entirely (offline-first).
		// A missing freshness signal (lastSyncAt zero) is treated as fresh — see
		// Snapshot.budgetStale (rollout-safe, never over-blocks on a missing signal).
		if e.budgetMode && e.snapshot.budgetStale(now, e.maxStaleness) {
			return tokenBuckets, &Violation{
				Metric: MetricUSD, SubjectID: b.SubjectID, Period: b.Period,
				PeriodKey: b.PeriodKey, Limit: b.Limit, Used: used, FailClosedStale: true,
			}
		}
	}
	return tokenBuckets, nil
}

// Add accrues a request's raw token delta onto each applicable bucket, called
// after the upstream response once token usage is known. No-op when disabled,
// when there are no buckets, or for a non-positive delta. delta is the raw token
// sum (input+output+cache_read+cache_creation+reasoning, design §3.4).
func (e *Enforcer) Add(buckets []TokenBucket, delta float64) {
	if e == nil || !e.enabled || e.counter == nil || delta <= 0 {
		return
	}
	for _, b := range buckets {
		e.counter.Add(b.SubjectID, MetricTokens, b.PeriodKey, delta)
	}
}

// SeedBaselines applies each subject's control-reported baselines to the counter
// at the current period's bucket (回填 — design §5.4). Called after a snapshot
// reload so a restart/another machine continues from the reported used rather
// than zero. Seeds BOTH metrics (P3): the tokens baseline tops up the
// local-increment counter; the usd baseline IS the enforcement value (the proxy
// never accrues usd increments — counterUsdSource reads this). SetBaseline is
// idempotent on an unchanged value, so calling this on every snapshot reload
// (which fires on any vault_change_seq advance) does not wipe local increments.
func SeedBaselines(counter *Counter, subjects []Subject, now time.Time) {
	if counter == nil {
		return
	}
	for i := range subjects {
		for _, b := range subjects[i].Baselines {
			counter.SetBaseline(subjects[i].SubjectID, b.Metric, PeriodKey(b.Period, now), b.Used)
		}
	}
}

// AddForSeat recomputes a seat's token buckets at time now and accrues delta
// onto each. Used at response time so the request pipeline doesn't have to
// thread the check-time buckets through several functions; recomputation is a
// cheap in-memory walk. If the request crossed a period boundary mid-flight it
// is accounted to the window it ended in — a negligible edge already within the
// accepted slight-overshoot tolerance (不变量 9).
func (e *Enforcer) AddForSeat(seatID string, delta float64, now time.Time) {
	if e == nil || !e.enabled || e.snapshot == nil || e.counter == nil || seatID == "" || delta <= 0 {
		return
	}
	e.Add(e.snapshot.tokenBucketsForSeat(seatID, now), delta)
}

// AccrueUsdForSeat prices a completed request LOCALLY via the edge price summary
// (D-U8/P7) and accrues the usd onto the seat's usd buckets, so usd "used" =
// server baseline + locally-priced increment (real-time, offline-capable). The
// correct token-type split lives in PriceSummary.Cost.
//
// Returns (usd, priced, hadSummary):
//   - hadSummary=false: no summary loaded yet (rollout / Personal empty snapshot)
//     → silent no-op; usd enforcement rides the baseline alone until one arrives.
//   - hadSummary=true, priced=false: the model isn't in the summary → no usd
//     accrued; the caller WARNs (a genuinely unpriced model — the token quota
//     floor backstops it and the server baseline catches up on re-sync).
//   - priced=true: usd accrued to every applicable usd bucket.
//
// No-op (0,false,false) when disabled / unwired / no seat. Token-type ints come
// straight from provider.TokenBreakdown (InputTokens is the TOTAL input).
func (e *Enforcer) AccrueUsdForSeat(seatID, model string, inputTotal, output, cacheRead, cacheCreation, reasoning int, now time.Time) (float64, bool, bool) {
	if e == nil || !e.enabled || e.snapshot == nil || e.counter == nil || seatID == "" {
		return 0, false, false
	}
	ps := e.snapshot.PriceSummary()
	if ps == nil {
		return 0, false, false
	}
	usd, priced := ps.Cost(model, inputTotal, output, cacheRead, cacheCreation, reasoning)
	if !priced || usd <= 0 {
		// priced-but-zero (free model / zero tokens) is a no-op, not a WARN.
		return usd, priced, true
	}
	for _, b := range e.snapshot.usdBucketsForSeat(seatID, now) {
		e.counter.Add(b.SubjectID, MetricUSD, b.PeriodKey, usd)
	}
	return usd, true, true
}
