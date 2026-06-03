package quota

import "time"

// Phase 2 enforcement. TOKEN quota is enforced from a local count (baseline +
// proxy-accrued increment). USD quota is enforced WITHOUT proxy-side pricing
// (design D-U1): the proxy reads a server-computed usd "used" via UsdUsedSource
// (P3: master baseline; P4: max(local collector, master)) and compares it to the
// limit — it never computes cost itself. The Add accrual path stays token-only.

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
}

// UsdUsedSource resolves a subject's current usd usage for enforcement. The proxy
// never computes cost itself (D-U1) — it reads a server-computed number. P3 wires
// counterUsdSource (= the master usd baseline seeded into the counter); P4 will
// wire max(local collector, master baseline).
type UsdUsedSource interface {
	UsdUsed(subjectID, periodKey string) float64
}

// counterUsdSource reads usd usage straight from the counter — i.e. the master
// usd baseline seeded by the snapshot (the counter never accrues usd increments,
// since the proxy doesn't compute cost). This is the P3 master-only source.
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
}

// NewEnforcer wires the gate. A nil snapshot/counter or enabled=false yields a
// no-op enforcer. usd defaults to the master-baseline source (counterUsdSource);
// P4 overrides it via SetUsdSource.
func NewEnforcer(snapshot *Snapshot, counter *Counter, enabled bool) *Enforcer {
	var src UsdUsedSource
	if counter != nil {
		src = counterUsdSource{counter}
	}
	return &Enforcer{snapshot: snapshot, counter: counter, usdSource: src, enabled: enabled}
}

// SetUsdSource overrides the usd used-source (P4: max(local collector, master
// baseline)). No-op on nil so the P3 default (master baseline) stays.
func (e *Enforcer) SetUsdSource(src UsdUsedSource) {
	if e != nil && src != nil {
		e.usdSource = src
	}
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
	// usd: used comes from the usd source (the proxy never computes cost) — P3
	// master baseline, P4 max(local, master). usd buckets are NOT returned: the
	// Add accrual path is token-only (no usd increment to add).
	for _, b := range e.snapshot.usdBucketsForSeat(seatID, now) {
		used := e.usdUsed(b.SubjectID, b.PeriodKey)
		if used >= b.Limit {
			return tokenBuckets, &Violation{
				Metric: MetricUSD, SubjectID: b.SubjectID, Period: b.Period,
				PeriodKey: b.PeriodKey, Limit: b.Limit, Used: used,
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
