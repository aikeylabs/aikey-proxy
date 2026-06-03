package quota

import (
	"testing"
	"time"
)

func newTestEnforcer(enabled bool, subjects []Subject) *Enforcer {
	snap := NewSnapshot()
	snap.ReplaceAll(subjects)
	return NewEnforcer(snap, NewCounter(), enabled)
}

var fixedNow = time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)

func TestEnforcerDisabledOrNoQuotaAlwaysAllows(t *testing.T) {
	subs := []Subject{{SubjectID: "seat-a", SubjectKind: KindSeat,
		Rules: []Rule{{Metric: MetricTokens, Period: PeriodMonthly, LimitAmount: 100}}}}

	// disabled → no buckets, no violation
	e := newTestEnforcer(false, subs)
	if b, v := e.Check("seat-a", fixedNow); b != nil || v != nil {
		t.Errorf("disabled: want allow/no-buckets, got buckets=%v violation=%v", b, v)
	}
	// enabled but seat has no quota → allow
	e2 := newTestEnforcer(true, subs)
	if _, v := e2.Check("seat-other", fixedNow); v != nil {
		t.Errorf("no-quota seat: want allow, got violation %+v", v)
	}
	// nil enforcer is safe
	var nilE *Enforcer
	if b, v := nilE.Check("seat-a", fixedNow); b != nil || v != nil {
		t.Errorf("nil enforcer must be safe no-op")
	}
}

func TestEnforcerTokenLimitBlocksNextRequest(t *testing.T) {
	e := newTestEnforcer(true, []Subject{{SubjectID: "seat-a", SubjectKind: KindSeat,
		Rules: []Rule{{Metric: MetricTokens, Period: PeriodMonthly, LimitAmount: 100}}}})

	// under limit → allow, returns the bucket
	buckets, v := e.Check("seat-a", fixedNow)
	if v != nil {
		t.Fatalf("fresh: want allow, got %+v", v)
	}
	if len(buckets) != 1 || buckets[0].Limit != 100 || buckets[0].PeriodKey != "monthly:2026-06" {
		t.Fatalf("bucket wrong: %+v", buckets)
	}

	// accrue 60 then 50 (the crossing request is allowed; total 110 >= 100)
	e.Add(buckets, 60)
	if _, v := e.Check("seat-a", fixedNow); v != nil {
		t.Fatalf("at 60/100: want allow, got %+v", v)
	}
	e.Add(buckets, 50)

	// now used 110 >= 100 → next request blocked
	_, v = e.Check("seat-a", fixedNow)
	if v == nil {
		t.Fatal("at 110/100: want block")
	}
	if v.Limit != 100 || v.Used != 110 || v.SubjectID != "seat-a" {
		t.Errorf("violation detail wrong: %+v", v)
	}
}

func TestEnforcerStrictestAcrossSeatAndGroup(t *testing.T) {
	// seat-a: own 1000/month; group eng: 100/month (stricter). Group should bind.
	e := newTestEnforcer(true, []Subject{
		{SubjectID: "seat-a", SubjectKind: KindSeat,
			Rules: []Rule{{Metric: MetricTokens, Period: PeriodMonthly, LimitAmount: 1000}}},
		{SubjectID: "grp-eng", SubjectKind: KindGroup, Members: []string{"seat-a"},
			Rules: []Rule{{Metric: MetricTokens, Period: PeriodMonthly, LimitAmount: 100}}},
	})

	buckets, v := e.Check("seat-a", fixedNow)
	if v != nil {
		t.Fatalf("fresh: want allow")
	}
	if len(buckets) != 2 {
		t.Fatalf("want 2 buckets (seat + group), got %d: %+v", len(buckets), buckets)
	}
	// accrue 150: seat (1000) ok, but group (100) exceeded → strictest blocks
	e.Add(buckets, 150)
	_, v = e.Check("seat-a", fixedNow)
	if v == nil || v.SubjectID != "grp-eng" || v.Limit != 100 {
		t.Errorf("strictest: want group block at 100, got %+v", v)
	}
}

func TestEnforcerCrossPeriodResets(t *testing.T) {
	e := newTestEnforcer(true, []Subject{{SubjectID: "seat-a", SubjectKind: KindSeat,
		Rules: []Rule{{Metric: MetricTokens, Period: PeriodDaily, LimitAmount: 100}}}})

	juneBuckets, _ := e.Check("seat-a", fixedNow) // 2026-06-03
	e.Add(juneBuckets, 200)
	if _, v := e.Check("seat-a", fixedNow); v == nil {
		t.Fatal("same day over limit must block")
	}
	// next day → new period_key bucket → fresh allowance
	nextDay := fixedNow.AddDate(0, 0, 1)
	if _, v := e.Check("seat-a", nextDay); v != nil {
		t.Errorf("new day: want allow (auto-reset), got %+v", v)
	}
}

// P3: usd is enforced against the seeded master baseline (the proxy never
// computes cost — counterUsdSource reads counter[usd]). The crossing is decided
// by the baseline; the proxy adds no usd increment.
func TestEnforcerUsdBlocksFromBaseline(t *testing.T) {
	snap := NewSnapshot()
	snap.ReplaceAll([]Subject{{SubjectID: "seat-a", SubjectKind: KindSeat,
		Rules: []Rule{{Metric: MetricUSD, Period: PeriodMonthly, LimitAmount: 50}}}})
	c := NewCounter()
	e := NewEnforcer(snap, c, true)
	pk := PeriodKey(PeriodMonthly, fixedNow)

	// usd baseline under limit → allow; usd-only subject yields no token buckets.
	c.SetBaseline("seat-a", MetricUSD, pk, 30)
	if buckets, v := e.Check("seat-a", fixedNow); v != nil || len(buckets) != 0 {
		t.Fatalf("usd 30/50: want allow + no token buckets, got buckets=%v v=%+v", buckets, v)
	}

	// usd baseline at limit → block with a usd-metric violation.
	c.SetBaseline("seat-a", MetricUSD, pk, 50)
	_, v := e.Check("seat-a", fixedNow)
	if v == nil || v.Metric != MetricUSD || v.Limit != 50 || v.Used != 50 || v.SubjectID != "seat-a" {
		t.Fatalf("usd 50/50: want usd block, got %+v", v)
	}

	// the proxy must NOT accrue usd locally — token accrual leaves usd untouched.
	e.AddForSeat("seat-a", 999, fixedNow)
	if got := c.Get("seat-a", MetricUSD, pk); got != 50 {
		t.Errorf("usd must stay = baseline (no local accrual), got %v", got)
	}
}

// P3: SetUsdSource lets P4 swap the usd used-source (max(local, master)) without
// touching enforcement. Here a stub source forces a block independent of the
// counter, proving Check routes usd through the source.
func TestEnforcerUsdSourceOverride(t *testing.T) {
	snap := NewSnapshot()
	snap.ReplaceAll([]Subject{{SubjectID: "seat-a", SubjectKind: KindSeat,
		Rules: []Rule{{Metric: MetricUSD, Period: PeriodMonthly, LimitAmount: 50}}}})
	e := NewEnforcer(snap, NewCounter(), true)
	e.SetUsdSource(stubUsdSource(80)) // counter says 0, source says 80 → block

	_, v := e.Check("seat-a", fixedNow)
	if v == nil || v.Metric != MetricUSD || v.Used != 80 {
		t.Fatalf("usd source override: want block at 80, got %+v", v)
	}
}

type stubUsdSource float64

func (s stubUsdSource) UsdUsed(_, _ string) float64 { return float64(s) }
