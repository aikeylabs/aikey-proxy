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

func TestEnforcerUsdRulesIgnoredThisStage(t *testing.T) {
	// usd-only subject → Stage 3 must not produce buckets (tokens only).
	e := newTestEnforcer(true, []Subject{{SubjectID: "seat-a", SubjectKind: KindSeat,
		Rules: []Rule{{Metric: MetricUSD, Period: PeriodMonthly, LimitAmount: 50}}}})
	buckets, v := e.Check("seat-a", fixedNow)
	if len(buckets) != 0 || v != nil {
		t.Errorf("usd rule must be ignored in token enforcement, got buckets=%v v=%v", buckets, v)
	}
}
