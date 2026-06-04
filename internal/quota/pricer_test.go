package quota

import (
	"math"
	"testing"
	"time"
)

// real claude-opus-4-8 rates (USD/token) from the edge summary.
func opusSummary() *PriceSummary {
	return &PriceSummary{Version: "t", Models: map[string]ModelUnitPrices{
		"claude-opus-4-8": {Input: 5e-6, Output: 2.5e-5, CacheCreation: 6.25e-6, CacheRead: 5e-7, Reasoning: 2.5e-5},
	}}
}

func TestPriceSummary_Cost_ExactWithSplit(t *testing.T) {
	ps := opusSummary()
	// inputTotal=100 with cacheRead=60 + cacheCreation=10 → pure input = 30.
	usd, ok := ps.Cost("claude-opus-4-8", 100, 20, 60, 10, 5)
	if !ok {
		t.Fatal("opus must be priced")
	}
	want := 30*5e-6 + 60*5e-7 + 10*6.25e-6 + 20*2.5e-5 + 5*2.5e-5
	if math.Abs(usd-want) > 1e-15 {
		t.Errorf("usd: want %v got %v", want, usd)
	}
}

func TestPriceSummary_Cost_CacheNotChargedAsInput(t *testing.T) {
	ps := opusSummary()
	// 1000 tokens all pure input vs all cache_read — cache_read is 0.1x input, so
	// charging cache at the input rate (the bug this split prevents) would be 10x.
	allInput, _ := ps.Cost("claude-opus-4-8", 1000, 0, 0, 0, 0)
	allCacheRead, _ := ps.Cost("claude-opus-4-8", 1000, 0, 1000, 0, 0)
	if allInput != 1000*5e-6 {
		t.Errorf("all-input: want %v got %v", 1000*5e-6, allInput)
	}
	if allCacheRead != 1000*5e-7 {
		t.Errorf("all-cacheRead: want %v got %v", 1000*5e-7, allCacheRead)
	}
	if math.Abs(allCacheRead*10-allInput) > 1e-15 {
		t.Errorf("cache_read must be 10x cheaper than input: input=%v cacheRead=%v", allInput, allCacheRead)
	}
}

func TestPriceSummary_Cost_UnknownNilAndClamp(t *testing.T) {
	ps := opusSummary()
	if _, ok := ps.Cost("gpt-4o", 100, 10, 0, 0, 0); ok {
		t.Error("unknown model must be unpriced (false)")
	}
	var nilPs *PriceSummary
	if _, ok := nilPs.Cost("claude-opus-4-8", 100, 10, 0, 0, 0); ok {
		t.Error("nil summary must be unpriced (false)")
	}
	// defensive: cache > total input → pure clamps to 0, never negative usd.
	if usd, _ := ps.Cost("claude-opus-4-8", 10, 0, 20, 0, 0); usd < 0 {
		t.Errorf("negative usd from over-cache: %v", usd)
	}
}

func TestAccrueUsdForSeat_AccruesAndBackstops(t *testing.T) {
	snap := NewSnapshot()
	snap.ReplaceAll([]Subject{{SubjectID: "seat-a", SubjectKind: KindSeat,
		Rules: []Rule{{Metric: MetricUSD, Period: PeriodMonthly, LimitAmount: 1.0}}}})
	snap.SetPriceSummary(opusSummary())
	counter := NewCounter()
	e := NewEnforcer(snap, counter, true)
	now := time.Now()
	pk := PeriodKey(PeriodMonthly, now)
	want := 30*5e-6 + 60*5e-7 + 10*6.25e-6 + 20*2.5e-5 + 5*2.5e-5

	// known model → usd accrued onto the usd bucket = priced cost.
	usd, priced, had := e.AccrueUsdForSeat("seat-a", "claude-opus-4-8", 100, 20, 60, 10, 5, now)
	if !had || !priced {
		t.Fatalf("want priced+hadSummary, got priced=%v had=%v", priced, had)
	}
	if math.Abs(usd-want) > 1e-15 {
		t.Errorf("returned usd: want %v got %v", want, usd)
	}
	if got := counter.Get("seat-a", MetricUSD, pk); math.Abs(got-want) > 1e-15 {
		t.Errorf("usd counter: want %v got %v", want, got)
	}

	// unknown model (summary present) → no accrual, priced=false, hadSummary=true.
	_, priced2, had2 := e.AccrueUsdForSeat("seat-a", "gpt-4o", 100, 10, 0, 0, 0, now)
	if !had2 || priced2 {
		t.Errorf("unknown model: want had=true priced=false, got had=%v priced=%v", had2, priced2)
	}
	if got := counter.Get("seat-a", MetricUSD, pk); math.Abs(got-want) > 1e-15 {
		t.Errorf("unknown model must not change usd counter: %v", got)
	}

	// no summary → silent no-op (hadSummary=false → caller stays quiet).
	snap.SetPriceSummary(nil)
	if _, _, had3 := e.AccrueUsdForSeat("seat-a", "claude-opus-4-8", 100, 20, 0, 0, 0, now); had3 {
		t.Error("no summary: hadSummary must be false")
	}
}

// End-to-end of P7: local pricing accrues usd → Check blocks once usd >= limit
// (baseline + locally-priced increment, no server round-trip).
func TestUsdEnforcement_ViaLocalPricing(t *testing.T) {
	snap := NewSnapshot()
	snap.ReplaceAll([]Subject{{SubjectID: "seat-a", SubjectKind: KindSeat,
		Rules: []Rule{{Metric: MetricUSD, Period: PeriodMonthly, LimitAmount: 0.001}}}})
	snap.SetPriceSummary(opusSummary())
	e := NewEnforcer(snap, NewCounter(), true)
	now := time.Now()

	// before any usage → allow.
	if _, v := e.Check("seat-a", now); v != nil {
		t.Fatal("should allow before any usage")
	}
	// one request: 100 output tokens → 100*2.5e-5 = 0.0025 > limit 0.001.
	e.AccrueUsdForSeat("seat-a", "claude-opus-4-8", 0, 100, 0, 0, 0, now)
	_, v := e.Check("seat-a", now)
	if v == nil || v.Metric != MetricUSD {
		t.Fatalf("want usd violation after local pricing, got %v", v)
	}
	if v.Used < 0.0025-1e-9 {
		t.Errorf("usd used: want >=0.0025 got %v", v.Used)
	}
}

// TestEnforcer_BudgetMode_FailClosedOnStale covers D-U7/P9: enforce_mode=budget
// fail-closes a usd-quota'd seat when the freshness signal is stale, while
// availability (default) never does, the signal being unavailable (zero) never
// over-blocks (rollout-safe), and seats without a usd rule are untouched.
func TestEnforcer_BudgetMode_FailClosedOnStale(t *testing.T) {
	mkEnf := func(budget bool) (*Enforcer, *Snapshot) {
		snap := NewSnapshot()
		snap.ReplaceAll([]Subject{{SubjectID: "seat-a", SubjectKind: KindSeat,
			Rules: []Rule{{Metric: MetricUSD, Period: PeriodMonthly, LimitAmount: 1.0}}}})
		e := NewEnforcer(snap, NewCounter(), true) // empty counter → usd 0 < 1.0 (under)
		if budget {
			e.SetBudgetMode(5 * time.Minute)
		}
		return e, snap
	}
	now := time.Now()
	stale := now.Add(-10 * time.Minute)
	fresh := now.Add(-1 * time.Minute)

	// availability (default): stale must NEVER fail-closed (offline-first).
	e, snap := mkEnf(false)
	snap.SetLastSyncAt(stale)
	if _, v := e.Check("seat-a", now); v != nil {
		t.Errorf("availability must not fail-closed on stale, got %+v", v)
	}

	// budget + stale + under-limit usd rule → fail-closed (FailClosedStale).
	e, snap = mkEnf(true)
	snap.SetLastSyncAt(stale)
	_, v := e.Check("seat-a", now)
	if v == nil || v.Metric != MetricUSD || !v.FailClosedStale {
		t.Fatalf("budget+stale: want usd FailClosedStale violation, got %+v", v)
	}

	// budget + fresh → allow.
	snap.SetLastSyncAt(fresh)
	if _, v := e.Check("seat-a", now); v != nil {
		t.Errorf("budget+fresh must allow, got %+v", v)
	}

	// budget + signal unavailable (zero) → allow (rollout-safe, no over-block).
	snap.SetLastSyncAt(time.Time{})
	if _, v := e.Check("seat-a", now); v != nil {
		t.Errorf("budget+no-signal must allow (rollout-safe), got %+v", v)
	}

	// budget + stale but seat has only a TOKEN rule (no usd) → allow.
	snapTok := NewSnapshot()
	snapTok.ReplaceAll([]Subject{{SubjectID: "seat-t", SubjectKind: KindSeat,
		Rules: []Rule{{Metric: MetricTokens, Period: PeriodMonthly, LimitAmount: 1000}}}})
	et := NewEnforcer(snapTok, NewCounter(), true)
	et.SetBudgetMode(5 * time.Minute)
	snapTok.SetLastSyncAt(stale)
	if _, v := et.Check("seat-t", now); v != nil {
		t.Errorf("token-only seat must not budget-fail-closed (no usd rule), got %+v", v)
	}
}
