package quota

import "testing"

func TestCounterAddGetAndCrossPeriodReset(t *testing.T) {
	c := NewCounter()

	// Accumulate within a bucket.
	if got := c.Add("seat-a", "usd", "monthly:2026-06", 10); got != 10 {
		t.Fatalf("add1: want 10 got %v", got)
	}
	if got := c.Add("seat-a", "usd", "monthly:2026-06", 5.5); got != 15.5 {
		t.Fatalf("add2: want 15.5 got %v", got)
	}
	if got := c.Get("seat-a", "usd", "monthly:2026-06"); got != 15.5 {
		t.Fatalf("get: want 15.5 got %v", got)
	}

	// A different metric is an independent bucket.
	if got := c.Get("seat-a", "tokens", "monthly:2026-06"); got != 0 {
		t.Errorf("metric isolation: want 0 got %v", got)
	}

	// A new period_key opens a fresh bucket (auto-reset across windows).
	if got := c.Get("seat-a", "usd", "monthly:2026-07"); got != 0 {
		t.Errorf("cross-period reset: want 0 got %v", got)
	}
	if got := c.Add("seat-a", "usd", "monthly:2026-07", 3); got != 3 {
		t.Errorf("new period bucket: want 3 got %v", got)
	}
	// The old period bucket is untouched.
	if got := c.Get("seat-a", "usd", "monthly:2026-06"); got != 15.5 {
		t.Errorf("old period mutated: want 15.5 got %v", got)
	}
}

func TestCounterBaselinePlusIncrement(t *testing.T) {
	c := NewCounter()
	pk := "monthly:2026-06"

	// seed baseline → Get reflects it
	c.SetBaseline("seat-a", "tokens", pk, 100)
	if got := c.Get("seat-a", "tokens", pk); got != 100 {
		t.Fatalf("after baseline: want 100 got %v", got)
	}
	// local increment stacks on top
	c.Add("seat-a", "tokens", pk, 50)
	if got := c.Get("seat-a", "tokens", pk); got != 150 {
		t.Fatalf("baseline+increment: want 150 got %v", got)
	}
	// re-seeding the SAME baseline must preserve the local increment (idempotent
	// — guards the every-vault-seq-advance reload from wiping increments)
	c.SetBaseline("seat-a", "tokens", pk, 100)
	if got := c.Get("seat-a", "tokens", pk); got != 150 {
		t.Errorf("same baseline must preserve increment: want 150 got %v", got)
	}
	// a CHANGED baseline resets the local increment (new baseline subsumes
	// reported usage; unreported local increment dropped)
	c.SetBaseline("seat-a", "tokens", pk, 200)
	if got := c.Get("seat-a", "tokens", pk); got != 200 {
		t.Errorf("changed baseline resets increment: want 200 got %v", got)
	}
}

// P3: SeedBaselines seeds BOTH metrics. tokens baseline tops up the local
// increment; usd baseline IS the enforcement value (counterUsdSource reads it,
// the proxy never accrues usd increments).
func TestSeedBaselinesBothMetrics(t *testing.T) {
	subjects := []Subject{
		{SubjectID: "seat-a", SubjectKind: KindSeat, Baselines: []Baseline{
			{Metric: MetricTokens, Period: PeriodMonthly, Used: 42},
			{Metric: MetricUSD, Period: PeriodMonthly, Used: 9.99},
		}},
		{SubjectID: "seat-b", SubjectKind: KindSeat}, // no baselines
	}
	c := NewCounter()
	SeedBaselines(c, subjects, fixedNow)

	pk := PeriodKey(PeriodMonthly, fixedNow)
	if got := c.Get("seat-a", MetricTokens, pk); got != 42 {
		t.Errorf("token baseline: want 42 got %v", got)
	}
	if got := c.Get("seat-a", MetricUSD, pk); got != 9.99 {
		t.Errorf("usd baseline must be seeded (P3): want 9.99 got %v", got)
	}
	if got := c.Get("seat-b", MetricTokens, pk); got != 0 {
		t.Errorf("no-baseline seat: want 0 got %v", got)
	}
}
