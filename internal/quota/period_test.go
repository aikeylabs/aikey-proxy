package quota

import (
	"testing"
	"time"
)

func TestPeriodKey(t *testing.T) {
	ts := time.Date(2026, 6, 3, 14, 30, 0, 0, time.UTC)
	if got := PeriodKey(PeriodMonthly, ts); got != "monthly:2026-06" {
		t.Errorf("monthly: got %q", got)
	}
	if got := PeriodKey(PeriodDaily, ts); got != "daily:2026-06-03" {
		t.Errorf("daily: got %q", got)
	}
	// Weekly buckets by ISO week (Mon-Sun); 2026-06-03 is a Wednesday in W23.
	if got := PeriodKey(PeriodWeekly, ts); got != "weekly:2026-W23" {
		t.Errorf("weekly: got %q", got)
	}
	// Weekly window resets next Monday 00:00 UTC (2026-06-08 for W23).
	if got := PeriodResetAt(PeriodWeekly, ts); !got.Equal(time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("weekly reset: got %v", got)
	}
	// Unknown period → stable fallback bucket; must never panic.
	if got := PeriodKey("yearly", ts); got != "yearly:all" {
		t.Errorf("unknown: got %q", got)
	}
	// Windows are UTC: a non-UTC clock time that falls in the previous UTC day
	// must bucket by the UTC day, not the local day.
	loc := time.FixedZone("UTC+8", 8*3600)
	tsLocal := time.Date(2026, 6, 3, 1, 0, 0, 0, loc) // == 2026-06-02 17:00 UTC
	if got := PeriodKey(PeriodDaily, tsLocal); got != "daily:2026-06-02" {
		t.Errorf("tz-independent daily: got %q", got)
	}
}
