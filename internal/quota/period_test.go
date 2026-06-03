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
	// Unknown period → stable fallback bucket; must never panic.
	if got := PeriodKey("weekly", ts); got != "weekly:all" {
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
