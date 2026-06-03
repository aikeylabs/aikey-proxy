package quota

import (
	"fmt"
	"time"
)

// Period kinds the proxy understands (design §3.4). The control side stores the
// period string on each Rule; the proxy maps (period, now) → a period_key that
// encodes the window, so crossing a window naturally opens a new counter bucket
// = auto reset with no cron (design invariant 5).
const (
	PeriodDaily   = "daily"
	PeriodMonthly = "monthly"
)

// PeriodKey returns the counter-bucket key for a period at time t, e.g.
// "monthly:2026-06" or "daily:2026-06-03".
//
// Windows are computed in UTC so a seat's quota period is stable regardless of
// the client machine's timezone and aligns with the server-side DWD baseline
// (which is UTC); a future move to per-tenant timezones would change only this
// function. An unknown period falls back to a stable per-period bucket so
// accounting still accumulates deterministically (never panics) — the snapshot
// loader is responsible for surfacing unknown periods.
func PeriodKey(period string, t time.Time) string {
	switch period {
	case PeriodDaily:
		return fmt.Sprintf("daily:%s", t.UTC().Format("2006-01-02"))
	case PeriodMonthly:
		return fmt.Sprintf("monthly:%s", t.UTC().Format("2006-01"))
	default:
		return period + ":all"
	}
}

// PeriodResetAt returns when the current period window ends (UTC) — the moment
// the counter bucket rolls over and quota frees up. Used for the 429 Retry-After
// / reset hint. For an unknown period it returns the zero time (no meaningful
// reset), so callers should treat zero as "unknown".
func PeriodResetAt(period string, t time.Time) time.Time {
	u := t.UTC()
	switch period {
	case PeriodDaily:
		d := time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
		return d.AddDate(0, 0, 1)
	case PeriodMonthly:
		m := time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC)
		return m.AddDate(0, 1, 0)
	default:
		return time.Time{}
	}
}
