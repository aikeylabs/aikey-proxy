package quota

import "sync"

// Counter is the proxy-side in-memory usage counter (design §0.5/§5.4). Keyed by
// (subject_id, metric, period_key); a new period_key opens a new bucket =
// auto-reset across windows (design invariant 5).
//
// Each bucket is two parts: a `baseline` (the current-period used reported by
// control, delivered via the snapshot — Stage 4 回填) plus a local `increment`
// (this process's accrual since the baseline was last adopted). Used = baseline
// + increment. The split is what makes a proxy restart not bypass quota (the
// baseline reseeds the bucket) and gives approximate cross-machine coordination
// (each proxy's baseline reflects all machines' *reported* usage).
//
// A mutex-guarded map keeps read-modify-write atomic; the per-request,
// low-cardinality access pattern doesn't need sync.Map.
type Counter struct {
	cells map[string]*cell
	mu    sync.Mutex
}

type cell struct {
	// subjectID/metric/periodKey are kept on the cell (not just encoded in the
	// map key) so IncrementRows can emit them for the write-behind flush without
	// parsing the joined key.
	subjectID string
	metric    string
	periodKey string
	baseline  float64
	increment float64
}

// NewCounter returns an empty counter.
func NewCounter() *Counter {
	return &Counter{cells: map[string]*cell{}}
}

func counterKey(subjectID, metric, periodKey string) string {
	return subjectID + "|" + metric + "|" + periodKey
}

func (c *Counter) at(subjectID, metric, periodKey string) *cell {
	k := counterKey(subjectID, metric, periodKey)
	x := c.cells[k]
	if x == nil {
		x = &cell{subjectID: subjectID, metric: metric, periodKey: periodKey}
		c.cells[k] = x
	}
	return x
}

// Add accumulates delta onto the (subject, metric, period) bucket's local
// increment and returns the new running total (baseline + increment).
func (c *Counter) Add(subjectID, metric, periodKey string, delta float64) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	x := c.at(subjectID, metric, periodKey)
	x.increment += delta
	return x.baseline + x.increment
}

// Get returns the current usage (baseline + local increment), 0 if absent.
func (c *Counter) Get(subjectID, metric, periodKey string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	x := c.cells[counterKey(subjectID, metric, periodKey)]
	if x == nil {
		return 0
	}
	return x.baseline + x.increment
}

// SetBaseline adopts a control-reported baseline for a bucket (Stage 4 回填 +
// D-U8/P8 reconnect reconciliation). Acts only when the baseline VALUE changes
// (the snapshot reload fires on every vault_change_seq advance — any vault write —
// so a no-op on unchanged value avoids needless churn).
//
// On change it reconciles to keep `used` = max(old used, new baseline) — monotonic
// within a period (P8 截止水位 via monotonicity):
//   - Adopt the new server baseline (authoritative for the usage it covers).
//   - KEEP only the local increment the new baseline does NOT yet cover — i.e.
//     usage the proxy already priced locally (P7) but the server hasn't
//     uploaded/materialized yet. Once it does, the baseline catches up, the gap
//     closes, and the increment is absorbed to 0.
//
// Why max (not the old reset-to-0): reset dropped not-yet-reported local usage on
// every sync → a transient UNDER-count (brief over-allow) until the next
// materialization. max removes that without DOUBLE-counting, because the increment
// only ever fills the gap ABOVE the baseline. This needs no explicit server-sent
// watermark: within a period the server baseline is cumulative-monotonic
// (SUM over usage_fact_dwd). Safe for P7 specifically — its local pricing is EXACT
// for known models and ZERO for unknown (never an over-estimate), so the
// "phantom over-estimate lingers" edge of a pure max cannot arise here. A rare
// server-side DOWNWARD correction is not reflected downward (conservative —
// favors not exceeding budget); acceptable + rare.
func (c *Counter) SetBaseline(subjectID, metric, periodKey string, baseline float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	x := c.at(subjectID, metric, periodKey)
	if x.baseline == baseline {
		return
	}
	oldUsed := x.baseline + x.increment
	x.baseline = baseline
	if baseline >= oldUsed {
		x.increment = 0
	} else {
		x.increment = oldUsed - baseline
	}
}

// SeedIncrement restores a bucket's local increment from the persisted
// write-behind checkpoint (quota_local_usage), so an OFFLINE proxy restart
// resumes from the persisted usage instead of zero (design P0). It is a SET (not
// add) and MUST run once at startup BEFORE any live accrual — re-running it later
// would clobber in-flight increments. baseline is seeded separately (SeedBaselines)
// and stays untouched here.
func (c *Counter) SeedIncrement(subjectID, metric, periodKey string, increment float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at(subjectID, metric, periodKey).increment = increment
}

// IncrementRows snapshots every bucket carrying a non-zero local increment, for
// the periodic write-behind flush to quota_local_usage. Zero-increment buckets
// are skipped (nothing to persist). Returned under the lock so it is a coherent
// point-in-time view.
func (c *Counter) IncrementRows() []LocalUsageRow {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []LocalUsageRow
	for _, x := range c.cells {
		if x.increment != 0 {
			out = append(out, LocalUsageRow{
				SubjectID: x.subjectID, Metric: x.metric,
				PeriodKey: x.periodKey, Increment: x.increment,
			})
		}
	}
	return out
}
