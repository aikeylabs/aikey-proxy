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
	mu    sync.Mutex
	cells map[string]*cell
}

type cell struct {
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

func (c *Counter) at(k string) *cell {
	x := c.cells[k]
	if x == nil {
		x = &cell{}
		c.cells[k] = x
	}
	return x
}

// Add accumulates delta onto the (subject, metric, period) bucket's local
// increment and returns the new running total (baseline + increment).
func (c *Counter) Add(subjectID, metric, periodKey string, delta float64) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	x := c.at(counterKey(subjectID, metric, periodKey))
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

// SetBaseline adopts a control-reported baseline for a bucket (Stage 4 回填).
// It only acts when the baseline VALUE changes: this matters because the snapshot
// reload fires on every vault_change_seq advance (any vault write, not just quota
// edits), and blindly reseeding each time would repeatedly wipe the local
// increment. When the baseline does change, the local increment is reset to 0 —
// the new baseline already includes reported usage; any not-yet-reported local
// increment is dropped (accepted slight under-count, design §5.4 / 不变量 9).
func (c *Counter) SetBaseline(subjectID, metric, periodKey string, baseline float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	x := c.at(counterKey(subjectID, metric, periodKey))
	if x.baseline != baseline {
		x.baseline = baseline
		x.increment = 0
	}
}
