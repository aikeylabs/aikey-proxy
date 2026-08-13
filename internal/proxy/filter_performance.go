package proxy

import (
	"sort"
	"sync/atomic"
	"time"
)

// filterLatencyWindowSize is a bounded, allocation-free-on-write rolling
// window. It is large enough for a useful rollout percentile while keeping the
// data strictly process-local and content-free. Reloading a Proxy generation
// intentionally starts a fresh window so samples never mix two detector builds.
const filterLatencyWindowSize = 2048

type filterLatencyLane struct {
	next  atomic.Uint64
	slots [filterLatencyWindowSize]atomic.Int64 // whole filter wall time, microseconds
}

// FilterLatencyLaneSnapshot is one externally readable latency lane. Count is
// the lifetime number of samples in this generation; WindowSamples is the
// bounded population used for the percentiles.
type FilterLatencyLaneSnapshot struct {
	Count            uint64  `json:"count"`
	WindowSamples    int     `json:"window_samples"`
	P50Ms            float64 `json:"p50_ms"`
	P95Ms            float64 `json:"p95_ms"`
	Under15MsPercent float64 `json:"under_15ms_percent"`
}

// FilterPerformanceSnapshot separates the steady-state incremental path (at
// least one unchanged piece reused from cache) from a cold path (no cache hit).
// It reports the whole compliance-filter wall time, not only child IPC time.
type FilterPerformanceSnapshot struct {
	WindowSize       int                       `json:"window_size"`
	SamplesStartedAt string                    `json:"samples_started_at,omitempty"`
	LastObservedAt   string                    `json:"last_observed_at,omitempty"`
	Incremental      FilterLatencyLaneSnapshot `json:"incremental"`
	Cold             FilterLatencyLaneSnapshot `json:"cold"`
}

type filterPerformanceMetrics struct {
	startedAt   atomic.Int64
	lastAt      atomic.Int64
	incremental filterLatencyLane
	cold        filterLatencyLane
}

func (m *filterPerformanceMetrics) observe(elapsed time.Duration, hadCacheHit bool) {
	now := time.Now().UTC().UnixNano()
	m.startedAt.CompareAndSwap(0, now)
	m.lastAt.Store(now)
	if hadCacheHit {
		m.incremental.observe(elapsed)
		return
	}
	m.cold.observe(elapsed)
}

func (l *filterLatencyLane) observe(elapsed time.Duration) {
	micros := elapsed.Microseconds()
	if micros < 1 {
		micros = 1
	}
	position := l.next.Add(1) - 1
	l.slots[position%filterLatencyWindowSize].Store(micros)
}

func (m *filterPerformanceMetrics) snapshot() FilterPerformanceSnapshot {
	snapshot := FilterPerformanceSnapshot{
		WindowSize:  filterLatencyWindowSize,
		Incremental: m.incremental.snapshot(),
		Cold:        m.cold.snapshot(),
	}
	if startedAt := m.startedAt.Load(); startedAt > 0 {
		snapshot.SamplesStartedAt = time.Unix(0, startedAt).UTC().Format(time.RFC3339Nano)
	}
	if lastAt := m.lastAt.Load(); lastAt > 0 {
		snapshot.LastObservedAt = time.Unix(0, lastAt).UTC().Format(time.RFC3339Nano)
	}
	return snapshot
}

func (l *filterLatencyLane) snapshot() FilterLatencyLaneSnapshot {
	total := l.next.Load()
	want := filterLatencyWindowSize
	if total < uint64(filterLatencyWindowSize) {
		want = int(total)
	}
	values := make([]int64, 0, want)
	for i := range l.slots {
		if value := l.slots[i].Load(); value > 0 {
			values = append(values, value)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	if len(values) == 0 {
		return FilterLatencyLaneSnapshot{Count: total}
	}
	under15 := 0
	for _, value := range values {
		if value <= 15_000 {
			under15++
		}
	}
	return FilterLatencyLaneSnapshot{
		Count:            total,
		WindowSamples:    len(values),
		P50Ms:            percentileMicros(values, 0.50) / 1000,
		P95Ms:            percentileMicros(values, 0.95) / 1000,
		Under15MsPercent: float64(under15) * 100 / float64(len(values)),
	}
}

func percentileMicros(sorted []int64, percentile float64) float64 {
	index := int(float64(len(sorted)-1)*percentile + 0.5)
	return float64(sorted[index])
}
