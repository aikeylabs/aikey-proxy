package proxy

import (
	"testing"
	"time"
)

func TestFilterPerformanceSeparatesIncrementalAndColdLanes(t *testing.T) {
	var metrics filterPerformanceMetrics
	metrics.observe(2*time.Millisecond, true)
	metrics.observe(4*time.Millisecond, true)
	metrics.observe(20*time.Millisecond, true)
	metrics.observe(12*time.Millisecond, false)

	snapshot := metrics.snapshot()
	if snapshot.WindowSize != filterLatencyWindowSize {
		t.Fatalf("window size = %d, want %d", snapshot.WindowSize, filterLatencyWindowSize)
	}
	if snapshot.SamplesStartedAt == "" || snapshot.LastObservedAt == "" {
		t.Fatalf("latency sample freshness timestamps are missing: %+v", snapshot)
	}
	if snapshot.Incremental.Count != 3 || snapshot.Incremental.WindowSamples != 3 {
		t.Fatalf("incremental population drift: %+v", snapshot.Incremental)
	}
	if snapshot.Incremental.P50Ms != 4 || snapshot.Incremental.P95Ms != 20 {
		t.Fatalf("incremental percentiles drift: %+v", snapshot.Incremental)
	}
	if snapshot.Incremental.Under15MsPercent < 66.66 || snapshot.Incremental.Under15MsPercent > 66.67 {
		t.Fatalf("incremental <=15ms ratio drift: %+v", snapshot.Incremental)
	}
	if snapshot.Cold.Count != 1 || snapshot.Cold.P50Ms != 12 || snapshot.Cold.P95Ms != 12 {
		t.Fatalf("cold population drift: %+v", snapshot.Cold)
	}
}

func TestFilterPerformanceWindowIsBounded(t *testing.T) {
	var metrics filterPerformanceMetrics
	for i := 0; i < filterLatencyWindowSize+7; i++ {
		metrics.observe(time.Duration(i+1)*time.Microsecond, false)
	}
	snapshot := metrics.snapshot()
	if snapshot.Cold.Count != filterLatencyWindowSize+7 {
		t.Fatalf("lifetime count = %d, want %d", snapshot.Cold.Count, filterLatencyWindowSize+7)
	}
	if snapshot.Cold.WindowSamples != filterLatencyWindowSize {
		t.Fatalf("rolling samples = %d, want %d", snapshot.Cold.WindowSamples, filterLatencyWindowSize)
	}
}

func BenchmarkFilterPerformanceObserve(b *testing.B) {
	var metrics filterPerformanceMetrics
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		metrics.observe(3*time.Millisecond, i%2 == 0)
	}
}
