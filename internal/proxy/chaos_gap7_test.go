//go:build chaos

// Chaos experiment — 缺口7: SSE streamDrainer accumulates the whole response body
// in `acc bytes.Buffer` (stream_drainer.go) for end-of-stream token extraction.
// Hypothesis H7: peak heap ≈ baseline + concurrent_streams × body_size (linear).
// This drives the real newStreamDrainer code path with in-memory pipes so the
// measured heap delta IS the acc buffer cost. See chaos plan
// workflow/CI/e2e/chaos/2026-06-09-proxy-gap7-gap8-chaos-plan.md.
//
// Run: go test -tags chaos -run TestChaosGap7 -v ./internal/proxy/

package proxy

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
)

func heapInuseBytes() uint64 {
	runtime.GC()
	runtime.GC() // second GC to settle finalizers / freed spans
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

// bodyOfApproxSize builds an Anthropic SSE body close to sizeBytes by scaling the
// content_block_delta chunk count.
func bodyOfApproxSize(sizeBytes int) string {
	const perChunk = len(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"chunk 0 "}}` + "\n\n")
	chunks := sizeBytes / perChunk
	if chunks < 1 {
		chunks = 1
	}
	return anthropicSSE(10, 25, chunks)
}

// holdConcurrentStreams spins up n drainers, feeds each the full body (so acc
// holds it), leaves upstream open so the drainer blocks on the next Read with a
// full buffer, measures the heap delta, then tears everything down. Returns the
// measured per-stream heap cost and the actual body length.
func holdConcurrentStreams(t *testing.T, n, bodySize int) (perStream float64, bodyLen int, deltaMB float64) {
	t.Helper()
	body := bodyOfApproxSize(bodySize)
	bodyLen = len(body)

	base := heapInuseBytes()

	drainers := make([]*streamDrainer, n)
	writers := make([]*io.PipeWriter, n)
	var clientWG sync.WaitGroup

	for i := 0; i < n; i++ {
		pr, pw := io.Pipe()
		writers[i] = pw
		baseEvent := events.UsageEvent{Timestamp: time.Now()}
		// nil collector → probe path, no store needed; the acc accumulation is
		// identical regardless of collector.
		d := newStreamDrainer(pr, &baseEvent, &provider.Anthropic{}, nil,
			context.Background(), context.Background(), nil, nil, nil, nil)
		drainers[i] = d
		// Drain the client side so the drainer's pw.Write never blocks; bytes are
		// discarded after the drainer has already copied them into acc.
		clientWG.Add(1)
		go func() { defer clientWG.Done(); io.Copy(io.Discard, d) }()
	}

	// Feed each upstream the full body. io.Pipe writes block until consumed, so
	// when WriteString returns the drainer has read everything into acc and is
	// now blocked on the next upstream.Read (pipe still open) — acc is full.
	var feedWG sync.WaitGroup
	for i := 0; i < n; i++ {
		feedWG.Add(1)
		go func(pw *io.PipeWriter) { defer feedWG.Done(); io.WriteString(pw, body) }(writers[i])
	}
	feedWG.Wait()
	time.Sleep(150 * time.Millisecond) // let the last acc.Write settle

	peak := heapInuseBytes()
	delta := int64(peak) - int64(base)
	if delta < 0 {
		delta = 0
	}
	perStream = float64(delta) / float64(n)
	deltaMB = float64(delta) / (1024 * 1024)

	// Teardown: close upstreams → drainers hit EOF, extract, exit.
	for i := 0; i < n; i++ {
		writers[i].Close()
		drainers[i].Close()
	}
	clientWG.Wait()
	return perStream, bodyLen, deltaMB
}

func TestChaosGap7_BufferMemory(t *testing.T) {
	const MB = 1024 * 1024

	t.Logf("=== 缺口7 SSE buffer memory — real newStreamDrainer path ===")
	t.Logf("Go=%s NumCPU=%d", runtime.Version(), runtime.NumCPU())

	// --- A2: fixed concurrency, vary body size → per-stream ≈ body size? ---
	t.Logf("\n--- A2: N=50 concurrent, vary body size ---")
	t.Logf("%-12s %-14s %-16s %-10s", "bodySize", "actualBodyLen", "perStreamHeap", "ratio")
	for _, sz := range []int{256 * 1024, 1 * MB, 4 * MB} {
		per, bodyLen, _ := holdConcurrentStreams(t, 50, sz)
		t.Logf("%-12s %-14d %-16s %.2fx",
			humanBytes(sz), bodyLen, humanBytes(int(per)), per/float64(bodyLen))
	}

	// --- A1: fixed body size, vary concurrency → linear in N? ---
	t.Logf("\n--- A1: bodySize=1MB, vary concurrency ---")
	t.Logf("%-8s %-16s %-16s", "N", "totalHeapDelta", "perStreamHeap")
	for _, n := range []int{10, 50, 100, 200} {
		per, _, deltaMB := holdConcurrentStreams(t, n, 1*MB)
		t.Logf("%-8d %-16s %-16s", n, fmt.Sprintf("%.1f MB", deltaMB), humanBytes(int(per)))
	}

	// --- Extrapolation for the decision matrix ---
	t.Logf("\n--- Extrapolation (Cluster) ---")
	perStream1MB, _, _ := holdConcurrentStreams(t, 100, 1*MB)
	for _, sc := range []struct {
		streams int
		avgMB   int
	}{{200, 2}, {500, 2}, {1000, 4}} {
		projMB := float64(sc.streams) * float64(sc.avgMB) * (perStream1MB / float64(MB))
		t.Logf("%d concurrent streams × %dMB avg response → ~%.0f MB heap just for acc buffers",
			sc.streams, sc.avgMB, projMB)
	}
	t.Logf("(perStream coefficient @1MB = %.2fx body size — bytes.Buffer growth-doubling overhead)",
		perStream1MB/float64(MB))
}

func humanBytes(n int) string {
	const (
		KB = 1024
		MB = 1024 * 1024
	)
	switch {
	case n >= MB:
		return fmt.Sprintf("%.2f MB", float64(n)/MB)
	case n >= KB:
		return fmt.Sprintf("%.0f KB", float64(n)/KB)
	default:
		return fmt.Sprintf("%d B", n)
	}
}
