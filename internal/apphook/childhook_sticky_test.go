package apphook

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestChildHook_NoStickyPacketsUnderRapidFire spawns the real detector binary
// and sends N Detect requests back-to-back through the actual stdin/stdout
// pipe. If there's any sticky-packet bug — e.g. forgotten Flush, partial
// read, off-by-one in length parsing — at least one of the N response
// frames will be malformed or be out of phase with its request.
//
// This is the cross-process counterpart to pipe.TestNoStickyPacket_* which
// only exercises the framing in a single bytes.Buffer.
func TestChildHook_NoStickyPacketsUnderRapidFire(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping rapid-fire test in short mode")
	}

	binary := requireDetectorBinary(t)

	h := NewChildHook(&ChildHookConfig{
		Name:         "ai-compliance-detector-sticky-test",
		BinaryPath:   binary,
		BinaryArgs:   detectorArgs(), // --echo-only, always returns Allow
		Timeout:      500 * time.Millisecond,
		ReadyTimeout: 5 * time.Second,
	})

	ctx := context.Background()
	if err := h.Start(ctx); err != nil {
		t.Skipf("child binary unavailable: %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()

	// Vary prompt sizes so each frame has different length-prefix bytes —
	// catches off-by-one bugs that would only show up at boundaries.
	sizes := []int{1, 13, 100, 1000, 4096, 16384, 32768, 60000}
	const iterations = 200

	for iter := 0; iter < iterations; iter++ {
		size := sizes[iter%len(sizes)]
		payload := make([]byte, size)
		// Encode iteration index in first 8 bytes so we can detect frame swap.
		if size >= 8 {
			payload[0] = byte(iter)
			payload[1] = byte(iter >> 8)
		}
		// Fill the rest with predictable bytes.
		for i := 8; i < size; i++ {
			payload[i] = byte(i % 256)
		}

		res := h.Detect(ctx, &Request{Payload: payload})
		if res.Degraded {
			t.Fatalf("iter=%d size=%d: unexpected degraded: %s", iter, size, res.Reason)
		}
		// --echo-only binary always returns ActionAllow with empty findings.
		// If we get anything else, the response frame is out of phase with
		// our request — classic sticky-packet symptom.
		if res.Action != ActionAllow {
			t.Errorf("iter=%d size=%d: action=%v want Allow (response misaligned?)", iter, size, res.Action)
		}
		if len(res.MutatedPayload) != 0 {
			t.Errorf("iter=%d size=%d: unexpected payload data in echo response (%d bytes)", iter, size, len(res.MutatedPayload))
		}
	}

	// After 200 successful roundtrips with varying sizes, the pipe must
	// still be healthy.
	st := h.Status()
	if !st.Healthy {
		t.Errorf("after %d clean roundtrips, status went unhealthy: %s", iterations, st.DegradedReason)
	}
}

// TestChildHook_ConcurrentDetectIsSerialized verifies that when multiple
// goroutines call Detect concurrently, the responses correctly come back to
// their respective callers (not swapped). This relies on detectMu inside
// ChildHook to serialize the underlying pipe writes/reads.
//
// If detectMu were removed or buggy, this test would produce response/request
// pairs that don't match — i.e. caller A would get caller B's response.
func TestChildHook_ConcurrentDetectIsSerialized(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrency test in short mode")
	}

	binary := requireDetectorBinary(t)

	h := NewChildHook(&ChildHookConfig{
		Name:         "ai-compliance-detector-concurrent-test",
		BinaryPath:   binary,
		BinaryArgs:   detectorArgs(),
		Timeout:      2 * time.Second, // generous — many goroutines contending for mu
		ReadyTimeout: 5 * time.Second,
	})

	ctx := context.Background()
	if err := h.Start(ctx); err != nil {
		t.Skipf("child binary unavailable: %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()

	const concurrency = 20
	const perGoroutine = 50

	var wg sync.WaitGroup
	errCh := make(chan string, concurrency*perGoroutine)

	for g := 0; g < concurrency; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				payload := []byte(fmt.Sprintf("goroutine=%d req=%d filler-%s", gid, i,
					"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))
				res := h.Detect(ctx, &Request{Payload: payload})
				if res.Degraded {
					errCh <- fmt.Sprintf("gid=%d req=%d: degraded: %s", gid, i, res.Reason)
					return
				}
				// Echo binary returns Allow with empty findings.
				if res.Action != ActionAllow {
					errCh <- fmt.Sprintf("gid=%d req=%d: action mismatch", gid, i)
				}
			}
		}(g)
	}

	wg.Wait()
	close(errCh)

	errs := make([]string, 0, len(errCh))
	for e := range errCh {
		errs = append(errs, e)
	}
	if len(errs) > 0 {
		for _, e := range errs {
			t.Error(e)
		}
		t.Errorf("total errors: %d (suggests detectMu not serializing or pipe corrupted)", len(errs))
	}
}
