package apphook

import (
	"context"
	"os"
	"sort"
	"testing"
	"time"
)

// TestChildHookFullStackLatency measures the END-TO-END latency that the
// proxy main loop experiences when it calls Hook.Detect through a real
// spawned child:
//
//	proxy code → ChildHook.Detect
//	          → write pipe (IPC out)
//	          → child reads + runs engine + writes response (IPC in)
//	          → ChildHook reads response
//	          ← return Response
//
// This is the number that matters for the 1ms SLO (§6 #3). The spike's
// realistic-bench measures only the in-process engine; this benchmark
// measures the additional IPC + Engine cost going through a real binary.
//
// Acceptance per 实施计划 §4.2 B5: p99 < 1ms for dev_with_creds scenario
// (the hardest spike workload).
//
// Run with: go test -run TestChildHookFullStackLatency -v ./internal/apphook/
func TestChildHookFullStackLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping latency bench in short mode")
	}
	if raceEnabled {
		t.Skip("latency SLO is meaningless under -race (instrumentation inflates ~10×)")
	}

	binary := requireDetectorBinary(t)

	h := NewChildHook(&ChildHookConfig{
		Name:         "ai-compliance-detector-bench",
		BinaryPath:   binary,
		BinaryArgs:   nil, // use embedded baseline pack (production path)
		Timeout:      100 * time.Millisecond,
		ReadyTimeout: 10 * time.Second,
	})

	ctx := context.Background()
	if err := h.Start(ctx); err != nil {
		t.Skipf("child binary unavailable: %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()

	scenarios := []struct {
		name   string
		prompt string
		// expectMaskedIfNERLoaded — if true, this prompt should produce
		// ActionMask. Caller asserts after the bench. This is the P0-4
		// protection: if NER is silently disabled, these would return Allow
		// and we'd never notice in a pure-latency-only test.
		expectMaskedIfNERLoaded bool
	}{
		{"clean", "How do I implement a binary tree in Go?", false},
		{"customer_service", "客户王小明想知道理赔流程", false},                                      // 王小明 alone may or may not match
		{"dev_with_creds_rule", "sk-ant-api03-VeryLongStringHereXXXXXXXXXXXXXXXX", true}, // rule path
		{"dev_with_creds_ner", "客户管理员密码 P@ssw0rd2024! 请确认", true},                        // NER token-CRF path
	}

	// Warmup
	for i := 0; i < 50; i++ {
		_ = h.Detect(ctx, &Request{Payload: []byte("warmup")})
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			const N = 1000
			durs := make([]time.Duration, N)
			payload := []byte(sc.prompt)
			var sampleAction Action

			for i := 0; i < N; i++ {
				t0 := time.Now()
				res := h.Detect(ctx, &Request{Payload: payload})
				durs[i] = time.Since(t0)
				if res.Degraded {
					t.Fatalf("iteration %d: unexpected degraded: %s", i, res.Reason)
				}
				sampleAction = res.Action
			}

			// Coverage check (P0-4): if this prompt is supposed to trigger
			// detection (rule or NER), an ActionAllow result means a layer
			// is silently disabled. Fail loudly per CLAUDE.md "失败要显眼".
			if sc.expectMaskedIfNERLoaded && sampleAction == ActionAllow {
				t.Errorf("prompt %q returned Allow but should mask — engine layer may be silently disabled (check ready sentinel)", sc.prompt)
			}

			sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })

			p50 := durs[N/2]
			p95 := durs[N*95/100]
			p99 := durs[N*99/100]
			p999 := durs[N*999/1000]

			t.Logf("scenario=%-20s p50=%-10s p95=%-10s p99=%-10s p999=%-10s",
				sc.name,
				p50.Round(time.Microsecond),
				p95.Round(time.Microsecond),
				p99.Round(time.Microsecond),
				p999.Round(time.Microsecond),
			)

			// SLO check: p99 < 1ms (§6 invariant #3). This number is environment-
			// sensitive — it includes the pipe IPC roundtrip (~50-100µs) + engine
			// detection + OS scheduling, so on a loaded dev machine or a shared CI
			// runner p99 can drift over 1ms and flake the DEFAULT `go test`. The
			// hard assertion is therefore GATED behind AIKEY_PERF_SLO=1 and only
			// enforced in a controlled perf lane; the default run logs the
			// percentiles above as an informational signal without failing
			// (2026-06-22 review: stop the env-sensitive SLO from blocking merges).
			if p99 > 1*time.Millisecond {
				if os.Getenv("AIKEY_PERF_SLO") == "1" {
					t.Errorf("p99 %s exceeds 1ms SLO (§6 invariant #3)", p99)
				} else {
					t.Logf("p99 %s exceeds 1ms SLO (§6 invariant #3) — informational; set AIKEY_PERF_SLO=1 to enforce in a controlled perf lane", p99)
				}
			}
		})
	}
}
