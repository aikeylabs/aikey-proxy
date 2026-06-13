package apphook

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestComplianceLatencyMatrix profiles the full-stack compliance Detect latency
// (proxy → IPC → detector engine → mask → back) across a matrix of
//
//	text length  ×  number of sensitive hits
//
// so capacity/sizing has real reference data, not a single point. Per the
// product ask (2026-06-13): daily prompts up to ~100K chars; report how latency
// scales with length AND hit count, plus the actually-detected count (the
// detector caps each piece at pipeInputCap=16KB, so hits past 16KB are NOT
// masked and latency plateaus — both surfaced here).
//
// Timeout is set generous (5s) ON PURPOSE: we measure TRUE latency, then flag
// which cells exceed the production 80ms Detect budget (→ would degrade/fail-open
// live) and the 15ms product target. Run:
//
//	go test -run TestComplianceLatencyMatrix -v ./internal/apphook/
func TestComplianceLatencyMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping latency matrix in short mode")
	}
	if raceEnabled {
		t.Skip("latency meaningless under -race")
	}
	binary := findDetectorBinary(t)
	h := NewChildHook(ChildHookConfig{
		Name:         "ai-compliance-detector-matrix",
		BinaryPath:   binary,
		Timeout:      5 * time.Second, // generous: measure true latency, not the 80ms cap
		ReadyTimeout: 10 * time.Second,
	})
	ctx := context.Background()
	if err := h.Start(ctx); err != nil {
		t.Skipf("child binary unavailable: %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()

	// A CN ID number — reliably caught by the built-in cn-pii pack.
	const idCard = "11010119900307851X"
	// Chinese filler (each rune ~3 bytes); length is measured in characters.
	filler := []rune("这是一段用于压测的中文客服对话内容上下文信息备注说明数据材料")

	makePrompt := func(chars, hits int) []byte {
		var b strings.Builder
		// Spread `hits` ID numbers roughly evenly across the text.
		every := 0
		if hits > 0 {
			every = chars / hits
		}
		placed := 0
		for b.Len() < chars*3 { // *3 ≈ utf8 bytes per CJK rune, loose cap
			runeCount := b.Len() / 3
			if hits > 0 && placed < hits && every > 0 && runeCount >= placed*every {
				b.WriteString(" 身份证 ")
				b.WriteString(idCard)
				b.WriteString(" ")
				placed++
			}
			b.WriteString(string(filler))
		}
		// Ensure all requested hits are present even for tiny `chars`.
		for placed < hits {
			b.WriteString(" 身份证 " + idCard + " ")
			placed++
		}
		return []byte(b.String())
	}

	pct := func(xs []time.Duration, p float64) time.Duration {
		if len(xs) == 0 {
			return 0
		}
		sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
		return xs[min(len(xs)-1, int(p*float64(len(xs))))]
	}

	// Production faithfully: the proxy caps each piece at pipeInputCap (16KB)
	// before handing it to the detector (filter_dispatch.go). Replicate that so we
	// measure the REAL path — a 100K-char message is scanned as its first 16KB.
	const pipeInputCap = 16 * 1024
	capPayload := func(p []byte) []byte {
		if len(p) > pipeInputCap {
			return p[:pipeInputCap]
		}
		return p
	}

	run := func(chars, hits, n int) (p50, p95, p99 time.Duration, maskedFound int, le15, le80 int) {
		prompt := capPayload(makePrompt(chars, hits))
		// warmup
		for i := 0; i < 20; i++ {
			_ = h.Detect(ctx, &Request{Payload: prompt})
		}
		durs := make([]time.Duration, 0, n)
		for i := 0; i < n; i++ {
			t0 := time.Now()
			resp := h.Detect(ctx, &Request{Payload: prompt})
			d := time.Since(t0)
			durs = append(durs, d)
			if d <= 15*time.Millisecond {
				le15++
			}
			if d <= 80*time.Millisecond {
				le80++
			}
			if i == 0 && resp != nil {
				// Masked = (IDs present in the SCANNED input, after the 16KB cap)
				// minus (IDs still present in the output). Correct even when the
				// cap truncated away some of the embedded IDs — surfaces the 16KB
				// coverage limit (a 100K prompt only masks hits in its first 16KB).
				inScanned := bytes.Count(prompt, []byte(idCard))
				remaining := 0
				if resp.Action == ActionMask {
					remaining = bytes.Count(resp.MutatedPayload, []byte(idCard))
				} else {
					remaining = inScanned // not masked at all
				}
				maskedFound = inScanned - remaining
			}
		}
		return pct(durs, .50), pct(durs, .95), pct(durs, .99), maskedFound, le15, le80
	}

	const N = 200
	hdr := "%-10s %-6s %-8s %-9s %-9s %-9s %-7s %-7s"
	t.Logf(hdr, "文本(字符)", "命中数", "实际masked", "p50", "p95", "p99", "≤15ms", "≤80ms")

	// (1) 长度扫描（固定 1 命中）— 展示延迟随长度变化 + 16KB 平台效应
	t.Log("--- 长度扫描 (固定 1 命中) ---")
	for _, c := range []int{100, 1000, 4000, 8000, 16000, 32000, 64000, 100000} {
		p50, p95, p99, mf, le15, le80 := run(c, 1, N)
		t.Logf(hdr, fmt.Sprintf("%d", c), "1", fmt.Sprintf("%d/1", mf),
			p50.Round(time.Microsecond), p95.Round(time.Microsecond), p99.Round(time.Microsecond),
			fmt.Sprintf("%d%%", le15*100/N), fmt.Sprintf("%d%%", le80*100/N))
	}
	// (2) 命中数扫描（固定 4000 字符）— 展示延迟随命中个数变化
	t.Log("--- 命中数扫描 (固定 4000 字符) ---")
	for _, hits := range []int{0, 1, 5, 20, 50} {
		p50, p95, p99, mf, le15, le80 := run(4000, hits, N)
		t.Logf(hdr, "4000", fmt.Sprintf("%d", hits), fmt.Sprintf("%d/%d", mf, hits),
			p50.Round(time.Microsecond), p95.Round(time.Microsecond), p99.Round(time.Microsecond),
			fmt.Sprintf("%d%%", le15*100/N), fmt.Sprintf("%d%%", le80*100/N))
	}
	// (3) 日常重载组合：10万字符 + 多命中
	t.Log("--- 重载组合 ---")
	for _, cell := range [][2]int{{100000, 1}, {100000, 20}, {16000, 50}} {
		p50, p95, p99, mf, le15, le80 := run(cell[0], cell[1], N)
		t.Logf(hdr, fmt.Sprintf("%d", cell[0]), fmt.Sprintf("%d", cell[1]), fmt.Sprintf("%d/%d", mf, cell[1]),
			p50.Round(time.Microsecond), p95.Round(time.Microsecond), p99.Round(time.Microsecond),
			fmt.Sprintf("%d%%", le15*100/N), fmt.Sprintf("%d%%", le80*100/N))
	}
}
