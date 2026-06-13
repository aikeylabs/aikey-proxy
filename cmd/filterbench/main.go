// cmd/filterbench — standalone compliance-detector latency/throughput harness.
//
// Spawns a real FilterPool (M detector child processes) exactly as the proxy
// supervisor does, then drives the full-stack Detect path (proxy → IPC → engine
// → mask → back) across a text-length × hit-count matrix, at a chosen
// concurrency. Reports p50/p95/p99 latency, masked count, and ≤15ms/≤budget
// rates. Built to run ON the target hardware (e.g. the x86 lobster) so the
// numbers reflect production CPU, not a dev laptop.
//
//	GOOS=linux GOARCH=amd64 go build -o filterbench ./cmd/filterbench
//	./filterbench -detector /path/to/ai-compliance-detector -workers 1 -conc 1 -timeout-ms 200
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

const pipeInputCap = 16 * 1024 // proxy caps each piece at 16KB before Detect

func main() {
	detector := flag.String("detector", "", "path to ai-compliance-detector binary")
	workers := flag.Int("workers", 1, "number of detector child processes (FILTER_WORKERS)")
	conc := flag.Int("conc", 1, "concurrent in-flight Detect calls")
	timeoutMs := flag.Int("timeout-ms", 200, "per-Detect deadline (ms)")
	n := flag.Int("n", 200, "iterations per cell")
	flag.Parse()
	if *detector == "" {
		fmt.Println("need -detector <path>")
		return
	}
	budget := time.Duration(*timeoutMs) * time.Millisecond

	hooks := make([]*apphook.ChildHook, *workers)
	for i := range hooks {
		hooks[i] = apphook.NewChildHook(apphook.ChildHookConfig{
			Name:         "filterbench",
			BinaryPath:   *detector,
			Timeout:      5 * time.Second, // generous: measure TRUE latency, flag >budget separately
			ReadyTimeout: 30 * time.Second,
		})
	}
	pool := apphook.NewFilterPool("filterbench", hooks)
	if err := pool.Start(context.Background()); err != nil {
		fmt.Printf("pool start failed: %v\n", err)
		return
	}
	defer func() { _ = pool.Shutdown(context.Background()) }()

	const idCard = "11010119900307851X"
	filler := []rune("这是一段用于压测的中文客服对话内容上下文信息备注说明数据材料")
	makePrompt := func(chars, hits int) []byte {
		var b strings.Builder
		every := 0
		if hits > 0 {
			every = chars / hits
		}
		placed := 0
		for b.Len() < chars*3 {
			if hits > 0 && placed < hits && every > 0 && b.Len()/3 >= placed*every {
				b.WriteString(" 身份证 " + idCard + " ")
				placed++
			}
			b.WriteString(string(filler))
		}
		for placed < hits {
			b.WriteString(" 身份证 " + idCard + " ")
			placed++
		}
		p := []byte(b.String())
		if len(p) > pipeInputCap {
			p = p[:pipeInputCap]
		}
		return p
	}
	pct := func(xs []time.Duration, p float64) time.Duration {
		if len(xs) == 0 {
			return 0
		}
		sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
		idx := int(p * float64(len(xs)))
		if idx >= len(xs) {
			idx = len(xs) - 1
		}
		return xs[idx]
	}
	cell := func(chars, hits int) {
		prompt := makePrompt(chars, hits)
		ctx := context.Background()
		for i := 0; i < 30; i++ { // warmup
			_ = pool.Detect(ctx, &apphook.Request{Payload: prompt})
		}
		durs := make([]time.Duration, *n)
		var maskedFound int
		sem := make(chan struct{}, *conc)
		var wg sync.WaitGroup
		for i := 0; i < *n; i++ {
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int) {
				defer wg.Done()
				defer func() { <-sem }()
				t0 := time.Now()
				resp := pool.Detect(ctx, &apphook.Request{Payload: prompt})
				durs[idx] = time.Since(t0)
				if idx == 0 && resp != nil {
					in := bytes.Count(prompt, []byte(idCard))
					rem := in
					if resp.Action == apphook.ActionMask {
						rem = bytes.Count(resp.MutatedPayload, []byte(idCard))
					}
					maskedFound = in - rem
				}
			}(i)
		}
		wg.Wait()
		le15, leB := 0, 0
		for _, d := range durs {
			if d <= 15*time.Millisecond {
				le15++
			}
			if d <= budget {
				leB++
			}
		}
		fmt.Printf("%-9d %-6d %-9s %-9s %-9s %-9s %-7s %-7s\n",
			chars, hits, fmt.Sprintf("%d", maskedFound),
			pct(durs, .5).Round(time.Microsecond), pct(durs, .95).Round(time.Microsecond), pct(durs, .99).Round(time.Microsecond),
			fmt.Sprintf("%d%%", le15*100/len(durs)), fmt.Sprintf("%d%%", leB*100/len(durs)))
	}

	fmt.Printf("# workers=%d conc=%d timeout=%dms n=%d\n", *workers, *conc, *timeoutMs, *n)
	fmt.Printf("%-9s %-6s %-9s %-9s %-9s %-9s %-7s %-7s\n", "字符", "命中", "实masked", "p50", "p95", "p99", "≤15ms", fmt.Sprintf("≤%dms", *timeoutMs))
	fmt.Println("--- 长度扫描 (1 命中) ---")
	for _, c := range []int{100, 1000, 4000, 8000, 16000, 100000} {
		cell(c, 1)
	}
	fmt.Println("--- 命中数扫描 (4000 字符) ---")
	for _, h := range []int{0, 1, 5, 20, 50} {
		cell(4000, h)
	}
}
