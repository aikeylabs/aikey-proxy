//go:build integration

// filter_integration_test.go — proxy-side integration test wiring applyInboundFilter
// (the cache + user-only history-leak fix) to a REAL ai-compliance-detector child over
// the production ChildHook/FilterPool pipe (no --echo-only → embedded baseline pack).
//
// WHY (vs the stub-based unit tests): the unit tests prove the cache/extract LOGIC in
// isolation with a fake hook. This proves the FULL path end-to-end — a sensitive token
// sitting in HISTORY (the 2026-06-16 lobster bug) is actually masked by the real engine
// through real IPC; the assistant reply is NOT scanned; and an identical re-send is
// served entirely from cache (0 extra detector calls). Reproduces + locks the regression.
//
// Run: make filter-integration  (builds the detector first). Skips if binary missing.
package proxy

import (
	"context"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// integSecret: synthetic Anthropic-style key — deterministic gitleaks-HP match in the
// baseline pack, ASCII (survives json re-marshal verbatim, no \uXXXX escaping to fight).
const integSecret = "sk-ant-api03-INTEGRATIONHISTORYLEAKTESTKEY0000000000000000"

func integDetectorBinary() string {
	_, file, _, _ := runtime.Caller(0)
	proxyDir := filepath.Dir(filepath.Dir(filepath.Dir(file))) // .../aikey-proxy
	return filepath.Join(filepath.Dir(proxyDir), "ai-compliance-detector", "bin", "detector")
}

// startRealDetectorPool spawns the real ai-compliance-detector child (embedded baseline
// pack) behind a FilterPool, skipping the test if the binary isn't built. Cleanup on test end.
func startRealDetectorPool(t *testing.T) *apphook.FilterPool {
	t.Helper()
	ch := apphook.NewChildHook(&apphook.ChildHookConfig{
		Name:         "ai-compliance-detector-integ",
		BinaryPath:   integDetectorBinary(),
		BinaryArgs:   nil,              // real engine + embedded baseline pack
		Timeout:      5 * time.Second,  // NER scan ≫ the 1ms default
		ReadyTimeout: 20 * time.Second, // CRF model load takes a few seconds
	})
	pool := apphook.NewFilterPool("integ", []*apphook.ChildHook{ch})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := pool.Start(ctx); err != nil {
		t.Skipf("detector binary unavailable (run 'make -C ../ai-compliance-detector build'): %v", err)
	}
	t.Cleanup(func() { _ = pool.Shutdown(context.Background()) })
	return pool
}

// countingHook delegates to a real Hook but counts Detect calls, so the test can prove
// cache reuse (fewer detector calls) THROUGH the real engine, not just a stub.
type countingHook struct {
	inner apphook.Hook
	calls atomic.Int64
}

func (c *countingHook) Name() string { return c.inner.Name() }
func (c *countingHook) Detect(ctx context.Context, req *apphook.Request) *apphook.Response {
	c.calls.Add(1)
	return c.inner.Detect(ctx, req)
}
func (c *countingHook) Status() *apphook.Status { return c.inner.Status() }

func TestFilterIntegration_HistoryLeakFixThroughRealDetector(t *testing.T) {
	pool := startRealDetectorPool(t)

	counter := &countingHook{inner: pool}
	p := &Proxy{}
	p.SetFilterHook(counter)
	p.SetFilterCacheEnabled(true, 50)

	apply := func(body string) string {
		r := newReq(body)
		r.Header.Set("X-Claude-Code-Session-Id", "integ-sess")
		if !p.applyInboundFilter(httptest.NewRecorder(), r, "claude-3", "personal", "", "", "",
			resolveSessionID(r, "anthropic", "anthropic"), discardLogger()) {
			t.Fatalf("request unexpectedly blocked: %s", body)
		}
		return readReqBody(t, r)
	}

	// ── Turn 1: user pastes the secret → must be masked outbound. Precondition: if the
	// real engine doesn't mask it, the baseline pack changed — fail loud, don't skip. ──
	turn1 := apply(`{"messages":[{"role":"user","content":"this is my key ` + integSecret + ` keep it safe"}]}`)
	if strings.Contains(turn1, integSecret) {
		t.Fatalf("turn1: real detector did not mask the secret (baseline pack regression?): %s", turn1)
	}
	callsAfterT1 := counter.calls.Load()

	// ── Turn 2 (THE BUG): secret now in HISTORY, latest user turn benign, + a model
	// reply. Must STILL be masked (history-leak fix); assistant reply must be untouched. ──
	convo := `{"messages":[` +
		`{"role":"user","content":"this is my key ` + integSecret + ` keep it safe"},` +
		`{"role":"assistant","content":"OK I saved your draft ad"},` +
		`{"role":"user","content":"make it shorter"}]}`
	turn2 := apply(convo)
	if strings.Contains(turn2, integSecret) {
		t.Errorf("turn2 HISTORY LEAK: earlier-turn secret forwarded in plaintext: %s", turn2)
	}
	if !strings.Contains(turn2, "OK I saved your draft ad") {
		t.Errorf("turn2: assistant reply must be untouched (responses are not compliance-scanned): %s", turn2)
	}
	if !strings.Contains(turn2, "make it shorter") {
		t.Errorf("turn2: benign latest user turn should pass through: %s", turn2)
	}
	callsAfterT2 := counter.calls.Load()
	// turn2 adds exactly 1 real scan: secret-in-history hits cache (same content as turn1),
	// only the NEW "make it shorter" is scanned; assistant is skipped entirely.
	if got := callsAfterT2 - callsAfterT1; got != 1 {
		t.Errorf("turn2 detector calls = %d, want 1 (history hit cache, only new user msg scanned, assistant skipped)", got)
	}

	// ── Turn 3: identical re-send (client retry). Both user pieces now cached → 0 extra
	// detector calls, but still masked (cache reuse correctness through the real path). ──
	turn3 := apply(convo)
	if strings.Contains(turn3, integSecret) {
		t.Errorf("turn3 (cache reuse) leaked the secret: %s", turn3)
	}
	if got := counter.calls.Load() - callsAfterT2; got != 0 {
		t.Errorf("turn3 detector calls = %d, want 0 (identical re-send fully served from cache)", got)
	}
}

// TestFilterIntegration_PerfBaseline measures, through the REAL detector, how per-request
// compliance latency scales with conversation length, cache OFF vs ON. It demonstrates the
// design's core claim: with the content cache, a growing conversation only pays to scan the
// NEW message each turn (flat latency), whereas without it every turn re-scans the whole
// history (latency grows linearly). Run via `make filter-integration` (prints the table).
func TestFilterIntegration_PerfBaseline(t *testing.T) {
	pool := startRealDetectorPool(t)

	// ~200-char benign messages → Allow path (no masking variance), realistic short-prompt size.
	msg := func(n int) string {
		return fmt.Sprintf(`{"role":"user","content":"benign user message number %d discussing project status, timelines, deliverables and general coordination details for the team this week, item %d, nothing sensitive here at all"}`, n, n)
	}
	// send builds an nMsgs-message request and returns the wall-clock of applyInboundFilter.
	send := func(p *Proxy, nMsgs int, sess string) time.Duration {
		parts := make([]string, nMsgs)
		for i := 0; i < nMsgs; i++ {
			parts[i] = msg(i)
		}
		body := `{"messages":[` + strings.Join(parts, ",") + `]}`
		r := newReq(body)
		r.Header.Set("X-Claude-Code-Session-Id", sess)
		t0 := time.Now()
		p.applyInboundFilter(httptest.NewRecorder(), r, "claude-3", "personal", "", "", "",
			resolveSessionID(r, "anthropic", "anthropic"), discardLogger())
		return time.Since(t0)
	}

	// Prime the detector (first scan after spawn loads caches; discard its timing).
	warm := &Proxy{}
	warm.SetFilterHook(pool)
	send(warm, 1, "warmup")

	t.Logf("单请求合规延迟 vs 对话长度(真 detector,~200字符/条良性消息):")
	t.Logf("%-10s | %-22s | %-26s", "对话(条)", "缓存关:每轮全扫", "缓存开:每轮只扫新增")
	for _, L := range []int{1, 5, 10, 20, 40} {
		// Cache OFF: fresh proxy, no cache, one L-message request → L scans.
		pOff := &Proxy{}
		pOff.SetFilterHook(pool)
		off := send(pOff, L, fmt.Sprintf("off-%d", L))

		// Cache ON: fresh proxy with cache; replay turns 1..L on one session so the prefix
		// accumulates in cache; measure the LAST turn (L-1 cached hits + 1 new scan).
		pOn := &Proxy{}
		pOn.SetFilterHook(pool)
		pOn.SetFilterCacheEnabled(true, 1000)
		var on time.Duration
		for turn := 1; turn <= L; turn++ {
			on = send(pOn, turn, fmt.Sprintf("on-%d", L))
		}
		t.Logf("%-10d | %-22s | %-22s", L, off.Round(10*time.Microsecond), on.Round(10*time.Microsecond))
	}
}

// TestFilterIntegration_DetectorMaskIsDeterministic verifies the load-bearing assumption
// behind "masking won't thrash the provider's prompt cache": scanning the SAME content
// through the REAL detector must yield BYTE-IDENTICAL masked output every time. If the
// detector's mask were non-deterministic (nonce/timestamp/unstable span), then on every
// cache miss / eviction / restart the masked text would differ → the LLM provider's
// prefix (token) cache would miss every turn. Cache is OFF here so we test the detector
// itself, not the proxy's content cache (which reuses bytes by construction).
func TestFilterIntegration_DetectorMaskIsDeterministic(t *testing.T) {
	pool := startRealDetectorPool(t)

	scan := func() string {
		p := &Proxy{}
		p.SetFilterHook(pool) // no SetFilterCacheEnabled → content cache OFF
		// Mix a credential (regex rule) + a phone (NER/CRF path) to exercise both maskers.
		r := newReq(`{"messages":[{"role":"user","content":"please store my key ` + integSecret + ` and phone 13812345678 safely for later"}]}`)
		r.Header.Set("X-Claude-Code-Session-Id", "determinism")
		p.applyInboundFilter(httptest.NewRecorder(), r, "claude-3", "personal", "", "", "",
			resolveSessionID(r, "anthropic", "anthropic"), discardLogger())
		return readReqBody(t, r)
	}

	first := scan()
	if strings.Contains(first, integSecret) {
		t.Fatalf("precondition: secret not masked by real detector: %s", first)
	}
	for i := 1; i <= 4; i++ {
		again := scan()
		if again != first {
			t.Errorf("detector mask NOT deterministic (run %d differs) — provider prompt-cache would break on every cache miss/eviction.\n run0: %s\n run%d: %s", i, first, i, again)
		}
	}
}

// TestFilterIntegration_IPCOverhead measures the proxy↔detector IPC round-trip cost in
// ISOLATION — framing encode/decode + pipe transmission + ChildHook writeMu/pending-map
// lock — using an --echo-only detector that skips rule load + scan entirely. This settles
// whether batching N pieces into one call would meaningfully cut latency: if the per-call
// IPC overhead is ≪ a real scan (~ms), then batching (which only saves N-1 IPC round-trips)
// can't help. Also stresses the lock under concurrency. Run via `make filter-integration`.
func TestFilterIntegration_IPCOverhead(t *testing.T) {
	ch := apphook.NewChildHook(&apphook.ChildHookConfig{
		Name:         "ai-compliance-detector-echo",
		BinaryPath:   integDetectorBinary(),
		BinaryArgs:   []string{"--echo-only"}, // skip rule load + scan → PURE IPC
		Timeout:      2 * time.Second,
		ReadyTimeout: 15 * time.Second,
	})
	pool := apphook.NewFilterPool("echo", []*apphook.ChildHook{ch})
	startCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := pool.Start(startCtx); err != nil {
		t.Skipf("detector binary unavailable (run 'make -C ../ai-compliance-detector build'): %v", err)
	}
	defer func() { _ = pool.Shutdown(context.Background()) }()

	payload := []byte("a short benign probe message of a few dozen bytes for ipc round-trip timing")
	detectOnce := func() time.Duration {
		t0 := time.Now()
		resp := pool.Detect(context.Background(), &apphook.Request{
			Direction:   apphook.DirectionInbound,
			Payload:     payload,
			TargetModel: "claude-3",
		})
		d := time.Since(t0)
		if resp == nil {
			t.Fatal("nil response from echo detector")
		}
		return d
	}

	for i := 0; i < 200; i++ { // warmup (JIT pipe, scheduler)
		detectOnce()
	}

	// ── Sequential: pure IPC round-trip per call (no scan, uncontended) ──
	const N = 4000
	seq := make([]time.Duration, N)
	for i := 0; i < N; i++ {
		seq[i] = detectOnce()
	}
	sort.Slice(seq, func(i, j int) bool { return seq[i] < seq[j] })
	pmin, p50, p99 := seq[0], seq[N/2], seq[N*99/100]

	// ── Concurrent: lock contention (writeMu + pending map) under C goroutines ──
	const C = 8
	per := N / C
	var wg sync.WaitGroup
	c0 := time.Now()
	for g := 0; g < C; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				detectOnce()
			}
		}()
	}
	wg.Wait()
	concTotal := time.Since(c0)
	concPer := concTotal / time.Duration(per*C)
	concThroughput := float64(per*C) / concTotal.Seconds()

	t.Logf("proxy↔detector IPC 往返(--echo-only,无扫描 = 纯编解码+管道+锁):")
	t.Logf("  顺序单调用:  min=%v  p50=%v  p99=%v   (N=%d)",
		pmin.Round(time.Microsecond), p50.Round(time.Microsecond), p99.Round(time.Microsecond), N)
	t.Logf("  并发 C=%d:    平均/调用=%v  吞吐=%.0f calls/s  总=%v   (看锁竞争退化)",
		C, concPer.Round(time.Microsecond), concThroughput, concTotal.Round(time.Millisecond))
	t.Logf("  结论参照:真扫一条 ~1–5ms。IPC p50=%v 占真扫的比例 ≈ %.1f%% (按 2ms)",
		p50.Round(time.Microsecond), float64(p50.Microseconds())/2000.0*100)
}
