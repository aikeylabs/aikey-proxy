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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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

// integSecret: synthetic JWT — a deterministic gitleaks-HP match (`secret.jwt`,
// confidence 85) in the baseline pack, ASCII (survives json re-marshal verbatim,
// no \uXXXX escaping to fight).
//
// WHY A JWT AND NOT AN API KEY (2026-08-08): these two tests measure the MASK
// mechanism — mask-output byte-stability and the content-cache call accounting.
// They need a fixture whose policy action is deterministically `mask`.
// CREDENTIAL_JWT is exactly that: entity_actions says mask and it has no
// context_rules entry, so the action never depends on the surrounding prose.
//
// The previous fixture was a `sk-ant-api03-…` string of the wrong length. It
// never matched `secret.anthropic-api-key` (which requires 93 chars + "AA") —
// only the CRF token model fired on it, and it passed solely because the
// pre-992d88d detector upgraded nearly every finding to mask. Once the context
// gate landed, that fixture degraded to `warn` and both tests went red. A real
// API key is now covered by TestFilterIntegration_SelfEvidentCredentialIsBlocked
// below, which asserts the stronger `block` outcome.
const integSecret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkludGVnVGVzdCJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// integSelfEvidentKey is a STRUCTURALLY VALID Anthropic key: the
// `secret.anthropic-api-key` rule requires exactly 93 chars of [a-zA-Z0-9_-]
// after the `sk-ant-api03-` prefix, then a literal "AA". 90 + 3 + "AA" = 93+AA.
// Not a live credential — the body is a repeating pattern.
var integSelfEvidentKey = "sk-ant-api03-" + strings.Repeat("Ab3Cd4Ef5", 10) + "xyzAA"

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
			resolveSessionID(r, "anthropic", "anthropic"), "", discardLogger()) {
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
	// The assistant reply is now SCANNED (P4, 方案 §3.4) but this one is benign, so
	// it must still come through verbatim — scanning ≠ masking.
	if !strings.Contains(turn2, "OK I saved your draft ad") {
		t.Errorf("turn2: benign assistant reply must survive the scan unmodified: %s", turn2)
	}
	if !strings.Contains(turn2, "make it shorter") {
		t.Errorf("turn2: benign latest user turn should pass through: %s", turn2)
	}
	callsAfterT2 := counter.calls.Load()
	// turn2 adds exactly 2 real scans: the secret-in-history hits cache (same content
	// as turn1); the NEW user turn and the assistant reply are each seen for the first
	// time. (Pre-P4 this was 1 — assistant was skipped, which is the leak 方案 §2.2.)
	if got := callsAfterT2 - callsAfterT1; got != 2 {
		t.Errorf("turn2 detector calls = %d, want 2 (history hit cache; new user turn + assistant reply each scanned once)", got)
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
			resolveSessionID(r, "anthropic", "anthropic"), "", discardLogger())
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
			resolveSessionID(r, "anthropic", "anthropic"), "", discardLogger())
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

// TestFilterIntegration_SelfEvidentCredentialIsBlocked locks the 2026-08-08
// plaintext-credential leak, end to end through the REAL detector and real IPC.
//
// THE BUG: "this is my key sk-ant-api03-…AA" carries none of the
// CREDENTIAL_API_KEY positive keywords ("api_key", "anthropic", "密钥", …), so
// the action policy's context gate returned warn WITHOUT ever consulting the
// score or entity_actions — and warn forwards the prompt unchanged. A live key
// reached the LLM in plaintext while, in the very same prompt, a phone number
// was masked. default_policy.json has said "CREDENTIAL_API_KEY": "block" the
// whole time; the gate simply ran first and short-circuited it.
//
// 能红 (verified): empty self_evident_rules in default_policy.json, or drop the
// `&& !selfEvident` guard in actionpolicy.decideFinding, and this test fails
// with the credential forwarded verbatim.
//
// Why this is an INTEGRATION test and not only a unit test: the 2026-08-06
// regression shipped because the action-policy change was covered by stub-based
// unit tests only. Nothing executed the real detector binary over the real pipe,
// so no test noticed that a real key now walked through. See
// workflow/CI/bugfix/2026-08-08-self-evident-credential-plaintext-leak.md.
func TestFilterIntegration_SelfEvidentCredentialIsBlocked(t *testing.T) {
	pool := startRealDetectorPool(t)
	p := &Proxy{}
	p.SetFilterHook(pool)

	rec := httptest.NewRecorder()
	r := newReq(`{"messages":[{"role":"user","content":"this is my key ` + integSelfEvidentKey + ` keep it safe"}]}`)
	r.Header.Set("X-Claude-Code-Session-Id", "self-evident")
	forwarded := p.applyInboundFilter(rec, r, "claude-3", "personal", "", "", "",
		resolveSessionID(r, "anthropic", "anthropic"), "", discardLogger())

	if forwarded {
		body := readReqBody(t, r)
		if strings.Contains(body, integSelfEvidentKey) {
			t.Fatalf("PLAINTEXT CREDENTIAL LEAK: a structurally valid Anthropic key was forwarded verbatim: %s", body)
		}
		t.Fatalf("self-evident credential was forwarded (masked) but CREDENTIAL_API_KEY entity action is block: %s", body)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("blocked request status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if !strings.Contains(rec.Body.String(), "COMPLIANCE_BLOCKED") {
		t.Errorf("block response must carry the COMPLIANCE_BLOCKED error code, got: %s", rec.Body.String())
	}
}

// integConnectionURI is the user-reported connection string, verbatim. It is
// not a live credential — `host` does not resolve and `hunter2` is the canonical
// joke password. Structurally it is exactly what the `secret.connection-uri-password`
// rule targets: a data-source scheme + RFC 3986 `user:password@host` userinfo.
const integConnectionURI = "postgres://admin:hunter2@host/db"

// TestFilterIntegration_ConnectionURICredentialIsBlocked locks the 2026-08-09
// CREDENTIAL_DSN plaintext leak, end to end through the REAL detector binary
// and the real IPC pipe.
//
// THE BUG: the shipped baseline had NO regex producing CREDENTIAL_DSN, so the
// entity came only from the CRF token model. On this prompt the CRF produced
// nothing at all, so the connection string — username, password, host and
// database — was forwarded to the LLM verbatim with no finding recorded. Even
// when the CRF did fire (longer prompts, as `ner.token.PWD`), the action
// policy's context gate downgraded it to warn: CREDENTIAL_DSN's positive
// keywords are "dsn" / "jdbc:" / "database_url" / "password=" / "数据库连接" /
// "datasource", and a user pasting a DSN types none of them.
//
// 能红 (verified): delete `secret.connection-uri-password` from
// credentials.yaml, or remove its id from default_policy.json →
// self_evident_rules, and this test fails with the DSN forwarded verbatim.
//
// Why an INTEGRATION test: the unit tests in ai-compliance-detector cover the
// rule and the policy separately; only this one proves the whole chain
// (baseline YAML → HP scan → validator → aggregator → exemption → block → 403)
// survives inside the binary the proxy actually spawns. See
// workflow/CI/bugfix/2026-08-09-dsn-connection-uri-plaintext-leak.md.
func TestFilterIntegration_ConnectionURICredentialIsBlocked(t *testing.T) {
	pool := startRealDetectorPool(t)
	p := &Proxy{}
	p.SetFilterHook(pool)

	rec := httptest.NewRecorder()
	r := newReq(`{"messages":[{"role":"user","content":"帮我看看这个连接串对不对 ` + integConnectionURI + `"}]}`)
	r.Header.Set("X-Claude-Code-Session-Id", "connection-uri")
	forwarded := p.applyInboundFilter(rec, r, "claude-3", "personal", "", "", "",
		resolveSessionID(r, "anthropic", "anthropic"), "", discardLogger())

	if forwarded {
		body := readReqBody(t, r)
		if strings.Contains(body, integConnectionURI) {
			t.Fatalf("PLAINTEXT CREDENTIAL LEAK: a database connection string with an inline password was forwarded verbatim: %s", body)
		}
		t.Fatalf("connection URI was forwarded (masked) but CREDENTIAL_DSN entity action is block: %s", body)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("blocked request status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if !strings.Contains(rec.Body.String(), "COMPLIANCE_BLOCKED") {
		t.Errorf("block response must carry the COMPLIANCE_BLOCKED error code, got: %s", rec.Body.String())
	}
}

// TestFilterIntegration_CredentialLessConnectionURIIsNotBlocked is the
// false-positive half, through the same real binary: a connection URI with no
// credentials must never 403 the user. Without the "non-empty password"
// requirement in the rule, every `postgres://host:5432/db` in every log line a
// developer pastes would become a refused request.
func TestFilterIntegration_CredentialLessConnectionURIIsNotBlocked(t *testing.T) {
	pool := startRealDetectorPool(t)
	p := &Proxy{}
	p.SetFilterHook(pool)

	for name, content := range map[string]string{
		"no_userinfo":           "connect with postgres://localhost:5432/mydb and retry",
		"placeholder_password":  "示例写法 postgres://user:password@localhost:5432/mydb",
		"template_interpolated": "docker-compose 里写 postgres://app:${DB_PASS}@db:5432/app",
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			r := newReq(`{"messages":[{"role":"user","content":"` + content + `"}]}`)
			r.Header.Set("X-Claude-Code-Session-Id", "connection-uri-fp")
			if !p.applyInboundFilter(rec, r, "claude-3", "personal", "", "", "",
				resolveSessionID(r, "anthropic", "anthropic"), "", discardLogger()) {
				t.Fatalf("credential-less connection URI was blocked (status %d): %s", rec.Code, rec.Body.String())
			}
		})
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

// ─────────────────────────────────────────────────────────────────────────────
// P4 — assistant 纳入扫描范围(占位符还原方案 §3.4)
// ─────────────────────────────────────────────────────────────────────────────

// filterDecisionStats is a slog.Handler that harvests the dispatcher's own
// per-request decision trace (event.name=proxy.filter.decision) — the PRODUCTION
// instrumentation, not a test-only counter — so the measurement below reports the
// same cache_hits / cache_miss numbers an operator would read from the logs.
type filterDecisionStats struct {
	hits, miss, pieces, masked int64
}

func (s *filterDecisionStats) Enabled(context.Context, slog.Level) bool { return true }
func (s *filterDecisionStats) WithAttrs([]slog.Attr) slog.Handler       { return s }
func (s *filterDecisionStats) WithGroup(string) slog.Handler            { return s }
func (s *filterDecisionStats) Handle(_ context.Context, r slog.Record) error {
	var isDecision bool
	var hits, miss, pieces, masked int64
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "event.name":
			isDecision = a.Value.String() == "proxy.filter.decision"
		case "cache_hits":
			hits = a.Value.Int64()
		case "cache_miss":
			miss = a.Value.Int64()
		case "pieces":
			pieces = a.Value.Int64()
		case "masked":
			masked = a.Value.Int64()
		}
		return true
	})
	if isDecision {
		s.hits += hits
		s.miss += miss
		s.pieces += pieces
		s.masked += masked
	}
	return nil
}

func (s *filterDecisionStats) hitRate() float64 {
	if s.hits+s.miss == 0 {
		return 0
	}
	return 100 * float64(s.hits) / float64(s.hits+s.miss)
}

// pctl returns the p-th percentile (nearest-rank) of an UNSORTED sample.
func pctl(d []time.Duration, p int) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := (p * len(s)) / 100
	if i >= len(s) {
		i = len(s) - 1
	}
	return s[i]
}

// TestFilterIntegration_P4RestoreLeakThroughRealDetector is the P4 E2E fence
// through the REAL detector (方案 §2.2 的活体版本).
//
// Turn 1: the user sends a phone number → the detector masks it to {{PHONE_1}}
// and the response leg restores the plaintext back to the CLIENT. Turn 2 the
// client replays that plaintext inside an ASSISTANT message. It must be masked
// again before it leaves the proxy.
//
// 能红 (the second half): the same request with `assistant` removed from the scan
// roles MUST leak — otherwise the first assertion is not proving anything about
// assistant scanning.
func TestFilterIntegration_P4RestoreLeakThroughRealDetector(t *testing.T) {
	pool := startRealDetectorPool(t)

	// A restorable entity: the detector masks CN phone numbers to {{PHONE_N}} and
	// the response leg swaps the original back — exactly the "既 mask 又还原" class
	// that makes the assistant path a leak (方案 §2.2 触发条件).
	const phone = "13812345678"

	send := func(roles []string, sess string) string {
		p := &Proxy{}
		p.SetFilterHook(pool)
		p.SetFilterCacheEnabled(true, 1000)
		p.SetFilterScanRoles(roles) // nil → default {user, assistant}
		body := `{"messages":[` +
			`{"role":"user","content":"我的手机号是 ` + phone + ` 请记录"},` +
			`{"role":"assistant","content":"好的,已记录您的手机号 ` + phone + ` ,后续会用它联系您"},` +
			`{"role":"user","content":"谢谢,再确认一下"}` +
			`]}`
		r := newReq(body)
		r.Header.Set("X-Claude-Code-Session-Id", sess)
		if !p.applyInboundFilter(httptest.NewRecorder(), r, "claude-3", "personal", "", "", "",
			resolveSessionID(r, "anthropic", "anthropic"), "", discardLogger()) {
			t.Fatalf("request blocked, precondition broken")
		}
		return readReqBody(t, r)
	}

	// Precondition: the real engine still masks this entity at all.
	probe := send(nil, "p4-precondition")
	if !strings.Contains(probe, "{{PHONE_") {
		t.Fatalf("precondition: real detector did not mask the phone (pack regression?): %s", probe)
	}

	// ① default policy — the assistant-borne plaintext must NOT reach upstream.
	withAssistant := send(nil, "p4-default")
	if strings.Contains(withAssistant, phone) {
		t.Errorf("RESTORE LEAK: assistant history carried the plaintext upstream: %s", withAssistant)
	}

	// ② 能红 control — drop assistant from the scan roles and the leak must return.
	userOnly := send([]string{"user"}, "p4-useronly")
	if !strings.Contains(userOnly, phone) {
		t.Fatalf("能红 control failed: with roles=[user] the plaintext was still masked, so ① proves nothing: %s", userOnly)
	}
	t.Logf("✅ 能红成立(真 detector):roles=[user assistant] 出站无原文;roles=[user] 出站含 %q", phone)
}

// TestFilterIntegration_P4AssistantScanCost is P4's HARD acceptance measurement
// (方案 §3.4 "必须实测"): it prices the assistant-scanning decision on realistic
// multi-turn traffic through the REAL detector, instead of asserting the
// cache-hit argument on paper.
//
// The load-bearing claim under test: assistant history is byte-identical across
// turns, so it is a content-hash cache HIT from its second appearance onward —
// i.e. the detector-call increment is bounded by "one extra scan per assistant
// turn, once", not "re-scan the whole doubled history every turn".
//
// Shape: SESSIONS independent conversations × TURNS turns; every turn resends the
// full history (Claude Code / Codex / OpenClaw all do this) and each assistant
// reply is 1–4KB. Reports, per policy: detector calls, cache hit rate (read from
// the dispatcher's own decision log), and the per-request S1 latency p50/p95.
func TestFilterIntegration_P4AssistantScanCost(t *testing.T) {
	pool := startRealDetectorPool(t)

	const (
		sessions = 20
		turns    = 10
	)

	// Realistic content. The user turn carries a restorable entity (a CN phone),
	// so the mask+restore path — the one that CREATES the assistant leak — is the
	// path being priced. The assistant reply repeats it (that is what restoration
	// puts in the client's history) and is padded to 1–4KB of prose.
	filler := "这里是模型给出的详细说明与后续建议,包含背景梳理、执行步骤、风险提示以及可选方案的对比分析。"
	userMsg := func(s, turn int) string {
		return fmt.Sprintf("会话%d 第%d轮:请帮我处理这条客户信息,联系电话 138%08d,处理完请总结要点。", s, turn, s*1000+turn)
	}
	assistantMsg := func(s, turn int) string {
		want := 1024 * (1 + turn%4) // 1KB / 2KB / 3KB / 4KB
		var b strings.Builder
		fmt.Fprintf(&b, "好的。已记录会话%d 第%d轮的联系电话 138%08d,以下是处理结果:", s, turn, s*1000+turn)
		for b.Len() < want {
			b.WriteString(filler)
		}
		return b.String()
	}
	// The CN address recognizer (NER/CRF) is the most expensive lane, and it runs
	// whether the verdict is audit or mask — so a separate run prices it.
	addrUserMsg := func(s, turn int) string {
		return fmt.Sprintf("会话%d 第%d轮:请把样品寄到北京市朝阳区建国路%d号院万达广场1号楼2单元301,联系电话 138%08d。",
			s, turn, 80+turn, s*1000+turn)
	}

	type result struct {
		label       string
		calls       int64
		hits, miss  int64
		pieces      int64
		p50, p95    time.Duration
		wall        time.Duration
		leakedPlain int
	}

	run := func(label string, roles []string, user func(int, int) string) result {
		counter := &countingHook{inner: pool}
		stats := &filterDecisionStats{}
		logger := slog.New(stats)
		p := &Proxy{}
		p.SetFilterHook(counter)
		p.SetFilterCacheEnabled(true, 1000) // production default window
		p.SetFilterScanRoles(roles)         // nil → default {user, assistant}

		lat := make([]time.Duration, 0, sessions*turns)
		leaked := 0
		t0 := time.Now()
		for s := 0; s < sessions; s++ {
			sess := fmt.Sprintf("%s-sess-%d", label, s)
			msgs := make([]string, 0, turns*2)
			for turn := 1; turn <= turns; turn++ {
				msgs = append(msgs, `{"role":"user","content":`+p4JSON(user(s, turn))+`}`)
				body := `{"messages":[` + strings.Join(msgs, ",") + `]}`
				r := newReq(body)
				r.Header.Set("X-Claude-Code-Session-Id", sess)
				start := time.Now()
				p.applyInboundFilter(httptest.NewRecorder(), r, "claude-3", "personal", "", "", "",
					resolveSessionID(r, "anthropic", "anthropic"), "", logger)
				lat = append(lat, time.Since(start))
				// Leak check on the LAST turn only (cheap): no plaintext phone from
				// an earlier assistant turn may survive in the forwarded body.
				if turn == turns {
					out := readReqBody(t, r)
					for k := 1; k < turns; k++ {
						if strings.Contains(out, fmt.Sprintf("138%08d", s*1000+k)) {
							leaked++
						}
					}
				}
				// The client appends the model's (restored) reply to its history.
				msgs = append(msgs, `{"role":"assistant","content":`+p4JSON(assistantMsg(s, turn))+`}`)
			}
		}
		return result{
			label: label, calls: counter.calls.Load(),
			hits: stats.hits, miss: stats.miss, pieces: stats.pieces,
			p50: pctl(lat, 50), p95: pctl(lat, 95), wall: time.Since(t0),
			leakedPlain: leaked,
		}
	}

	// Prime the detector (first scan after spawn loads caches/models).
	warm := &Proxy{}
	warm.SetFilterHook(pool)
	wr := newReq(`{"messages":[{"role":"user","content":"预热请求,联系电话 13800000000"}]}`)
	warm.applyInboundFilter(httptest.NewRecorder(), wr, "claude-3", "personal", "", "", "",
		resolveSessionID(wr, "anthropic", "anthropic"), "", discardLogger())

	results := []result{
		run("baseline user-only", []string{"user"}, userMsg),
		run("P4 user+assistant", nil, userMsg),
		run("P4 地址路(NER)", nil, addrUserMsg),
	}

	t.Logf("P4 多轮场景实测 —— %d 会话 × %d 轮,每轮全量重发历史,assistant 回复 1–4KB,真 detector + 生产缓存(window=1000)",
		sessions, turns)
	t.Logf("%-22s | %-8s | %-8s | %-9s | %-9s | %-10s | %-9s | %-9s | %s",
		"策略", "片段数", "真扫次数", "缓存命中", "命中率", "S1 p50", "S1 p95", "总耗时", "assistant 原文泄漏")
	for _, r := range results {
		hr := 0.0
		if r.hits+r.miss > 0 {
			hr = 100 * float64(r.hits) / float64(r.hits+r.miss)
		}
		t.Logf("%-22s | %-8d | %-8d | %-9d | %-8.1f%% | %-10v | %-9v | %-9v | %d",
			r.label, r.pieces, r.calls, r.hits, hr,
			r.p50.Round(10*time.Microsecond), r.p95.Round(10*time.Microsecond),
			r.wall.Round(time.Millisecond), r.leakedPlain)
	}

	base, p4 := results[0], results[1]
	t.Logf("detector 调用增量:%d → %d(+%d,+%.0f%%);片段数增量:%d → %d(+%.0f%%)",
		base.calls, p4.calls, p4.calls-base.calls,
		100*float64(p4.calls-base.calls)/float64(base.calls),
		base.pieces, p4.pieces, 100*float64(p4.pieces-base.pieces)/float64(base.pieces))

	// ── Assertions (not just a printout) ──────────────────────────────────────
	//
	// 1) The leak is closed under the P4 policy and OPEN under the baseline —
	//    the 能红 evidence at scale (if the baseline also showed 0 leaks the whole
	//    measurement would be comparing two identical things).
	if p4.leakedPlain != 0 {
		t.Errorf("P4 策略下仍有 %d 条 assistant 历史原文出站", p4.leakedPlain)
	}
	if base.leakedPlain == 0 {
		t.Fatalf("能红对照失效:baseline(roles=[user])居然零泄漏 —— 本测量没有区分度")
	}
	// 2) The load-bearing performance claim: each assistant turn costs ONE extra
	//    detector call for the whole conversation (its first appearance), not one
	//    per turn thereafter. Ideal增量 = sessions*(turns-1) — the last assistant
	//    reply is never resent. Allow a small margin for cache/TTL noise.
	idealDelta := int64(sessions * (turns - 1))
	if got := p4.calls - base.calls; got > idealDelta*11/10 {
		t.Errorf("assistant 扫描增量 %d 超过理论上限 %d(+10%%)——说明 assistant 历史没有稳定命中缓存,§3.4 的性能论证不成立", got, idealDelta)
	}
}

// mustJSON quotes a string as a JSON value (test helper for building bodies with
// CJK content safely).
func p4JSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// integUpperCaseAWSKey is a structurally valid AWS access key id: `AKIA` plus
// 16 upper-case alphanumerics. Not a live credential — the body is random.
const integUpperCaseAWSKey = "AKIA3XZQ7KL2WMPVR4TY"

// TestFilterIntegration_UpperCaseCredentialIsBlocked locks the 2026-08-09 S1
// fast-path case-sensitivity bypass, end to end through the REAL detector
// binary and the real IPC pipe.
//
// THE BUG: the engine short-circuits a prompt that matches none of the union of
// every rule's context_keywords, returning zero findings without running HP, HR
// or NER at all. That union is built case-SENSITIVELY, and the shipped keywords
// are all lower case (`akia`, `ezak`, `postgres://`, …) while the credentials
// they anchor are upper case. So a bare `AKIA…` key in a prompt with no other
// keyword was not "detected and allowed" — it was never scanned, and the key
// went to the LLM verbatim.
//
// 能红 (verified): compliance.Engine.SetFastPathCaseSensitive(true) — i.e.
// reverting the trie to acmatch.NewMatcher — makes this prompt short-circuit
// again and the key is forwarded. See
// cmd/detector/fastpath_case_and_self_evident_test.go for the in-repo control.
//
// Why an INTEGRATION test: the defect lives in a performance short-circuit that
// only exists on the real Detect path, and it silently suppressed EVERY layer
// below it — precisely the shape of failure that unit tests on the individual
// suites cannot see, because each suite in isolation detects the key fine.
func TestFilterIntegration_UpperCaseCredentialIsBlocked(t *testing.T) {
	pool := startRealDetectorPool(t)
	p := &Proxy{}
	p.SetFilterHook(pool)

	rec := httptest.NewRecorder()
	r := newReq(`{"messages":[{"role":"user","content":"here you go ` + integUpperCaseAWSKey + ` keep it safe"}]}`)
	r.Header.Set("X-Claude-Code-Session-Id", "fastpath-case")
	forwarded := p.applyInboundFilter(rec, r, "claude-3", "personal", "", "", "",
		resolveSessionID(r, "anthropic", "anthropic"), "", discardLogger())

	if forwarded {
		body := readReqBody(t, r)
		if strings.Contains(body, integUpperCaseAWSKey) {
			t.Fatalf("PLAINTEXT CREDENTIAL LEAK: an upper-case AWS access key id was forwarded verbatim "+
				"(fast-path short-circuit skipped the scan): %s", body)
		}
		t.Fatalf("upper-case credential was forwarded (masked) but CREDENTIAL_API_KEY entity action is block: %s", body)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("blocked request status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if !strings.Contains(rec.Body.String(), "COMPLIANCE_BLOCKED") {
		t.Errorf("block response must carry the COMPLIANCE_BLOCKED error code, got: %s", rec.Body.String())
	}
}
