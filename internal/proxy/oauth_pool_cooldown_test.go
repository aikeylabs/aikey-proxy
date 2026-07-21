package proxy

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

func resp(status int, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header}
}

func TestCooldownDecision_Classification(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)

	// 401 → cool down (broken account), default window.
	if until, ok := cooldownDecision(resp(401, nil), now); !ok || until != now.Add(poolCooldownDefault) {
		t.Fatalf("401 must cool down for the default window, got until=%v ok=%v", until, ok)
	}

	// 429 WITH real exhaustion evidence (status flip + window at 1.0) → cool down
	// until the exhausted window's unified reset epoch (B1: the reactive path now
	// consumes unified-reset instead of the flat default).
	resetAt := now.Add(42 * time.Minute)
	rl := http.Header{
		"Anthropic-Ratelimit-Unified-Status":         {"rate_limited"},
		"Anthropic-Ratelimit-Unified-5h-Utilization": {"1.0"},
		"Anthropic-Ratelimit-Unified-5h-Reset":       {strconv.FormatInt(resetAt.Unix(), 10)},
	}
	if until, ok := cooldownDecision(resp(429, rl), now); !ok || !until.Equal(resetAt) {
		t.Fatalf("exhaustion 429 must cool until the exhausted window's reset, got until=%v ok=%v", until, ok)
	}

	// B1 fence (2026-07-19, sub2api-style value-based discrimination): the
	// unified-* headers ride on EVERY anthropic response — a WAF/business 429
	// that carries routine telemetry (status=allowed, util well under 1.0) shows
	// NO exhaustion evidence and must NOT cool the account. The old
	// name-contains-"ratelimit" rule cooled it 5min; a correlated WAF burst
	// could chain-cool the whole pool.
	wafWithTelemetry := http.Header{
		"Anthropic-Ratelimit-Unified-Status":         {"allowed"},
		"Anthropic-Ratelimit-Unified-5h-Utilization": {"0.42"},
		"Anthropic-Ratelimit-Unified-Reset":          {strconv.FormatInt(resetAt.Unix(), 10)},
	}
	if _, ok := cooldownDecision(resp(429, wafWithTelemetry), now); ok {
		t.Fatal("429 with routine unified telemetry but NO exhaustion evidence must NOT cool the account")
	}

	// 429 with Retry-After → honor it (capped).
	ra := http.Header{"Retry-After": {"30"}}
	if until, ok := cooldownDecision(resp(429, ra), now); !ok || until != now.Add(30*time.Second) {
		t.Fatalf("Retry-After must set the cooldown, got %v ok=%v", until, ok)
	}
	big := http.Header{"Retry-After": {"99999"}}
	if until, _ := cooldownDecision(resp(429, big), now); until != now.Add(poolCooldownMax) {
		t.Fatalf("oversized Retry-After must be capped at max, got %v", until)
	}

	// evidence of limiting but NO reset info anywhere → transient per-minute
	// class → SHORT cool (not the 5-min default; R4 限流→短退避).
	transient := http.Header{"Anthropic-Ratelimit-Unified-Status": {"rate_limited"}}
	if until, ok := cooldownDecision(resp(429, transient), now); !ok || until != now.Add(poolCooldown429NoReset) {
		t.Fatalf("limit evidence without reset info must short-cool (%v), got until=%v ok=%v",
			poolCooldown429NoReset, until, ok)
	}

	// 429 WITHOUT any rate-limit signal = WAF business rejection → NOT the
	// account's fault, do not cool it down.
	if _, ok := cooldownDecision(resp(429, nil), now); ok {
		t.Fatal("WAF 429 (no rate-limit signal) must NOT cool down the account")
	}

	// 529 (P0-B): the upstream's explicit overload signal → immediate short
	// overload-scoped cooldown (distinct from both the 429 semantics and the
	// generic-5xx streak path).
	if until, ok := cooldownDecision(resp(529, nil), now); !ok || until != now.Add(poolCooldown529Overload) {
		t.Fatalf("529 must cool for the overload window, got until=%v ok=%v", until, ok)
	}

	// Success / other → no cooldown.
	if _, ok := cooldownDecision(resp(200, nil), now); ok {
		t.Fatal("200 must not cool down")
	}
	if _, ok := cooldownDecision(resp(500, nil), now); ok {
		t.Fatal("500 must not cool down IMMEDIATELY (generic 5xx cools via the consecutive streak, P0-B)")
	}
}

// P0-B fence (2026-07-19): generic 5xx / transport failures cool an account only
// after CONSECUTIVE repeats; any success resets the streak; a literally-built
// store (nil streak map) stays safe.
func TestPoolCooldownStore_ServerErrorStreak(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	s := &poolCooldownStore{m: map[string]time.Time{}, now: func() time.Time { return now }}

	if _, cooled := s.noteServerError("acc-a"); cooled {
		t.Fatal("first server error must not cool (transient blip)")
	}
	if _, cooled := s.noteServerError("acc-a"); cooled {
		t.Fatal("second server error must not cool")
	}
	until, cooled := s.noteServerError("acc-a")
	if !cooled || until != now.Add(serverErrCooldown) {
		t.Fatalf("threshold(%d) consecutive errors must cool for %v, got until=%v cooled=%v",
			serverErrStreakThreshold, serverErrCooldown, until, cooled)
	}
	if !s.skipSet()["acc-a"] {
		t.Fatal("streak cool must land in the skip set")
	}

	// success resets: 2 errors + success + 2 errors → never cooled.
	if _, cooled := s.noteServerError("acc-b"); cooled {
		t.Fatal("b: first error must not cool")
	}
	if _, cooled := s.noteServerError("acc-b"); cooled {
		t.Fatal("b: second error must not cool")
	}
	s.noteSuccess("acc-b")
	if _, cooled := s.noteServerError("acc-b"); cooled {
		t.Fatal("b: streak must reset on success — error after success is a fresh streak")
	}
	if _, cooled := s.noteServerError("acc-b"); cooled {
		t.Fatal("b: second error of the fresh streak must not cool")
	}
}

// TestCooldownDecision_CodexRateLimit covers the codex (ChatGPT) 429 wire format
// (sub2api-derived, R37 2026-07-04): codex carries x-codex-* usage headers instead
// of Retry-After/*ratelimit*. A codex 429 with ONLY these headers must still be
// recognized as a rate-limit (not mis-read as a WAF rejection → 打死号), and its
// reset-after-seconds drives the cooldown.
func TestCooldownDecision_CodexRateLimit(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)

	// Only ONE window exhausted (used≥100) → cool for THAT window's reset (300s),
	// even though there is NO Retry-After and NO *ratelimit* header (only x-codex-*).
	// The other window is below 100% so it does not gate.
	sec := http.Header{
		"X-Codex-Secondary-Used-Percent":       {"100"},
		"X-Codex-Secondary-Reset-After-Seconds": {"300"},
		"X-Codex-Primary-Used-Percent":         {"40"},
		"X-Codex-Primary-Reset-After-Seconds":  {"600000"},
	}
	if until, ok := cooldownDecision(resp(429, sec), now); !ok || until != now.Add(300*time.Second) {
		t.Fatalf("codex one-window-exhausted 429 must cool for that window's reset (300s), got until=%v ok=%v", until, ok)
	}

	// Both windows exhausted, LONGER reset is on PRIMARY → cool for the longer wall.
	wk := http.Header{
		"X-Codex-Primary-Used-Percent":         {"100"},
		"X-Codex-Primary-Reset-After-Seconds":  {"3600"},
		"X-Codex-Secondary-Used-Percent":       {"100"},
		"X-Codex-Secondary-Reset-After-Seconds": {"120"},
	}
	if until, ok := cooldownDecision(resp(429, wk), now); !ok || until != now.Add(3600*time.Second) {
		t.Fatalf("codex both-exhausted 429 must cool for the longer reset (3600s), got until=%v ok=%v", until, ok)
	}

	// D9 REGRESSION (bugfix 2026-07-06-codex-ratelimit-reset-window-by-name): both
	// windows exhausted, but the LONGER wall is the SECONDARY window. The old code
	// returned the PRIMARY reset first (assuming primary=7d) and under-cooled to
	// the shorter wall → re-429. Must cool for the longer reset (1800s) regardless
	// of which window is named primary/secondary.
	bugBothExhaustedLongerSecondary := http.Header{
		"X-Codex-Primary-Used-Percent":         {"100"},
		"X-Codex-Primary-Reset-After-Seconds":  {"120"}, // 5h — shorter
		"X-Codex-Secondary-Used-Percent":       {"100"},
		"X-Codex-Secondary-Reset-After-Seconds": {"1800"}, // 7d — longer, MUST win
	}
	if until, ok := cooldownDecision(resp(429, bugBothExhaustedLongerSecondary), now); !ok || until != now.Add(1800*time.Second) {
		t.Fatalf("D9: both-exhausted must cool for the LONGER reset (1800s) regardless of primary/secondary name, got until=%v ok=%v", until, ok)
	}

	// 429 but neither window at 100% → cool for the larger visible reset.
	partial := http.Header{
		"X-Codex-Primary-Used-Percent":         {"80"},
		"X-Codex-Primary-Reset-After-Seconds":  {"200"},
		"X-Codex-Secondary-Used-Percent":       {"90"},
		"X-Codex-Secondary-Reset-After-Seconds": {"50"},
	}
	if until, ok := cooldownDecision(resp(429, partial), now); !ok || until != now.Add(200*time.Second) {
		t.Fatalf("codex sub-100%% 429 must cool for the larger reset (200s), got until=%v ok=%v", until, ok)
	}

	// A codex 429 whose reset exceeds the cap is clamped.
	huge := http.Header{
		"X-Codex-Primary-Used-Percent":        {"100"},
		"X-Codex-Primary-Reset-After-Seconds": {"999999"},
	}
	if until, _ := cooldownDecision(resp(429, huge), now); until != now.Add(poolCooldownMax) {
		t.Fatalf("oversized codex reset must be capped at max, got %v", until)
	}
}

func TestPoolCooldownStore_Snapshot(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	s := &poolCooldownStore{m: map[string]time.Time{}, now: func() time.Time { return now }}

	if s.snapshot() != nil {
		t.Fatal("empty store → nil snapshot (health shows nothing cooled)")
	}
	s.mark("acc-a", now.Add(90*time.Second))
	if snap := s.snapshot(); snap["acc-a"] != 90 {
		t.Fatalf("acc-a should show ~90s remaining, got %d", snap["acc-a"])
	}
	// Advance past the cooldown → dropped from the snapshot.
	now = now.Add(2 * time.Minute)
	if s.snapshot() != nil {
		t.Fatal("lapsed cooldown must drop from the health snapshot")
	}
}

func TestPoolCooldownStore_MarkAndExpire(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	s := &poolCooldownStore{m: map[string]time.Time{}, now: func() time.Time { return now }}

	if len(s.skipSet()) != 0 {
		t.Fatal("empty store → empty skip set")
	}
	s.mark("acc-a", now.Add(5*time.Minute))
	s.mark("", now.Add(time.Hour)) // empty id → ignored
	if skip := s.skipSet(); !skip["acc-a"] || len(skip) != 1 {
		t.Fatalf("acc-a must be cooling down, got %v", skip)
	}

	// A longer mark extends; a shorter one does not shrink.
	s.mark("acc-a", now.Add(time.Minute))
	// Advance 2 min: still within the original 5-min window.
	now = now.Add(2 * time.Minute)
	if !s.skipSet()["acc-a"] {
		t.Fatal("longer cooldown must not be shortened by a later shorter mark")
	}
	// Advance past 5 min → lapses + is dropped.
	now = now.Add(4 * time.Minute)
	if s.skipSet()["acc-a"] {
		t.Fatal("lapsed cooldown must be dropped")
	}
	if len(s.m) != 0 {
		t.Fatalf("lapsed entry must be pruned, map still has %d", len(s.m))
	}
}
