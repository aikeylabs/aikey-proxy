package proxy

import (
	"bytes"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// resp builds a synthetic response for the cooldown classifiers, which read only
// StatusCode and Header. There is no Body and no transport ever produced this
// value, so the bodyclose findings against call sites below are false positives —
// suppressed individually rather than here, because bodyclose reports at the call
// site and a directive on this function does not reach it. Note it fires on only
// three of the ~a dozen resp() calls in this file, which is itself the tell.
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

	// A temporary aggregate rate-limit is NOT evidence that either quota window
	// is exhausted. The aggregate reset can point hours ahead even while both
	// concrete windows remain allowed and below 100%; using it here strands a
	// healthy account. Honor the provider's short Retry-After instead.
	temporaryWithFarAggregateReset := http.Header{
		"Anthropic-Ratelimit-Unified-Status":         {"rate_limited"},
		"Anthropic-Ratelimit-Unified-Reset":          {strconv.FormatInt(now.Add(3*time.Hour).Unix(), 10)},
		"Anthropic-Ratelimit-Unified-5h-Status":      {"allowed"},
		"Anthropic-Ratelimit-Unified-5h-Utilization": {"0.42"},
		"Anthropic-Ratelimit-Unified-7d-Status":      {"allowed"},
		"Anthropic-Ratelimit-Unified-7d-Utilization": {"0.57"},
		"Retry-After": {"2"},
	}
	if until, ok := cooldownDecision(resp(429, temporaryWithFarAggregateReset), now); !ok || until != now.Add(2*time.Second) { //nolint:bodyclose // synthetic response: no Body, no transport — nothing to close
		t.Fatalf("temporary aggregate 429 must honor Retry-After instead of the far aggregate reset, got until=%v ok=%v", until, ok)
	}
	state := cooldownRouteState(resp(429, temporaryWithFarAggregateReset), now, now.Add(2*time.Second)) //nolint:bodyclose // synthetic response: no Body, no transport — nothing to close
	if state.Status != poolRouteRateLimited || state.RetryAt != now.Add(2*time.Second).Unix() {
		t.Fatalf("temporary aggregate 429 must remain rate_limited with the short retry, got %+v", state)
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

func TestCooldownDecision_TemporaryFallbackIsPoolConfigurable(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	temporary := http.Header{"Anthropic-Ratelimit-Unified-Status": {"rate_limited"}}

	if until, ok := cooldownDecisionWithTemporaryFallback(resp(429, temporary), now, 11*time.Second); !ok || until != now.Add(11*time.Second) { //nolint:bodyclose // synthetic response: no Body, no transport — nothing to close
		t.Fatalf("temporary 429 must use the pool fallback, got until=%v ok=%v", until, ok)
	}
	withRetryAfter := temporary.Clone()
	withRetryAfter.Set("Retry-After", "23")
	if until, ok := cooldownDecisionWithTemporaryFallback(resp(429, withRetryAfter), now, 11*time.Second); !ok || until != now.Add(23*time.Second) { //nolint:bodyclose // synthetic response: no Body, no transport — nothing to close
		t.Fatalf("Retry-After must override the pool fallback, got until=%v ok=%v", until, ok)
	}
	resetAt := now.Add(4 * time.Minute)
	withWindowReset := temporary.Clone()
	withWindowReset.Set("Anthropic-Ratelimit-Unified-5h-Status", "exhausted")
	withWindowReset.Set("Anthropic-Ratelimit-Unified-5h-Reset", strconv.FormatInt(resetAt.Unix(), 10))
	if until, ok := cooldownDecisionWithTemporaryFallback(resp(429, withWindowReset), now, 11*time.Second); !ok || until != resetAt { //nolint:bodyclose // synthetic response: no Body, no transport — nothing to close
		t.Fatalf("exhausted-window reset must override the pool fallback, got until=%v ok=%v", until, ok)
	}
}

func TestGroupTemporaryRateLimitCooldown(t *testing.T) {
	for _, routingConfig := range []string{"", `{}`, `{"protocol":"anthropic"}`} {
		got, err := groupTemporaryRateLimitCooldown(routingConfig)
		if err != nil || got != 5*time.Second {
			t.Fatalf("routing_config=%q: got=%v err=%v, want 5s", routingConfig, got, err)
		}
	}
	got, err := groupTemporaryRateLimitCooldown(`{"protocol":"anthropic","temporary_rate_limit_cooldown_seconds":17}`)
	if err != nil || got != 17*time.Second {
		t.Fatalf("custom pool cooldown: got=%v err=%v, want 17s", got, err)
	}
	for _, routingConfig := range []string{
		`{"temporary_rate_limit_cooldown_seconds":0}`,
		`{"temporary_rate_limit_cooldown_seconds":3601}`,
		`not-json`,
	} {
		got, err := groupTemporaryRateLimitCooldown(routingConfig)
		if err == nil || got != poolCooldown429NoReset {
			t.Fatalf("invalid routing_config=%q: got=%v err=%v, want default plus error", routingConfig, got, err)
		}
	}
}

func TestGroupTemporaryRateLimitCooldown_InvalidConfigWarnsOnlyOn429(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	got := groupTemporaryRateLimitCooldownForResponse(
		http.StatusTooManyRequests,
		`{"temporary_rate_limit_cooldown_seconds":0}`,
		"group-test",
		logger,
	)
	if got != poolCooldown429NoReset {
		t.Fatalf("invalid policy fallback=%v, want %v", got, poolCooldown429NoReset)
	}
	for _, fragment := range []string{
		observability.EventProxyGroupRoutingConfigInvalid,
		"oauth_group_id=group-test",
		"between 1 and 3600",
	} {
		if !strings.Contains(logs.String(), fragment) {
			t.Fatalf("WARN log %q missing %q", logs.String(), fragment)
		}
	}

	logs.Reset()
	_ = groupTemporaryRateLimitCooldownForResponse(
		http.StatusOK,
		`{"temporary_rate_limit_cooldown_seconds":0}`,
		"group-test",
		logger,
	)
	if logs.Len() != 0 {
		t.Fatalf("non-429 response must not parse or log the pool cooldown policy: %s", logs.String())
	}
}

func TestCooldownRouteState_WindowExhaustedCarriesProviderReset(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	resetAt := now.Add(3 * time.Hour)
	h := http.Header{
		"Anthropic-Ratelimit-Unified-Status":         {"exceeded"},
		"Anthropic-Ratelimit-Unified-5h-Utilization": {"1.0"},
		"Anthropic-Ratelimit-Unified-5h-Reset":       {strconv.FormatInt(resetAt.Unix(), 10)},
	}
	// Routing caps the local cooldown to one hour, while the display must still
	// name the provider's actual three-hour window boundary.
	state := cooldownRouteState(resp(http.StatusTooManyRequests, h), now, now.Add(poolCooldownMax))
	if state.Status != poolRouteWindowExhausted || state.RetryAt != resetAt.Unix() {
		t.Fatalf("window state = %+v, want exhausted reset=%d", state, resetAt.Unix())
	}

	transient := cooldownRouteState(
		resp(http.StatusTooManyRequests, http.Header{"Retry-After": {"30"}}),
		now, now.Add(30*time.Second))
	if transient.Status != poolRouteRateLimited || transient.RetryAt != now.Add(30*time.Second).Unix() {
		t.Fatalf("transient 429 must not masquerade as exhausted: %+v", transient)
	}
}

// P0-B fence (2026-07-19): generic HTTP 5xx responses cool an account only
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
		"X-Codex-Secondary-Used-Percent":        {"100"},
		"X-Codex-Secondary-Reset-After-Seconds": {"300"},
		"X-Codex-Primary-Used-Percent":          {"40"},
		"X-Codex-Primary-Reset-After-Seconds":   {"600000"},
	}
	if until, ok := cooldownDecision(resp(429, sec), now); !ok || until != now.Add(300*time.Second) {
		t.Fatalf("codex one-window-exhausted 429 must cool for that window's reset (300s), got until=%v ok=%v", until, ok)
	}

	// Both windows exhausted, LONGER reset is on PRIMARY → cool for the longer wall.
	wk := http.Header{
		"X-Codex-Primary-Used-Percent":          {"100"},
		"X-Codex-Primary-Reset-After-Seconds":   {"3600"},
		"X-Codex-Secondary-Used-Percent":        {"100"},
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
		"X-Codex-Primary-Used-Percent":          {"100"},
		"X-Codex-Primary-Reset-After-Seconds":   {"120"}, // 5h — shorter
		"X-Codex-Secondary-Used-Percent":        {"100"},
		"X-Codex-Secondary-Reset-After-Seconds": {"1800"}, // 7d — longer, MUST win
	}
	if until, ok := cooldownDecision(resp(429, bugBothExhaustedLongerSecondary), now); !ok || until != now.Add(1800*time.Second) {
		t.Fatalf("D9: both-exhausted must cool for the LONGER reset (1800s) regardless of primary/secondary name, got until=%v ok=%v", until, ok)
	}

	// 429 but neither window at 100% → cool for the larger visible reset.
	partial := http.Header{
		"X-Codex-Primary-Used-Percent":          {"80"},
		"X-Codex-Primary-Reset-After-Seconds":   {"200"},
		"X-Codex-Secondary-Used-Percent":        {"90"},
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

func TestAuthFailureTombstone_IsolatedByGroupAndSeat(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	key := grKey()
	accountID := "shared-pool-account"
	store := newPoolCooldownStore()
	t.Cleanup(store.flushPersistence)
	store.markAuthFailedToken("group-1", "seat-a", accountID, oauthTokenFingerprint("seat-a-old-token"))

	seatARuntime := mustJSON(t, map[string]vkeys.GroupRuntimeAccount{
		accountID: encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account"}, "seat-a-old-token"),
	})
	seatBRuntime := mustJSON(t, map[string]vkeys.GroupRuntimeAccount{
		accountID: encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account"}, "seat-b-healthy-token"),
	})
	if !store.authFailureSkipSet("group-1", "seat-a", seatARuntime, key)[accountID] {
		t.Fatal("revoked member route was not blocked")
	}
	if store.authFailureSkipSet("group-1", "seat-b", seatBRuntime, key)[accountID] {
		t.Fatal("one member's revoked token blocked another seat using the same pool account")
	}
	if store.authFailureSkipSet("group-2", "seat-a", seatARuntime, key)[accountID] {
		t.Fatal("one group's revoked token blocked another group")
	}
	snapshot := store.authFailureSnapshot()
	if len(snapshot) != 1 || snapshot[0].OAuthGroupID != "group-1" || snapshot[0].SeatID != "seat-a" || snapshot[0].AccountID != accountID {
		t.Fatalf("auth failure health scope lost: %+v", snapshot)
	}

	seatANewRuntime := mustJSON(t, map[string]vkeys.GroupRuntimeAccount{
		accountID: encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account"}, "seat-a-new-token"),
	})
	if store.authFailureSkipSet("group-1", "seat-a", seatANewRuntime, key)[accountID] {
		t.Fatal("new token version inherited the old member tombstone")
	}
	if len(store.authFailureSnapshot()) != 0 {
		t.Fatalf("new token version did not clear scoped tombstone: %+v", store.authFailureSnapshot())
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

func TestPoolCooldownStore_EarliestRetryAfterSeconds(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	now := time.Unix(1_750_000_000, 500_000_000)
	s := &poolCooldownStore{m: map[string]time.Time{}, now: func() time.Time { return now }}
	s.mark("route-later", now.Add(5*time.Second))
	s.mark("route-earlier", now.Add(1500*time.Millisecond))
	s.mark("other-route", now.Add(time.Second))

	seconds, ok := s.earliestRetryAfterSeconds(
		map[string]bool{"route-later": true, "route-earlier": true},
		map[string]bool{"route-later": true, "route-earlier": true, "other-route": true},
	)
	if !ok || seconds != 2 {
		t.Fatalf("earliest route cooldown must round 1.5s up to 2s, got seconds=%d ok=%v", seconds, ok)
	}
}

// Regression fence (2026-07-22): current_routed already used the same
// cooldown-aware picker as the hot path, but the display stamp stayed stale
// because a cooldown mutation never woke the supervisor. The hook is about
// WHOLE-ACCOUNT skip-set membership, not timestamps: entering and expiring
// notify; extending an active cooldown and model-tier-only cooldowns do not.
func TestPoolCooldownStore_AccountSetChangeHook(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	now := time.Unix(1_750_000_000, 0)
	s := &poolCooldownStore{
		m:               map[string]time.Time{},
		tierM:           map[string]time.Time{},
		serverErrStreak: map[string]int{},
		now:             func() time.Time { return now },
	}
	var calls atomic.Int32
	s.setAccountSetChangedHook(func() { calls.Add(1) })

	s.mark("acc-a", now.Add(5*time.Minute))
	if got := calls.Load(); got != 1 {
		t.Fatalf("entering cooldown must notify once, got %d", got)
	}
	// Neither a shorter no-op nor a longer extension changes skip membership.
	s.mark("acc-a", now.Add(time.Minute))
	s.mark("acc-a", now.Add(10*time.Minute))
	s.mark("acc-past", now.Add(-time.Second))
	if got := calls.Load(); got != 1 {
		t.Fatalf("cooldown timestamp updates must not restamp, got %d notifications", got)
	}
	// A tier-specific cool affects only some models and cannot be projected into
	// the model-agnostic current_routed boolean.
	s.markTier("acc-a", "premium", now.Add(time.Hour))
	if got := calls.Load(); got != 1 {
		t.Fatalf("tier cooldown must not notify current_routed, got %d", got)
	}

	now = now.Add(11 * time.Minute)
	_ = s.skipSet() // lazy expiry is the membership-removal edge
	if got := calls.Load(); got != 2 {
		t.Fatalf("cooldown expiry must notify once, got %d", got)
	}

	for i := 0; i < serverErrStreakThreshold; i++ {
		_, _ = s.noteServerError("acc-b")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("5xx streak entering cooldown must notify once, got %d", got)
	}
}
