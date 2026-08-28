package proxy

// P1-C fences (2026-07-19): model-tier-scoped cooldown for the Fable 7d_oi
// weekly window — a premium-model exhaustion must not block the account (or the
// pool) for other models, and the user must be TOLD to switch model. Wire
// format per sub2api production code (research doc 三期).

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAnthropicWindowExhausted(t *testing.T) {
	h := func(kv ...string) http.Header {
		out := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			out.Set(kv[i], kv[i+1])
		}
		return out
	}
	cases := []struct {
		name   string
		header http.Header
		window string
		want   bool
	}{
		{"7d_oi status rejected", h("Anthropic-Ratelimit-Unified-7d_oi-Status", "rejected"), "7d_oi", true},
		{"7d_oi util 1.0", h("Anthropic-Ratelimit-Unified-7d_oi-Utilization", "1.0"), "7d_oi", true},
		{"7d_oi util float-noise ~1.0", h("Anthropic-Ratelimit-Unified-7d_oi-Utilization", "0.9999999999"), "7d_oi", true},
		{"7d_oi util under", h("Anthropic-Ratelimit-Unified-7d_oi-Utilization", "0.42"), "7d_oi", false},
		// sub2api-documented quirk: the 7d_oi surpassed-threshold carries a FLOAT
		// ("1.0"), never "true" — it must NOT satisfy the boolean surpassed check.
		{"7d_oi surpassed float quirk", h("Anthropic-Ratelimit-Unified-7d_oi-Surpassed-Threshold", "1.0"), "7d_oi", false},
		{"5h surpassed true", h("Anthropic-Ratelimit-Unified-5h-Surpassed-Threshold", "true"), "5h", true},
		{"5h clean", h("Anthropic-Ratelimit-Unified-5h-Utilization", "0.6"), "5h", false},
	}
	for _, c := range cases {
		if got := anthropicWindowExhausted(c.header, c.window); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestAnthropicTierOnlyLimit(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	reset := now.Add(3 * 24 * time.Hour)

	// tier window exhausted alone → tier-only, cooled until the 7d_oi reset.
	h := http.Header{
		"Anthropic-Ratelimit-Unified-7d_oi-Status":   {"rejected"},
		"Anthropic-Ratelimit-Unified-7d_oi-Reset":    {strconv.FormatInt(reset.Unix(), 10)},
		"Anthropic-Ratelimit-Unified-5h-Utilization": {"0.4"},
	}
	until, tier, ok := anthropicTierOnlyLimit(h, now)
	if !ok || tier != "fable" || !until.Equal(reset) {
		t.Fatalf("tier-only limit expected (fable until %v), got until=%v tier=%q ok=%v", reset, until, tier, ok)
	}

	// DUAL exhaustion (7d_oi + general 5h) → NOT tier-only: the stronger
	// whole-account path must own it.
	h.Set("Anthropic-Ratelimit-Unified-5h-Utilization", "1.0")
	if _, _, ok := anthropicTierOnlyLimit(h, now); ok {
		t.Fatal("dual exhaustion must not classify as tier-only")
	}

	// DUAL exhaustion via the general WEEKLY window (7d_oi + 7d, 5h healthy) —
	// the guard's `"7d"` branch, untested before the 2026-08-19 coverage audit.
	// Misclassifying this as tier-only would only cool the fable scope and keep
	// routing Sonnet/Opus traffic to a fully rate-limited account.
	hWeekly := http.Header{
		"Anthropic-Ratelimit-Unified-7d_oi-Status":   {"rejected"},
		"Anthropic-Ratelimit-Unified-5h-Utilization": {"0.4"},
		"Anthropic-Ratelimit-Unified-7d-Utilization": {"1.0"},
	}
	if _, _, ok := anthropicTierOnlyLimit(hWeekly, now); ok {
		t.Fatal("7d_oi + general 7d dual exhaustion must not classify as tier-only")
	}

	// reset falls back to the aggregate unified-reset; milliseconds auto-detect.
	h2 := http.Header{
		"Anthropic-Ratelimit-Unified-7d_oi-Utilization": {"1.0"},
		"Anthropic-Ratelimit-Unified-Reset":             {strconv.FormatInt(reset.UnixMilli(), 10)},
	}
	until2, _, ok2 := anthropicTierOnlyLimit(h2, now)
	if !ok2 || !until2.Equal(reset) {
		t.Fatalf("aggregate-reset fallback (ms) expected until=%v, got until=%v ok=%v", reset, until2, ok2)
	}
}

func TestUnknownExhaustedWindows(t *testing.T) {
	h := http.Header{
		"Anthropic-Ratelimit-Unified-5h-Utilization":   {"1.0"},          // known
		"Anthropic-Ratelimit-Unified-7d_oi-Status":     {"rejected"},     // known tier
		"Anthropic-Ratelimit-Unified-9d_x-Utilization": {"1.0"},          // future window → surfaced
		"Anthropic-Ratelimit-Unified-Status":           {"rate_limited"}, // aggregate → ignored
	}
	got := unknownExhaustedWindows(h)
	if len(got) != 1 || got[0] != "9d_x" {
		t.Fatalf("want [9d_x], got %v", got)
	}
}

func TestTierForModel(t *testing.T) {
	if tier := tierForModel("claude-fable-5"); tier == nil || tier.Key != "fable" {
		t.Fatalf("claude-fable-5 must map to the fable tier, got %+v", tier)
	}
	if tier := tierForModel("claude-fable-5[1m]"); tier == nil || tier.Key != "fable" {
		t.Fatalf("[1m] variant must map to the fable tier, got %+v", tier)
	}
	if tier := tierForModel("claude-sonnet-4-5"); tier != nil {
		t.Fatalf("sonnet is standard tier, got %+v", tier)
	}
	if tier := tierForModel(""); tier != nil {
		t.Fatalf("empty model is standard tier, got %+v", tier)
	}
}

func TestPoolCooldownStore_TierScope(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	s := &poolCooldownStore{m: map[string]time.Time{}, now: func() time.Time { return now }}

	s.markTier("acc-a", "fable", now.Add(48*time.Hour))

	// fable requests skip the account; other models (and the base set) don't.
	if !s.skipSetFor("claude-fable-5")["acc-a"] {
		t.Fatal("fable request must skip the tier-cooled account")
	}
	if s.skipSetFor("claude-sonnet-4-5")["acc-a"] {
		t.Fatal("sonnet request must NOT skip a fable-tier-cooled account")
	}
	if s.skipSet()["acc-a"] {
		t.Fatal("tier cooldown must not leak into the whole-account skip set")
	}
	if until, ok := s.tierCooldownUntil("fable"); !ok || until != now.Add(48*time.Hour) {
		t.Fatalf("tierCooldownUntil mismatch: %v %v", until, ok)
	}

	// lapse → gone everywhere.
	now = now.Add(49 * time.Hour)
	if s.skipSetFor("claude-fable-5")["acc-a"] {
		t.Fatal("lapsed tier cooldown must drop")
	}
	if _, ok := s.tierCooldownUntil("fable"); ok {
		t.Fatal("lapsed tier cooldown must not report a reset horizon")
	}
}

// Integration: a Fable-only 429 tier-cools the account — Fable traffic fails
// over / gets guided, while Sonnet traffic KEEPS USING the same account.
func TestGroupModelTier_FableExhaustionDoesNotBlockOtherModels(t *testing.T) {
	p, tr := singleAccountPool(t)

	fableBody := `{"model":"claude-fable-5","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`
	reset := time.Now().Add(72 * time.Hour)
	tr.respHeader = http.Header{
		"Anthropic-Ratelimit-Unified-7d_oi-Status": {"rejected"},
		"Anthropic-Ratelimit-Unified-7d_oi-Reset":  {strconv.FormatInt(reset.Unix(), 10)},
	}
	tr.statusByAuth = map[string]int{"Bearer tok-1": http.StatusTooManyRequests}

	// Fable request 1: upstream 429 (7d_oi exhausted) → tier cooldown lands;
	// single-account pool so the client sees the flushed 429.
	req, w := groupReq(fableBody)
	p.Handle(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("single-account fable 429 flushes through, got %d", w.Code)
	}
	if p.poolCooldown.skipSet()["acc-1"] {
		t.Fatal("tier-only 429 must NOT whole-account cool (Sonnet would be blocked too)")
	}

	// Sonnet request on the SAME account: skip set for sonnet is empty → serves.
	tr.statusByAuth = nil
	tr.status = 0
	tr.calls = 0
	req2, w2 := groupReq(groupBody)
	p.Handle(w2, req2)
	if w2.Code != http.StatusOK || tr.calls != 1 {
		t.Fatalf("sonnet must keep serving on the tier-cooled account, got %d (calls=%d)", w2.Code, tr.calls)
	}

	// Fable request 2: the account is tier-skipped → ZERO upstream attempts and
	// the client gets the Phase-2 guidance (429 + MODEL_TIER_EXHAUSTED + switch
	// hint), not the misleading "all accounts unavailable".
	tr.calls = 0
	req3, w3 := groupReq(fableBody)
	p.Handle(w3, req3)
	if tr.calls != 0 {
		t.Fatalf("tier-cooled account must not be attempted for fable, got %d calls", tr.calls)
	}
	if w3.Code != http.StatusTooManyRequests {
		t.Fatalf("tier-exhausted guidance is a 429, got %d", w3.Code)
	}
	body := w3.Body.String()
	if !strings.Contains(body, "MODEL_TIER_EXHAUSTED") || !strings.Contains(body, "switch your model") {
		t.Fatalf("guidance must carry the code and the switch-model hint, got %s", body)
	}
}

// Integration: DUAL exhaustion (7d_oi + general 5h) is a whole-account limit —
// tier scoping must not weaken it.
func TestGroupModelTier_DualExhaustionCoolsWholeAccount(t *testing.T) {
	p, tr := singleAccountPool(t)
	reset := time.Now().Add(2 * time.Hour)
	tr.respHeader = http.Header{
		"Anthropic-Ratelimit-Unified-7d_oi-Status":   {"rejected"},
		"Anthropic-Ratelimit-Unified-5h-Utilization": {"1.0"},
		"Anthropic-Ratelimit-Unified-5h-Reset":       {strconv.FormatInt(reset.Unix(), 10)},
	}
	tr.status = http.StatusTooManyRequests
	req, w := groupReq(`{"model":"claude-fable-5","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`)
	p.Handle(w, req)
	_ = w
	if !p.poolCooldown.skipSet()["acc-1"] {
		t.Fatal("dual exhaustion must whole-account cool")
	}
}

// Integration: with a second account available, a Fable-only 429 on the primary
// fails over IN-REQUEST — the fable user still gets a 200.
func TestGroupModelTier_FableFailsOverToAccountWithHeadroom(t *testing.T) {
	p, tr, tokToAcct := twoAccountPool(t)
	fableBody := `{"model":"claude-fable-5","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`
	_, ptok := probePrimary(t, p, tr, tokToAcct)

	tr.respHeader = http.Header{"Anthropic-Ratelimit-Unified-7d_oi-Status": {"rejected"}}
	tr.statusByAuth = map[string]int{"Bearer " + ptok: http.StatusTooManyRequests}
	req, w := groupReq(fableBody)
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("fable request must fail over to the account with tier headroom, got %d: %s", w.Code, w.Body.String())
	}
	if tr.calls != 2 {
		t.Fatalf("want 2 upstream attempts, got %d", tr.calls)
	}
}
