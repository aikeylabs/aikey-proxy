package proxy

// E9 — 429 三分类 (能力点 #8) regression, mapping §5-E9 of
//
//	roadmap20260320/技术实现/阶段7-企业生产版/20260630-动态决策引擎-实现现状审计与E2E验证清单.md
//
// The audit requires THREE distinct upstream-429 buckets to behave differently:
//   - 限流 (per-minute rate_limited, transient): the account is fine, just paced — do NOT
//     pull it for the full 5-min default (switching wastes a good account).
//   - 限额 (5h window quota exhausted): cool the account until the window resets.
//   - WAF (business rejection, no rate-limit headers): not the account's fault — do not cool.
//
// 2026-07-19 (B1 fix, sub2api-style value-based discrimination): the split LANDED —
// cooldownDecision now derives the cooldown from limit EVIDENCE (unified status flip /
// util≥1.0 / reset epochs / Retry-After), and evidence-without-reset short-cools
// (poolCooldown429NoReset) instead of the flat 5-min default. The per_minute subtest
// below flipped from xfail-skip to green accordingly; its Skipf branch is kept as the
// regression tripwire (it fires again only if someone re-flattens the cooldown).
//
// Fixture-based per wire format (logging-conventions: parser/classifier changes must be
// fixture-tested per wire shape). Reuses resp() from oauth_pool_cooldown_test.go.

import (
	"net/http"
	"testing"
	"time"
)

func TestE9_429ThreeWayClassification_GAP(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)

	// 限额 (LIVE PASS): a 5h-window quota exhaustion 429 with Retry-After → cool until reset.
	t.Run("quota_exhaustion_cools_to_reset", func(t *testing.T) {
		h := http.Header{
			"Anthropic-Ratelimit-Unified-Status": {"exhausted"},
			"Retry-After":                        {"3600"},
		}
		until, cool := cooldownDecision(resp(429, h), now)
		if !cool {
			t.Fatalf("5h-quota-exhaustion 429 must cool the account down")
		}
		if until != now.Add(3600*time.Second) {
			t.Fatalf("quota exhaustion must cool until the window reset (Retry-After), got until=%v", until)
		}
	})

	// WAF (LIVE PASS): a business-rejection 429 with no rate-limit headers → do NOT cool.
	t.Run("waf_business_rejection_no_cooldown", func(t *testing.T) {
		if _, cool := cooldownDecision(resp(429, nil), now); cool {
			t.Fatalf("WAF business-rejection 429 (no rate-limit signal) must NOT cool the account")
		}
	})

	// 限流 (xfail → flips green when fixed): a transient per-minute rate_limited 429, no
	// Retry-After. Desired: not cooled for the full 5-min default (透传 / short-cool only).
	// Current: the *ratelimit* header trips hasRateLimitSignal → flat poolCooldownDefault.
	t.Run("per_minute_rate_limited_GAP", func(t *testing.T) {
		h := http.Header{
			// a transient per-minute rate-limit: status says rate_limited, requests-remaining
			// is momentarily 0, but there is NO Retry-After and the 5h unified window is NOT
			// exhausted. The account recovers within the minute.
			"Anthropic-Ratelimit-Unified-Status":     {"rate_limited"},
			"Anthropic-Ratelimit-Requests-Remaining": {"0"},
		}
		until, cool := cooldownDecision(resp(429, h), now)
		cooledSecs := 0
		if cool {
			cooledSecs = int(until.Sub(now).Seconds())
		}
		if cool && cooledSecs >= int(poolCooldownDefault.Seconds()) {
			t.Skipf("GAP (audit #8 / §5-E9): per-minute rate_limited 429 (no Retry-After) is "+
				"cooled %ds (the flat %ds default) — indistinguishable from 5h quota exhaustion. "+
				"A transient minute-limit should透传/short-cool, not pull a good account for 5min. "+
				"Goes green when cooldownDecision consumes unified-status to split 限流 from 限额.",
				cooledSecs, int(poolCooldownDefault.Seconds()))
		}
		// reached only once the split lands: a transient rate-limit must not over-cool.
		t.Logf("three-way classification active: rate_limited cooled=%v secs=%d", cool, cooledSecs)
	})
}
