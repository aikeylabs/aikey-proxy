// oauth_pool_model_tier.go — P1-C: model-tier-scoped rate limits (Fable 7d window).
//
// Anthropic subscription limits are LAYERED: besides the general 5h and 7d
// windows there is a premium-model-only weekly window — the Fable family's
// `anthropic-ratelimit-unified-7d_oi-*` (wire format verified by sub2api
// production code, see research/2026-07-19-sub2api-池生命周期与429分类-对照研读.md
// 三期). When ONLY that window is exhausted the account is still perfectly
// usable for every other model — cooling the whole account (what the generic
// evidence path would do, since the aggregate unified-status mirrors the
// representative claim) blocked Sonnet traffic too and, through in-request
// failover, could cascade a whole pool offline for ALL models because one
// model family's weekly budget ran out.
//
// This module classifies a 429 into "tier-only" vs "general" exhaustion and
// supplies the tier table. The cooldown store keeps tier-scoped entries
// (oauth_pool_cooldown.go); the resolver skips an account only for requests
// whose model maps into a cooled tier (group_serve.go).
//
// Tier table discipline (R44 精神: 未实证不写): only the Fable tier is listed —
// its window id and matcher mirror sub2api's live-verified behavior. The old
// design-doc mention of an `opus-7d` window id has NOT been observed in that
// verified source, so it is not mapped; unknownExhaustedWindows below logs any
// unmapped exhausted window id so the gap self-surfaces from production logs
// (this replaces the deferred burn-in probe — Phase 0 folded into post-deploy
// log verification, 用户拍板 2026-07-19).
package proxy

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// modelTier maps one premium model family to its dedicated upstream window.
type modelTier struct {
	// Key names the tier in cooldown scopes, logs and client messages.
	Key string
	// WindowID is the `anthropic-ratelimit-unified-<id>-*` header segment.
	WindowID string
	// Match reports whether a requested model belongs to this tier.
	Match func(model string) bool
}

// modelTiers is the single truth table for premium tiers. Extending it (e.g.
// a future opus-specific window) is one row — the detection, cooldown scoping,
// resolver filtering and client guidance all key off this table.
var modelTiers = []modelTier{
	{
		Key:      "fable",
		WindowID: "7d_oi",
		// name-contains matcher covers claude-fable-5, claude-fable-5[1m] and
		// future dated variants (mirrors sub2api's isAnthropicFableModel).
		Match: func(model string) bool { return strings.Contains(strings.ToLower(model), "fable") },
	},
}

// tierForModel returns the tier a requested model belongs to (nil for the
// standard tier — the general 5h/7d windows).
func tierForModel(model string) *modelTier {
	if model == "" {
		return nil
	}
	for i := range modelTiers {
		if modelTiers[i].Match(model) {
			return &modelTiers[i]
		}
	}
	return nil
}

// anthropicWindowExhausted reports whether ONE unified window shows concrete
// exhaustion evidence: per-window status flip, surpassed-threshold="true"
// (5h/7d carry a boolean; the 7d_oi variant carries a float and is therefore
// judged by status/utilization only — sub2api-documented wire quirk), or
// utilization at/over 1.0 (with an epsilon for float wire values).
func anthropicWindowExhausted(h http.Header, windowID string) bool {
	prefix := "anthropic-ratelimit-unified-" + windowID + "-"
	switch strings.ToLower(strings.TrimSpace(h.Get(prefix + "status"))) {
	case "rate_limited", "rejected", "exceeded", "exhausted":
		return true
	}
	if strings.EqualFold(strings.TrimSpace(h.Get(prefix+"surpassed-threshold")), "true") {
		return true
	}
	if v := strings.TrimSpace(h.Get(prefix + "utilization")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 1.0-1e-9 {
			return true
		}
	}
	return false
}

// anthropicWindowResetTime reads a window's reset epoch (seconds, with
// milliseconds auto-detected — sub2api-observed wire variance), falling back to
// the aggregate unified-reset (which mirrors the representative claim when the
// tier window IS the trigger). Zero time when nothing parses to the future.
func anthropicWindowResetTime(h http.Header, windowID string, now time.Time) time.Time {
	for _, key := range []string{
		"anthropic-ratelimit-unified-" + windowID + "-reset",
		"anthropic-ratelimit-unified-reset",
	} {
		v := strings.TrimSpace(h.Get(key))
		if v == "" {
			continue
		}
		epoch, err := strconv.ParseInt(v, 10, 64)
		if err != nil || epoch <= 0 {
			continue
		}
		if epoch > 1e12 { // milliseconds on the wire
			epoch /= 1000
		}
		if t := time.Unix(epoch, 0); t.After(now) {
			return t
		}
	}
	return time.Time{}
}

// anthropicTierOnlyLimit classifies a 429: when a premium tier's window is
// exhausted while NEITHER general window (5h/7d) is, the limit is TIER-ONLY —
// the caller must cool (account, tier), NOT the whole account (the sub2api
// "must not fall through" guard). Dual exhaustion (tier + a general window)
// returns nil so the stronger whole-account path handles it.
func anthropicTierOnlyLimit(h http.Header, now time.Time) (until time.Time, tierKey string, ok bool) {
	if anthropicWindowExhausted(h, "5h") || anthropicWindowExhausted(h, "7d") {
		return time.Time{}, "", false
	}
	for i := range modelTiers {
		t := &modelTiers[i]
		if !anthropicWindowExhausted(h, t.WindowID) {
			continue
		}
		until = anthropicWindowResetTime(h, t.WindowID, now)
		if until.IsZero() {
			until = now.Add(poolCooldownDefault) // no readable reset → conservative default
		}
		return until, t.Key, true
	}
	return time.Time{}, "", false
}

// unknownExhaustedWindows returns exhausted unified window ids this build does
// NOT map (not 5h/7d/known tiers) — the self-surfacing observability hook that
// replaces the burn-in probe: if the upstream ships a new per-model window, a
// WARN with its id appears in production logs and the tier table gains a row.
func unknownExhaustedWindows(h http.Header) []string {
	known := map[string]bool{"5h": true, "7d": true}
	for i := range modelTiers {
		known[modelTiers[i].WindowID] = true
	}
	var out []string
	seen := map[string]bool{}
	const pre = "anthropic-ratelimit-unified-"
	for k := range h {
		lk := strings.ToLower(k)
		if !strings.HasPrefix(lk, pre) {
			continue
		}
		rest := strings.TrimPrefix(lk, pre)
		// window id = up to the FIRST dash ("7d_oi-utilization" → "7d_oi";
		// "5h-surpassed-threshold" → "5h"); aggregate headers (unified-status /
		// unified-reset) have no dash and are skipped.
		idx := strings.Index(rest, "-")
		if idx <= 0 {
			continue
		}
		windowID := rest[:idx]
		if known[windowID] || seen[windowID] {
			continue
		}
		seen[windowID] = true
		if anthropicWindowExhausted(h, windowID) {
			out = append(out, windowID)
		}
	}
	return out
}
