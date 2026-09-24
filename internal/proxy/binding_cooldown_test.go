package proxy

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TestBindingCooldown_CodexTemporary429UsesBindingFallback pins the SECOND
// caller of cooldownDecisionWithTemporaryFallback. Binding failover reuses the
// account axis's evidence (Retry-After, a concrete window reset) under its own
// administrator ceiling, and keeps its historical 30-second fallback when there
// is none. A codex 429 with both windows below 100% carries no concrete reset:
// until 2026-09-24 the codex branch still offered the longer visible reset
// (capped at one hour) as evidence, so every such 429 cooled the hop for the
// whole ceiling (5 minutes by default) instead of 30 seconds or Retry-After.
// spec: R-oauth-account-pool-4 a 429 must tell window exhaustion from a temporary limit
// bugfix: workflow/CI/bugfix/2026-09-24-codex-sub100-429-overcool.md
func TestBindingCooldown_CodexTemporary429UsesBindingFallback(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	codex := func(primaryUsed, primaryReset, secondaryUsed, secondaryReset int) http.Header {
		return http.Header{
			"X-Codex-Primary-Used-Percent":          {strconv.Itoa(primaryUsed)},
			"X-Codex-Primary-Reset-After-Seconds":   {strconv.Itoa(primaryReset)},
			"X-Codex-Secondary-Used-Percent":        {strconv.Itoa(secondaryUsed)},
			"X-Codex-Secondary-Reset-After-Seconds": {strconv.Itoa(secondaryReset)},
		}
	}
	notFullRetryAfter := codex(80, 7200, 40, 400000)
	notFullRetryAfter.Set("Retry-After", "20")

	cases := []struct {
		name   string
		header http.Header
		want   time.Duration
	}{
		{"window-not-full/no-retry-after", codex(80, 7200, 40, 400000), 30 * time.Second},
		{"window-not-full/retry-after", notFullRetryAfter, 20 * time.Second},
		{"window-full", codex(100, 120, 40, 400000), 120 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newBindingCooldownStore()
			until, cooled := store.note("binding-codex", http.StatusTooManyRequests, tc.header, cooldownForTest(), now)
			if !cooled {
				t.Fatal("a codex 429 carrying usage evidence must start a binding cooldown")
			}
			if got := until.Sub(now); got != tc.want {
				t.Fatalf("binding cooldown = %v, want %v", got, tc.want)
			}
		})
	}
}
