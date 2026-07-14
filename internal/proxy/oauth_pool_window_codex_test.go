package proxy

import (
	"net/http"
	"testing"
	"time"
)

// TestWindowPreCutDecision_Codex pins the Codex branch of the N10 pre-cut against
// the real wire captured 2026-07-06 (research/oauth-codex-ratelimit/): X-Codex-*
// used-percent + absolute reset-at ride on the /responses 200. Pre-cut fires when
// any window ≥ the randomized cap, cooling until that window's OWN reset (latest
// among over-cap windows) — no 5h/7d classification, mirroring the D9 fix.
func TestWindowPreCutDecision_Codex(t *testing.T) {
	now := time.Unix(1_783_300_000, 0)
	const resetAt5h = int64(1_783_341_932) // future, ~5h out (from the live capture)
	const resetAt7d = int64(1_783_928_732) // further future, ~7d out

	hdr := func(kv map[string]string) http.Header {
		h := http.Header{}
		for k, v := range kv {
			h.Set(k, v)
		}
		return h
	}

	t.Run("below cap → no pre-cut", func(t *testing.T) {
		h := hdr(map[string]string{
			"X-Codex-Primary-Used-Percent":   "1",
			"X-Codex-Primary-Window-Minutes": "300",
			"X-Codex-Primary-Reset-At":       "1783341932",
			"X-Codex-Secondary-Used-Percent": "0",
		})
		if _, ok := windowPreCutDecision(h, 95, now); ok {
			t.Fatal("util below cap must not pre-cut")
		}
	})

	t.Run("at/over cap → pre-cut until that window reset-at", func(t *testing.T) {
		h := hdr(map[string]string{
			"X-Codex-Primary-Used-Percent": "96",
			"X-Codex-Primary-Reset-At":     "1783341932",
			"X-Codex-Secondary-Used-Percent": "0",
		})
		until, ok := windowPreCutDecision(h, 95, now)
		if !ok || !until.Equal(time.Unix(resetAt5h, 0)) {
			t.Fatalf("over-cap must pre-cut until reset-at %d, got until=%v ok=%v", resetAt5h, until, ok)
		}
	})

	t.Run("both windows over cap → cool until the LATER reset", func(t *testing.T) {
		h := hdr(map[string]string{
			"X-Codex-Primary-Used-Percent":   "100",
			"X-Codex-Primary-Reset-At":       "1783341932", // 5h (sooner)
			"X-Codex-Secondary-Used-Percent": "100",
			"X-Codex-Secondary-Reset-At":     "1783928732", // 7d (later) — must win
		})
		until, ok := windowPreCutDecision(h, 95, now)
		if !ok || !until.Equal(time.Unix(resetAt7d, 0)) {
			t.Fatalf("both-over must cool until the later reset %d, got until=%v ok=%v", resetAt7d, until, ok)
		}
	})

	t.Run("no absolute reset-at → falls back to now+reset-after-seconds", func(t *testing.T) {
		h := hdr(map[string]string{
			"X-Codex-Primary-Used-Percent":          "98",
			"X-Codex-Primary-Reset-After-Seconds":   "3600",
		})
		until, ok := windowPreCutDecision(h, 95, now)
		if !ok || !until.Equal(now.Add(3600*time.Second)) {
			t.Fatalf("relative fallback must cool now+3600s, got until=%v ok=%v", until, ok)
		}
	})

	t.Run("cap disabled (>=100) → never pre-cut", func(t *testing.T) {
		h := hdr(map[string]string{"X-Codex-Primary-Used-Percent": "100", "X-Codex-Primary-Reset-At": "1783341932"})
		if _, ok := windowPreCutDecision(h, 100, now); ok {
			t.Fatal("capPct>=100 means no meaningful cap")
		}
	})

	t.Run("anthropic path unchanged (no codex headers)", func(t *testing.T) {
		h := hdr(map[string]string{"anthropic-ratelimit-unified-5h-utilization": "0.96"})
		if _, ok := windowPreCutDecision(h, 95, now); !ok {
			t.Fatal("anthropic util over cap must still pre-cut (byte-identical path)")
		}
	})
}

// TestObservedResetEpoch_Codex pins the Path-Z re-roll signal for Codex: report
// the SOONEST future reset-at so master re-rolls the cap when the shorter window
// rolls over. Anthropic responses still return the anthropic reset unchanged.
func TestObservedResetEpoch_Codex(t *testing.T) {
	// Build headers with Set() so keys are canonicalized exactly as Go's HTTP
	// parser does for a real upstream response (a raw map literal would store a
	// non-canonical lowercase key that http.Header.Get can't find).
	codex := http.Header{}
	codex.Set("X-Codex-Primary-Reset-At", "1783341932") // soonest
	codex.Set("X-Codex-Secondary-Reset-At", "1783928732")
	if epoch, ok := observedResetEpoch(codex); !ok || epoch != 1783341932 {
		t.Fatalf("codex observed reset must be the soonest reset-at, got %d ok=%v", epoch, ok)
	}

	anthropic := http.Header{}
	anthropic.Set("anthropic-ratelimit-unified-reset", "1783341000")
	if epoch, ok := observedResetEpoch(anthropic); !ok || epoch != 1783341000 {
		t.Fatalf("anthropic path must be unchanged, got %d ok=%v", epoch, ok)
	}

	if _, ok := observedResetEpoch(http.Header{}); ok {
		t.Fatal("no reset headers → (0,false)")
	}
}
