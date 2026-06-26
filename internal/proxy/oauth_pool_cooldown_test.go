package proxy

import (
	"net/http"
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

	// 429 WITH a rate-limit signal → cool down.
	rl := http.Header{"Anthropic-Ratelimit-Reset": {"123"}}
	if _, ok := cooldownDecision(resp(429, rl), now); !ok {
		t.Fatal("exhaustion 429 (rate-limit header) must cool down")
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

	// 429 WITHOUT any rate-limit signal = WAF business rejection → NOT the
	// account's fault, do not cool it down.
	if _, ok := cooldownDecision(resp(429, nil), now); ok {
		t.Fatal("WAF 429 (no rate-limit signal) must NOT cool down the account")
	}

	// Success / other → no cooldown.
	if _, ok := cooldownDecision(resp(200, nil), now); ok {
		t.Fatal("200 must not cool down")
	}
	if _, ok := cooldownDecision(resp(500, nil), now); ok {
		t.Fatal("500 must not cool down (transient upstream, not account-specific)")
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
