package proxy

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

func hdr(kv map[string]string) http.Header {
	h := http.Header{}
	for k, v := range kv {
		h.Set(k, v)
	}
	return h
}

func TestWindowPreCutDecision(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	reset := now.Add(time.Hour)
	resetStr := strconv.FormatInt(reset.Unix(), 10)

	// 5h utilization at/over the cap → pre-cut, cool until the window reset.
	if until, ok := windowPreCutDecision(hdr(map[string]string{hdrUtil5h: "0.97", hdrReset: resetStr}), 96, now); !ok || !until.Equal(reset) {
		t.Fatalf("util 0.97 ≥ cap 96%% must pre-cut until reset, got until=%v ok=%v", until, ok)
	}
	// Under the cap → no pre-cut.
	if _, ok := windowPreCutDecision(hdr(map[string]string{hdrUtil5h: "0.50"}), 96, now); ok {
		t.Fatal("util under cap must not pre-cut")
	}
	// 7d window over the cap (5h fine) → pre-cut (either window triggers).
	if _, ok := windowPreCutDecision(hdr(map[string]string{hdrUtil5h: "0.10", hdrUtil7d: "0.99"}), 96, now); !ok {
		t.Fatal("7d util over cap must pre-cut")
	}
	// No utilization header at all → nothing to pre-cut on.
	if _, ok := windowPreCutDecision(hdr(map[string]string{hdrReset: resetStr}), 96, now); ok {
		t.Fatal("no utilization signal → no pre-cut")
	}
	// No meaningful cap (>=100 or <=0) → never pre-cut, even at high util.
	if _, ok := windowPreCutDecision(hdr(map[string]string{hdrUtil5h: "0.99"}), 100, now); ok {
		t.Fatal("cap>=100 → no pre-cut")
	}
	if _, ok := windowPreCutDecision(hdr(map[string]string{hdrUtil5h: "0.99"}), 0, now); ok {
		t.Fatal("cap<=0 → no pre-cut")
	}
	// Over cap but no reset header → conservative default cooldown.
	if until, ok := windowPreCutDecision(hdr(map[string]string{hdrUtil5h: "0.99"}), 96, now); !ok || !until.Equal(now.Add(poolCooldownDefault)) {
		t.Fatalf("missing reset → default cooldown, got %v", until)
	}
	// A past reset epoch must not yield a past cool-until.
	past := strconv.FormatInt(now.Add(-time.Hour).Unix(), 10)
	if until, _ := windowPreCutDecision(hdr(map[string]string{hdrUtil5h: "0.99", hdrReset: past}), 96, now); !until.After(now) {
		t.Fatalf("past reset must fall back to a future cool-until, got %v", until)
	}
	// Wire-casing variance: Go canonicalizes header keys, so a real upstream's
	// casing still matches the lowercase const.
	hWire := http.Header{}
	hWire.Set("Anthropic-Ratelimit-Unified-5h-Utilization", "0.98")
	if _, ok := windowPreCutDecision(hWire, 96, now); !ok {
		t.Fatal("header key canonicalization should match real upstream casing")
	}
}

func TestParseUtil(t *testing.T) {
	if _, ok := parseUtil(hdr(nil), hdrUtil5h); ok {
		t.Fatal("missing header → not present")
	}
	if v, ok := parseUtil(hdr(map[string]string{hdrUtil5h: "0.83"}), hdrUtil5h); !ok || v != 0.83 {
		t.Fatalf("0.83 → (0.83,true), got (%v,%v)", v, ok)
	}
	if _, ok := parseUtil(hdr(map[string]string{hdrUtil5h: "not-a-number"}), hdrUtil5h); ok {
		t.Fatal("unparseable → not present (don't pre-cut on garbage)")
	}
}
