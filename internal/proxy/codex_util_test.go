package proxy

import (
	"net/http"
	"testing"
)

// TestParseCodexUtil pins parseCodexUtil against the REAL wire captured 2026-07-06
// (research/oauth-codex-ratelimit/2026-07-06-codex-ratelimit-taxonomy.md) plus the
// adversarial cases the live capture warned about (the primary/secondary name is
// NOT tied to a fixed window — classification MUST be by window-minutes).
func TestParseCodexUtil(t *testing.T) {
	hdr := func(kv map[string]string) http.Header {
		h := http.Header{}
		for k, v := range kv {
			h.Set(k, v)
		}
		return h
	}

	cases := []struct {
		name           string
		h              http.Header
		wantOK         bool
		want5h, want7d float64
		want7dPresent  bool
	}{
		{
			// Exact live Plus capture: primary IS the 5h window here (300min),
			// secondary the 7d (10080min) — the intuitive order, and the OPPOSITE
			// of sub2api's "primary=weekly" comment.
			name: "live_plus_capture_primary_is_5h",
			h: hdr(map[string]string{
				"X-Codex-Primary-Used-Percent":     "1",
				"X-Codex-Primary-Window-Minutes":   "300",
				"X-Codex-Secondary-Used-Percent":   "0",
				"X-Codex-Secondary-Window-Minutes": "10080",
			}),
			wantOK: true, want5h: 0.01, want7d: 0.0, want7dPresent: true,
		},
		{
			// Adversarial: primary carries the 7d window (10080min), secondary the
			// 5h (300min). Classification by DURATION must map secondary→util_5h and
			// primary→util_7d. If someone reverts to trust-the-name this fails.
			name: "inverted_primary_is_7d",
			h: hdr(map[string]string{
				"X-Codex-Primary-Used-Percent":     "50",
				"X-Codex-Primary-Window-Minutes":   "10080",
				"X-Codex-Secondary-Used-Percent":   "90",
				"X-Codex-Secondary-Window-Minutes": "300",
			}),
			wantOK: true, want5h: 0.90, want7d: 0.50, want7dPresent: true,
		},
		{
			// percent can exceed 100 briefly → clamp to fraction 1.0.
			name: "over_100_clamped",
			h: hdr(map[string]string{
				"X-Codex-Primary-Used-Percent":     "150",
				"X-Codex-Primary-Window-Minutes":   "300",
				"X-Codex-Secondary-Used-Percent":   "0",
				"X-Codex-Secondary-Window-Minutes": "10080",
			}),
			wantOK: true, want5h: 1.0, want7d: 0.0, want7dPresent: true,
		},
		{
			// Only the 5h window present (no secondary) → util_7d stays 0.
			name: "only_5h_window",
			h: hdr(map[string]string{
				"X-Codex-Primary-Used-Percent":   "80",
				"X-Codex-Primary-Window-Minutes": "300",
			}),
			wantOK: true, want5h: 0.80, want7d: 0.0,
		},
		{
			// Anthropic response (no X-Codex-* headers) → not codex, skip.
			name: "anthropic_headers_only",
			h: hdr(map[string]string{
				"anthropic-ratelimit-unified-5h-utilization": "0.42",
			}),
			wantOK: false,
		},
		{
			// Empty / garbage → skip.
			name:   "no_headers",
			h:      http.Header{},
			wantOK: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got5h, got7d, ok := parseCodexUtil(c.h)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if !floatEq(got5h, c.want5h) || (got7d != nil) != c.want7dPresent {
				t.Errorf("util5h,util7d = %v,%v; want %v,present=%v", got5h, got7d, c.want5h, c.want7dPresent)
			} else if got7d != nil && !floatEq(*got7d, c.want7d) {
				t.Errorf("util7d = %v; want %v", *got7d, c.want7d)
			}
		})
	}
}

func floatEq(a, b float64) bool {
	const eps = 1e-9
	d := a - b
	return d < eps && d > -eps
}
