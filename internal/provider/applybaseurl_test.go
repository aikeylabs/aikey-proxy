package provider

import (
	"net/http"
	"net/url"
	"testing"
)

// TestApplyBaseURL covers the v4.3 (2026-05-01) config-table-driven path
// stitch contract: lookup host in provider_routes → strip leading version
// from request path → re-attach version from table. The same upstream URL
// results no matter whether the client included /v1 in the request and
// regardless of which form the vault entry's base_url was stored in.
//
// Cf. workflow/CI/bugfix/2026-05-01-import-kimi-base-url-host-routing.md.
func TestApplyBaseURL(t *testing.T) {
	cases := []struct {
		name     string
		baseURL  string // vault.entries.base_url for this request's active key
		reqPath  string // request path AFTER `/<provider>` strip
		wantHost string
		wantPath string
	}{
		// ── In-table host: kimi-coding (api.kimi.com → /coding + /v1) ──────
		{
			name:     "kimi_coding_client_sends_v1",
			baseURL:  "https://api.kimi.com/coding/v1",
			reqPath:  "/v1/chat/completions",
			wantHost: "api.kimi.com",
			wantPath: "/coding/v1/chat/completions",
		},
		{
			name:     "kimi_coding_client_omits_v1",
			baseURL:  "https://api.kimi.com/coding/v1",
			reqPath:  "/chat/completions",
			wantHost: "api.kimi.com",
			wantPath: "/coding/v1/chat/completions",
		},
		{
			name:     "kimi_coding_legacy_stored_root",
			baseURL:  "https://api.kimi.com/coding", // older entry without trailing /v1
			reqPath:  "/v1/chat/completions",
			wantHost: "api.kimi.com",
			wantPath: "/coding/v1/chat/completions",
		},

		// ── In-table host: moonshot platform (same provider=kimi, diff URL) ─
		{
			name:     "moonshot_platform_client_sends_v1",
			baseURL:  "https://api.moonshot.cn/v1",
			reqPath:  "/v1/chat/completions",
			wantHost: "api.moonshot.cn",
			wantPath: "/v1/chat/completions",
		},
		{
			name:     "moonshot_platform_client_omits_v1",
			baseURL:  "https://api.moonshot.cn",
			reqPath:  "/chat/completions",
			wantHost: "api.moonshot.cn",
			wantPath: "/v1/chat/completions",
		},

		// ── In-table host: openai (single-segment /v1 dedup) ─────────────
		{
			name:     "openai_official",
			baseURL:  "https://api.openai.com/v1",
			reqPath:  "/v1/chat/completions",
			wantHost: "api.openai.com",
			wantPath: "/v1/chat/completions",
		},
		{
			name:     "openai_official_no_v1_in_request",
			baseURL:  "https://api.openai.com/v1",
			reqPath:  "/chat/completions",
			wantHost: "api.openai.com",
			wantPath: "/v1/chat/completions",
		},

		// ── In-table host: anthropic (no path before version) ─────────────
		{
			name:     "anthropic_official",
			baseURL:  "https://api.anthropic.com",
			reqPath:  "/v1/messages",
			wantHost: "api.anthropic.com",
			wantPath: "/v1/messages",
		},

		// ── In-table host: perplexity (version="" — no API version segment) ─
		{
			name:     "perplexity_no_version",
			baseURL:  "https://api.perplexity.ai",
			reqPath:  "/chat/completions",
			wantHost: "api.perplexity.ai",
			wantPath: "/chat/completions",
		},

		// ── In-table host: gemini (non-/v1 version) ────────────────────────
		{
			name:     "gemini_v1beta",
			baseURL:  "https://generativelanguage.googleapis.com",
			reqPath:  "/v1beta/models/gemini-pro:generateContent",
			wantHost: "generativelanguage.googleapis.com",
			wantPath: "/v1beta/models/gemini-pro:generateContent",
		},
		{
			name:     "gemini_v1beta_re_attaches",
			baseURL:  "https://generativelanguage.googleapis.com",
			reqPath:  "/models/gemini-pro:generateContent",
			wantHost: "generativelanguage.googleapis.com",
			wantPath: "/v1beta/models/gemini-pro:generateContent",
		},

		// ── Segment-alignment guard ───────────────────────────────────────
		{
			name:     "openai_v1abc_not_swallowed",
			baseURL:  "https://api.openai.com/v1",
			reqPath:  "/v1abc/x",
			wantHost: "api.openai.com",
			wantPath: "/v1/v1abc/x", // /v1abc is NOT a /v1/ segment, must NOT strip
		},

		// ── Out-of-table host: degraded fallback (literal-prepend) ────────
		// Kept for backward compatibility — third-party gateways absent
		// from yaml provider_routes still flow, just without dedup. The
		// expected fix is to add such gateways to yaml; until then this
		// branch keeps requests routable.
		{
			name:     "unknown_host_literal_prepend",
			baseURL:  "https://example.private/api/v9",
			reqPath:  "/foo",
			wantHost: "example.private",
			wantPath: "/api/v9/foo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "http://placeholder"+tc.reqPath, nil)
			req.URL = &url.URL{Path: tc.reqPath}
			if err := applyBaseURL(req, tc.baseURL); err != nil {
				t.Fatalf("applyBaseURL: %v", err)
			}
			if req.URL.Host != tc.wantHost {
				t.Errorf("Host = %q, want %q", req.URL.Host, tc.wantHost)
			}
			if req.URL.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", req.URL.Path, tc.wantPath)
			}
		})
	}
}

// TestProviderRoutesTable verifies the embedded yaml parses and exposes the
// expected motivating-bug rows (kimi.com vs moonshot.cn). Smoke-level so
// we catch yaml-format regressions without re-asserting every row.
func TestProviderRoutesTable(t *testing.T) {
	cases := []struct {
		host     string
		provider string
		baseURL  string
		version  string
	}{
		// 2026-05-08 Kimi 双平台拆分: api.kimi.com → kimi_code (canonical),
		// api.moonshot.cn → moonshot,两个独立 provider_code,与同步过来的
		// pkg/providerroutes/data/provider_fingerprint.yaml 一致。
		{"api.kimi.com", "kimi_code", "https://api.kimi.com/coding", "/v1"},
		{"api.moonshot.cn", "moonshot", "https://api.moonshot.cn", "/v1"},
		{"api.anthropic.com", "anthropic", "https://api.anthropic.com", "/v1"},
		{"api.openai.com", "openai", "https://api.openai.com", "/v1"},
		{"api.perplexity.ai", "perplexity", "https://api.perplexity.ai", ""},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			r, ok := Routes().ByHost(tc.host)
			if !ok {
				t.Fatalf("host %q missing from provider_routes table", tc.host)
			}
			if r.Provider != tc.provider {
				t.Errorf("provider = %q, want %q", r.Provider, tc.provider)
			}
			if r.BaseURL != tc.baseURL {
				t.Errorf("base_url = %q, want %q", r.BaseURL, tc.baseURL)
			}
			if r.Version != tc.version {
				t.Errorf("version = %q, want %q", r.Version, tc.version)
			}
		})
	}
}
