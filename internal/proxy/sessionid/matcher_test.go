package sessionid

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDefaultLoads verifies the embedded session-fingerprint.yaml parses
// cleanly at boot. If a future edit corrupts the yaml, this fails
// in CI rather than at proxy startup.
func TestDefaultLoads(t *testing.T) {
	m := Default()
	if m == nil {
		t.Fatal("Default() returned nil")
	}
	if m.bodyMaxBytes <= 0 {
		t.Fatalf("body_max_bytes want >0, got %d", m.bodyMaxBytes)
	}
}

// makeReq builds a minimal POST request the matcher can probe.
// Helper centralizes the boilerplate so test cases stay focused on
// the (headers, body, protocol, provider) combination under test.
func makeReq(headers map[string]string, body []byte) *http.Request {
	req := httptest.NewRequest("POST", "https://example.com/v1/messages", bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Content-Length needs to match body for the parseBodyJSON
	// pre-flight check to behave realistically.
	req.ContentLength = int64(len(body))
	return req
}

// TestExtract_Anthropic_ClaudeCliHeader — the canonical Claude Code
// CLI happy path. Header must win on first try; body must not be read.
func TestExtract_Anthropic_ClaudeCliHeader(t *testing.T) {
	m := Default()
	req := makeReq(map[string]string{
		"X-Claude-Code-Session-Id": "abc-claude-session",
	}, []byte(`{"model":"claude-3-7","messages":[{"role":"user","content":"hi"}]}`))

	got := m.Extract(req, "anthropic", "anthropic")
	if got != "abc-claude-session" {
		t.Errorf("Extract(anthropic) = %q, want abc-claude-session", got)
	}

	// Body must still be readable downstream (i.e. not consumed by
	// the matcher). This is the silent-regression guard for body
	// reset logic.
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), `"messages"`) {
		t.Errorf("downstream body lost / partial after Extract: %q", body)
	}
}

// TestExtract_Anthropic_ThirdPartyAgentConvention — third-party Agent
// without Claude Code's proprietary header opts into X-Aikey-Session-Id.
// The second source in the anthropic rule should hit.
func TestExtract_Anthropic_ThirdPartyAgentConvention(t *testing.T) {
	m := Default()
	req := makeReq(map[string]string{
		"X-Aikey-Session-Id": "third-party-session-42",
	}, nil)
	got := m.Extract(req, "anthropic", "anthropic")
	if got != "third-party-session-42" {
		t.Errorf("Extract(anthropic, third-party header) = %q", got)
	}
}

// TestExtract_Kimi_BodyJSONField — Kimi's prompt_cache_key lives in
// the body. This exercises the body parsing path including reset.
func TestExtract_Kimi_BodyJSONField(t *testing.T) {
	m := Default()
	body := []byte(`{"model":"kimi-k2","prompt_cache_key":"kimi-session-xyz","messages":[]}`)
	req := makeReq(nil, body)

	got := m.Extract(req, "openai_compatible", "kimi_code")
	if got != "kimi-session-xyz" {
		t.Errorf("Extract(kimi body) = %q, want kimi-session-xyz", got)
	}

	// Body must be fully replayed for downstream — Kimi proxy will
	// forward this body to upstream, so missing bytes breaks the call.
	replayed, _ := io.ReadAll(req.Body)
	if !bytes.Equal(replayed, body) {
		t.Errorf("body not preserved: got %q, want %q", replayed, body)
	}
}

// TestExtract_Kimi_HeaderShortCircuitsBody — when Kimi callers send
// the X-Aikey-Kimi-Session header, the body parse must NOT trigger
// (perf-sensitive: header is the fast path).
func TestExtract_Kimi_HeaderShortCircuitsBody(t *testing.T) {
	m := Default()
	body := []byte(`{"prompt_cache_key":"body-value"}`)
	req := makeReq(map[string]string{
		"X-Aikey-Kimi-Session": "header-value",
	}, body)

	got := m.Extract(req, "openai_compatible", "kimi_code")
	if got != "header-value" {
		t.Errorf("header should win over body: got %q", got)
	}
	// Body bytes intact (header hit means parseBodyJSON never ran;
	// req.Body still has the original reader).
	replayed, _ := io.ReadAll(req.Body)
	if !bytes.Equal(replayed, body) {
		t.Errorf("body modified despite header short-circuit: got %q", replayed)
	}
}

// TestExtract_OpenAI_BodyConversationId — OpenAI / ChatGPT API style.
func TestExtract_OpenAI_BodyConversationId(t *testing.T) {
	m := Default()
	body := []byte(`{"model":"gpt-4","conversation_id":"openai-conv-7","messages":[]}`)
	req := makeReq(nil, body)
	got := m.Extract(req, "openai", "openai")
	if got != "openai-conv-7" {
		t.Errorf("Extract(openai body) = %q, want openai-conv-7", got)
	}
}

// TestExtract_OpenAI_CursorHeader — Cursor or similar OpenAI-protocol
// client setting only the convention header.
func TestExtract_OpenAI_CursorHeader(t *testing.T) {
	m := Default()
	req := makeReq(map[string]string{
		"X-Aikey-Session-Id": "cursor-sess-9",
	}, []byte(`{}`))
	got := m.Extract(req, "openai", "openai")
	if got != "cursor-sess-9" {
		t.Errorf("Extract(openai header) = %q", got)
	}
}

// TestExtract_UnknownProtocol_FallsBackToCommon — protocol that matches
// no rule, but the convention header is set. common_fallback must catch.
func TestExtract_UnknownProtocol_FallsBackToCommon(t *testing.T) {
	m := Default()
	req := makeReq(map[string]string{
		"X-Aikey-Session-Id": "fallback-sess",
	}, nil)
	got := m.Extract(req, "some_future_protocol", "")
	if got != "fallback-sess" {
		t.Errorf("Extract(unknown proto, conv header) = %q, want fallback-sess", got)
	}
}

// TestExtract_NoSourceMatches_ReturnsEmpty — the silent "no session
// dimension" case. Caller writes NULL to DB.
func TestExtract_NoSourceMatches_ReturnsEmpty(t *testing.T) {
	m := Default()
	req := makeReq(nil, []byte(`{"unrelated":"field"}`))
	got := m.Extract(req, "openai", "openai")
	if got != "" {
		t.Errorf("Extract(no headers, no relevant body) = %q, want empty", got)
	}
}

// TestExtract_OversizedBodyDoesNotParse — defensive: a body larger
// than body_max_bytes must skip JSON parsing (return "") and not
// hold MBs in memory. Use a body MUCH larger than the 64KB default
// so even partial reads can't accidentally satisfy.
func TestExtract_OversizedBodyDoesNotParse(t *testing.T) {
	m := Default()
	// 128KB of padding then the field — guaranteed past the cap.
	padding := strings.Repeat("x", 128*1024)
	body := []byte(`{"padding":"` + padding + `","conversation_id":"would-be-session"}`)
	req := makeReq(nil, body)

	got := m.Extract(req, "openai", "openai")
	if got != "" {
		t.Errorf("oversized body should not yield session_id: got %q", got)
	}
	// Body must still be available for downstream (we only LimitRead'd,
	// then stitched back).
	replayed, _ := io.ReadAll(req.Body)
	if !bytes.Equal(replayed, body) {
		t.Errorf("oversized body not preserved after extract: len=%d want=%d", len(replayed), len(body))
	}
}

// TestExtract_NilBody — request with no body shouldn't panic;
// body_json_field source returns "" and any header source still works.
func TestExtract_NilBody(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.com/", nil)
	req.Body = nil
	req.Header.Set("X-Aikey-Session-Id", "h-sess")

	got := Default().Extract(req, "openai", "openai")
	if got != "h-sess" {
		t.Errorf("Extract(nil body, header set) = %q", got)
	}
}

// TestExtract_MalformedJSON_FallsThrough — body present but not parseable
// as JSON. body_json_field returns ""; header sources still work.
func TestExtract_MalformedJSON_FallsThrough(t *testing.T) {
	m := Default()
	req := makeReq(map[string]string{
		"X-Aikey-Session-Id": "header-saved-the-day",
	}, []byte(`not json {{{`))
	// openai rule tries header first, so this primarily proves the
	// matcher doesn't panic on malformed JSON.
	got := m.Extract(req, "openai", "openai")
	if got != "header-saved-the-day" {
		t.Errorf("Extract(malformed body, header set) = %q", got)
	}
}

// TestExtract_ProviderScopedRule — kimi_code provider must hit the
// kimi rule, NOT the generic openai rule. Verifies provider scoping.
func TestExtract_ProviderScopedRule(t *testing.T) {
	m := Default()
	// Kimi-specific body field; openai-rule doesn't have this source.
	req := makeReq(nil, []byte(`{"prompt_cache_key":"kimi-only-sess"}`))
	got := m.Extract(req, "openai_compatible", "kimi_code")
	if got != "kimi-only-sess" {
		t.Errorf("kimi-scoped rule didn't hit: got %q", got)
	}
}

// TestExtract_ClaudeHeaderCrossProtocol pins the invariant that
// X-Claude-Code-Session-Id is honored across protocols, not just
// anthropic. Rationale: Claude Code routinely wraps non-Anthropic
// upstreams (users reroute its base URL to OpenAI / Kimi / etc.) and
// the IDE-conversation identifier is still meaningful for session
// aggregation on those routes. Pre-2026-05-26 the proxy hard-coded
// this; with the yaml extractor, common_fallback enforces it.
func TestExtract_ClaudeHeaderCrossProtocol(t *testing.T) {
	m := Default()
	cases := []struct {
		name     string
		protocol string
		provider string
	}{
		{"openai_protocol", "openai", "openai"},
		{"openai_compatible_kimi", "openai_compatible", "kimi_code"},
		{"unknown_protocol", "some_future_thing", "fooprovider"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := makeReq(map[string]string{
				"X-Claude-Code-Session-Id": "claude-session-cross",
			}, nil)
			if got := m.Extract(req, tc.protocol, tc.provider); got != "claude-session-cross" {
				t.Errorf("Claude header must work cross-protocol; got %q for protocol=%q provider=%q", got, tc.protocol, tc.provider)
			}
		})
	}
}

// TestExtract_ConventionHeaderBeatsClaude — explicit convention header
// takes precedence over the implicit IDE header in common_fallback.
// Why: if a third-party Agent goes to the effort of setting the
// official convention header, that's a clearer signal than an
// accidental IDE-leaked header.
func TestExtract_ConventionHeaderBeatsClaude(t *testing.T) {
	req := makeReq(map[string]string{
		"X-Aikey-Session-Id":       "convention-wins",
		"X-Claude-Code-Session-Id": "claude-loses-here",
	}, nil)
	if got := Default().Extract(req, "openai", "openai"); got != "convention-wins" {
		t.Errorf("X-Aikey-Session-Id should beat X-Claude-Code-Session-Id in common_fallback ordering, got %q", got)
	}
}

// TestExtract_AnthropicRule_ConventionBeatsClaudeHeader — the same
// precedence rule but inside the per-protocol anthropic rule (not via
// common_fallback). This is the critical case for third-party Agents
// hitting /anthropic/v1/...: aikey-proxy's oauthInject stamps a fake
// X-Claude-Code-Session-Id UUID on every OAuth request for WAF defeat,
// so the explicit user-set X-Aikey-Session-Id MUST win at extraction
// time — otherwise the convention header is silently overridden by
// the stamped UUID. 2026-05-26 follow-up fix to the initial P3 wiring.
func TestExtract_AnthropicRule_ConventionBeatsClaudeHeader(t *testing.T) {
	req := makeReq(map[string]string{
		"X-Claude-Code-Session-Id": "stamped-by-oauthinject",
		"X-Aikey-Session-Id":       "user-set-explicit",
	}, nil)
	if got := Default().Extract(req, "anthropic", "anthropic"); got != "user-set-explicit" {
		t.Errorf("explicit X-Aikey-Session-Id must beat stamped X-Claude-Code-Session-Id on anthropic protocol; got %q", got)
	}
}

// TestExtract_AnthropicRule_ClaudeOnlyStillWorks — the existing common
// case: real Claude Code sends only X-Claude-Code-Session-Id (it
// doesn't know about X-Aikey-Session-Id). With the new ordering, the
// matcher should still pick up the Claude header by falling through.
func TestExtract_AnthropicRule_ClaudeOnlyStillWorks(t *testing.T) {
	req := makeReq(map[string]string{
		"X-Claude-Code-Session-Id": "real-claude-uuid",
	}, nil)
	if got := Default().Extract(req, "anthropic", "anthropic"); got != "real-claude-uuid" {
		t.Errorf("Claude header must still win when X-Aikey-Session-Id is absent; got %q", got)
	}
}

// TestExtract_NilRequest — defensive against caller bugs.
func TestExtract_NilRequest(t *testing.T) {
	got := Default().Extract(nil, "anthropic", "anthropic")
	if got != "" {
		t.Errorf("Extract(nil req) = %q, want empty", got)
	}
}

// TestLookupJSONPath_Nested — covers the one-level-nested syntax used
// by the (currently aspirational) OpenAI metadata.user_id rule.
func TestLookupJSONPath_Nested(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{
			"user_id": "user-42",
		},
		"other": "ignored",
	}
	if got := lookupJSONPath(obj, "metadata.user_id"); got != "user-42" {
		t.Errorf("nested path lookup = %q", got)
	}
	if got := lookupJSONPath(obj, "other"); got != "ignored" {
		t.Errorf("top-level lookup = %q", got)
	}
	if got := lookupJSONPath(obj, "missing"); got != "" {
		t.Errorf("missing path = %q, want empty", got)
	}
	if got := lookupJSONPath(obj, "metadata.missing"); got != "" {
		t.Errorf("missing nested = %q, want empty", got)
	}
}

// TestLoadRejectsInvalidConfig — boot-time validation catches bad yaml
// before Default() can hand it out to callers.
func TestLoadRejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing body_max_bytes",
			yaml: `rules: []
common_fallback: []`,
			want: "body_max_bytes must be > 0",
		},
		{
			name: "rule missing protocol",
			yaml: `rules:
  - match: { protocol: "" }
    sources:
      - { type: header, name: "X-Foo" }
common_fallback: []
body_max_bytes: 1024`,
			want: "match.protocol must be non-empty",
		},
		{
			name: "header source missing name",
			yaml: `rules:
  - match: { protocol: "anthropic" }
    sources:
      - { type: header, name: "" }
common_fallback: []
body_max_bytes: 1024`,
			want: "header source missing name",
		},
		{
			name: "body source missing path",
			yaml: `rules:
  - match: { protocol: "openai" }
    sources:
      - { type: body_json_field, path: "" }
common_fallback: []
body_max_bytes: 1024`,
			want: "body_json_field source missing path",
		},
		{
			name: "unknown source type",
			yaml: `rules:
  - match: { protocol: "openai" }
    sources:
      - { type: "totally_made_up", name: "X-Foo" }
common_fallback: []
body_max_bytes: 1024`,
			want: "unknown source type",
		},
		{
			name: "malformed yaml",
			yaml: `rules: [`,
			want: "parse fingerprint yaml",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v; want substring %q", err, tc.want)
			}
		})
	}
}
