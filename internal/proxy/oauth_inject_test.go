package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// --- helpers ---

// reuse this helper without re-plumbing.
//
//nolint:unparam // `method` kept parameterized so non-POST cases can
func newJSONRequest(method, url string, body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(b))
	return req
}

func readBodyJSON(t *testing.T, req *http.Request) map[string]any {
	t.Helper()
	b, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	return m
}

func claudeCred() *OAuthCredential {
	return &OAuthCredential{
		AccessToken: "oauth-token-abc",
		Provider:    "anthropic",
		AccountID:   "acct_123",
		ExternalID:  "a030ddd8-0f4f-4515-b9fc-ef5cb03ffe66",
	}
}

// --- oauthInject dispatch ---

func TestOAuthInject_RemovesAPIKeyHeaders(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("x-api-key", "sk-old")
	req.Header.Set("X-Api-Key", "sk-old2")

	oauthInject(req, &OAuthCredential{AccessToken: "tok"}, "unknown_provider")

	if v := req.Header.Get("x-api-key"); v != "" {
		t.Errorf("x-api-key should be removed, got %q", v)
	}
	if v := req.Header.Get("X-Api-Key"); v != "" {
		t.Errorf("X-Api-Key should be removed, got %q", v)
	}
}

func TestOAuthInject_DispatchesByProvider(t *testing.T) {
	tests := []struct {
		provider    string
		wantBearer  string
		checkHeader string // one characteristic header to verify dispatch
		wantValue   string
	}{
		{"anthropic", "Bearer oauth-tok", "anthropic-version", "2023-06-01"},
		{"openai", "Bearer oauth-tok", "originator", "opencode"},
		{"kimi", "Bearer oauth-tok", "X-Msh-Platform", "kimi_cli"},
		{"moonshot", "Bearer oauth-tok", "X-Msh-Platform", "kimi_cli"},
		{"unknown", "Bearer oauth-tok", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/v1/messages", nil)
			cred := &OAuthCredential{AccessToken: "oauth-tok", AccountID: "a1"}
			oauthInject(req, cred, tt.provider)

			if got := req.Header.Get("Authorization"); got != tt.wantBearer {
				t.Errorf("Authorization = %q, want %q", got, tt.wantBearer)
			}
			if tt.checkHeader != "" {
				if got := req.Header.Get(tt.checkHeader); got != tt.wantValue {
					t.Errorf("%s = %q, want %q", tt.checkHeader, got, tt.wantValue)
				}
			}
		})
	}
}

// --- injectClaudeOAuth ---

func TestInjectClaudeOAuth_BetaQueryParam(t *testing.T) {
	t.Run("adds ?beta=true when absent", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages", nil)
		injectClaudeOAuth(req, claudeCred())

		if got := req.URL.Query().Get("beta"); got != "true" {
			t.Errorf("beta query param = %q, want %q", got, "true")
		}
	})

	t.Run("preserves existing ?beta=true", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages?beta=true", nil)
		injectClaudeOAuth(req, claudeCred())

		if got := req.URL.Query().Get("beta"); got != "true" {
			t.Errorf("beta query param = %q, want %q", got, "true")
		}
	})

	t.Run("preserves other query params", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages?foo=bar", nil)
		injectClaudeOAuth(req, claudeCred())

		if got := req.URL.Query().Get("foo"); got != "bar" {
			t.Errorf("foo query param = %q, want %q", got, "bar")
		}
		if got := req.URL.Query().Get("beta"); got != "true" {
			t.Errorf("beta query param = %q, want %q", got, "true")
		}
	})
}

func TestInjectClaudeOAuth_AnthropicVersion(t *testing.T) {
	t.Run("sets when absent", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages", nil)
		injectClaudeOAuth(req, claudeCred())

		if got := req.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Errorf("anthropic-version = %q, want %q", got, "2023-06-01")
		}
	})

	t.Run("preserves client-set value", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages", nil)
		req.Header.Set("anthropic-version", "2024-01-01")
		injectClaudeOAuth(req, claudeCred())

		if got := req.Header.Get("anthropic-version"); got != "2024-01-01" {
			t.Errorf("anthropic-version = %q, want client-set %q", got, "2024-01-01")
		}
	})
}

func TestInjectClaudeOAuth_BetaHeader(t *testing.T) {
	t.Run("full fingerprint when no existing beta", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages", nil)
		injectClaudeOAuth(req, claudeCred())

		beta := req.Header.Get("anthropic-beta")
		if !strings.Contains(beta, "oauth-2025-04-20") {
			t.Errorf("anthropic-beta missing oauth flag: %q", beta)
		}
		if !strings.Contains(beta, "claude-code-20250219") {
			t.Errorf("anthropic-beta missing claude-code flag: %q", beta)
		}
		// Persona headers should be set in this path
		if got := req.Header.Get("X-App"); got != "cli" {
			t.Errorf("X-App = %q, want %q", got, "cli")
		}
		if got := req.Header.Get("X-Stainless-Lang"); got != "js" {
			t.Errorf("X-Stainless-Lang = %q, want %q", got, "js")
		}
	})

	t.Run("appends oauth flag to existing beta", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages", nil)
		req.Header.Set("anthropic-beta", "claude-code-20250219,interleaved-thinking-2025-05-14")
		injectClaudeOAuth(req, claudeCred())

		beta := req.Header.Get("anthropic-beta")
		if !strings.Contains(beta, "oauth-2025-04-20") {
			t.Errorf("anthropic-beta should contain oauth flag: %q", beta)
		}
		// Original flags preserved
		if !strings.Contains(beta, "claude-code-20250219") {
			t.Errorf("anthropic-beta should still contain claude-code flag: %q", beta)
		}
	})

	t.Run("does not duplicate oauth flag", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages", nil)
		req.Header.Set("anthropic-beta", "claude-code-20250219,oauth-2025-04-20")
		injectClaudeOAuth(req, claudeCred())

		beta := req.Header.Get("anthropic-beta")
		count := strings.Count(beta, "oauth-2025-04-20")
		if count != 1 {
			t.Errorf("oauth flag appears %d times, want 1: %q", count, beta)
		}
	})
}

func TestInjectClaudeOAuth_SessionID(t *testing.T) {
	t.Run("generates session ID when absent", func(t *testing.T) {
		body := map[string]any{"model": "claude-3", "messages": []any{}}
		req := newJSONRequest("POST", "/v1/messages", body)
		injectClaudeOAuth(req, claudeCred())

		sid := req.Header.Get("X-Claude-Code-Session-Id")
		if sid == "" {
			t.Fatal("X-Claude-Code-Session-Id should be set")
		}
		// UUID v4 format: 8-4-4-4-12
		parts := strings.Split(sid, "-")
		if len(parts) != 5 {
			t.Errorf("session ID not UUID format: %q", sid)
		}
	})

	t.Run("preserves client session ID", func(t *testing.T) {
		body := map[string]any{"model": "claude-3", "messages": []any{}}
		req := newJSONRequest("POST", "/v1/messages", body)
		req.Header.Set("X-Claude-Code-Session-Id", "client-session-123")
		injectClaudeOAuth(req, claudeCred())

		if got := req.Header.Get("X-Claude-Code-Session-Id"); got != "client-session-123" {
			t.Errorf("session ID = %q, want preserved %q", got, "client-session-123")
		}
	})
}

func TestInjectClaudeOAuth_MetadataUserID(t *testing.T) {
	t.Run("injects user_id with ExternalID", func(t *testing.T) {
		body := map[string]any{"model": "claude-3", "messages": []any{}}
		req := newJSONRequest("POST", "/v1/messages", body)

		cred := claudeCred()
		injectClaudeOAuth(req, cred)

		m := readBodyJSON(t, req)
		metadata, ok := m["metadata"].(map[string]any)
		if !ok {
			t.Fatal("metadata not found in body")
		}
		userID, ok := metadata["user_id"].(string)
		if !ok {
			t.Fatal("metadata.user_id not found")
		}

		// Verify format: user_<64hex>_account_<uuid>_session_<uuid>
		if !strings.HasPrefix(userID, "user_") {
			t.Errorf("user_id should start with 'user_': %q", userID)
		}
		if !strings.Contains(userID, "_account_"+cred.ExternalID+"_session_") {
			t.Errorf("user_id should contain account UUID %q: %q", cred.ExternalID, userID)
		}
	})

	t.Run("preserves existing user_id", func(t *testing.T) {
		body := map[string]any{
			"model":    "claude-3",
			"messages": []any{},
			"metadata": map[string]any{"user_id": "existing-user-id"},
		}
		req := newJSONRequest("POST", "/v1/messages", body)
		injectClaudeOAuth(req, claudeCred())

		m := readBodyJSON(t, req)
		metadata := m["metadata"].(map[string]any)
		if got := metadata["user_id"].(string); got != "existing-user-id" {
			t.Errorf("user_id = %q, want preserved %q", got, "existing-user-id")
		}
	})
}

// --- injectCodexOAuth ---

func TestInjectCodexOAuth(t *testing.T) {
	t.Run("sets required headers", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/responses", nil)
		cred := &OAuthCredential{AccessToken: "codex-tok", AccountID: "acct-456"}
		injectCodexOAuth(req, cred)

		if got := req.Header.Get("Authorization"); got != "Bearer codex-tok" {
			t.Errorf("Authorization = %q", got)
		}
		if got := req.Header.Get("originator"); got != "opencode" {
			t.Errorf("originator = %q, want %q", got, "opencode")
		}
		if got := req.Header.Get("ChatGPT-Account-Id"); got != "acct-456" {
			t.Errorf("ChatGPT-Account-Id = %q, want %q", got, "acct-456")
		}
	})

	t.Run("preserves client-set originator", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/responses", nil)
		req.Header.Set("originator", "custom-cli")
		cred := &OAuthCredential{AccessToken: "tok", AccountID: "a1"}
		injectCodexOAuth(req, cred)

		if got := req.Header.Get("originator"); got != "custom-cli" {
			t.Errorf("originator = %q, want preserved %q", got, "custom-cli")
		}
	})

	t.Run("skips account ID when empty", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/responses", nil)
		cred := &OAuthCredential{AccessToken: "tok", AccountID: ""}
		injectCodexOAuth(req, cred)

		if got := req.Header.Get("ChatGPT-Account-Id"); got != "" {
			t.Errorf("ChatGPT-Account-Id should be empty, got %q", got)
		}
	})
}

// --- injectKimiOAuth ---

func TestInjectKimiOAuth(t *testing.T) {
	t.Run("sets required headers", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		cred := &OAuthCredential{AccessToken: "kimi-tok"}
		injectKimiOAuth(req, cred)

		if got := req.Header.Get("Authorization"); got != "Bearer kimi-tok" {
			t.Errorf("Authorization = %q", got)
		}
		if got := req.Header.Get("X-Msh-Platform"); got != "kimi_cli" {
			t.Errorf("X-Msh-Platform = %q, want %q", got, "kimi_cli")
		}
		if got := req.Header.Get("User-Agent"); got != "KimiCLI/1.24.0" {
			t.Errorf("User-Agent = %q, want %q", got, "KimiCLI/1.24.0")
		}
	})

	t.Run("preserves client-set headers", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		req.Header.Set("X-Msh-Platform", "custom_platform")
		req.Header.Set("User-Agent", "CustomCLI/2.0")
		cred := &OAuthCredential{AccessToken: "kimi-tok"}
		injectKimiOAuth(req, cred)

		if got := req.Header.Get("X-Msh-Platform"); got != "custom_platform" {
			t.Errorf("X-Msh-Platform = %q, want preserved %q", got, "custom_platform")
		}
		if got := req.Header.Get("User-Agent"); got != "CustomCLI/2.0" {
			t.Errorf("User-Agent = %q, want preserved %q", got, "CustomCLI/2.0")
		}
	})
}

// --- injectMetadataUserIDIfAbsent ---

func TestInjectMetadataUserIDIfAbsent(t *testing.T) {
	t.Run("injects when no metadata", func(t *testing.T) {
		body := map[string]any{"model": "claude-3"}
		req := newJSONRequest("POST", "/v1/messages", body)
		injectMetadataUserIDIfAbsent(req, "test-user-id")

		m := readBodyJSON(t, req)
		metadata := m["metadata"].(map[string]any)
		if got := metadata["user_id"].(string); got != "test-user-id" {
			t.Errorf("user_id = %q, want %q", got, "test-user-id")
		}
	})

	t.Run("injects when metadata exists but no user_id", func(t *testing.T) {
		body := map[string]any{"model": "claude-3", "metadata": map[string]any{"foo": "bar"}}
		req := newJSONRequest("POST", "/v1/messages", body)
		injectMetadataUserIDIfAbsent(req, "test-user-id")

		m := readBodyJSON(t, req)
		metadata := m["metadata"].(map[string]any)
		if got := metadata["user_id"].(string); got != "test-user-id" {
			t.Errorf("user_id = %q, want %q", got, "test-user-id")
		}
		if got := metadata["foo"].(string); got != "bar" {
			t.Errorf("foo = %q, should be preserved", got)
		}
	})

	t.Run("skips when user_id already exists", func(t *testing.T) {
		body := map[string]any{
			"model":    "claude-3",
			"metadata": map[string]any{"user_id": "existing"},
		}
		req := newJSONRequest("POST", "/v1/messages", body)
		injectMetadataUserIDIfAbsent(req, "new-user-id")

		m := readBodyJSON(t, req)
		metadata := m["metadata"].(map[string]any)
		if got := metadata["user_id"].(string); got != "existing" {
			t.Errorf("user_id = %q, want preserved %q", got, "existing")
		}
	})

	t.Run("handles non-JSON body gracefully", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader("not json"))
		req.ContentLength = 8
		injectMetadataUserIDIfAbsent(req, "test-user-id")

		b, _ := io.ReadAll(req.Body)
		if string(b) != "not json" {
			t.Errorf("body = %q, want preserved %q", string(b), "not json")
		}
	})

	t.Run("handles nil body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/messages", nil)
		req.Body = nil
		injectMetadataUserIDIfAbsent(req, "test-user-id") // should not panic
	})
}

// --- generateUUID ---

func TestGenerateUUID(t *testing.T) {
	uuid, err := generateUUID()
	if err != nil {
		t.Fatalf("generateUUID: %v", err)
	}

	// Format: 8-4-4-4-12 hex chars
	parts := strings.Split(uuid, "-")
	if len(parts) != 5 {
		t.Fatalf("UUID format invalid: %q", uuid)
	}
	if len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		t.Errorf("UUID segment lengths wrong: %q", uuid)
	}

	// Version 4 check: third segment starts with '4'
	if parts[2][0] != '4' {
		t.Errorf("UUID version byte = %c, want '4': %q", parts[2][0], uuid)
	}

	// Uniqueness sanity
	uuid2, err := generateUUID()
	if err != nil {
		t.Fatalf("generateUUID: %v", err)
	}
	if uuid == uuid2 {
		t.Error("two UUIDs should not be identical")
	}
}

// --- Full Claude flow integration test ---

func TestInjectClaudeOAuth_FullFlow_ThirdPartyClient(t *testing.T) {
	// Simulates a third-party client (Cursor/Cline) sending a bare request.
	// Proxy should inject ALL required layers for Claude OAuth.
	body := map[string]any{
		"model":      "claude-sonnet-4-20250514",
		"max_tokens": 1024,
		"messages":   []any{map[string]any{"role": "user", "content": "hello"}},
	}
	req := newJSONRequest("POST", "https://api.anthropic.com/v1/messages", body)

	cred := claudeCred()
	injectClaudeOAuth(req, cred)

	// Layer 1: Bearer token
	if got := req.Header.Get("Authorization"); got != "Bearer oauth-token-abc" {
		t.Errorf("Authorization = %q", got)
	}

	// Layer 2: anthropic-version
	if got := req.Header.Get("anthropic-version"); got != "2023-06-01" {
		t.Errorf("anthropic-version = %q", got)
	}

	// Layer 3: ?beta=true
	if got := req.URL.Query().Get("beta"); got != "true" {
		t.Errorf("?beta = %q", got)
	}

	// Layer 4: anthropic-beta with oauth flag + persona headers
	beta := req.Header.Get("anthropic-beta")
	if !strings.Contains(beta, "oauth-2025-04-20") {
		t.Errorf("missing oauth beta flag: %q", beta)
	}
	if req.Header.Get("X-Stainless-Lang") != "js" {
		t.Error("missing X-Stainless-Lang")
	}

	// Layer 5: session ID
	sid := req.Header.Get("X-Claude-Code-Session-Id")
	if sid == "" {
		t.Error("missing X-Claude-Code-Session-Id")
	}

	// Layer 6: metadata.user_id with ExternalID
	m := readBodyJSON(t, req)
	metadata, ok := m["metadata"].(map[string]any)
	if !ok {
		t.Fatal("missing metadata in body")
	}
	userID := metadata["user_id"].(string)
	if !strings.Contains(userID, "_account_"+cred.ExternalID+"_session_") {
		t.Errorf("user_id missing ExternalID: %q", userID)
	}
}

func TestInjectClaudeOAuth_FullFlow_ClaudeCLI(t *testing.T) {
	// Simulates Claude CLI sending a request with its own persona headers.
	// Proxy should NOT overwrite CLI-set values (forward compatibility).
	body := map[string]any{
		"model":    "claude-sonnet-4-20250514",
		"messages": []any{map[string]any{"role": "user", "content": "hello"}},
		"metadata": map[string]any{"user_id": "user_cli_set_id"},
	}
	req := newJSONRequest("POST", "https://api.anthropic.com/v1/messages?beta=true", body)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14")
	req.Header.Set("User-Agent", "claude-cli/2.2.0 (external, cli)")
	req.Header.Set("X-Claude-Code-Session-Id", "cli-session-abc")
	req.Header.Set("X-App", "cli")

	cred := claudeCred()
	injectClaudeOAuth(req, cred)

	// anthropic-version: preserved
	if got := req.Header.Get("anthropic-version"); got != "2023-06-01" {
		t.Errorf("anthropic-version overwritten: %q", got)
	}

	// anthropic-beta: oauth flag not duplicated
	beta := req.Header.Get("anthropic-beta")
	if strings.Count(beta, "oauth-2025-04-20") != 1 {
		t.Errorf("oauth flag duplicated: %q", beta)
	}

	// User-Agent: CLI version preserved (not overwritten to 2.1.22)
	if got := req.Header.Get("User-Agent"); got != "claude-cli/2.2.0 (external, cli)" {
		t.Errorf("User-Agent overwritten: %q", got)
	}

	// Session ID: preserved
	if got := req.Header.Get("X-Claude-Code-Session-Id"); got != "cli-session-abc" {
		t.Errorf("session ID overwritten: %q", got)
	}

	// metadata.user_id: preserved
	m := readBodyJSON(t, req)
	metadata := m["metadata"].(map[string]any)
	if got := metadata["user_id"].(string); got != "user_cli_set_id" {
		t.Errorf("user_id overwritten: %q", got)
	}

	// ?beta=true: preserved
	if got := req.URL.Query().Get("beta"); got != "true" {
		t.Errorf("?beta overwritten: %q", got)
	}
}

func TestInjectClaudeOAuth_PartialHeaders_PreservesClientSet(t *testing.T) {
	// A non-Claude-Code client (Cursor) sets User-Agent + X-Stainless-OS,
	// nothing else. Proxy must:
	//   - OVERRIDE User-Agent to the verified Claude Code persona UA
	//     (third-party UAs leak through to Anthropic OAuth WAF and trigger
	//     429 business rejection — see oauth_inject.go injectClaudeOAuth
	//     comments for the full reasoning)
	//   - PRESERVE other persona headers the client did set (X-Stainless-OS)
	//   - FILL IN the rest with verified defaults
	req := httptest.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("User-Agent", "Cursor/1.0")
	req.Header.Set("X-Stainless-OS", "Darwin")

	injectClaudeOAuth(req, claudeCred())

	// User-Agent overridden because Cursor isn't claude-cli/*
	if got := req.Header.Get("User-Agent"); got != "claude-cli/2.1.22 (external, cli)" {
		t.Errorf("User-Agent should be forced to claude-cli persona, got %q", got)
	}
	// Other client-set persona header preserved
	if got := req.Header.Get("X-Stainless-OS"); got != "Darwin" {
		t.Errorf("X-Stainless-OS overwritten: got %q, want %q", got, "Darwin")
	}

	// Missing values filled in
	if got := req.Header.Get("X-App"); got != "cli" {
		t.Errorf("X-App not filled: got %q, want %q", got, "cli")
	}
	if got := req.Header.Get("X-Stainless-Lang"); got != "js" {
		t.Errorf("X-Stainless-Lang not filled: got %q, want %q", got, "js")
	}
	if got := req.Header.Get("X-Stainless-Arch"); got != "arm64" {
		t.Errorf("X-Stainless-Arch not filled: got %q, want %q", got, "arm64")
	}
	if got := req.Header.Get("X-Stainless-Runtime"); got != "node" {
		t.Errorf("X-Stainless-Runtime not filled: got %q, want %q", got, "node")
	}
}

// TestInjectClaudeOAuth_RealClaudeCodeUA_Preserved guards forward-compatibility:
// when Claude Code CLI itself is the client (UA starts with "claude-cli/"),
// proxy must NOT downgrade its UA to the hardcoded 2.1.22. A future CLI version
// may carry a newer fingerprint Anthropic expects (e.g. claude-cli/3.x with new
// X-Stainless-Package-Version pairings); preserving the inbound UA keeps the
// pairing intact.
func TestInjectClaudeOAuth_RealClaudeCodeUA_Preserved(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("User-Agent", "claude-cli/3.5.0 (external, cli)")

	injectClaudeOAuth(req, claudeCred())

	if got := req.Header.Get("User-Agent"); got != "claude-cli/3.5.0 (external, cli)" {
		t.Errorf("real claude-cli UA should be preserved, got %q", got)
	}
}

// ─── WAF body fingerprint (full sub2api strategy + UA dispatch) ──────────────
//
// Pinned by research doc workflow/CI/research/oauth-token-response-identity/2026-04-15-oauth-token-response-identity.md
// (sections "2026-05-06 增补 I" + "Round 5 / sub2api 对比"):
//   - Anthropic OAuth-path WAF gates premium models on body.system[0]; without
//     the magic intro / billing-header form, the WAF returns 429 with no
//     rate-limit headers (business rejection masquerading as rate limit).
//   - We apply the sub2api system-rewrite strategy (billing+intro at system[0]
//     + relocate the client's system into messages) ONLY for non-Claude-CLI
//     clients (UA-detected at start of injectClaudeOAuth). Real CLI traffic
//     already carries its own fingerprint and is skipped to avoid wasted I/O
//     and accidental damage.
//   - cch is kept a STABLE constant (not body-hashed): the WAF doesn't verify
//     it (Round 5B) and a body hash would mutate system[0] every turn and
//     break prompt caching. The relocated client system carries cache_control
//     (client's own, else auto-filled ephemeral) so it still caches.
//
// Tests below exercise injectClaudeWAFFingerprintFull directly (UA dispatch
// is tested separately via injectClaudeOAuth end-to-end).

// regex matchers for the structural assertions
var billingHeaderRe = regexp.MustCompile(`^x-anthropic-billing-header: cc_version=\d+\.\d+\.\d+\.[0-9a-f]{3}; cc_entrypoint=cli; cch=[0-9a-f]{5};$`)

func TestInjectClaudeWAFFingerprintFull_NoSystem_BuildsBillingPlusIntro(t *testing.T) {
	req := newJSONRequest("POST", "/v1/messages", map[string]any{
		"model":    "claude-opus-4-7",
		"messages": []any{map[string]any{"role": "user", "content": "Reply with: pong"}},
	})

	injectClaudeWAFFingerprintFull(req)

	body := readBodyJSON(t, req)
	sys, ok := body["system"].([]any)
	if !ok || len(sys) != 2 {
		t.Fatalf("system should be 2-block array, got %v (len=%d)", body["system"], len(sys))
	}
	billing := sys[0].(map[string]any)
	if billing["type"] != "text" {
		t.Errorf("system[0].type = %q; want text", billing["type"])
	}
	billingText, _ := billing["text"].(string)
	if !billingHeaderRe.MatchString(billingText) {
		t.Errorf("system[0] should be a fully-signed billing header, got %q", billingText)
	}
	intro := sys[1].(map[string]any)
	if intro["text"] != claudeCodeSystemPrompt {
		t.Errorf("system[1].text = %q; want claudeCodeSystemPrompt", intro["text"])
	}
	if cc, ok := intro["cache_control"].(map[string]any); !ok || cc["type"] != "ephemeral" {
		t.Errorf("system[1].cache_control should be {type:ephemeral}, got %v", intro["cache_control"])
	}
}

func TestInjectClaudeWAFFingerprintFull_StringSystem_MovedToMessages(t *testing.T) {
	originalSystem := "You are a helpful coding assistant. Always answer in Chinese."
	req := newJSONRequest("POST", "/v1/messages", map[string]any{
		"model":    "claude-opus-4-7",
		"system":   originalSystem,
		"messages": []any{map[string]any{"role": "user", "content": "Hi"}},
	})

	injectClaudeWAFFingerprintFull(req)

	body := readBodyJSON(t, req)
	// system replaced with 2-block billing+intro
	sys := body["system"].([]any)
	if len(sys) != 2 {
		t.Fatalf("system should be 2-block, got %d", len(sys))
	}
	if !billingHeaderRe.MatchString(sys[0].(map[string]any)["text"].(string)) {
		t.Errorf("system[0] should be billing header, got %v", sys[0])
	}
	// original system should be moved into messages[0] (instr) + messages[1] (ack) pair
	msgs := body["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages (instr/ack/user), got %d", len(msgs))
	}
	m0content := msgs[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(m0content, originalSystem) {
		t.Errorf("messages[0] should contain original system text, got %q", m0content)
	}
	if !strings.HasPrefix(m0content, "[System Instructions]") {
		t.Errorf("messages[0] should start with [System Instructions], got %q", m0content)
	}
	if msgs[1].(map[string]any)["role"] != "assistant" {
		t.Errorf("messages[1] should be assistant ack, got %v", msgs[1])
	}
}

func TestInjectClaudeWAFFingerprintFull_ArraySystem_MovedToMessages(t *testing.T) {
	clientBlock := map[string]any{"type": "text", "text": "be terse"}
	req := newJSONRequest("POST", "/v1/messages", map[string]any{
		"model":    "claude-sonnet-4-6",
		"system":   []any{clientBlock},
		"messages": []any{map[string]any{"role": "user", "content": "Hi"}},
	})

	injectClaudeWAFFingerprintFull(req)

	body := readBodyJSON(t, req)
	sys := body["system"].([]any)
	if len(sys) != 2 || !billingHeaderRe.MatchString(sys[0].(map[string]any)["text"].(string)) {
		t.Fatalf("system should be 2-block billing+intro, got %v", sys)
	}
	msgs := body["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}
	m0text := msgs[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(m0text, "be terse") {
		t.Errorf("messages[0] should contain client's text-block content, got %q", m0text)
	}
}

func TestInjectClaudeWAFFingerprintFull_AlreadyMagicIntro_NoOp(t *testing.T) {
	// Real Claude CLI traffic that somehow reaches the full path (e.g.
	// dispatch bug, defensive). Idempotency check should leave it alone.
	original := []any{
		map[string]any{"type": "text", "text": claudeCodeSystemPrompt},
		map[string]any{"type": "text", "text": "additional context block"},
	}
	originalMessages := []any{map[string]any{"role": "user", "content": "Hi"}}
	req := newJSONRequest("POST", "/v1/messages", map[string]any{
		"model":    "claude-opus-4-7",
		"system":   original,
		"messages": originalMessages,
	})

	injectClaudeWAFFingerprintFull(req)

	body := readBodyJSON(t, req)
	sys := body["system"].([]any)
	if len(sys) != 2 {
		t.Errorf("idempotent for magic-intro-already-present, got len=%d", len(sys))
	}
	if sys[0].(map[string]any)["text"] != claudeCodeSystemPrompt {
		t.Errorf("system[0] should remain magic intro, got %v", sys[0])
	}
	msgs := body["messages"].([]any)
	if len(msgs) != 1 {
		t.Errorf("idempotent: messages should be unchanged (1 entry), got %d", len(msgs))
	}
}

func TestInjectClaudeWAFFingerprintFull_AlreadyBillingHeader_NoOp(t *testing.T) {
	// Real Claude CLI 2.1.92+ uses the billing-header form at system[0].
	// Round 4b verified that any cc_entrypoint value satisfies WAF; this
	// test pins the idempotent recognition of that form.
	billingBlock := map[string]any{
		"type": "text",
		"text": "x-anthropic-billing-header: cc_version=2.1.128.f14; cc_entrypoint=cli; cch=00000;",
	}
	req := newJSONRequest("POST", "/v1/messages", map[string]any{
		"model":    "claude-opus-4-7",
		"system":   []any{billingBlock},
		"messages": []any{map[string]any{"role": "user", "content": "Hi"}},
	})

	injectClaudeWAFFingerprintFull(req)

	body := readBodyJSON(t, req)
	sys := body["system"].([]any)
	if len(sys) != 1 {
		t.Errorf("idempotent for billing-already-present, got len=%d", len(sys))
	}
	first := sys[0].(map[string]any)["text"].(string)
	if !strings.HasPrefix(first, "x-anthropic-billing-header:") {
		t.Errorf("system[0] should remain billing header, got %q", first)
	}
}

func TestInjectClaudeWAFFingerprintFull_HaikuModel_Skipped(t *testing.T) {
	// Round 1 + sub2api confirmation: WAF doesn't apply to haiku models.
	req := newJSONRequest("POST", "/v1/messages", map[string]any{
		"model":    "claude-haiku-4-5-20251001",
		"messages": []any{map[string]any{"role": "user", "content": "Hi"}},
	})

	injectClaudeWAFFingerprintFull(req)

	body := readBodyJSON(t, req)
	if _, ok := body["system"]; ok {
		t.Errorf("haiku request should NOT have system injected, got %v", body["system"])
	}
}

func TestInjectClaudeWAFFingerprintFull_NonJSONBody_LeavesUnchanged(t *testing.T) {
	// Defensive: non-JSON body must be preserved unchanged.
	originalBody := []byte("event: ping\ndata: {}\n\n")
	req := httptest.NewRequest("POST", "/v1/messages", bytes.NewReader(originalBody))
	req.Header.Set("Content-Type", "text/event-stream")
	req.ContentLength = int64(len(originalBody))

	injectClaudeWAFFingerprintFull(req)

	got, _ := io.ReadAll(req.Body)
	if string(got) != string(originalBody) {
		t.Errorf("non-JSON body should be preserved.\n  before: %q\n  after:  %q",
			originalBody, got)
	}
}

// ─── UA-based dispatch in injectClaudeOAuth ──────────────────────────────────

func TestClientIsClaudeCode(t *testing.T) {
	cases := []struct {
		ua   string
		want bool
	}{
		{"claude-cli/2.1.128 (external, cli)", true},
		{"claude-cli/3.0.0", true},
		{"claude-cli/", true}, // technically valid prefix
		{"opencode/0.5.2", false},
		{"Cursor/0.42.0", false},
		{"node", false},
		{"", false},
		{"Claude-CLI/2.1.0", false},  // case-sensitive
		{"my-claude-cli/1.0", false}, // prefix must be exact
	}
	for _, tc := range cases {
		req := httptest.NewRequest("POST", "/v1/messages", nil)
		if tc.ua != "" {
			req.Header.Set("User-Agent", tc.ua)
		}
		got := clientIsClaudeCode(req)
		if got != tc.want {
			t.Errorf("clientIsClaudeCode(%q) = %v; want %v", tc.ua, got, tc.want)
		}
	}
}

func TestInjectClaudeOAuth_RealClaudeCLI_SkipsWAFInjection(t *testing.T) {
	// Real Claude CLI inbound — body.system stays untouched (no billing/intro
	// blocks injected, no messages prepended).
	req := newJSONRequest("POST", "/v1/messages", map[string]any{
		"model":    "claude-opus-4-7",
		"messages": []any{map[string]any{"role": "user", "content": "Hi"}},
	})
	req.Header.Set("User-Agent", "claude-cli/2.1.128 (external, cli)")

	injectClaudeOAuth(req, claudeCred())

	body := readBodyJSON(t, req)
	if _, ok := body["system"]; ok {
		t.Errorf("real claude-cli inbound: system should NOT be injected, got %v", body["system"])
	}
	msgs := body["messages"].([]any)
	if len(msgs) != 1 {
		t.Errorf("real claude-cli inbound: messages should NOT be rewritten, got len=%d", len(msgs))
	}
}

func TestInjectClaudeOAuth_NonClaudeCLI_AppliesFullWAFInjection(t *testing.T) {
	// Third-party client (opencode) — inbound UA does NOT start with claude-cli/,
	// so injectClaudeOAuth applies the full sub2api strategy.
	req := newJSONRequest("POST", "/v1/messages", map[string]any{
		"model":    "claude-opus-4-7",
		"messages": []any{map[string]any{"role": "user", "content": "Hi"}},
	})
	req.Header.Set("User-Agent", "opencode/0.5.2")

	injectClaudeOAuth(req, claudeCred())

	body := readBodyJSON(t, req)
	sys, ok := body["system"].([]any)
	if !ok || len(sys) != 2 {
		t.Fatalf("opencode inbound: should have full 2-block system, got %v", body["system"])
	}
	if !billingHeaderRe.MatchString(sys[0].(map[string]any)["text"].(string)) {
		t.Errorf("system[0] should be billing header, got %v", sys[0])
	}
	if sys[1].(map[string]any)["text"] != claudeCodeSystemPrompt {
		t.Errorf("system[1] should be magic intro, got %v", sys[1])
	}
}

// ─── algorithms (computeClaudeCodeVersionFingerprint) ───────────────────────

func TestComputeClaudeCodeVersionFingerprint_Deterministic(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hello world this is a test"}]}`)
	fp1 := computeClaudeCodeVersionFingerprint(body, "2.1.128")
	fp2 := computeClaudeCodeVersionFingerprint(body, "2.1.128")
	if fp1 != fp2 {
		t.Errorf("fp not deterministic: %q != %q", fp1, fp2)
	}
	hexRe := regexp.MustCompile(`^[0-9a-f]{3}$`)
	if !hexRe.MatchString(fp1) {
		t.Errorf("fp must be exactly 3 hex chars, got %q", fp1)
	}
}

func TestComputeClaudeCodeVersionFingerprint_VersionMatters(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hello world"}]}`)
	if computeClaudeCodeVersionFingerprint(body, "2.1.128") == computeClaudeCodeVersionFingerprint(body, "2.1.92") {
		t.Errorf("expected fp to differ across versions")
	}
}

func TestComputeClaudeCodeVersionFingerprint_ShortText(t *testing.T) {
	// Algorithm pads with '0' when chars[7] / [20] are out of bounds.
	body := []byte(`{"messages":[{"role":"user","content":"abc"}]}`)
	fp := computeClaudeCodeVersionFingerprint(body, "2.1.128")
	hexRe := regexp.MustCompile(`^[0-9a-f]{3}$`)
	if !hexRe.MatchString(fp) {
		t.Errorf("short-text fp must still be 3 hex, got %q", fp)
	}
}

// ─── cache_control preservation + cch stability (prompt-cache fix) ───────────

// relocatedFirstBlock returns messages[0].content[0] (the relocated [System
// Instructions] block) from a WAF-rewritten body.
func relocatedFirstBlock(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	msgs, ok := body["messages"].([]any)
	if !ok || len(msgs) == 0 {
		t.Fatalf("no messages in rewritten body: %v", body["messages"])
	}
	return msgs[0].(map[string]any)["content"].([]any)[0].(map[string]any)
}

func TestInjectClaudeWAFFingerprintFull_RelocatedBlock_DefaultsCacheControl(t *testing.T) {
	// Client sent a plain-string system with NO cache_control. The relocated
	// instruction block must get an auto-filled ephemeral cache_control so the
	// (often large) prompt still caches on the OAuth path.
	req := newJSONRequest("POST", "/v1/messages", map[string]any{
		"model":    "claude-opus-4-7",
		"system":   "You are a helpful assistant. Be terse.",
		"messages": []any{map[string]any{"role": "user", "content": "Hi"}},
	})

	injectClaudeWAFFingerprintFull(req)

	block := relocatedFirstBlock(t, readBodyJSON(t, req))
	cc, ok := block["cache_control"].(map[string]any)
	if !ok || cc["type"] != "ephemeral" {
		t.Errorf("relocated block should default to ephemeral cache_control, got %v", block["cache_control"])
	}
}

func TestInjectClaudeWAFFingerprintFull_RelocatedBlock_PreservesClientCacheControl(t *testing.T) {
	// Client sent a system block WITH its own cache_control (1h ttl). The
	// relocated block must carry the client's exact value, not the default.
	clientCC := map[string]any{"type": "ephemeral", "ttl": "1h"}
	req := newJSONRequest("POST", "/v1/messages", map[string]any{
		"model": "claude-sonnet-4-6",
		"system": []any{
			map[string]any{"type": "text", "text": "big project context", "cache_control": clientCC},
		},
		"messages": []any{map[string]any{"role": "user", "content": "Hi"}},
	})

	injectClaudeWAFFingerprintFull(req)

	block := relocatedFirstBlock(t, readBodyJSON(t, req))
	cc, ok := block["cache_control"].(map[string]any)
	if !ok || cc["type"] != "ephemeral" || cc["ttl"] != "1h" {
		t.Errorf("relocated block should preserve client cache_control {ephemeral,1h}, got %v", block["cache_control"])
	}
}

func TestInjectClaudeWAFFingerprintFull_CCHStaysConstant_AcrossBodies(t *testing.T) {
	// system[0] (billing) must be byte-identical across two requests whose
	// only difference is the trailing user message — otherwise the prompt
	// cache prefix invalidates every turn. cch must stay the stable 00000
	// placeholder (not a body digest).
	billing := func(lastMsg string) string {
		req := newJSONRequest("POST", "/v1/messages", map[string]any{
			"model":    "claude-opus-4-7",
			"system":   "stable system prompt for caching",
			"messages": []any{map[string]any{"role": "user", "content": lastMsg}},
		})
		injectClaudeWAFFingerprintFull(req)
		return readBodyJSON(t, req)["system"].([]any)[0].(map[string]any)["text"].(string)
	}
	a := billing("first question")
	b := billing("a totally different second question")
	if a != b {
		t.Errorf("system[0] billing must be stable across bodies for caching:\n a=%q\n b=%q", a, b)
	}
	if !strings.Contains(a, "cch=00000;") {
		t.Errorf("cch should stay the stable 00000 placeholder, got %q", a)
	}
}
