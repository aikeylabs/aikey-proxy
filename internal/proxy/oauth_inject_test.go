package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- helpers ---

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
	uuid := generateUUID()

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
	uuid2 := generateUUID()
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
	// A client sets User-Agent and X-Stainless-OS but nothing else.
	// Proxy should preserve those two and fill in all the rest.
	req := httptest.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("User-Agent", "Cursor/1.0")
	req.Header.Set("X-Stainless-OS", "Darwin")

	injectClaudeOAuth(req, claudeCred())

	// Client-set values preserved
	if got := req.Header.Get("User-Agent"); got != "Cursor/1.0" {
		t.Errorf("User-Agent overwritten: got %q, want %q", got, "Cursor/1.0")
	}
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
