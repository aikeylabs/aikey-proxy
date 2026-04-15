package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// oauthInject replaces the original API Key auth with OAuth credential injection.
// Provider-specific persona headers are required — without them, providers reject
// the request (Claude: 429 business rejection, Kimi: 403 access_terminated_error).
//
// Verified patterns from:
//   workflow/CI/researchs/oauth-token-exchange-test/main.go (Claude)
//   workflow/CI/researchs/oauth-codex-test/main.go (Codex)
//   workflow/CI/researchs/oauth-kimi-test/main.go (Kimi)
func oauthInject(req *http.Request, cred *OAuthCredential, providerCode string) {
	// Remove any existing API Key header (proxy may have set it from vault)
	req.Header.Del("x-api-key")
	req.Header.Del("X-Api-Key")

	switch providerCode {
	case "anthropic":
		injectClaudeOAuth(req, cred)
	case "openai":
		injectCodexOAuth(req, cred)
	case "kimi", "moonshot":
		injectKimiOAuth(req, cred)
	default:
		// Generic: just set Bearer token
		req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	}
}

// injectClaudeOAuth injects the full Claude Code persona.
//
// CRITICAL (2026-04-14 verified):
//   Bearer token alone → 401 "OAuth authentication not supported"
//   + anthropic-beta + X-Stainless-* → 429 business rejection (no X-RateLimit-Reset)
//   + metadata.user_id + X-Claude-Code-Session-Id → 200 success
//
// All three layers are required. Missing any one triggers rejection.
func injectClaudeOAuth(req *http.Request, cred *OAuthCredential) {
	// 1. Bearer token
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)

	// 2. Claude Code fingerprint headers
	// Why preserve existing: Claude Code CLI sets its own anthropic-beta, User-Agent,
	// and X-Stainless-* headers. We only add oauth-specific beta flag and ensure
	// the critical persona headers exist. Overwriting would break newer CLI versions
	// that add new beta flags (e.g. context_management requires a specific beta).

	// Append oauth beta to existing anthropic-beta (don't overwrite)
	existingBeta := req.Header.Get("anthropic-beta")
	if existingBeta != "" {
		if !strings.Contains(existingBeta, "oauth-2025-04-20") {
			req.Header.Set("anthropic-beta", existingBeta+",oauth-2025-04-20")
		}
	} else {
		// No existing beta — set full fingerprint (direct API call, not via Claude Code CLI)
		req.Header.Set("anthropic-beta", "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14")
		req.Header.Set("User-Agent", "claude-cli/2.1.22 (external, cli)")
		req.Header.Set("X-App", "cli")
		req.Header.Set("Anthropic-Dangerous-Direct-Browser-Access", "true")
		req.Header.Set("X-Stainless-Lang", "js")
		req.Header.Set("X-Stainless-Package-Version", "0.70.0")
		req.Header.Set("X-Stainless-OS", "Linux")
		req.Header.Set("X-Stainless-Arch", "arm64")
		req.Header.Set("X-Stainless-Runtime", "node")
		req.Header.Set("X-Stainless-Runtime-Version", "v24.13.0")
		req.Header.Set("X-Stainless-Retry-Count", "0")
		req.Header.Set("X-Stainless-Timeout", "600")
	}

	// 3. Claude Code session persona (CRITICAL: completes the persona)
	// Why conditional: Claude Code CLI already sets these when running via proxy.
	// Other tools (Cursor, Cline) don't — proxy injects them only when absent.
	// Overwriting CLI's session_id would break session tracking.
	if req.Header.Get("X-Claude-Code-Session-Id") == "" {
		sessionID := generateUUID()
		req.Header.Set("X-Claude-Code-Session-Id", sessionID)

		// 4. metadata.user_id — only inject if CLI didn't set it
		// (checked inside injectMetadataUserIDIfAbsent)
		deviceHash := sha256.Sum256([]byte(cred.AccountID))
		deviceID := hex.EncodeToString(deviceHash[:])
		userID := fmt.Sprintf("user_%s_account__session_%s", deviceID, sessionID)
		injectMetadataUserIDIfAbsent(req, userID)
	}
}

// injectCodexOAuth injects Codex (ChatGPT Plus/Pro) headers.
//
// Verified 2026-04-15:
//   - originator: opencode (required by Codex API)
//   - ChatGPT-Account-Id: from JWT claims (for org subscriptions)
//   - API URL: chatgpt.com/backend-api/codex/responses (Responses API format)
//
// Why inject-if-absent: Codex CLI may set its own originator or account ID
// in future versions. Overwriting would break forward compatibility.
func injectCodexOAuth(req *http.Request, cred *OAuthCredential) {
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	setIfAbsent(req, "originator", "opencode")
	if cred.AccountID != "" {
		setIfAbsent(req, "ChatGPT-Account-Id", cred.AccountID)
	}
}

// injectKimiOAuth injects Kimi (Moonshot) headers.
//
// Verified 2026-04-15:
//   Without X-Msh-Platform + KimiCLI UA → 403 "only available for Coding Agents"
//   With headers → 200 success
//
// Why inject-if-absent: Kimi CLI may update its platform tag or UA version.
// Preserving CLI-set values ensures forward compatibility.
func injectKimiOAuth(req *http.Request, cred *OAuthCredential) {
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	setIfAbsent(req, "X-Msh-Platform", "kimi_cli")
	setIfAbsent(req, "User-Agent", "KimiCLI/1.24.0")
}

// setIfAbsent sets a header only if it's not already present in the request.
// Why: CLI tools (Claude Code, Codex, Kimi CLI) set their own persona headers.
// Overwriting them would break forward compatibility when CLIs upgrade.
func setIfAbsent(req *http.Request, key, value string) {
	if req.Header.Get(key) == "" {
		req.Header.Set(key, value)
	}
}

// injectMetadataUserIDIfAbsent reads the request body JSON and injects
// metadata.user_id only if it's not already set. This preserves the CLI's
// own user_id when proxying Claude Code requests (forward compatibility).
func injectMetadataUserIDIfAbsent(req *http.Request, userID string) {
	if req.Body == nil {
		return
	}
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}
	req.Body.Close()

	var body map[string]any
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		return
	}

	// Check if metadata.user_id already exists — if so, leave it untouched
	if metadata, ok := body["metadata"].(map[string]any); ok {
		if _, exists := metadata["user_id"]; exists {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
			return
		}
	}

	// Not present — inject it
	metadata, ok := body["metadata"].(map[string]any)
	if !ok {
		metadata = make(map[string]any)
	}
	metadata["user_id"] = userID
	body["metadata"] = metadata

	newBody, err := json.Marshal(body)
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		return
	}

	req.Body = io.NopCloser(bytes.NewReader(newBody))
	req.ContentLength = int64(len(newBody))
}

// injectMetadataUserID reads the request body JSON, injects/overwrites
// metadata.user_id, then rewrites the body.
func injectMetadataUserID(req *http.Request, userID string) {
	if req.Body == nil {
		return
	}
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}
	req.Body.Close()

	var body map[string]any
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		// Not JSON — restore original body unchanged
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		return
	}

	// Inject or overwrite metadata.user_id
	metadata, ok := body["metadata"].(map[string]any)
	if !ok {
		metadata = make(map[string]any)
	}
	metadata["user_id"] = userID
	body["metadata"] = metadata

	newBody, err := json.Marshal(body)
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		return
	}

	req.Body = io.NopCloser(bytes.NewReader(newBody))
	req.ContentLength = int64(len(newBody))
}

// generateUUID generates a random UUID v4.
func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
