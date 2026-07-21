package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// oauthInject replaces the original API Key auth with OAuth credential injection.
// Provider-specific persona headers are required — without them, providers reject
// the request (Claude: 429 business rejection, Kimi: 403 access_terminated_error).
//
// Verified patterns from:
//
//	workflow/CI/research/oauth-token-exchange-test/main.go (Claude)
//	workflow/CI/research/oauth-codex-test/main.go (Codex)
//	workflow/CI/research/oauth-kimi-test/main.go (Kimi)
func oauthInject(req *http.Request, cred *OAuthCredential, providerCode string) {
	// Remove any existing API Key header (proxy may have set it from vault)
	req.Header.Del("x-api-key")
	req.Header.Del("X-Api-Key")

	switch providerCode {
	case "anthropic":
		injectClaudeOAuth(req, cred)
	case "openai":
		injectCodexOAuth(req, cred)
	// 2026-05-08 Kimi 双平台拆分: 'kimi' 是 deprecated alias,'kimi_code' 与
	// 'moonshot' 都用 Kimi OAuth 协议 (kimi-cli upstream client_id);三者共用
	// 同一注入路径。
	case "kimi_code", "moonshot", "kimi":
		injectKimiOAuth(req, cred)
	default:
		// Generic: just set Bearer token
		req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	}
}

// injectClaudeOAuth injects the full Claude Code persona.
//
// Layered requirements:
//   - 2026-04-16 verified (header layer):
//     Bearer token alone → 401 "OAuth authentication not supported"
//   - ?beta=true + anthropic-version → accepted as OAuth
//   - anthropic-beta + X-Stainless-* → 429 business rejection (no rate-limit headers)
//   - metadata.user_id + X-Claude-Code-Session-Id → 200 (header layer satisfied)
//   - 2026-05-06 verified (body layer): for premium models (Sonnet/Opus),
//     headers alone are NOT enough. WAF additionally checks system[0]:
//     must equal claudeCodeSystemPrompt OR contain x-anthropic-billing-header
//     with cc_entrypoint=. Otherwise: same 429-no-rate-limit-headers signature.
//     Haiku is exempt from the body check.
//
// See injectClaudeWAFFingerprint + research doc
// workflow/CI/research/oauth-token-response-identity/2026-04-15-oauth-token-response-identity.md
// (sections "2026-05-06 增补 I" + "Round 5 / sub2api 对比").
func injectClaudeOAuth(req *http.Request, cred *OAuthCredential) {
	// Capture inbound origin before any header rewrites. Step 4b below
	// forces UA to "claude-cli/X.Y.Z (external, cli)" for non-CLI clients,
	// which would mask third-party origin from later detection. We need
	// the genuine inbound UA for the step-7 WAF dispatch (skip vs apply).
	inboundClientIsClaudeCode := clientIsClaudeCode(req)

	// 1. Bearer token
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)

	// 2. anthropic-version — required for all Anthropic API calls.
	// Why here: OAuth path skips provider.RewriteRequest (which normally sets this).
	// Without it, Anthropic returns 400 "missing anthropic-version header".
	setIfAbsent(req, "anthropic-version", "2023-06-01")

	// 3. ?beta=true query parameter — required for OAuth token access.
	// Why: research test verified that API URL must include ?beta=true.
	// Without it, Anthropic returns 401 "OAuth authentication not supported".
	// Ref: workflow/CI/research/oauth-token-exchange-test/main.go line 59-60
	q := req.URL.Query()
	if q.Get("beta") == "" {
		q.Set("beta", "true")
		req.URL.RawQuery = q.Encode()
	}

	// 4. Claude Code fingerprint headers
	// Why preserve existing: Claude Code CLI sets its own anthropic-beta, User-Agent,
	// and X-Stainless-* headers. We only add oauth-specific beta flag and ensure
	// the critical persona headers exist. Overwriting would break newer CLI versions
	// that add new beta flags (e.g. context_management requires a specific beta).

	// Append oauth beta to existing anthropic-beta (don't overwrite existing flags)
	existingBeta := req.Header.Get("anthropic-beta")
	if existingBeta != "" {
		if !strings.Contains(existingBeta, "oauth-2025-04-20") {
			req.Header.Set("anthropic-beta", existingBeta+",oauth-2025-04-20")
		}
	} else {
		setIfAbsent(req, "anthropic-beta", "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14")
	}

	// Claude Code persona headers — each guarded independently.
	// Why per-header: a client may set some but not all (e.g. User-Agent without
	// X-Stainless-*). Blanket overwrite would destroy client-set values.
	//
	// User-Agent is the one exception that needs conditional overwrite. The
	// rest of these are setIfAbsent so a future Claude Code CLI version's own
	// values (UA, X-Stainless-Package-Version, etc.) aren't downgraded to the
	// hardcoded defaults below. But for User-Agent, third-party clients
	// (opencode/Vercel AI SDK, Cursor, Cline) always set their own UA, which
	// leaks through setIfAbsent and reaches Anthropic's OAuth WAF — it then
	// rejects the request as "not a Claude Code session" with 429 + no
	// X-RateLimit-Reset (business rejection signature, ref
	// workflow/CI/research/oauth-token-exchange-test/main.go:16-17).
	//
	// Detect-and-replace: trust the inbound UA only if it already starts with
	// "claude-cli/" (real CLI, forward-compat with future versions); otherwise
	// force the verified persona UA. Other persona headers stay setIfAbsent
	// because third-party clients rarely set them, so the leak vector is
	// User-Agent specific.
	if !strings.HasPrefix(req.Header.Get("User-Agent"), "claude-cli/") {
		req.Header.Set("User-Agent", "claude-cli/2.1.22 (external, cli)")
	}
	setIfAbsent(req, "X-App", "cli")
	setIfAbsent(req, "Anthropic-Dangerous-Direct-Browser-Access", "true")
	setIfAbsent(req, "X-Stainless-Lang", "js")
	setIfAbsent(req, "X-Stainless-Package-Version", "0.70.0")
	setIfAbsent(req, "X-Stainless-OS", "Linux")
	setIfAbsent(req, "X-Stainless-Arch", "arm64")
	setIfAbsent(req, "X-Stainless-Runtime", "node")
	setIfAbsent(req, "X-Stainless-Runtime-Version", "v24.13.0")
	setIfAbsent(req, "X-Stainless-Retry-Count", "0")
	setIfAbsent(req, "X-Stainless-Timeout", "600")

	// 5. Claude Code session persona (CRITICAL: completes the persona)
	// Why conditional: Claude Code CLI already sets these when running via proxy.
	// Other tools (Cursor, Cline) don't — proxy injects them only when absent.
	// Overwriting CLI's session_id would break session tracking.
	if req.Header.Get("X-Claude-Code-Session-Id") == "" {
		// Skip session-id + metadata injection if the CSPRNG fails (effectively
		// never on a healthy host); a missing session-id header is safe — the
		// upstream treats it as a fresh session.
		if sessionID, uuidErr := generateUUID(); uuidErr == nil {
			req.Header.Set("X-Claude-Code-Session-Id", sessionID)

			// 6. metadata.user_id — only inject if CLI didn't set it
			// (checked inside injectMetadataUserIDIfAbsent)
			// Why: Anthropic requires metadata.user_id with format:
			//   user_<64hex_device_id>_account_<account_uuid>_session_<session_uuid>
			// Missing account_uuid → 429 business rejection (not real rate limit).
			// Ref: workflow/CI/research/oauth-token-exchange-test/main.go line 16-17
			deviceHash := sha256.Sum256([]byte(cred.AccountID))
			deviceID := hex.EncodeToString(deviceHash[:])
			accountUUID := cred.ExternalID // OAuth provider's account UUID
			userID := fmt.Sprintf("user_%s_account_%s_session_%s", deviceID, accountUUID, sessionID)
			injectMetadataUserIDIfAbsent(req, userID)
		}
	}

	// 7. WAF body fingerprint dispatch (2026-05-06 research).
	// Anthropic's OAuth WAF gates premium models (Sonnet/Opus) on a body-side
	// Claude Code fingerprint check. Bisection verified the rule (research doc
	// 2026-05-06 增补 I + Round 5 sub2api 对比); we apply it ONLY to non-claude-cli
	// clients here. Real Claude CLI traffic already carries the fingerprint in
	// body.system, so a body rewrite is at best wasted I/O and at worst risks
	// damaging real-CLI traffic semantics.
	//
	// Detection signal: inbound User-Agent prefix `claude-cli/` — captured BEFORE
	// step 4b (UA detect-and-replace), which would force every UA to claude-cli/2.1.22
	// regardless of origin.
	if !inboundClientIsClaudeCode {
		injectClaudeWAFFingerprintFull(req)
		// Tool-name TitleCase rewrite for Anthropic's third-party gate. See
		// oauth_tool_rewrite.go for protocol details and bisection-doc refs.
		// Reverse rewrite happens in proxy.go ModifyResponse via the mapping
		// stored on req.Context().
		rewriteToolNamesForward(req)
	}

	// NOTE: oauth_group POOL requests pass the REAL client identity upstream
	// unchanged. The former AccountPersona normalization (N users → one frozen
	// SHA256(accountID) identity) was removed 2026-06-29: a frozen synthetic
	// fingerprint can't track Claude Code version bumps, so it drifts stale and
	// becomes its OWN detection signal — worse than transparent pass-through.
	// Risk is now bounded by a ≤3-users-per-account cap, not by disguise.
}

// claudeCodeSystemPrompt is the byte-exact 57-char marker that Anthropic's
// OAuth-path WAF uses to gate premium model access (Sonnet/Opus). Bisection-
// verified 2026-05-06: when system[0].text equals exactly this string, the
// WAF lets the request through; otherwise (and absent the alternative
// billing-header form) the WAF returns 429 "rate_limit_error" with NO
// anthropic-ratelimit-* headers — i.e. business rejection disguised as
// rate limit.
//
// Reference:
//
//	workflow/CI/research/oauth-token-response-identity/2026-04-15-oauth-token-response-identity.md
//	(sections "2026-05-06 增补 I" and "Round 5 / sub2api 对比")
const claudeCodeSystemPrompt = "You are Claude Code, Anthropic's official CLI for Claude."

// isHaikuRequest checks the body's "model" field for a haiku marker. WAF
// skips body fingerprint check for haiku models (round 1 verified).
func isHaikuRequest(body map[string]any) bool {
	model, _ := body["model"].(string)
	return strings.Contains(strings.ToLower(model), "haiku")
}

// normalizeSystemAndCheckFingerprint normalizes body.system to an array
// representation and reports whether system[0] already satisfies the WAF
// fingerprint.
//
// Returns:
//   - normalized: array form of the system field (caller can prepend to it)
//   - alreadyOK:  true if system[0] already matches; caller should no-op
func normalizeSystemAndCheckFingerprint(system any) (normalized []any, alreadyOK bool) {
	switch v := system.(type) {
	case nil:
		return []any{}, false
	case string:
		// String form: wrap as a single text block.
		block := map[string]any{"type": "text", "text": v}
		return []any{block}, hasFingerprint(block)
	case []any:
		if len(v) > 0 {
			if first, ok := v[0].(map[string]any); ok && hasFingerprint(first) {
				return v, true
			}
		}
		return v, false
	case map[string]any:
		// Non-standard but possible: single block object instead of array.
		// Wrap as array so caller can prepend cleanly.
		return []any{v}, hasFingerprint(v)
	default:
		// Unknown shape — wrap and let WAF prepend handle it.
		return []any{v}, false
	}
}

// hasFingerprint reports whether the given block is a text block whose
// content satisfies the WAF check (either the exact magic intro, or a
// billing-header form). All other shapes return false.
func hasFingerprint(block map[string]any) bool {
	if t, _ := block["type"].(string); t != "text" {
		return false
	}
	text, _ := block["text"].(string)
	if text == claudeCodeSystemPrompt {
		return true
	}
	// Billing-header form: "x-anthropic-billing-header: ... cc_entrypoint=..."
	// Round 4b verified that any cc_entrypoint value passes; only the prefix
	// + the cc_entrypoint key need to be present.
	if strings.HasPrefix(text, "x-anthropic-billing-header:") &&
		strings.Contains(text, "cc_entrypoint=") {
		return true
	}
	return false
}

// injectCodexOAuth injects Codex (ChatGPT Plus/Pro) headers.
//
// Verified 2026-04-15:
//   - originator: codex_cli_rs (the OFFICIAL codex CLI value; was "opencode",
//     inherited from opencode's codex.ts). Source of truth: openai/codex
//     codex-rs/login/src/auth/default_client.rs DEFAULT_ORIGINATOR="codex_cli_rs"
//     (sent on every /responses request via add_originator_header). This is only
//     a FALLBACK: setIfAbsent preserves the value a real codex CLI already sends,
//     so we merely stop mislabelling originator-less traffic as the third-party
//     "opencode" tool. NOTE: this is a required API header, NOT a persona/UA
//     fingerprint — we deliberately do NOT inject a synthetic User-Agent/session
//     here (that identity-forgery layer was removed 2026-06-29 for transparent
//     proxy + ≤3-users/account; see CC账号池 requirement).
//   - ChatGPT-Account-Id: from JWT claims (for org subscriptions)
//   - API URL: chatgpt.com/backend-api/codex/responses (Responses API format)
//
// Why inject-if-absent: Codex CLI may set its own originator or account ID
// in future versions. Overwriting would break forward compatibility.
//
// ChatGPT-Account-Id source (fixed 2026-07-04, R34 codex pools): the real
// chatgpt_account_id lives in ExternalID (the broker extracts it from the token
// JWT's auth.chatgpt_account_id claim). AccountID is OUR identifier — the
// broker's random account row id on the personal path, the pool's internal
// account id on the group path — sending it upstream was a wrong value that only
// went unnoticed because Codex CLI usually sets its own header (setIfAbsent).
// ExternalID first; AccountID kept as a legacy fallback for old vault rows that
// predate ExternalID.
func injectCodexOAuth(req *http.Request, cred *OAuthCredential) {
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	setIfAbsent(req, "originator", "codex_cli_rs")
	if id := cred.ExternalID; id != "" {
		setIfAbsent(req, "ChatGPT-Account-Id", id)
	} else if cred.AccountID != "" {
		setIfAbsent(req, "ChatGPT-Account-Id", cred.AccountID)
	}
}

// injectKimiOAuth injects Kimi (Moonshot) headers.
//
// Verified 2026-04-15:
//
//	Without X-Msh-Platform + KimiCLI UA → 403 "only available for Coding Agents"
//	With headers → 200 success
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

// setRequestBody atomically replaces req.Body AND req.ContentLength,
// guaranteeing they stay in sync. This is critical: a mismatch between
// Body and ContentLength causes upstream to read partial/corrupt data.
func setRequestBody(req *http.Request, bodyBytes []byte) {
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))
}

// injectMetadataUserIDIfAbsent reads the request body JSON and injects
// metadata.user_id only if it's not already set. This preserves the CLI's
// own user_id when proxying Claude Code requests (forward compatibility).
//
// Fence I13 body chokepoint (2026-07-21): this is the ONLY place the proxy
// writes an identifier into an outbound body, so the member-identity guard sits
// here rather than at today's single call site — a future caller ("attribute
// upstream usage per member") inherits the fence instead of re-opening the hole.
// Refusing the write is the safe failure: metadata.user_id is optional to the
// WAF's persona check in the sense that a MISSING one degrades to a fresh
// session, whereas a leaked one is unrecoverable — the third party has it.
func injectMetadataUserIDIfAbsent(req *http.Request, userID string) {
	if shape := memberIdentityShape(userID); shape != "" {
		tc := traceFromContext(req.Context())
		slog.Warn("refused to write member identity into upstream body",
			"event.name", observability.EventProxyRequestIdentityBlocked,
			"identity_shape", shape,
			"path", req.URL.Path,
			"trace_id", tc.TraceID,
			"span_id", tc.SpanID,
			"request_id", tc.RequestID,
		)
		return
	}
	mutateJSONBody(req, func(body map[string]any) bool {
		// Skip if metadata.user_id already present.
		if metadata, ok := body["metadata"].(map[string]any); ok {
			if _, exists := metadata["user_id"]; exists {
				return false
			}
		}
		metadata, ok := body["metadata"].(map[string]any)
		if !ok {
			metadata = make(map[string]any)
		}
		metadata["user_id"] = userID
		body["metadata"] = metadata
		return true
	})
}

// mutateJSONBody applies `mutate` to the request's JSON body.
// `mutate` returns true if the body was changed (re-marshal required),
// false to keep the original body.
//
// Guarantees (critical for upstream correctness):
//   - req.Body and req.ContentLength are always updated together
//   - On any error path, the original body is restored (not dropped)
//   - Never leaves req.Body as a consumed reader
func mutateJSONBody(req *http.Request, mutate func(body map[string]any) bool) {
	if req.Body == nil {
		return
	}
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		// Body read failure: can't recover content — leave req.Body as-is
		// (reverse-proxy will treat this request as failed on next read).
		return
	}
	req.Body.Close()

	var body map[string]any
	if jErr := json.Unmarshal(bodyBytes, &body); jErr != nil {
		// Not JSON — restore original body unchanged
		setRequestBody(req, bodyBytes)
		return
	}

	changed := mutate(body)
	if !changed {
		setRequestBody(req, bodyBytes)
		return
	}

	newBody, err := json.Marshal(body)
	if err != nil {
		// Re-marshal failed (shouldn't happen for map[string]any) — restore original
		setRequestBody(req, bodyBytes)
		return
	}
	setRequestBody(req, newBody)
}

// generateUUID generates a random UUID v4. It returns an error if the system
// CSPRNG fails so callers never silently fall back to a non-random identifier.
func generateUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
