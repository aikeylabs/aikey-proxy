package proxy

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const (
	ctxKeyRoute contextKey = iota
	ctxKeyStartTime
	ctxKeyIsStreaming
)

// routeFromContext retrieves the resolved route from request context.
func routeFromContext(ctx context.Context) *vkeys.ResolvedRoute {
	r, _ := ctx.Value(ctxKeyRoute).(*vkeys.ResolvedRoute)
	return r
}

// startTimeFromContext retrieves the request start time from context.
func startTimeFromContext(ctx context.Context) time.Time {
	t, _ := ctx.Value(ctxKeyStartTime).(time.Time)
	return t
}

// isStreamingFromContext checks if the request was a streaming request.
func isStreamingFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyIsStreaming).(bool)
	return v
}

// isAikeyProbe returns true when the caller (typically `aikey test` / doctor /
// add) has marked the request as a connectivity probe via `X-Aikey-Probe: 1`.
//
// Probe traffic flows through the regular data plane for credential injection
// + forwarding, but must NOT be recorded into reporter / WAL / collector —
// otherwise pre-flight tests inflate usage counters and (for OAuth/team keys
// with upstream billing) look like real work to the provider.
//
// Keep this helper next to the other header extractors so every emission site
// in proxy.go / recordEvent / streaming callback shares one definition.
const headerAikeyProbe = "X-Aikey-Probe"

func isAikeyProbe(r *http.Request) bool {
	return r != nil && r.Header.Get(headerAikeyProbe) == "1"
}

// extractVirtualKey extracts the virtual key token from the request.
// It looks for tokens with the "aikey_vk_" prefix in:
// 1. Authorization: Bearer <token>
// 2. x-api-key: <token>
func extractVirtualKey(req *http.Request) string {
	// Check Authorization: Bearer <token> (OpenAI-style)
	if auth := req.Header.Get("Authorization"); auth != "" {
		if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
			token = strings.TrimSpace(token)
			if strings.HasPrefix(token, "aikey_vk_") {
				return token
			}
		}
	}

	// Check x-api-key header (Anthropic-style)
	if apiKey := req.Header.Get("x-api-key"); apiKey != "" {
		apiKey = strings.TrimSpace(apiKey)
		if strings.HasPrefix(apiKey, "aikey_vk_") {
			return apiKey
		}
	}

	return ""
}

// extractRawAuthValue extracts the raw API key/token value from request headers,
// regardless of prefix.  Returns "" if no auth header is present.
// Used by path-prefix routing for two-phase auth handling:
//   1. aikey_vk_ prefix → route token Registry resolve
//   2. Anything else (incl. native provider tokens from CLI tools) → fallback to default binding
// Why non-aikey_vk_ is NOT rejected: CLI tools (claude, cursor, openai) send their own
// auth headers through the proxy; the binding logic replaces them with the real key.
func extractRawAuthValue(req *http.Request) string {
	// Check x-api-key first (Anthropic-style, most common for path-prefix)
	if apiKey := req.Header.Get("x-api-key"); apiKey != "" {
		return strings.TrimSpace(apiKey)
	}
	// Check Authorization: Bearer <token> (OpenAI-style)
	if auth := req.Header.Get("Authorization"); auth != "" {
		if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return strings.TrimSpace(token)
		}
	}
	return ""
}

// isProviderCompatible checks if a route token's provider matches the request path's provider.
// Compares canonical codes so broker aliases (claude→anthropic, codex→openai) match correctly.
func isProviderCompatible(route *vkeys.ResolvedRoute, canonicalCode string) bool {
	routeCanonical := providerCanonicalCode(route.ProviderCode)
	if routeCanonical == canonicalCode {
		return true
	}
	// Team managed keys with ProviderBaseURLs support multiple providers.
	// TODO: when ProviderBaseURLs is added to ResolvedRoute, check it here.
	return false
}

// extractProviderFromPath checks if path starts with a known provider prefix
// (e.g., "/anthropic/v1/messages") and returns the provider code and the
// stripped path (e.g., "anthropic", "/v1/messages"). Returns ("", "") if no
// prefix matched.
func extractProviderFromPath(path string) (providerCode, strippedPath string) {
	// List covers both canonical codes and common brand-name aliases that may
	// appear in base URLs written by older CLI versions or non-normalised keys.
	known := []string{"anthropic", "claude", "openai", "google", "kimi", "deepseek", "moonshot"}
	for _, code := range known {
		prefix := "/" + code
		if strings.HasPrefix(path, prefix+"/") || path == prefix {
			return code, strings.TrimPrefix(path, prefix)
		}
	}
	return "", ""
}

// providerToProtocol maps a provider code (or brand alias) to its proxy protocol name.
func providerToProtocol(providerCode string) string {
	switch strings.ToLower(providerCode) {
	case "anthropic", "claude":
		return "anthropic"
	default:
		return "openai_compatible"
	}
}

// providerDefaultBaseURL returns the default upstream base URL for a provider.
// Accepts both canonical codes ("anthropic") and brand aliases ("claude").
//
// ⚠️  CROSS-LANGUAGE DRIFT RISK — MUST STAY IN SYNC WITH Rust registry.
//
// This table mirrors `aikey-cli/data/provider_registry.yaml`. Any new
// provider added there MUST get a matching branch here (and in
// providerCanonicalCode below). See the YAML's top-of-file comment for the
// long-term codegen plan; until that lands, adding a provider is a
// two-language change.
//
// Last synced (2026-04-24): added P0 (groq / xai / openrouter / perplexity)
// + P1 (zhipu / qwen / doubao / siliconflow) alongside the original 6.
func providerDefaultBaseURL(providerCode string) string {
	switch strings.ToLower(providerCode) {
	case "anthropic", "claude":
		return "https://api.anthropic.com"
	case "openai", "gpt", "chatgpt", "codex":
		// Why: OpenAI SDK clients (including Codex) treat base_url as already
		// containing /v1, sending paths like /responses or /chat/completions
		// without the /v1 prefix. Without /v1 here, requests hit wrong endpoints.
		// Ref: bugfix/20260406-ux-feedback-p0-p1-fixes.md
		return "https://api.openai.com/v1"
	case "google", "gemini":
		return "https://generativelanguage.googleapis.com"
	case "kimi", "moonshot":
		// Why no /v1: path-prefix routing strips "/kimi" leaving "/v1/chat/completions".
		// applyBaseURL prepends the base path, so /coding + /v1/... = /coding/v1/...
		// If we used /coding/v1 here, it would become /coding/v1/v1/... (double v1)
		// because the duplicate-prefix check only matches identical prefixes.
		return "https://api.kimi.com/coding"
	case "deepseek":
		// Why: same reason as openai — deepseek SDK expects /v1 in base_url.
		return "https://api.deepseek.com/v1"

	// ── P0 (2026-04-24) ── OpenAI-compatible Western providers ──
	case "groq":
		return "https://api.groq.com/openai/v1"
	case "xai", "grok", "xai_grok":
		return "https://api.x.ai/v1"
	case "openrouter":
		return "https://openrouter.ai/api/v1"
	case "perplexity", "pplx":
		return "https://api.perplexity.ai/v1"

	// ── P1 (2026-04-24) ── China-market providers ──
	case "zhipu", "glm", "zhipuai":
		return "https://open.bigmodel.cn/api/paas/v4"
	case "qwen", "dashscope", "tongyi":
		return "https://dashscope.aliyuncs.com/compatible-mode/v1"
	case "doubao", "ark", "volcengine":
		return "https://ark.cn-beijing.volces.com/api/v3"
	case "siliconflow":
		return "https://api.siliconflow.cn/v1"

	default:
		return ""
	}
}

// providerCanonicalCode maps a brand alias back to the canonical provider code
// used in vault queries (e.g. "claude" → "anthropic").
//
// ⚠️ Same cross-language drift warning as providerDefaultBaseURL — keep in
// sync with Rust's `provider_registry::canonical()` / the YAML oauth_aliases.
func providerCanonicalCode(providerCode string) string {
	switch strings.ToLower(providerCode) {
	case "claude":
		return "anthropic"
	case "gpt", "chatgpt", "codex":
		return "openai"
	case "gemini":
		return "google"

	// ── P0/P1 additions (2026-04-24) ──
	case "grok", "xai_grok":
		return "xai"
	case "pplx":
		return "perplexity"
	case "glm", "zhipuai":
		return "zhipu"
	case "dashscope", "tongyi":
		return "qwen"
	case "ark", "volcengine":
		return "doubao"

	default:
		return strings.ToLower(providerCode)
	}
}

// writeJSONError writes a JSON error response in OpenAI-compatible format.
func writeJSONError(w http.ResponseWriter, statusCode int, errType, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	// Write error JSON inline to avoid encoding/json import for this simple case.
	w.Write([]byte(`{"error":{"message":"` + escapeJSON(message) + `","type":"` + errType + `","code":"` + code + `"}}`))
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
