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
func providerDefaultBaseURL(providerCode string) string {
	switch strings.ToLower(providerCode) {
	case "anthropic", "claude":
		return "https://api.anthropic.com"
	case "openai", "gpt", "chatgpt":
		return "https://api.openai.com/v1"
	case "google", "gemini":
		return "https://generativelanguage.googleapis.com"
	case "kimi", "moonshot":
		return "https://api.moonshot.cn/v1"
	case "deepseek":
		return "https://api.deepseek.com/v1"
	default:
		return ""
	}
}

// providerCanonicalCode maps a brand alias back to the canonical provider code
// used in vault queries (e.g. "claude" → "anthropic").
func providerCanonicalCode(providerCode string) string {
	switch strings.ToLower(providerCode) {
	case "claude":
		return "anthropic"
	case "gpt", "chatgpt":
		return "openai"
	case "gemini":
		return "google"
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
