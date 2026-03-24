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
