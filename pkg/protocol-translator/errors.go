package translator

import (
	"encoding/json"
	"fmt"
)

// TranslateError represents a recoverable failure inside a translator
// transform. ALL pair-author code returns errors through this type
// (not Go's `error` interface) so the App pipeline / proxy layer can
// reliably extract HTTP status + OpenAI error shape without runtime
// type assertions.
//
// Why a struct vs string-based error: CLIProxyAPI's CLI-style
// `func(...) []byte` (no error) silently swallows malformed input
// (returns the original body unchanged) — that pattern is forbidden
// here per CLAUDE.md "失败要显眼". Structured errors carry HTTPStatus
// + Code + Retriable so the caller can serve consistent OpenAI-shape
// responses without bespoke per-error mapping.
type TranslateError struct {
	// Code is an AiKey-internal taxonomy. Stable across versions —
	// dashboards / alert rules can pattern-match on it. See the const
	// block below for the enumeration.
	Code string

	// Upstream is the original provider error code, when one exists
	// (e.g. Anthropic's `invalid_request_error` / `rate_limit_error`).
	// Empty for errors AiKey detected before forwarding.
	Upstream string

	// HTTPStatus is the status code the App pipeline writes to the
	// client. MUST be set; default zero is invalid.
	HTTPStatus int

	// Message is the user-facing English string. Pairs SHOULD include
	// enough context to help a developer debug (which field failed,
	// what was expected) without leaking secrets (no body bytes, no
	// bearer tokens).
	Message string

	// Retriable hints whether the client should retry the request as-is.
	// True for transient upstream conditions (5xx, 429); false for
	// permanent failures (malformed request body, validation errors).
	// Pairs that don't differentiate set false (safer default — don't
	// loop forever on permanent errors).
	Retriable bool

	// Param names the specific request parameter that caused the error,
	// when known (e.g. "messages", "tool_choice"). Surfaces in the
	// OpenAI error response's `param` field, which standard SDKs render
	// in their error messages. Empty when not applicable.
	Param string
}

// Error implements the standard `error` interface so TranslateError can
// be returned where Go expects `error`. The string format is
// machine-parseable but humans should read `Message` directly.
func (e *TranslateError) Error() string {
	return fmt.Sprintf("translate: %s (http=%d, upstream=%q, param=%q): %s",
		e.Code, e.HTTPStatus, e.Upstream, e.Param, e.Message)
}

// Error codes (AiKey internal taxonomy). Stable identifiers; do NOT
// rename existing codes — dashboards / alerts pattern-match on them.
// New codes can be added freely.
const (
	// CodeBadRequest — translator detected a client-side problem in
	// the inbound request (malformed JSON, n>1, etc.). 400 to client.
	CodeBadRequest = "AIKEY_BAD_REQUEST"

	// CodeUnsupportedParam — a specific request field is not supportable
	// by this pair (e.g. response_format=json_schema before阶段 1).
	// 400 to client with `param` populated.
	CodeUnsupportedParam = "AIKEY_UNSUPPORTED_PARAMETER"

	// CodeUpstreamRateLimit — upstream returned 429 / overloaded.
	// Forward 429 to client; Retriable=true.
	CodeUpstreamRateLimit = "AIKEY_UPSTREAM_RATE_LIMIT"

	// CodeUpstreamAuth — upstream rejected our credentials (401/403).
	// Forward to client so they re-auth. Retriable=false (a retry with
	// the same bearer will fail the same way).
	CodeUpstreamAuth = "AIKEY_UPSTREAM_AUTH"

	// CodeUpstream5xx — upstream returned 500/502/503/504 or had a
	// connection failure. Forward 502 or 503 depending on the exact
	// cause. Retriable=true.
	CodeUpstream5xx = "AIKEY_UPSTREAM_5XX"

	// CodeTranslationFailed — translator implementation bug: a field
	// mapping or response parse failed in a way that shouldn't happen
	// given the inputs we accepted. 500 to client; this is the "if you
	// see this in production, file a bug" code.
	CodeTranslationFailed = "AIKEY_TRANSLATION_FAILED"

	// CodeStreamNotSupported — client requested stream=true but the
	// (from, to) pair doesn't implement StreamChunkTransform yet
	// (阶段 0 reality: only NonStream is implemented). 400 to client
	// with an actionable hint to retry stream=false or wait for the
	// streaming-support milestone.
	CodeStreamNotSupported = "AIKEY_STREAM_NOT_YET_SUPPORTED"
)

// openAIErrorBody is the JSON shape OpenAI clients (including the
// official Python / Node SDKs) expect for error responses. Keeping it
// here as a private struct + marshaling helper means pair authors
// never construct this shape by hand.
type openAIErrorBody struct {
	Error openAIErrorPayload `json:"error"`
}

type openAIErrorPayload struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
	Param   string `json:"param,omitempty"`
}

// ToOpenAIShape renders this error as the JSON body an OpenAI client
// would expect. The App pipeline / proxy layer calls this when writing
// the failed response. Returns valid JSON unconditionally (json.Marshal
// on this concrete struct cannot fail — but we still check defensively
// to satisfy gosec / static analyzers).
//
// The `type` field maps from our internal Code taxonomy:
//
//   - AIKEY_BAD_REQUEST / AIKEY_UNSUPPORTED_PARAMETER → "invalid_request_error"
//   - AIKEY_UPSTREAM_AUTH → "authentication_error"
//   - AIKEY_UPSTREAM_RATE_LIMIT → "rate_limit_error"
//   - AIKEY_UPSTREAM_5XX → "server_error"
//   - AIKEY_TRANSLATION_FAILED → "server_error"
//   - AIKEY_STREAM_NOT_YET_SUPPORTED → "invalid_request_error"
func (e *TranslateError) ToOpenAIShape() []byte {
	body := openAIErrorBody{
		Error: openAIErrorPayload{
			Message: e.Message,
			Type:    openAITypeForCode(e.Code),
			Code:    e.Code,
			Param:   e.Param,
		},
	}
	out, err := json.Marshal(body)
	if err != nil {
		// Should be unreachable: openAIErrorBody is a closed struct
		// with only string fields. Defensive fallback returns a
		// hand-rolled valid JSON string so callers never have to
		// handle a marshal failure here.
		return []byte(`{"error":{"message":"internal: failed to marshal translate error","type":"server_error","code":"AIKEY_TRANSLATION_FAILED"}}`)
	}
	return out
}

// openAITypeForCode maps an AiKey Code to the OpenAI `error.type` value
// SDKs branch on. The mapping is intentionally many-to-few — we have
// more granular codes than OpenAI has types, but standard SDK retry
// logic only cares about the type bucket.
func openAITypeForCode(code string) string {
	switch code {
	case CodeBadRequest, CodeUnsupportedParam, CodeStreamNotSupported:
		return "invalid_request_error"
	case CodeUpstreamAuth:
		return "authentication_error"
	case CodeUpstreamRateLimit:
		return "rate_limit_error"
	default:
		// CodeUpstream5xx, CodeTranslationFailed, unknown
		return "server_error"
	}
}
