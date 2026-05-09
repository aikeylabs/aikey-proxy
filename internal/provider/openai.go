package provider

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// OpenAI implements the OpenAI-compatible provider protocol.
// Used for OpenAI, and any OpenAI-compatible API.
type OpenAI struct{}

func (o *OpenAI) Name() string { return "openai" }

func (o *OpenAI) RewriteRequest(req *http.Request, realKey string, baseURL string) error {
	if err := applyBaseURL(req, baseURL); err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+realKey)
	return nil
}

// ExtractTokens parses OpenAI token usage.
//
// Two wire formats supported (auto-detected via field presence):
//
// 1. Chat Completions API (`/v1/chat/completions`):
//
//	{"usage": {"prompt_tokens": N, "completion_tokens": N}}
//
// 2. Responses API (`/v1/responses`, used by codex with wire_api="responses"):
//
//	{"usage": {"input_tokens": N, "output_tokens": N}}
//
// Streaming: Chat Completions requires stream_options.include_usage=true; the
// last data chunk before [DONE] carries the same usage object. Responses API
// emits `response.completed` with embedded `response.usage`.
//
// Per principles/logging-conventions.md: every silent-zero path emits a WARN
// with event.name=proxy.extraction.shape_mismatch + body_preview so an
// operator can tell from one log line which wire format was unrecognized.
func (o *OpenAI) ExtractTokens(data []byte, streaming bool, logger *slog.Logger) (int, int) {
	if logger == nil {
		logger = slog.Default()
	}
	if !streaming {
		var resp openaiUsageEnvelope
		if err := json.Unmarshal(data, &resp); err != nil {
			logger.Warn("openai extractor: unmarshal failed",
				"event.name", observability.EventProxyExtractionMismatch,
				"error.code", observability.ErrCodeUsageExtractionFailed,
				"error", err.Error(),
				"body_len", len(data),
				"body_preview", previewBody(data, 200),
			)
			return 0, 0
		}
		if resp.Usage == nil {
			logger.Warn("openai extractor: usage field missing on non-streaming response",
				"event.name", observability.EventProxyExtractionMismatch,
				"error.code", observability.ErrCodeUsageExtractionFailed,
				"body_len", len(data),
				"body_preview", previewBody(data, 200),
			)
			return 0, 0
		}
		in, out := resp.Usage.Resolve()
		if in == 0 && out == 0 {
			logger.Warn("openai extractor: usage object present but all token fields zero (likely unknown wire format)",
				"event.name", observability.EventProxyExtractionMismatch,
				"error.code", observability.ErrCodeUsageExtractionFailed,
				"body_len", len(data),
				"body_preview", previewBody(data, 200),
			)
		}
		return in, out
	}

	// Streaming: scan SSE lines for a chunk that contains usage.
	// Both Chat Completions ([DONE] sentinel) and Responses API
	// (response.completed event with embedded response.usage) are tried.
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		// Strip SSE "data:" prefix. Some providers use "data: " (with space,
		// per SSE spec), others use "data:" (no space, e.g. KIMI/Moonshot).
		// Why both: SSE spec says the space after colon is optional;
		// TrimPrefix("data: ") misses "data:{" leaving the line unparsed.
		line = bytes.TrimPrefix(line, []byte("data: "))
		line = bytes.TrimPrefix(line, []byte("data:"))
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var chunk openaiUsageEnvelope
		if err := json.Unmarshal(line, &chunk); err != nil {
			// Per-frame parse errors during streaming are common (heartbeat
			// frames, partial chunks). Don't WARN per-frame — only WARN at
			// stream end if no usage was captured at all.
			continue
		}
		// Why pointer check (Usage != nil) instead of value > 0:
		// some providers return prompt_tokens=0 for fully cached requests.
		if chunk.Usage != nil {
			in, out := chunk.Usage.Resolve()
			if in == 0 && out == 0 {
				logger.Warn("openai extractor: streaming usage frame had all-zero tokens",
					"event.name", observability.EventProxyExtractionMismatch,
					"error.code", observability.ErrCodeUsageExtractionFailed,
					"frame_preview", previewBody(line, 200),
				)
			}
			return in, out
		}
		// Responses API: usage is nested under "response" on the
		// response.completed event.
		if chunk.Response != nil && chunk.Response.Usage != nil {
			in, out := chunk.Response.Usage.Resolve()
			if in == 0 && out == 0 {
				logger.Warn("openai extractor: Responses API streaming usage had all-zero tokens",
					"event.name", observability.EventProxyExtractionMismatch,
					"error.code", observability.ErrCodeUsageExtractionFailed,
					"frame_preview", previewBody(line, 200),
				)
			}
			return in, out
		}
	}
	logger.Warn("openai extractor: no usage chunk found in stream",
		"event.name", observability.EventProxyExtractionMismatch,
		"error.code", observability.ErrCodeUsageExtractionFailed,
		"body_len", len(data),
		"body_preview", previewBody(data, 200),
	)
	return 0, 0
}

// openaiUsageData mirrors fields from both Chat Completions and Responses APIs.
// Resolve() picks whichever pair is non-zero so a single struct handles both.
type openaiUsageData struct {
	// Chat Completions API
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	// Responses API (codex, GPT-5, etc.)
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Resolve returns (input, output) from whichever wire format populated them.
// If both are populated (shouldn't happen but tolerated), Chat Completions wins.
func (u *openaiUsageData) Resolve() (int, int) {
	in := u.PromptTokens
	if in == 0 {
		in = u.InputTokens
	}
	out := u.CompletionTokens
	if out == 0 {
		out = u.OutputTokens
	}
	return in, out
}

// openaiUsageEnvelope wraps both top-level usage (Chat Completions, streaming
// chunks) and response-nested usage (Responses API streaming).
type openaiUsageEnvelope struct {
	Usage *openaiUsageData `json:"usage"`
	// Responses API streaming wraps usage in `response`:
	//   {"type":"response.completed","response":{"usage":{...}}}
	Response *struct {
		Usage *openaiUsageData `json:"usage"`
	} `json:"response,omitempty"`
}

// ExtractTokenBreakdown delegates to ExtractTokens for the token numbers
// (OpenAI-compatible providers don't expose a separate cache bucket in the
// way Anthropic does — `prompt_tokens` already reflects the full billable
// input, cached or not; a future enhancement could surface
// `prompt_tokens_details.cached_tokens` via CacheReadInputTokens, but the
// UI consumer treats zero as "no cache info" which is the correct default
// today), plus extracts `choices[0].finish_reason` for StopReason metadata.
//
// Streaming spec: `finish_reason` only appears on the final delta chunk
// (before `[DONE]`). We scan SSE lines same as ExtractTokens and capture
// the last non-empty finish_reason seen.
func (o *OpenAI) ExtractTokenBreakdown(data []byte, streaming bool, logger *slog.Logger) TokenBreakdown {
	in, out := o.ExtractTokens(data, streaming, logger)
	br := TokenBreakdown{InputTokens: in, OutputTokens: out}
	br.StopReason = extractOpenAIStopReason(data, streaming)
	br.Model = extractOpenAIModel(data, streaming)
	return br
}

// extractOpenAIModel reads top-level `model` from a complete chat-completion
// response (non-streaming) or any SSE chunk (streaming). OpenAI / Kimi /
// Moonshot all repeat the model id on every chunk, so the first non-empty
// hit wins.
//
// 2026-05-09: response-first model — captures upstream-resolved model
// (often more specific than what the client sent, e.g. dated pin like
// "gpt-4o-2024-08-06"). Empty string when unparseable / cut early; the
// proxy falls back to the request-body model in that case.
func extractOpenAIModel(data []byte, streaming bool) string {
	type envelope struct {
		Model string `json:"model"`
	}
	if !streaming {
		var e envelope
		if json.Unmarshal(data, &e) == nil {
			return e.Model
		}
		return ""
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		line = bytes.TrimPrefix(line, []byte("data: "))
		line = bytes.TrimPrefix(line, []byte("data:"))
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var e envelope
		if json.Unmarshal(line, &e) == nil && e.Model != "" {
			return e.Model
		}
	}
	return ""
}

// extractOpenAIStopReason reads `choices[0].finish_reason` from a complete
// response (non-streaming) or the final delta chunk (streaming). Returns
// empty string if not present or unparseable.
func extractOpenAIStopReason(data []byte, streaming bool) string {
	type choice struct {
		FinishReason string `json:"finish_reason"`
	}
	type chunk struct {
		Choices []choice `json:"choices"`
	}

	if !streaming {
		var c chunk
		if json.Unmarshal(data, &c) == nil && len(c.Choices) > 0 {
			return c.Choices[0].FinishReason
		}
		return ""
	}

	// Streaming: walk SSE lines, capture the last non-empty finish_reason.
	// Note the reverse direction would be more efficient but parsing order
	// matches ExtractTokens for consistency.
	var lastReason string
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		line = bytes.TrimPrefix(line, []byte("data: "))
		line = bytes.TrimPrefix(line, []byte("data:"))
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var c chunk
		if json.Unmarshal(line, &c) == nil && len(c.Choices) > 0 {
			if r := c.Choices[0].FinishReason; r != "" {
				lastReason = r
			}
		}
	}
	return lastReason
}

// previewBody returns a UTF-8 safe preview of the body (≤max bytes) for
// inclusion in WARN logs. Trims any trailing newlines and replaces non-ASCII
// control bytes with '?' so the log line stays grep-friendly. Long bodies
// get a "..." suffix.
func previewBody(data []byte, max int) string {
	if len(data) == 0 {
		return ""
	}
	end := len(data)
	suffix := ""
	if end > max {
		end = max
		suffix = "..."
	}
	// Make a sanitized copy: replace control bytes other than \t with '?'.
	out := make([]byte, end)
	for i, b := range data[:end] {
		if b < 0x20 && b != '\t' {
			out[i] = '?'
		} else if b == 0x7f {
			out[i] = '?'
		} else {
			out[i] = b
		}
	}
	return string(out) + suffix
}
