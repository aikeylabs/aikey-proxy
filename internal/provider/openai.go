package provider

import (
	"bytes"
	"encoding/json"
	"net/http"
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
// Non-streaming response body:
//
//	{"usage": {"prompt_tokens": N, "completion_tokens": N}}
//
// Streaming: requires stream_options.include_usage=true; the last data chunk
// before [DONE] carries the same usage object.
func (o *OpenAI) ExtractTokens(data []byte, streaming bool) (int, int) {
	// usageChunk uses a pointer for Usage so we can distinguish "field absent"
	// (nil) from "field present with zero values" (e.g. prompt_tokens: 0).
	type usageData struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	}
	type usageChunk struct {
		Usage *usageData `json:"usage"`
	}
	if !streaming {
		var resp usageChunk
		if json.Unmarshal(data, &resp) == nil && resp.Usage != nil {
			return resp.Usage.PromptTokens, resp.Usage.CompletionTokens
		}
		return 0, 0
	}

	// Streaming: scan SSE lines for a chunk that contains usage.
	// The usage object appears in the final data chunk before [DONE]
	// (requires stream_options.include_usage=true in the request).
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
		var chunk usageChunk
		// Why pointer check (Usage != nil) instead of PromptTokens > 0:
		// some providers return prompt_tokens=0 for fully cached requests;
		// the old > 0 check silently dropped those as "no usage".
		if json.Unmarshal(line, &chunk) == nil && chunk.Usage != nil {
			return chunk.Usage.PromptTokens, chunk.Usage.CompletionTokens
		}
	}
	return 0, 0
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
func (o *OpenAI) ExtractTokenBreakdown(data []byte, streaming bool) TokenBreakdown {
	in, out := o.ExtractTokens(data, streaming)
	br := TokenBreakdown{InputTokens: in, OutputTokens: out}
	br.StopReason = extractOpenAIStopReason(data, streaming)
	return br
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
