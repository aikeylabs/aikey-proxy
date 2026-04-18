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

// ExtractTokenBreakdown delegates to ExtractTokens. OpenAI-compatible
// providers don't expose a separate cache bucket in the way Anthropic does
// — `prompt_tokens` already reflects the full billable input, cached or not.
// A future enhancement could surface `prompt_tokens_details.cached_tokens`
// via the CacheReadInputTokens field, but the UI consumer treats zero as
// "no cache info" which is the correct default today.
func (o *OpenAI) ExtractTokenBreakdown(data []byte, streaming bool) TokenBreakdown {
	in, out := o.ExtractTokens(data, streaming)
	return TokenBreakdown{InputTokens: in, OutputTokens: out}
}
