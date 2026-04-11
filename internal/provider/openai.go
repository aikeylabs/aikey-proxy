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
		line = bytes.TrimPrefix(bytes.TrimSpace(line), []byte("data: "))
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
