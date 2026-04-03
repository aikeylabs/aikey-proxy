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
	type usagePayload struct {
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if !streaming {
		var resp usagePayload
		if json.Unmarshal(data, &resp) == nil {
			return resp.Usage.PromptTokens, resp.Usage.CompletionTokens
		}
		return 0, 0
	}

	// Streaming: scan SSE lines for a chunk that contains usage.
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimPrefix(bytes.TrimSpace(line), []byte("data: "))
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var chunk usagePayload
		if json.Unmarshal(line, &chunk) == nil && chunk.Usage.PromptTokens > 0 {
			return chunk.Usage.PromptTokens, chunk.Usage.CompletionTokens
		}
	}
	return 0, 0
}
