package provider

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// Anthropic implements the Anthropic-compatible provider protocol.
type Anthropic struct{}

func (a *Anthropic) Name() string { return "anthropic" }

func (a *Anthropic) RewriteRequest(req *http.Request, realKey string, baseURL string) error {
	if err := applyBaseURL(req, baseURL); err != nil {
		return err
	}

	// Set the real API key via x-api-key header.
	req.Header.Set("x-api-key", realKey)

	// Remove Authorization header if present (some clients set both).
	req.Header.Del("Authorization")

	// Ensure anthropic-version is set.
	if req.Header.Get("anthropic-version") == "" {
		req.Header.Set("anthropic-version", "2023-06-01")
	}

	return nil
}

// ExtractTokens parses Anthropic token usage.
//
// Non-streaming response body:
//
//	{"usage": {"input_tokens": N, "output_tokens": N}}
//
// Streaming SSE contains two relevant events:
//
//	data: {"type":"message_start","message":{"usage":{"input_tokens":N}}}
//	data: {"type":"message_delta","usage":{"output_tokens":N}}
func (a *Anthropic) ExtractTokens(data []byte, streaming bool) (int, int) {
	if !streaming {
		var resp struct {
			Usage struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(data, &resp) == nil {
			return resp.Usage.InputTokens, resp.Usage.OutputTokens
		}
		return 0, 0
	}

	// Streaming: scan SSE lines.
	var inputTokens, outputTokens int
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		line = bytes.TrimPrefix(line, []byte("data: "))
		line = bytes.TrimPrefix(line, []byte("data:"))
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var event struct {
			Type    string `json:"type"`
			Message struct {
				Usage struct {
					InputTokens int `json:"input_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Usage struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(line, &event) != nil {
			continue
		}
		switch event.Type {
		case "message_start":
			inputTokens = event.Message.Usage.InputTokens
		case "message_delta":
			outputTokens = event.Usage.OutputTokens
		}
	}
	return inputTokens, outputTokens
}
