package provider

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
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
// Non-streaming response body (with prompt caching):
//
//	{"usage": {
//	  "input_tokens": N,                   // fresh/uncached input
//	  "cache_creation_input_tokens": N,    // written to cache this turn
//	  "cache_read_input_tokens": N,        // replayed from cache
//	  "output_tokens": N
//	}}
//
// Streaming SSE:
//
//	data: {"type":"message_start","message":{"usage":{"input_tokens":N,"cache_read_input_tokens":N,...}}}
//	data: {"type":"message_delta","usage":{"output_tokens":N}}
//
// Why sum all three input-side fields: Anthropic's `input_tokens` excludes
// cached reads and cache writes. Claude Code's in-prompt counter ("43.4k
// tokens") reflects the total context being sent, so a statusline that
// reports only `input_tokens` looks broken (↑1 vs ~43k) for any conversation
// that has filled the cache. Summing into the returned input preserves the
// "how much did I send" semantics; a later cost-accounting pass can re-split
// the fields with their respective price multipliers (~1.25x write / ~0.1x read).
func (a *Anthropic) ExtractTokens(data []byte, streaming bool, logger *slog.Logger) (int, int) {
	if logger == nil {
		logger = slog.Default()
	}
	if !streaming {
		var resp struct {
			Usage anthropicUsage `json:"usage"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			logger.Warn("anthropic extractor: unmarshal failed",
				"event.name", observability.EventProxyExtractionMismatch,
				"error.code", observability.ErrCodeUsageExtractionFailed,
				"error", err.Error(),
				"body_len", len(data),
				"body_preview", previewBody(data, 200),
			)
			return 0, 0
		}
		in, out := resp.Usage.totalInput(), resp.Usage.OutputTokens
		if in == 0 && out == 0 {
			logger.Warn("anthropic extractor: usage parsed but all token fields zero (likely unknown wire format)",
				"event.name", observability.EventProxyExtractionMismatch,
				"error.code", observability.ErrCodeUsageExtractionFailed,
				"body_len", len(data),
				"body_preview", previewBody(data, 200),
			)
		}
		return in, out
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
				Usage anthropicUsage `json:"usage"`
			} `json:"message"`
			Usage anthropicUsage `json:"usage"`
		}
		// Per-frame parse errors are common in streaming (heartbeats,
		// partial chunks). WARN only at stream end if no usage observed.
		if json.Unmarshal(line, &event) != nil {
			continue
		}
		switch event.Type {
		case "message_start":
			inputTokens = event.Message.Usage.totalInput()
		case "message_delta":
			outputTokens = event.Usage.OutputTokens
		}
	}
	if inputTokens == 0 && outputTokens == 0 {
		logger.Warn("anthropic extractor: no usage observed across stream",
			"event.name", observability.EventProxyExtractionMismatch,
			"error.code", observability.ErrCodeUsageExtractionFailed,
			"body_len", len(data),
			"body_preview", previewBody(data, 200),
		)
	}
	return inputTokens, outputTokens
}

// anthropicUsage mirrors the fields we care about in Anthropic's usage object.
// Cache fields are `omitempty` from upstream for API key requests that don't
// use caching, so unmarshal zero-defaults them and totalInput() is still correct.
type anthropicUsage struct {
	InputTokens              int `json:"input_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	OutputTokens             int `json:"output_tokens"`
}

func (u anthropicUsage) totalInput() int {
	return u.InputTokens + u.CacheCreationInputTokens + u.CacheReadInputTokens
}

// ExtractTokenBreakdown returns the same totals as ExtractTokens plus the
// per-bucket split that Anthropic exposes when prompt caching is in use.
// The streaming parser mirrors ExtractTokens exactly; only the output struct
// differs, so a future consolidation could collapse the two — left as-is for
// now to keep the interface-stable ExtractTokens untouched.
//
// StopReason is populated from `stop_reason`: top-level for non-streaming
// responses, or `message_delta.delta.stop_reason` for streaming.
func (a *Anthropic) ExtractTokenBreakdown(data []byte, streaming bool, logger *slog.Logger) TokenBreakdown {
	if logger == nil {
		logger = slog.Default()
	}
	if !streaming {
		var resp struct {
			Usage      anthropicUsage `json:"usage"`
			StopReason string         `json:"stop_reason"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			logger.Warn("anthropic breakdown: unmarshal failed",
				"event.name", observability.EventProxyExtractionMismatch,
				"error.code", observability.ErrCodeUsageExtractionFailed,
				"error", err.Error(),
				"body_len", len(data),
				"body_preview", previewBody(data, 200),
			)
			return TokenBreakdown{}
		}
		u := resp.Usage
		return TokenBreakdown{
			InputTokens:              u.totalInput(),
			OutputTokens:             u.OutputTokens,
			CacheReadInputTokens:     u.CacheReadInputTokens,
			CacheCreationInputTokens: u.CacheCreationInputTokens,
			StopReason:               resp.StopReason,
		}
	}

	var br TokenBreakdown
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
				Usage anthropicUsage `json:"usage"`
			} `json:"message"`
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
			Usage anthropicUsage `json:"usage"`
		}
		if json.Unmarshal(line, &event) != nil {
			continue
		}
		switch event.Type {
		case "message_start":
			u := event.Message.Usage
			br.InputTokens = u.totalInput()
			br.CacheReadInputTokens = u.CacheReadInputTokens
			br.CacheCreationInputTokens = u.CacheCreationInputTokens
		case "message_delta":
			br.OutputTokens = event.Usage.OutputTokens
			if event.Delta.StopReason != "" {
				br.StopReason = event.Delta.StopReason
			}
		}
	}
	return br
}
