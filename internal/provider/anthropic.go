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

func (a *Anthropic) RewriteRequest(req *http.Request, realKey, baseURL string) error {
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
func (a *Anthropic) ExtractTokens(data []byte, streaming bool, logger *slog.Logger) (inputTokens, outputTokens int) {
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
				"body_preview", previewBody(data),
			)
			return 0, 0
		}
		in, out := resp.Usage.totalInput(), resp.Usage.OutputTokens
		if in == 0 && out == 0 {
			logger.Warn("anthropic extractor: usage parsed but all token fields zero (likely unknown wire format)",
				"event.name", observability.EventProxyExtractionMismatch,
				"error.code", observability.ErrCodeUsageExtractionFailed,
				"body_len", len(data),
				"body_preview", previewBody(data),
			)
		}
		return in, out
	}

	// Streaming: scan SSE lines.
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
			"body_preview", previewBody(data),
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
			Model      string         `json:"model"`
			StopReason string         `json:"stop_reason"`
			Usage      anthropicUsage `json:"usage"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			logger.Warn("anthropic breakdown: unmarshal failed",
				"event.name", observability.EventProxyExtractionMismatch,
				"error.code", observability.ErrCodeUsageExtractionFailed,
				"error", err.Error(),
				"body_len", len(data),
				"body_preview", previewBody(data),
			)
			return TokenBreakdown{}
		}
		u := resp.Usage
		return TokenBreakdown{
			// 方案 A: InputTokens is the PURE (uncached) input — Anthropic's native
			// usage.input_tokens. Cache lives in the separate buckets below; total
			// context = InputTokens + CacheRead + CacheCreation. (ExtractTokens still
			// returns the TOTAL for its stable legacy contract.) This makes
			// DWD.input_tokens semantically "uncached" so downstream billing/metrics
			// neither double-count nor over-charge cache. See
			// roadmap20260320/技术实现/update/20260604-token-input-纯输入语义治本-方案A.md.
			InputTokens:              u.InputTokens,
			OutputTokens:             u.OutputTokens,
			CacheReadInputTokens:     u.CacheReadInputTokens,
			CacheCreationInputTokens: u.CacheCreationInputTokens,
			StopReason:               resp.StopReason,
			// Upstream-resolved model (often pinned to a dated alias —
			// e.g. client sent `claude-opus-4-7`, response carries
			// `claude-opus-4-7-20251015`). 2026-05-09: response-first.
			Model: resp.Model,
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
			Type  string `json:"type"`
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
			Message struct {
				Model string         `json:"model"`
				Usage anthropicUsage `json:"usage"`
			} `json:"message"`
			Usage anthropicUsage `json:"usage"` // Anthropic streaming: model is on the message envelope
			// of the first `message_start` frame, alongside usage.
		}
		if json.Unmarshal(line, &event) != nil {
			continue
		}
		switch event.Type {
		case "message_start":
			u := event.Message.Usage
			br.InputTokens = u.InputTokens // 方案 A: PURE uncached (cache in fields below)
			br.CacheReadInputTokens = u.CacheReadInputTokens
			br.CacheCreationInputTokens = u.CacheCreationInputTokens
			// Capture upstream model from the same frame. Only
			// overwrite if non-empty — guards against late frames in
			// the same stream that re-emit `message_start` without
			// model (defensive; not observed in practice).
			if event.Message.Model != "" {
				br.Model = event.Message.Model
			}
		case "message_delta":
			br.OutputTokens = event.Usage.OutputTokens
			if event.Delta.StopReason != "" {
				br.StopReason = event.Delta.StopReason
			}
		}
	}
	return br
}
