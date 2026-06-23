package provider

import (
	"log/slog"
	"net/http"
)

// Kimi implements the Moonshot AI (Kimi) provider protocol.
// Kimi is fully OpenAI-compatible; the only difference is the default base URL.
//
// API reference: https://platform.moonshot.cn/docs/api/chat
// Default base URL: https://api.moonshot.cn/v1
// Auth: Authorization: Bearer <key>
type Kimi struct{}

// ExtractTokens delegates to the OpenAI-compatible implementation
// since Kimi follows the same response format.
func (k *Kimi) ExtractTokens(data []byte, streaming bool, logger *slog.Logger) (inputTokens, outputTokens int) {
	return (&OpenAI{}).ExtractTokens(data, streaming, logger)
}

// ExtractTokenBreakdown delegates to the OpenAI implementation; Kimi has no
// provider-specific cache semantics beyond what OpenAI exposes.
func (k *Kimi) ExtractTokenBreakdown(data []byte, streaming bool, logger *slog.Logger) TokenBreakdown {
	return (&OpenAI{}).ExtractTokenBreakdown(data, streaming, logger)
}

func (k *Kimi) Name() string { return "kimi" }

func (k *Kimi) RewriteRequest(req *http.Request, realKey, baseURL string) error {
	if err := applyBaseURL(req, baseURL); err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+realKey)
	return nil
}
