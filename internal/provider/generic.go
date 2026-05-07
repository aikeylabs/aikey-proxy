package provider

import (
	"log/slog"
	"net/http"
)

// ExtractTokens delegates to the OpenAI-compatible implementation
// since Generic follows the same response format convention.
func (g *Generic) ExtractTokens(data []byte, streaming bool, logger *slog.Logger) (int, int) {
	return (&OpenAI{}).ExtractTokens(data, streaming, logger)
}

// ExtractTokenBreakdown delegates to the OpenAI implementation; generic
// providers inherit whatever breakdown OpenAI surfaces (currently none).
func (g *Generic) ExtractTokenBreakdown(data []byte, streaming bool, logger *slog.Logger) TokenBreakdown {
	return (&OpenAI{}).ExtractTokenBreakdown(data, streaming, logger)
}

// Generic implements a generic OpenAI-compatible provider protocol.
// This is a fallback for any provider that follows the OpenAI API convention.
type Generic struct{}

func (g *Generic) Name() string { return "generic" }

func (g *Generic) RewriteRequest(req *http.Request, realKey string, baseURL string) error {
	if err := applyBaseURL(req, baseURL); err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+realKey)
	return nil
}
