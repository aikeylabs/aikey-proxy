package provider

import (
	"fmt"
	"net/http"
	"net/url"
)

// OpenAI implements the OpenAI-compatible provider protocol.
// Used for OpenAI, and any OpenAI-compatible API.
type OpenAI struct{}

func (o *OpenAI) Name() string { return "openai" }

func (o *OpenAI) RewriteRequest(req *http.Request, realKey string, baseURL string) error {
	target, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse base_url: %w", err)
	}

	// Preserve the original request path (e.g., /v1/chat/completions).
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host

	// Set the real API key in Authorization header.
	req.Header.Set("Authorization", "Bearer "+realKey)

	return nil
}
