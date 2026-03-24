package provider

import (
	"fmt"
	"net/http"
	"net/url"
)

// Anthropic implements the Anthropic-compatible provider protocol.
type Anthropic struct{}

func (a *Anthropic) Name() string { return "anthropic" }

func (a *Anthropic) RewriteRequest(req *http.Request, realKey string, baseURL string) error {
	target, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse base_url: %w", err)
	}

	// Preserve the original request path (e.g., /v1/messages).
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host

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
