package provider

import (
	"fmt"
	"net/http"
	"net/url"
)

// Generic implements a generic OpenAI-compatible provider protocol.
// This is a fallback for any provider that follows the OpenAI API convention.
type Generic struct{}

func (g *Generic) Name() string { return "generic" }

func (g *Generic) RewriteRequest(req *http.Request, realKey string, baseURL string) error {
	target, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse base_url: %w", err)
	}

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host

	req.Header.Set("Authorization", "Bearer "+realKey)

	return nil
}
