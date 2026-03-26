package provider

import (
	"fmt"
	"net/http"
	"net/url"
)

// Kimi implements the Moonshot AI (Kimi) provider protocol.
// Kimi is fully OpenAI-compatible; the only difference is the default base URL.
//
// API reference: https://platform.moonshot.cn/docs/api/chat
// Default base URL: https://api.moonshot.cn/v1
// Auth: Authorization: Bearer <key>
type Kimi struct{}

func (k *Kimi) Name() string { return "kimi" }

func (k *Kimi) RewriteRequest(req *http.Request, realKey string, baseURL string) error {
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
