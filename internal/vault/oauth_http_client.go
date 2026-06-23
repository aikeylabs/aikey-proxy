package vault

import (
	"context"
	"fmt"
	"net/url"
	"time"

	broker "github.com/AiKeyLabs/aikey-auth-broker"
	"github.com/imroc/req/v3"
)

// ImpersonateChromeHTTPClient implements broker.OAuthHTTPClient with Chrome TLS
// fingerprint impersonation for Cloudflare bypass.
//
// Required by Claude's token endpoint (platform.claude.com/v1/oauth/token).
// Also works for Codex/Kimi endpoints (standard TLS is fine, but Chrome TLS is safe).
//
// Verified 2026-04-15:
//   - Go net/http → 403/429 on Claude token endpoint (Cloudflare TLS detection)
//   - ImpersonateChrome() → 200 (bypass)
//   - Token endpoint requires MINIMAL headers: Content-Type + Accept + User-Agent: axios/1.13.6
//   - Adding Sec-Fetch-*/Origin/Referer → 429 rate limiting
type ImpersonateChromeHTTPClient struct {
	client *req.Client
}

// NewImpersonateChromeHTTPClient creates an HTTP client with Chrome TLS fingerprint.
func NewImpersonateChromeHTTPClient() *ImpersonateChromeHTTPClient {
	c := req.C().
		SetTimeout(60 * time.Second).
		ImpersonateChrome().
		SetCookieJar(nil)
	return &ImpersonateChromeHTTPClient{client: c}
}

func (c *ImpersonateChromeHTTPClient) PostForm(_ context.Context, targetURL string, values url.Values, _ ...broker.HTTPOption) (body []byte, statusCode int, err error) {
	// Always use minimal headers for token endpoints (verified 2026-04-15).
	// User-Agent: axios/1.13.6 matches the verified working pattern.
	// No Sec-Fetch, no Origin, no Referer.
	resp, err := c.client.R().
		SetHeader("Accept", "application/json, text/plain, */*").
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("User-Agent", "axios/1.13.6").
		SetFormDataFromValues(values).
		Post(targetURL)
	if err != nil {
		return nil, 0, fmt.Errorf("http post: %w", err)
	}
	return resp.Bytes(), resp.StatusCode, nil
}

// Compile-time interface check.
var _ broker.OAuthHTTPClient = (*ImpersonateChromeHTTPClient)(nil)
