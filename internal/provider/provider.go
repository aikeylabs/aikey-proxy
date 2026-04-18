package provider

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// applyBaseURL sets the scheme, host, and prepends the base URL's path prefix
// to the request path. For example:
//
//	baseURL = "https://api.moonshot.cn/v1", req.URL.Path = "/chat/completions"
//	→ req.URL = "https://api.moonshot.cn/v1/chat/completions"
func applyBaseURL(req *http.Request, baseURL string) error {
	target, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse base_url: %w", err)
	}

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host

	// Prepend base URL path prefix (e.g., /v1) if present.
	// Why: skip prepend if request path already starts with the prefix to avoid
	// double-prefix like /v1/v1/chat/completions. This happens when path-prefix
	// routing strips "/openai" from "/openai/v1/..." leaving "/v1/..." and the
	// base_url is "https://api.openai.com/v1".
	// Ref: bugfix/20260406-ux-feedback-p0-p1-fixes.md
	if target.Path != "" && target.Path != "/" {
		prefix := strings.TrimRight(target.Path, "/")
		if !strings.HasPrefix(req.URL.Path, prefix+"/") && req.URL.Path != prefix {
			req.URL.Path = prefix + req.URL.Path
			if req.URL.RawPath != "" {
				req.URL.RawPath = prefix + req.URL.RawPath
			}
		}
	}

	return nil
}

// TokenBreakdown is the richer counterpart of ExtractTokens's (in, out) pair.
// It separates cached input into its two Anthropic-native buckets so the UI
// can show a breakdown like "↑70K ↓150 · (↑53K ↓32 cached)". OpenAI-style
// providers fill only InputTokens / OutputTokens and leave the cache fields
// zero. Why not widen ExtractTokens directly: external tests and several
// call sites rely on the (int, int) shape — adding a parallel method is
// cheaper than churning them.
type TokenBreakdown struct {
	// InputTokens is the *total* input charged against context — for
	// Anthropic this equals input + cache_creation + cache_read. Callers
	// that want to split it must use the *InputTokens fields below.
	InputTokens int
	// OutputTokens is the model's generated output in tokens.
	OutputTokens int
	// CacheReadInputTokens is the portion of InputTokens that was replayed
	// from the provider's cache (Anthropic prompt-caching "read"). Zero when
	// the provider has no cache or the client didn't opt in.
	CacheReadInputTokens int
	// CacheCreationInputTokens is the portion of InputTokens that was
	// written to the cache this turn. Zero under the same conditions.
	CacheCreationInputTokens int
}

// Provider adapts requests for a specific AI provider protocol.
type Provider interface {
	// Name returns the provider protocol name ("openai", "anthropic").
	Name() string

	// RewriteRequest modifies the outgoing request:
	// - Sets the real API key in the appropriate header
	// - Sets the correct Host and URL
	RewriteRequest(req *http.Request, realKey string, baseURL string) error

	// ExtractTokens parses token counts from a provider response.
	// For non-streaming requests, data is the full JSON response body.
	// For streaming requests, data is the full accumulated SSE stream.
	// Returns (inputTokens, outputTokens); returns (0, 0) if unavailable.
	ExtractTokens(data []byte, streaming bool) (inputTokens, outputTokens int)

	// ExtractTokenBreakdown is the richer sibling of ExtractTokens. It returns
	// the same input/output totals plus provider-specific cache details. The
	// default implementation for OpenAI-family providers simply delegates to
	// ExtractTokens and leaves the cache fields at zero.
	ExtractTokenBreakdown(data []byte, streaming bool) TokenBreakdown
}

// Registry maps protocol names to provider implementations.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry creates a registry with all built-in providers.
func NewRegistry() *Registry {
	r := &Registry{
		providers: make(map[string]Provider),
	}
	r.Register(&OpenAI{})
	r.Register(&Anthropic{})
	r.Register(&Kimi{})
	r.Register(&Generic{})
	return r
}

// Register adds a provider to the registry.
func (r *Registry) Register(p Provider) {
	r.providers[p.Name()] = p
}

// Get returns the provider for the given protocol name.
// "openai_compatible" is accepted as an alias for "openai".
func (r *Registry) Get(name string) (Provider, error) {
	if name == "openai_compatible" {
		name = "openai"
	}
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider protocol %q", name)
	}
	return p, nil
}
