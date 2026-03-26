package provider

import (
	"fmt"
	"net/http"
)

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
func (r *Registry) Get(name string) (Provider, error) {
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider protocol %q", name)
	}
	return p, nil
}
