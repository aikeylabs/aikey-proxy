package provider

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// applyBaseURL sets scheme/host on req and stitches the upstream URL.
//
// v4.3 (2026-05-01): config-table driven. The path stitch contract is:
//
//	final_url = baseURL + version + (req.URL.Path with leading version stripped)
//
// where (baseURL, version) come from the per-host provider_routes table
// (loaded via fingerprint.LookupRouteByHost). Clients differ in whether
// they put the API version in the request path (kimi-cli sends
// /v1/chat/..., OpenAI SDK sends /chat/...); stripping the version from
// the request once and re-appending it via the table guarantees a single
// /version/ segment in the final URL no matter what the client sent.
//
// Falls back to literal-prepend (no version awareness) when:
//   - baseURL host is not in provider_routes (third-party gateway absent
//     from the table); the caller is expected to register the gateway as
//     a new yaml row per the "all gateways in the table" rule. Until then
//     proxy degrades to "use baseURL path verbatim, prepend it to req.path"
//     so requests still flow, just without de-duplication.
//
// Why a single mathematical rule + table: every special-case version-path
// dance is in declarative data, not branching code. New gateway = 1 yaml
// row. New API version (e.g. /v2) = update the row's version field.
func applyBaseURL(req *http.Request, baseURL string) error {
	target, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse base_url: %w", err)
	}

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host

	// Look up the canonical (base_url path, version) for this host. If
	// found, prefer it over the parsed target.Path because target.Path
	// may have come from a vault entry that included the version segment
	// — the table separates them cleanly so we can re-attach version
	// exactly once.
	basePath, version := lookupRoutePath(target.Host, target.Path)

	// Strip leading version from request path (client sent it, table will
	// re-attach). Segment-aligned to avoid /v1 swallowing /v1abc.
	reqPath := req.URL.Path
	if version != "" {
		if strings.HasPrefix(reqPath, version+"/") {
			reqPath = strings.TrimPrefix(reqPath, version)
		} else if reqPath == version {
			reqPath = ""
		}
	}

	stitched := basePath + version + reqPath
	if stitched == "" {
		stitched = "/"
	}

	req.URL.Path = stitched
	if req.URL.RawPath != "" {
		req.URL.RawPath = stitched
	}
	return nil
}

// lookupRoutePath resolves (base path, version) for an upstream host.
// Returns (parsedPath, "") for hosts not in the routes table — degraded
// behaviour that prepends the URL's path verbatim (no version dedup), so
// unknown third-party gateways still flow but should be added to yaml
// provider_routes for proper routing.
func lookupRoutePath(host string, parsedPath string) (basePath, version string) {
	host = strings.ToLower(host)
	if route, ok := providerRouteByHost(host); ok {
		// route.BaseURL is the canonical full root; extract just its path
		// component so we don't smuggle scheme/host into the stitch.
		if u, err := url.Parse(route.BaseURL); err == nil {
			return strings.TrimRight(u.Path, "/"), route.Version
		}
	}
	// Fallback: treat the full parsed path as base, version unknown (no
	// re-attach). This is the legacy behaviour for hosts not yet in table.
	return strings.TrimRight(parsedPath, "/"), ""
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
	// StopReason is the raw termination reason emitted by the provider in
	// the final response chunk. Values are provider-specific and passed
	// through un-normalized so consumers can pattern-match against the
	// canonical set each provider documents. Examples:
	//   - Anthropic: "end_turn" | "tool_use" | "max_tokens" | "stop_sequence"
	//   - OpenAI/Kimi: "stop" | "tool_calls" | "length" | "content_filter"
	// Empty string when the upstream response did not carry it (error, or
	// stream cut before the usage/finish frame arrived).
	StopReason string
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
