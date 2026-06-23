package provider

import (
	"fmt"
	"log/slog"
	"net/http"
)

// applyBaseURL delegates to pkg/providerroutes.Table.Stitch — the
// single source of truth for path stitching across the project (proxy,
// control service, future consumers). All algorithm + lookup + table
// loading logic lives in pkg/providerroutes; this thin wrapper exists
// only because each provider's RewriteRequest predates the package and
// callers expect this name.
//
// See pkg/providerroutes/doc.go and stitch.go for the contract.
func applyBaseURL(req *http.Request, baseURL string) error {
	return Routes().Stitch(req, baseURL)
}

// TokenBreakdown is the richer counterpart of ExtractTokens's (in, out) pair.
// It separates cached input into its two Anthropic-native buckets so the UI
// can show a breakdown like "↑70K ↓150 · (↑53K ↓32 cached)". OpenAI-style
// providers fill only InputTokens / OutputTokens and leave the cache fields
// zero (until 方案 A Phase 2b surfaces OpenAI cached_tokens). Why not widen
// ExtractTokens directly: external tests and several call sites rely on the
// (int, int) shape — adding a parallel method is cheaper than churning them.
//
// 方案 A semantics (2026-06-04): InputTokens here is the PURE (uncached) input;
// ExtractTokens's (in) keeps the legacy TOTAL contract. The invariant linking
// them is: ExtractTokens.in == InputTokens + CacheReadInputTokens +
// CacheCreationInputTokens. This makes the reported/persisted input_tokens
// "uncached" so downstream billing + token metrics neither double-count nor
// over-charge cache. See
// roadmap20260320/技术实现/update/20260604-token-input-纯输入语义治本-方案A.md.
type TokenBreakdown struct {
	// StopReason is the raw termination reason emitted by the provider in
	// the final response chunk. Values are provider-specific and passed
	// through un-normalized so consumers can pattern-match against the
	// canonical set each provider documents. Examples:
	//   - Anthropic: "end_turn" | "tool_use" | "max_tokens" | "stop_sequence"
	//   - OpenAI/Kimi: "stop" | "tool_calls" | "length" | "content_filter"
	// Empty string when the upstream response did not carry it (error, or
	// stream cut before the usage/finish frame arrived).
	StopReason string
	// Model is the **upstream-resolved** model identifier carried in the
	// response. Often more specific than what the client sent in the
	// request body (e.g. client `claude-opus-4-7` → upstream
	// `claude-opus-4-7-20251015` with date pin). When non-empty, the
	// proxy prefers this over the request-body model so the WAL /
	// receipt records the actual version that was billed.
	//
	// Empty string when the response didn't carry it (rare — major
	// providers always echo it):
	//   - Stream cut before the first frame (Anthropic message_start /
	//     OpenAI first chunk).
	//   - Non-200 / 4xx responses (no usage/model frame at all).
	//   - body > extractBodyHardLimit (4 MB) — extractor skipped.
	// In those cases the proxy falls back to the request-body model
	// captured by extractModel().
	//
	// 2026-05-09: added so receipts surface the actual billed version
	// instead of the client-side alias. See receipt design doc.
	Model string
	// InputTokens is the PURE (uncached) input — billed at the input rate.
	// Cache is NOT included here (it lives in the two Cache*InputTokens fields);
	// total context = InputTokens + CacheReadInputTokens + CacheCreationInputTokens.
	InputTokens int
	// OutputTokens is the model's generated output in tokens.
	OutputTokens int
	// CacheReadInputTokens is the cache-replayed input (Anthropic prompt-caching
	// "read"), billed at the cache-read rate. Separate from InputTokens. Zero
	// when the provider has no cache or the client didn't opt in.
	CacheReadInputTokens int
	// CacheCreationInputTokens is the input written to the cache this turn,
	// billed at the cache-creation rate. Separate from InputTokens. Zero under
	// the same conditions.
	CacheCreationInputTokens int
	// ReasoningTokens is the model's internal reasoning/thinking tokens
	// (OpenAI o-series usage.completion_tokens_details.reasoning_tokens;
	// Gemini thoughtsTokenCount). Billed at the output rate. Zero for models
	// without a separate reasoning bucket (Anthropic folds thinking into output).
	ReasoningTokens int
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
	//
	// logger is used to emit WARN entries on every silent-fail path
	// (unmarshal error, missing usage field, no usage chunk in stream, etc.)
	// per principles/logging-conventions.md. Pass a request-scoped logger so
	// trace_id / request_id auto-attach to the WARN. nil is allowed but
	// strongly discouraged in production paths — pass slog.Default() if
	// truly no request context.
	ExtractTokens(data []byte, streaming bool, logger *slog.Logger) (inputTokens, outputTokens int)

	// ExtractTokenBreakdown is the richer sibling of ExtractTokens. It returns
	// the same input/output totals plus provider-specific cache details. The
	// default implementation for OpenAI-family providers simply delegates to
	// ExtractTokens and leaves the cache fields at zero.
	ExtractTokenBreakdown(data []byte, streaming bool, logger *slog.Logger) TokenBreakdown
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
