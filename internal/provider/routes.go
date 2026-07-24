package provider

import (
	"strings"

	"github.com/AiKeyLabs/pkg/providerroutes"
)

// Routes returns the process-wide provider routing table — a thin
// re-export of pkg/providerroutes.Default() so callers in this package
// don't need to import the leaf package directly.
func Routes() *providerroutes.Table {
	return providerroutes.Default()
}

// CanonicalCode normalizes the provider aliases accepted at client-facing
// boundaries to the canonical provider code used by the route table. Keeping
// this beside Routes gives proxy and admin callers one mapping instead of
// maintaining separate switches.
func CanonicalCode(providerCode string) string {
	switch strings.ToLower(strings.TrimSpace(providerCode)) {
	case "claude":
		return "anthropic"
	case "gpt", "chatgpt", "codex":
		return "openai"
	case "gemini":
		return "google"
	case "kimi":
		return "kimi_code"
	case "grok", "xai_grok":
		return "xai"
	case "pplx":
		return "perplexity"
	case "glm", "zhipuai":
		return "zhipu"
	case "dashscope", "tongyi":
		return "qwen"
	case "ark", "volcengine":
		return "doubao"
	default:
		return strings.ToLower(strings.TrimSpace(providerCode))
	}
}

// CanonicalProtocol normalizes legacy protocol spellings to the route-table
// vocabulary. Provider is an independent axis: this function never derives a
// protocol from a provider.
func CanonicalProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "openai":
		return "openai_compatible"
	case "google":
		return "gemini"
	case "claude":
		return "anthropic"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

// ProtocolFamily resolves the upstream wire protocol from the independent
// provider + protocol axes. Multi-protocol providers deliberately fail closed
// when protocolHint is missing or invalid; silently choosing their first YAML
// row would make routing depend on row order.
//
// The single-protocol fallback keeps legacy credentials (whose protocol_type
// predates the two-axis model and may therefore be empty) working.
func ProtocolFamily(providerCode, protocolHint string) (string, bool) {
	providerCode = CanonicalCode(providerCode)
	protocolHint = CanonicalProtocol(protocolHint)
	if route, ok := Routes().ByProviderProtocol(providerCode, protocolHint); ok {
		return route.Protocol, true
	}
	protocols := Routes().ProtocolsForProvider(providerCode)
	if len(protocols) != 1 {
		return "", false
	}
	return protocols[0], true
}
