package provider

import (
	"strings"

	"github.com/AiKeyLabs/pkg/providerregistry"
	"github.com/AiKeyLabs/pkg/providerroutes"
)

// Routes returns the process-wide provider routing table — a thin
// re-export of pkg/providerroutes.Default() so callers in this package
// don't need to import the leaf package directly.
func Routes() *providerroutes.Table {
	return providerroutes.Default()
}

// CanonicalCode normalizes the provider aliases accepted at client-facing
// boundaries to the canonical provider code used by the route table.
//
// The alias table is READ FROM aikey-cli/data/provider_registry.yaml via
// pkg/providerregistry. It used to be a switch here, duplicating the same 15
// mappings the Rust CLI and the web bundles already derive from that yaml —
// which requirement spec
// workflow/CI/requirements/2026-07-18-provider-protocol-compatibility-and-baseurl.md
// §10 prohibits ("不得维护硬编码 switch 作为第二套静默真相源"). Adding a provider
// is now a one-line yaml edit; the package's SHA gate fails the build if the
// embedded copy drifts from the canonical source.
//
// Unknown input is returned lowercased and trimmed rather than rejected,
// matching Rust's provider_registry::canonical() exactly — see the note on
// Registry.Canonical for why that passthrough must not be "fixed".
func CanonicalCode(providerCode string) string {
	return providerregistry.Default().Canonical(providerCode)
}

// CanonicalProtocol normalizes legacy protocol spellings to the route-table
// vocabulary. Provider is an independent axis: this function never derives a
// protocol from a provider.
//
// NOTE: unlike CanonicalCode this stays a switch, because PROTOCOL aliases have
// no source of truth yet — provider_registry.yaml describes providers, and
// provider_fingerprint.yaml's rows carry a protocol value but no alias table for
// it. Left as-is deliberately rather than folded into the registry, which would
// put protocol vocabulary in a file whose declared scope is provider identity.
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
