package provider

import "github.com/AiKeyLabs/pkg/providerroutes"

// Routes returns the process-wide provider routing table — a thin
// re-export of pkg/providerroutes.Default() so callers in this package
// don't need to import the leaf package directly.
func Routes() *providerroutes.Table {
	return providerroutes.Default()
}

// ProtocolFamily resolves the upstream wire protocol from the independent
// provider + protocol axes. Multi-protocol providers deliberately fail closed
// when protocolHint is missing or invalid; silently choosing their first YAML
// row would make routing depend on row order.
//
// The single-protocol fallback keeps legacy credentials (whose protocol_type
// predates the two-axis model and may therefore be empty) working.
func ProtocolFamily(providerCode, protocolHint string) (string, bool) {
	if route, ok := Routes().ByProviderProtocol(providerCode, protocolHint); ok {
		return route.Protocol, true
	}
	protocols := Routes().ProtocolsForProvider(providerCode)
	if len(protocols) != 1 {
		return "", false
	}
	return protocols[0], true
}
