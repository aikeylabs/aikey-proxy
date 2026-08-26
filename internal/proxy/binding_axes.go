package proxy

import (
	"fmt"

	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// normalizeBindingForClientRoute preserves the three independent routing axes:
// the client-facing route, the real upstream provider, and the wire protocol.
// It always returns a copy because vault/app readers may cache and reuse their
// binding object across concurrent requests.
//
// Legacy rows are repaired only where the missing value is unambiguous:
// ClientRoute comes from the request lookup, ProviderCode falls back to that
// route, and ProtocolType may inherit only a provider with one protocol. A
// multi-protocol provider without protocol_type fails closed instead of making
// YAML row order a routing decision.
func normalizeBindingForClientRoute(binding *vault.ProviderBinding, requestedClientRoute string) (*vault.ProviderBinding, error) {
	if binding == nil {
		return nil, fmt.Errorf("binding is nil")
	}

	resolved := *binding
	requested := provider.CanonicalCode(requestedClientRoute)
	storedClientRoute := provider.CanonicalCode(resolved.ClientRoute)
	if storedClientRoute == "" {
		storedClientRoute = requested
	}
	if requested == "" {
		requested = storedClientRoute
	}
	if storedClientRoute != "" && requested != "" && storedClientRoute != requested {
		return nil, fmt.Errorf("binding client_route %q does not match requested route %q", resolved.ClientRoute, requestedClientRoute)
	}
	resolved.ClientRoute = storedClientRoute

	resolved.ProviderCode = provider.CanonicalCode(resolved.ProviderCode)
	if resolved.ProviderCode == "" {
		// Pre-two-axis vaults stored only the client route. This fallback is
		// compatibility for those rows, not a new Provider=Route assumption.
		resolved.ProviderCode = storedClientRoute
	}
	if resolved.ProviderCode == "" {
		return nil, fmt.Errorf("binding has no upstream provider")
	}

	protocolHint := provider.CanonicalProtocol(resolved.ProtocolType)
	protocolType, ok := provider.ProtocolFamily(resolved.ProviderCode, protocolHint)
	if !ok {
		if protocolHint == "" {
			return nil, fmt.Errorf("provider %q requires an explicit protocol_type", resolved.ProviderCode)
		}
		// Distinguish the two remaining fail-closed shapes so the error points at
		// what the operator can actually change (2026-08-25): a KNOWN provider
		// carrying a protocol the matrix declares illegal for it, vs a CUSTOM
		// provider (zero matrix rows) whose declared protocol is not a protocol
		// this build recognizes at all.
		if len(provider.Routes().ProtocolsForProvider(provider.CanonicalCode(resolved.ProviderCode))) == 0 {
			return nil, fmt.Errorf("custom provider %q declares unrecognized protocol_type %q; register the credential with a supported protocol (e.g. openai_compatible, anthropic)", resolved.ProviderCode, resolved.ProtocolType)
		}
		return nil, fmt.Errorf("provider %q does not support protocol_type %q", resolved.ProviderCode, resolved.ProtocolType)
	}
	resolved.ProtocolType = protocolType

	// A client route selects a wire contract, not the physical provider. This
	// is what makes anthropic -> mock -> anthropic legal while still rejecting
	// an OpenAI model routed into a Mock-Anthropic credential.
	//
	// 🔴 2026-08-25: ClientRouteSupportsProtocol, NOT ProtocolFamily. Since
	// ProtocolFamily learned to trust a custom provider's declared protocol, using
	// it here would let a client route the table has never heard of confirm
	// whatever protocol it was handed — the check would return true for every
	// input and quietly stop rejecting anything. The relaxation belongs to the
	// CREDENTIAL axis; the client surface is still the table's question alone.
	// 需求规格 §11.4.
	if requested != "" {
		if !provider.ClientRouteSupportsProtocol(requested, protocolType) {
			return nil, fmt.Errorf("client route %q does not support binding protocol_type %q", requested, protocolType)
		}
	}

	return &resolved, nil
}

// oauthInjectionProvider maps the physical Mock Provider to the provider
// persona its selected protocol emulates. For real providers the physical
// provider remains authoritative.
func oauthInjectionProvider(providerCode, protocolType string) (string, bool) {
	canonical := provider.CanonicalCode(providerCode)
	if canonical != "mock" {
		return canonical, canonical != ""
	}
	switch provider.CanonicalProtocol(protocolType) {
	case "anthropic":
		return "anthropic", true
	case "openai_compatible":
		return "openai", true
	default:
		return "", false
	}
}
