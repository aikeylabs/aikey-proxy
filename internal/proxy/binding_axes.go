package proxy

import (
	"fmt"
	"strings"

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

	// 2026-08-25: ForCredential, not the strict ProtocolFamily. This binding is a
	// STORED CREDENTIAL, so a provider the routing table has never heard of is a
	// custom third-party provider the console deliberately allowed (its own
	// third-party dialog recommends the flow for Ollama / LM Studio / vLLM), and
	// its declared protocol_type is the only truth there is. The strict function
	// rejected every one of them, which is why such a credential could be created
	// and shown as a live channel yet 502 on the first request. See the long note
	// on ProtocolFamilyForCredential for the three conditions that keep this from
	// widening the matrix for providers the table DOES know.
	// bugfix: workflow/CI/bugfix/20260825-custom-thirdparty-provider-axes-rejected.md (regression: make -C aikey-proxy test-bugfix-custom-provider-axes)
	protocolHint := provider.CanonicalProtocol(resolved.ProtocolType)
	protocolType, ok := provider.ProtocolFamilyForCredential(resolved.ProviderCode, protocolHint)
	if !ok {
		if protocolHint == "" {
			return nil, fmt.Errorf("provider %q requires an explicit protocol_type", resolved.ProviderCode)
		}
		return nil, fmt.Errorf("provider %q does not support protocol_type %q", resolved.ProviderCode, resolved.ProtocolType)
	}
	resolved.ProtocolType = protocolType

	// A client route selects a wire contract, not the physical provider. This
	// is what makes anthropic -> mock -> anthropic legal while still rejecting
	// an OpenAI model routed into a Mock-Anthropic credential.
	//
	// 🚫 This half MUST keep using the strict ProtocolFamily. The question here is
	// "does the CLIENT SURFACE carry this protocol", and the answer has to come
	// from the table. Answering it with ProtocolFamilyForCredential would let an
	// unknown client route confirm whatever protocol was handed to it — the check
	// would return true for every input and stop rejecting anything.
	if requested != "" {
		requestedProtocol, routeOK := provider.ProtocolFamily(requested, protocolType)
		if !routeOK || !strings.EqualFold(requestedProtocol, protocolType) {
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
