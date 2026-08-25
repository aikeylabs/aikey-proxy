package proxy

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

func TestNormalizeBindingForClientRouteKeepsIndependentAxes(t *testing.T) {
	tests := []struct {
		name       string
		binding    vault.ProviderBinding
		client     string
		wantClient string
		wantVendor string
		wantProto  string
		wantError  bool
	}{
		{
			name:       "Mock Anthropic behind Anthropic client route",
			binding:    vault.ProviderBinding{ProviderCode: "mock", ProtocolType: "anthropic"},
			client:     "anthropic",
			wantClient: "anthropic", wantVendor: "mock", wantProto: "anthropic",
		},
		{
			name:       "Mock OpenAI legacy protocol alias",
			binding:    vault.ProviderBinding{ProviderCode: "mock", ProtocolType: "openai"},
			client:     "openai",
			wantClient: "openai", wantVendor: "mock", wantProto: "openai_compatible",
		},
		{
			name:       "GLM Anthropic endpoint behind Anthropic client route",
			binding:    vault.ProviderBinding{ProviderCode: "zhipu", ProtocolType: "anthropic"},
			client:     "claude",
			wantClient: "anthropic", wantVendor: "zhipu", wantProto: "anthropic",
		},
		{
			name:       "legacy single-protocol binding",
			binding:    vault.ProviderBinding{ProviderCode: "anthropic"},
			client:     "anthropic",
			wantClient: "anthropic", wantVendor: "anthropic", wantProto: "anthropic",
		},
		{
			name:      "protocol mismatch is rejected",
			binding:   vault.ProviderBinding{ProviderCode: "mock", ProtocolType: "anthropic"},
			client:    "openai",
			wantError: true,
		},
		{
			name:      "multi-protocol provider without protocol fails closed",
			binding:   vault.ProviderBinding{ProviderCode: "mock"},
			client:    "anthropic",
			wantError: true,
		},
		// Custom third-party providers (bugfix
		// 2026-08-25-custom-provider-protocolfamily-failclosed-502): a
		// console-registered provider_code with zero fingerprint-matrix rows must
		// resolve through its explicitly declared protocol — this is the exact
		// binding a `key sync` + auto-assign lands for the console's 第三方供应商
		// mode, and it used to 502 on the member's first request. The two error
		// rows pin the fail-closed edges the fix must NOT loosen.
		{
			name:       "custom provider behind openai client route",
			binding:    vault.ProviderBinding{ProviderCode: "customtest", ProtocolType: "openai_compatible"},
			client:     "openai",
			wantClient: "openai", wantVendor: "customtest", wantProto: "openai_compatible",
		},
		{
			name:       "custom provider behind anthropic client route",
			binding:    vault.ProviderBinding{ProviderCode: "customrelay", ProtocolType: "anthropic"},
			client:     "anthropic",
			wantClient: "anthropic", wantVendor: "customrelay", wantProto: "anthropic",
		},
		{
			name:      "custom provider without protocol fails closed",
			binding:   vault.ProviderBinding{ProviderCode: "customtest"},
			client:    "openai",
			wantError: true,
		},
		{
			name:      "custom provider with unrecognized protocol fails closed",
			binding:   vault.ProviderBinding{ProviderCode: "customtest", ProtocolType: "not-a-protocol"},
			client:    "openai",
			wantError: true,
		},
		{
			name:      "custom provider protocol must still match the client route",
			binding:   vault.ProviderBinding{ProviderCode: "customtest", ProtocolType: "anthropic"},
			client:    "openai",
			wantError: true,
		},
		// bugfix 2026-08-25-protocolfamily-swallows-wrong-nonempty-hint: before
		// the gate, this binding was silently "corrected" to anthropic and SERVED
		// (the client route matches the provider's own protocol, so the route
		// cross-check never caught it). The declared dialect and the spoken
		// dialect must never differ silently.
		{
			name:      "known provider with explicitly wrong protocol fails closed",
			binding:   vault.ProviderBinding{ProviderCode: "anthropic", ProtocolType: "openai_compatible"},
			client:    "anthropic",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.binding
			got, err := normalizeBindingForClientRoute(&tt.binding, tt.client)
			if (err != nil) != tt.wantError {
				t.Fatalf("error=%v, wantError=%v", err, tt.wantError)
			}
			if tt.wantError {
				return
			}
			if got.ClientRoute != tt.wantClient || got.ProviderCode != tt.wantVendor || got.ProtocolType != tt.wantProto {
				t.Fatalf("normalized binding=%+v, want client=%q provider=%q protocol=%q", got, tt.wantClient, tt.wantVendor, tt.wantProto)
			}
			if tt.binding != original {
				t.Fatalf("input binding mutated: got %+v, want %+v", tt.binding, original)
			}
		})
	}
}
