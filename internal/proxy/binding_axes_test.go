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
