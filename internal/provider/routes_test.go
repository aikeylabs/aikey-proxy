package provider

import "testing"

func TestProtocolFamilyLookupUsesProviderAndProtocolAxes(t *testing.T) {
	tests := []struct {
		name         string
		providerCode string
		protocolHint string
		want         string
		wantOK       bool
	}{
		{name: "mock anthropic", providerCode: "mock", protocolHint: "anthropic", want: "anthropic", wantOK: true},
		{name: "mock openai", providerCode: "mock", protocolHint: "openai_compatible", want: "openai_compatible", wantOK: true},
		{name: "mock missing protocol fails closed", providerCode: "mock", wantOK: false},
		{name: "mock invalid protocol fails closed", providerCode: "mock", protocolHint: "gemini", wantOK: false},
		{name: "legacy single-protocol provider", providerCode: "openai", want: "openai_compatible", wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ProtocolFamily(tt.providerCode, tt.protocolHint)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("ProtocolFamily(%q, %q) = (%q, %v), want (%q, %v)", tt.providerCode, tt.protocolHint, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestProtocolFamilyNormalizesLegacyAliasesWithoutCollapsingAxes(t *testing.T) {
	tests := []struct {
		provider string
		protocol string
		want     string
	}{
		{provider: "claude", protocol: "anthropic", want: "anthropic"},
		{provider: "openai", protocol: "openai", want: "openai_compatible"},
		{provider: "gemini", protocol: "google", want: "gemini"},
		{provider: "mock", protocol: "openai", want: "openai_compatible"},
	}
	for _, tt := range tests {
		got, ok := ProtocolFamily(tt.provider, tt.protocol)
		if !ok || got != tt.want {
			t.Errorf("ProtocolFamily(%q, %q) = (%q, %v), want (%q, true)", tt.provider, tt.protocol, got, ok, tt.want)
		}
	}
}
