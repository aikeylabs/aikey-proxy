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

// TestProtocolFamilyCustomProviderTrustsExplicitVocabularyHint fences the
// custom third-party provider rule (bugfix
// 2026-08-25-custom-provider-protocolfamily-failclosed-502): a provider with
// zero matrix rows resolves to its EXPLICITLY declared protocol when that
// protocol is part of the table's vocabulary — mirroring master's
// validateProviderProtocol, which waves unknown providers through at credential
// creation. Failing closed here while master allowed the registration made the
// console's advertised 第三方供应商 path (incl. Ollama/LM Studio/vLLM) 502 on
// the member's first request. The last two rows pin what MUST keep failing
// closed: no hint, and a hint outside the protocol vocabulary.
func TestProtocolFamilyCustomProviderTrustsExplicitVocabularyHint(t *testing.T) {
	tests := []struct {
		name         string
		providerCode string
		protocolHint string
		want         string
		wantOK       bool
	}{
		{name: "custom openai_compatible", providerCode: "customtest", protocolHint: "openai_compatible", want: "openai_compatible", wantOK: true},
		{name: "custom anthropic", providerCode: "customtest", protocolHint: "anthropic", want: "anthropic", wantOK: true},
		{name: "custom legacy openai alias normalizes", providerCode: "customtest", protocolHint: "openai", want: "openai_compatible", wantOK: true},
		{name: "custom without protocol fails closed", providerCode: "customtest", wantOK: false},
		{name: "custom garbage protocol fails closed", providerCode: "customtest", protocolHint: "not-a-protocol", wantOK: false},
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

// TestProtocolFamilyNeverCorrectsExplicitWrongHint fences bugfix
// 2026-08-25-protocolfamily-swallows-wrong-nonempty-hint: the legacy fallbacks
// (single-protocol len==1, multi-protocol bare-host answer) serve only
// credentials with an EMPTY protocol_type. A non-empty pair the table refused
// must fail closed on BOTH fallback exits — silently "correcting" it means the
// binding declares one wire dialect and the proxy speaks another, the exact
// silent-misroute class the 2026-07-24 axes split exists to kill. The last two
// rows pin that the empty-hint legacy behavior the fallbacks exist for is
// untouched.
func TestProtocolFamilyNeverCorrectsExplicitWrongHint(t *testing.T) {
	tests := []struct {
		name         string
		providerCode string
		protocolHint string
		want         string
		wantOK       bool
	}{
		{name: "single-protocol provider swallowed wrong hint pre-fix", providerCode: "anthropic", protocolHint: "openai_compatible", wantOK: false},
		{name: "multi-protocol provider swallowed wrong hint via bare-host legacy pre-fix", providerCode: "zhipu", protocolHint: "gemini", wantOK: false},
		{name: "single-protocol empty-hint legacy still resolves", providerCode: "anthropic", want: "anthropic", wantOK: true},
		{name: "multi-protocol empty-hint legacy still resolves bare-host face", providerCode: "zhipu", want: "openai_compatible", wantOK: true},
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
