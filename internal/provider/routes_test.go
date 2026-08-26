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

// TestProtocolFamilyCustomProviderVocabularyIsNotAdapterCoverage pins §11 rule 6
// of the compatibility spec: the credential axis asks "is this protocol part of
// the table's VOCABULARY", NOT "does this build ship an adapter for it".
//
// Why this needs its own fence: `gemini` is in the vocabulary (google has a row)
// but the proxy carries no gemini adapter, so a custom provider declaring
// `gemini` is allowed HERE and rejected at the adapter. That asymmetry looks like
// a bug to the next reader, and "tightening" it here would silently make custom
// providers stricter than the very vendor whose protocol they borrow — `google` +
// `gemini` resolves today, and holding the two to different rules is the exact
// inconsistency §11 rule 6 exists to prevent.
//
// The client-route half of the same question is the opposite answer and is fenced
// separately in client_route_protocol_test.go ("custom route cannot confirm an
// adapterless protocol either") — the two must not be collapsed.
//
// This assertion previously lived on ProtocolFamilyForCredential, which this
// change folded back into ProtocolFamily; carried over so the documented rule
// keeps a fence.
// spec: workflow/CI/requirements/2026-07-18-provider-protocol-compatibility-and-baseurl.md §11 rule 6
// bugfix: workflow/CI/bugfix/20260825-custom-thirdparty-provider-axes-rejected.md
func TestProtocolFamilyCustomProviderVocabularyIsNotAdapterCoverage(t *testing.T) {
	fam, ok := ProtocolFamily("thirdparty_relay", "gemini")
	if !ok || fam != "gemini" {
		t.Fatalf("ProtocolFamily(\"thirdparty_relay\", \"gemini\") = (%q, %v), want (\"gemini\", true) — the credential axis is a vocabulary check, not an adapter check", fam, ok)
	}
	if _, err := NewRegistry().Get("gemini"); err == nil {
		t.Skip("a gemini adapter now exists — the asymmetry this test documents is gone")
	}
	// Same treatment for the vendor whose protocol it is: no special-casing.
	if _, googleOK := ProtocolFamily("google", "gemini"); !googleOK {
		t.Errorf("google+gemini must resolve too, otherwise custom providers are being held to a different rule than the vendor they borrow the protocol from")
	}
}
