package provider

import "testing"

// ProtocolFamilyForCredential is the widening that let custom third-party
// providers route again (2026-08-25). These cases pin each of its three
// conditions independently, so a later simplification that drops one of them
// shows up as a named failure rather than as a quietly wider matrix.
//
// Docs: workflow/CI/bugfix/20260825-custom-thirdparty-provider-axes-rejected.md
func TestProtocolFamilyForCredential(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		declared string
		want     string
		wantOK   bool
	}{
		// The defect itself: a provider absent from provider_fingerprint.yaml.
		{"custom provider declaring openai_compatible", "thirdparty_relay", "openai_compatible", "openai_compatible", true},
		{"custom provider declaring anthropic", "thirdparty_relay", "anthropic", "anthropic", true},
		{"custom provider legacy protocol alias", "thirdparty_relay", "openai", "openai_compatible", true},

		// Condition 2 — nothing declared is not something to trust.
		{"custom provider with no declaration", "thirdparty_relay", "", "", false},

		// Condition 3 — vocabulary. `not_a_protocol` appears in no row at all.
		{"custom provider with an invented protocol", "thirdparty_relay", "not_a_protocol", "", false},

		// Condition 1 — a provider the table DOES describe is still judged by its
		// rows. mock is the case that can actually go red here: providers such as
		// zhipu resolve through LegacyProtocolForProvider and so never reach this
		// branch (see the note in ProtocolFamily).
		{"known provider, protocol its rows lack", "mock", "gemini", "", false},
		{"known provider, protocol its rows lack (invented)", "mock", "not_a_protocol", "", false},

		// Known providers must be byte-identical to the strict function, quirks
		// included — this function delegates to it first and adds nothing.
		{"known provider exact pair", "openai", "openai_compatible", "openai_compatible", true},
		{"known provider multi-protocol exact pair", "mock", "anthropic", "anthropic", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ProtocolFamilyForCredential(tt.provider, tt.declared)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("ProtocolFamilyForCredential(%q,%q) = (%q,%v), want (%q,%v)",
					tt.provider, tt.declared, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// The widening must not change ANY answer the strict lookup already had. If a
// future edit reorders the conditions so a known provider takes the widened
// branch, this goes red on the exact provider that moved.
func TestProtocolFamilyForCredential_LeavesKnownProvidersUntouched(t *testing.T) {
	protocols := []string{"", "anthropic", "openai_compatible", "gemini", "not_a_protocol"}
	for _, route := range Routes().All() {
		for _, proto := range protocols {
			wantFam, wantOK := ProtocolFamily(route.Provider, proto)
			if !wantOK {
				continue // only the answers the strict function HAS are frozen here
			}
			gotFam, gotOK := ProtocolFamilyForCredential(route.Provider, proto)
			if gotFam != wantFam || gotOK != wantOK {
				t.Errorf("provider %q protocol %q: strict=(%q,%v) credential=(%q,%v) — the widening changed a known provider's answer",
					route.Provider, proto, wantFam, wantOK, gotFam, gotOK)
			}
		}
	}
}

// A custom provider declaring `gemini` is ADMITTED here and refused later by the
// adapter registry, because condition 3 is a vocabulary check and the proxy
// ships no gemini adapter. That asymmetry is deliberate — `google` + `gemini`
// behaves the same way — so it is pinned rather than left to be rediscovered as
// a bug. If a gemini adapter is ever added, this test simply stops being
// interesting; it does not need to change.
func TestProtocolFamilyForCredential_VocabularyIsNotAdapterCoverage(t *testing.T) {
	fam, ok := ProtocolFamilyForCredential("thirdparty_relay", "gemini")
	if !ok || fam != "gemini" {
		t.Fatalf("got (%q,%v), want (\"gemini\",true) — condition 3 is a vocabulary check", fam, ok)
	}
	if _, err := NewRegistry().Get("gemini"); err == nil {
		t.Skip("a gemini adapter now exists — the asymmetry this test documents is gone")
	}
	// Same treatment for the vendor whose protocol it is: no special-casing.
	if _, googleOK := ProtocolFamily("google", "gemini"); !googleOK {
		t.Errorf("google+gemini must resolve too, otherwise custom providers are being held to a different rule")
	}
}
