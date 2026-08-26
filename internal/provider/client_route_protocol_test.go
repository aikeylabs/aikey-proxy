package provider

import "testing"

// The client-surface axis, tested directly.
//
// # Why this exists (2026-08-25)
//
// `ProtocolFamily` learned to trust an explicitly declared protocol for a
// provider the routing table has zero rows for — right for a CREDENTIAL, whose
// declaration is the only truth a custom third-party provider has. Reusing it
// for the client-route question turned that check into a tautology: an unknown
// route would confirm whatever protocol it was handed, so it returned true for
// every input while still looking like it was enforcing something.
//
// The binding-level fence ("custom client route may not confirm its own
// protocol") catches the same regression through normalizeBindingForClientRoute.
// This one pins the rule at its source, so the reason is readable without
// reconstructing a binding.
func TestClientRouteSupportsProtocol(t *testing.T) {
	tests := []struct {
		name        string
		clientRoute string
		protocol    string
		want        bool
	}{
		{"known route, protocol it really carries", "anthropic", "anthropic", true},
		{"known route, protocol it does not carry", "anthropic", "openai_compatible", false},
		{
			// 🔴 The case that makes this falsifiable. A custom route has no rows,
			// so there is nothing that could confirm it — and the credential-side
			// relaxation must not leak here.
			name: "custom route confirms nothing", clientRoute: "thirdparty_relay", protocol: "openai_compatible", want: false,
		},
		{"custom route cannot confirm an adapterless protocol either", "thirdparty_relay", "gemini", false},
		{"empty route", "", "anthropic", false},
		{"empty protocol", "anthropic", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClientRouteSupportsProtocol(tt.clientRoute, tt.protocol); got != tt.want {
				t.Fatalf("ClientRouteSupportsProtocol(%q, %q) = %v, want %v",
					tt.clientRoute, tt.protocol, got, tt.want)
			}
		})
	}
}

// A credential and a client route ask different questions of the same pair, and
// the difference is the whole point: swap one for the other and the axes split
// silently stops being enforced.
func TestCredentialAndClientRouteDisagreeOnACustomProvider(t *testing.T) {
	const custom, protocol = "thirdparty_relay", "openai_compatible"
	if fam, ok := ProtocolFamily(custom, protocol); !ok || fam != protocol {
		t.Fatalf("a custom provider's CREDENTIAL must be trusted: got (%q, %v)", fam, ok)
	}
	if ClientRouteSupportsProtocol(custom, protocol) {
		t.Fatal("a custom CLIENT ROUTE must confirm nothing — this is the tautology guard")
	}
}
