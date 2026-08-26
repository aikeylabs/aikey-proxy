package proxy

import (
	"strings"
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
		// wantErrReason pins WHICH check rejected, not merely that something did.
		// Without it a case can stay green while the check it was written for is
		// deleted, because a later check happens to reject the same input for an
		// unrelated reason — which is exactly what the 2026-08-25 mutation drill
		// found for three of these cases. Empty = only "an error occurred" is
		// asserted (pre-existing cases, left as they were).
		wantErrReason string
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
		// ── Custom third-party providers (2026-08-25 regression) ──────────────
		// The console's third-party mode registers a provider code that is
		// deliberately absent from provider_fingerprint.yaml, and master allows
		// it (validateProviderProtocol: "provider not in matrix (custom) — allow").
		// Between 2026-07-24 and this change the proxy rejected all of them, so
		// such a credential could be created, shown as a live channel, and 502 on
		// its first request. bugfix: 20260825-custom-thirdparty-provider-axes-rejected.md
		{
			name:       "custom third-party provider declaring openai_compatible routes",
			binding:    vault.ProviderBinding{ProviderCode: "thirdparty_relay", ProtocolType: "openai_compatible"},
			client:     "openai",
			wantClient: "openai", wantVendor: "thirdparty_relay", wantProto: "openai_compatible",
		},
		{
			name:       "custom third-party provider declaring anthropic routes",
			binding:    vault.ProviderBinding{ProviderCode: "thirdparty_relay", ProtocolType: "anthropic"},
			client:     "anthropic",
			wantClient: "anthropic", wantVendor: "thirdparty_relay", wantProto: "anthropic",
		},
		{
			// Condition 2: nothing declared, nothing to trust. A custom provider has
			// no table row to inherit from either, so this must stay fail-closed.
			name:          "custom third-party provider without protocol fails closed",
			binding:       vault.ProviderBinding{ProviderCode: "thirdparty_relay"},
			client:        "openai",
			wantError:     true,
			wantErrReason: `provider "thirdparty_relay" requires an explicit protocol_type`,
		},
		{
			// Condition 3: a protocol no row in the table uses at all — a typo, not
			// a wire format. Refused here rather than several frames deeper.
			name:          "custom third-party provider with an invented protocol is rejected",
			binding:       vault.ProviderBinding{ProviderCode: "thirdparty_relay", ProtocolType: "not_a_protocol"},
			client:        "openai",
			wantError:     true,
			wantErrReason: `custom provider "thirdparty_relay" declares unrecognized protocol_type`,
		},
		{
			// Condition 1 — the fence that keeps the widening from leaking onto
			// providers the table DOES describe. `mock` has rows and none of them
			// say gemini, so the table's answer stands. (Picked over zhipu+gemini
			// on purpose: zhipu resolves through LegacyProtocolForProvider and so
			// could never have gone red here.)
			name:          "known provider still fails closed on a protocol its rows lack",
			binding:       vault.ProviderBinding{ProviderCode: "mock", ProtocolType: "gemini"},
			client:        "anthropic",
			wantError:     true,
			wantErrReason: `provider "mock" does not support`,
		},
		{
			// The client-route half must stay strict: an OpenAI-speaking relay may
			// not be served through the Anthropic client surface. If this ever goes
			// green, binding_axes.go:64 has been switched to the credential-trusting
			// lookup and the check has become self-satisfying.
			name:          "custom third-party provider cannot cross client routes",
			binding:       vault.ProviderBinding{ProviderCode: "thirdparty_relay", ProtocolType: "openai_compatible"},
			client:        "anthropic",
			wantError:     true,
			wantErrReason: `client route "anthropic" does not support`,
		},
		{
			// The case that makes the client-route check FALSIFIABLE. Everywhere
			// else `requested` is a vendor the table knows, so swapping that call
			// to the credential-trusting lookup changes nothing and the mutation
			// drill stays green. Here the client route is itself custom (the Rust
			// CLI derives client_route = provider_code when the protocol has no
			// client surface of its own), so the strict lookup is the ONLY thing
			// rejecting it. If that call site is ever switched to the
			// credential-trusting lookup, this is the case that goes red.
			name:          "custom client route may not confirm its own protocol",
			binding:       vault.ProviderBinding{ClientRoute: "thirdparty_relay", ProviderCode: "thirdparty_relay", ProtocolType: "gemini"},
			client:        "thirdparty_relay",
			wantError:     true,
			wantErrReason: `client route "thirdparty_relay" does not support`,
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
				if tt.wantErrReason != "" && !strings.Contains(err.Error(), tt.wantErrReason) {
					t.Fatalf("rejected for the wrong reason:\n  got:  %v\n  want it to contain: %s", err, tt.wantErrReason)
				}
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
