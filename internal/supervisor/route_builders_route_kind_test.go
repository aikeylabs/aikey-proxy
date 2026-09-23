package supervisor

// route_builders_route_kind_test.go — hop ⑤ of the `route_kind` relay chain:
// ManagedKey.RouteKind (read from the node vault, hop ④) must be copied onto
// the ResolvedRoute the worker actually serves from.
//
// managedKeyToRoute copies mk.* → ResolvedRoute.* FIELD BY FIELD BY HAND. A
// forgotten line is not a compile error and not a log line: the field is the
// zero value, and an empty RouteKind means the worker treats a DEVICE-ROUTING
// token as an ordinary seat token — it picks an account by itself instead of
// serving the one the control plane bound to that device. This is the same
// failure mode that made `RouteSource` drift twice in 2026-04 (see this
// package's route_builders.go header and
// workflow/CI/bugfix/2026-04-18-third-party-review-fixes.md); the fix then was
// to funnel both construction paths through this one builder, and this fence is
// what keeps a NEW field from being dropped inside it.
//
// Design: roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/design.md §4b.7
// Spec: R-device-routing-token-dispatch-20

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// TestRouteBuilders_CopiesRouteKind pins hop ⑤: the classifier survives route
// assembly, and `route_source` is NOT repurposed to carry it.
func TestRouteBuilders_CopiesRouteKind(t *testing.T) {
	mk := vault.ManagedKey{
		VirtualKeyID: "aikey_team_vk_drt",
		ProtocolType: "anthropic",
		BaseURL:      "https://api.example.com",
		OrgID:        "org-1",
		SeatID:       "seat-drt",
		ProviderCode: "anthropic",
		OauthGroupID: "grp-1",
		RouteKind:    "device_routing_token",
	}
	r := managedKeyToRoute(&mk)
	if r == nil {
		t.Fatal("expected non-nil route")
	}
	if r.RouteKind != "device_routing_token" {
		t.Errorf("RouteKind = %q, want \"device_routing_token\" — the route classifier was dropped "+
			"during assembly. The worker's strict branch keys on it, so an empty value means a "+
			"device-routing token is served down the seat path and picks its own account "+
			"(R-device-routing-token-dispatch-20).", r.RouteKind)
	}
	// 🔴 route_source is the USAGE/WAL attribution key and must stay "team".
	// Carrying the new classifier in it instead of alongside it would silently
	// re-label every device-routing token's usage rows.
	if r.RouteSource != "team" {
		t.Errorf("RouteSource = %q, want \"team\" — route_source is the usage/WAL key and does not "+
			"change for device-routing tokens (design §4b hard values: route_kind is a NEW field, "+
			"route_source stays \"team\")", r.RouteSource)
	}
}

// An ordinary managed key must stay byte-identical: no kind, and nothing about
// the existing route changes just because the field now exists.
func TestRouteBuilders_OrdinaryManagedKeyHasNoRouteKind(t *testing.T) {
	mk := vault.ManagedKey{
		VirtualKeyID: "aikey_team_vk_plain",
		ProtocolType: "anthropic",
		BaseURL:      "https://api.example.com",
		OrgID:        "org-1",
		SeatID:       "seat-1",
		ProviderCode: "anthropic",
		PlaintextKey: "sk-real",
	}
	r := managedKeyToRoute(&mk)
	if r.RouteKind != "" {
		t.Errorf("RouteKind = %q, want empty for an ordinary managed key — a kind must never be "+
			"invented for a seat token, or the worker's strict branch would claim traffic it "+
			"has no device decision for", r.RouteKind)
	}
	if r.RouteSource != "team" {
		t.Errorf("RouteSource = %q, want \"team\"", r.RouteSource)
	}
}
