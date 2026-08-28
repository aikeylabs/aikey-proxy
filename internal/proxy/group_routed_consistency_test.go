package proxy

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// This proves the ACTUAL forward routing that the A2 display (is_current_routed /
// current_routed) claims to reflect — the answer to "刷新后变更选中账号，proxy 是否会同步路
// 由到最新选中的那个号".
//
// The hot path (resolveGroupCredential) and the display stamp
// (supervisor.computeRoutedAccountID) BOTH read RoutingOverrideCache.Assignment ?? seat-
// assign rank-0, so:
//
//	(1) an engine override → the proxy FORWARDS to the override account, and it FOLLOWS
//	    override changes on the very next request (RoutingOverrideCache is read live). This
//	    is the display↔actual CONSISTENCY the user asked about — confirmed.
//	(2) BUT when the routed account is COOLED (N8c skip) the hot path falls through to the
//	    next usable candidate, while the display stamp has no cooling input and keeps
//	    naming rank-0 → display can diverge from actual. Companion (display side):
//	    supervisor.TestComputeRoutedAccountID_DisplayIsOverrideOnly_NoCoolingAwareness.
func TestResolveGroup_RoutedFollowsOverride_AndCoolingFallsThrough(t *testing.T) {
	key := grKey()
	seat := "seat-routed-1"
	order := rankOrder(seat, "acc-a", "acc-b")
	primary, secondary := order[0], order[1]

	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-a", Identity: "a@x", ProviderCode: "anthropic"},
		{AccountID: "acc-b", Identity: "b@x", ProviderCode: "anthropic"},
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-a": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}, "tok-a"),
		"acc-b": encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}, "tok-b"),
	}
	route := &vkeys.ResolvedRoute{SeatID: seat, OauthGroupID: "grp", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}

	// (1a) engine override → proxy forwards to the OVERRIDE account (the displayed pick).
	res, err := resolveGroupCredential(route, key, 1_000_000, nil, secondary)
	if err != nil {
		t.Fatalf("resolve with override: %v", err)
	}
	if res.AccountID != secondary {
		t.Fatalf("override must route to %q, got %q", secondary, res.AccountID)
	}

	// (1b) override CHANGES → the next request re-routes to the new account (the "selected
	// account changed → proxy re-routes to the latest" guarantee).
	res, err = resolveGroupCredential(route, key, 1_000_000, nil, primary)
	if err != nil {
		t.Fatalf("resolve with changed override: %v", err)
	}
	if res.AccountID != primary {
		t.Fatalf("changed override must re-route to %q, got %q", primary, res.AccountID)
	}

	// (2) rank-0 COOLED (in skip), no override → the hot path forwards to the next usable
	// account. THIS is what the proxy actually serves; the display stamp does not model it.
	res, err = resolveGroupCredential(route, key, 1_000_000, map[string]bool{primary: true}, "")
	if err != nil {
		t.Fatalf("resolve with rank-0 cooled: %v", err)
	}
	if res.AccountID != secondary {
		t.Fatalf("rank-0 cooled → hot path must forward to next usable %q, got %q (display would still show %q → the documented gap)", secondary, res.AccountID, primary)
	}
}
