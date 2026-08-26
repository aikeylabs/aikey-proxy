package vault

// revoked_virtual_keys_test.go — fences for the control-plane revocation gate
// (2026-08-26). See workflow/CI/bugfix/20260826-proxy-revocation-window-unbounded.md.
//
// 🔴 WHY THIS LIVES IN THE VAULT AND NOT ONLY IN THE ROUTE REGISTRY.
// A team virtual key is reachable by TWO different bearers:
//
//	aikey_team_<vk_id>          → vkeys registry  → buildManagedRoutes
//	aikey_active_<provider>     → provider binding → GetTeamKeyByID   ← the wrapper
//
// The second is the one a real user is on (the wrapper injects the active
// sentinel on every launch). Filtering only the registry left it fully served:
// measured live on 2026-08-26, a suspended seat kept getting 200s for 91s and
// counting, with the registry filter already in place and passing its own tests.

import "testing"

// reuses chainVault (managed_keys_binding_id_test.go), which seeds vk-1.
func TestRevokedVirtualKeyIsNotServedByEitherRead(t *testing.T) {
	r := chainVault(t, true)

	// Precondition: both material reads serve the key when nothing is revoked.
	if mk, err := r.GetTeamKeyByID("vk-1", "anthropic", "anthropic"); err != nil || mk == nil {
		t.Fatalf("precondition: GetTeamKeyByID should serve vk-1 (mk=%v err=%v)", mk, err)
	}
	if mk, err := r.GetActiveTeamKeyByProvider("anthropic", "anthropic"); err != nil || mk == nil {
		t.Fatalf("precondition: GetActiveTeamKeyByProvider should serve vk-1 (mk=%v err=%v)", mk, err)
	}

	r.SetRevokedVirtualKeys(map[string]bool{"vk-1": true})

	// 能红: delete either gate in vault.go and the corresponding read serves a
	// key the control plane has revoked — which is exactly the live defect.
	if mk, err := r.GetTeamKeyByID("vk-1", "anthropic", "anthropic"); err != nil || mk != nil {
		t.Fatalf("GetTeamKeyByID must NOT serve a revoked key — this is the follow-active "+
			"path the wrapper uses (mk=%v err=%v)", mk, err)
	}
	if mk, err := r.GetActiveTeamKeyByProvider("anthropic", "anthropic"); err != nil || mk != nil {
		t.Fatalf("GetActiveTeamKeyByProvider must NOT serve a revoked key (mk=%v err=%v)", mk, err)
	}
}

// 🔴 The gate must stay OFF the org/seat derivation read. GetActiveManagedKeys
// feeds the quota, compliance and group-runtime rails, which use it only to
// answer "which org and seats does this node serve". Filtering it there would
// make a revocation silently reconfigure enforcement subsystems that have
// nothing to do with revocation — a side effect nobody asked for and nothing
// would report.
//
// 能红: add an IsVirtualKeyRevoked gate to GetActiveManagedKeys.
func TestRevocationDoesNotFilterTheOrgSeatDerivationRead(t *testing.T) {
	r := chainVault(t, true)
	r.SetRevokedVirtualKeys(map[string]bool{"vk-1": true})

	keys, err := r.GetActiveManagedKeys()
	if err != nil {
		t.Fatalf("GetActiveManagedKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("GetActiveManagedKeys must stay unfiltered (it derives org/seat for the "+
			"other rails); got %d keys, want 1", len(keys))
	}
}

// A cleared / never-published filter must behave exactly as before the change.
func TestNoRevocationFilterIsTodaysBehaviour(t *testing.T) {
	r := chainVault(t, true)
	if r.IsVirtualKeyRevoked("vk-1") {
		t.Fatalf("an unpublished filter must revoke nothing")
	}
	r.SetRevokedVirtualKeys(map[string]bool{"vk-1": true})
	r.SetRevokedVirtualKeys(nil)
	if r.IsVirtualKeyRevoked("vk-1") {
		t.Fatalf("a cleared filter must revoke nothing")
	}
	if mk, _ := r.GetTeamKeyByID("vk-1", "anthropic", "anthropic"); mk == nil {
		t.Fatalf("a cleared filter must serve the key again")
	}
}
