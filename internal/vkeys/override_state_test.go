package vkeys

import "testing"

// TestClassifyOverride_FourStatesAndPrecedence pins the classifier the
// device-routing-token strict branch answers with: the control plane named ONE
// account, so the worker must report why THAT account cannot serve instead of
// quietly serving a different one.
//
// The precedence is the load-bearing half. Every pair of overlapping states has
// a different remedy and a different HTTP status, so a classifier that reports
// the wrong one sends the operator to the wrong place:
//
//	material_not_ready   → 503, the node is still syncing (nobody must act)
//	credential_unusable  → 503, the control plane must rebind (admin/member acts)
//	quota_exhausted      → 429, the window must recover (wait)
//
// An account that is BOTH cooling and hard-revoked is reported as
// credential_unusable: waiting out the cooldown cannot help a token the upstream
// already rejected.
//
// spec: R-device-routing-token-dispatch-7.S4 材料未到或凭证失效不报成额度用完
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/device-routing-token-dispatch/spec.md
func TestClassifyOverride_FourStatesAndPrecedence(t *testing.T) {
	const pinned = "acc-pinned"
	const other = "acc-other"
	const now int64 = 1_700_000_000

	refs := []GroupAccountRef{{AccountID: pinned}, {AccountID: other}}
	healthy := GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: now + 3600}
	set := func(ids ...string) map[string]bool {
		out := map[string]bool{}
		for _, id := range ids {
			out[id] = true
		}
		return out
	}
	future := now + 600
	past := now - 600

	cases := []struct {
		name        string
		refs        []GroupAccountRef
		material    map[string]GroupRuntimeAccount
		override    string
		cooling     map[string]bool
		authRevoked map[string]bool
		want        OverrideState
	}{
		{
			name:     "usable oauth account",
			refs:     refs,
			material: map[string]GroupRuntimeAccount{pinned: healthy},
			override: pinned,
			want:     OverrideUsable,
		},
		{
			name:     "usable api key never expires and has no window",
			refs:     refs,
			material: map[string]GroupRuntimeAccount{pinned: {CredentialType: "api_key"}},
			override: pinned,
			want:     OverrideUsable,
		},
		{
			name:     "not in the candidate list",
			refs:     []GroupAccountRef{{AccountID: other}},
			material: map[string]GroupRuntimeAccount{pinned: healthy, other: healthy},
			override: pinned,
			want:     OverrideMaterialNotReady,
		},
		{
			name:     "in the candidate list but material has not arrived",
			refs:     refs,
			material: map[string]GroupRuntimeAccount{other: healthy},
			override: pinned,
			want:     OverrideMaterialNotReady,
		},
		{
			name:     "no material at all",
			refs:     refs,
			material: nil,
			override: pinned,
			want:     OverrideMaterialNotReady,
		},
		{
			// The caller refuses a missing header with NO_DECISION before it ever
			// gets here; classifying "" as ready would be the one answer that lets
			// an empty decision reach PickRoutedAccount as "no override".
			name:     "empty override is never usable",
			refs:     refs,
			material: map[string]GroupRuntimeAccount{pinned: healthy},
			override: "",
			want:     OverrideMaterialNotReady,
		},
		{
			name:        "locally remembered hard revoke while the material still looks fine",
			refs:        refs,
			material:    map[string]GroupRuntimeAccount{pinned: healthy},
			override:    pinned,
			authRevoked: set(pinned),
			want:        OverrideCredentialUnusable,
		},
		{
			name:     "needs_login",
			refs:     refs,
			material: map[string]GroupRuntimeAccount{pinned: {CredentialType: "oauth_account", NeedsLogin: true, ExpiresAt: now + 3600}},
			override: pinned,
			want:     OverrideCredentialUnusable,
		},
		{
			name:     "access token expired",
			refs:     refs,
			material: map[string]GroupRuntimeAccount{pinned: {CredentialType: "oauth_account", ExpiresAt: now - 1}},
			override: pinned,
			want:     OverrideCredentialUnusable,
		},
		{
			name:     "cooling",
			refs:     refs,
			material: map[string]GroupRuntimeAccount{pinned: healthy},
			override: pinned,
			cooling:  set(pinned),
			want:     OverrideQuotaExhausted,
		},
		{
			name: "5h window exhausted and not reset yet",
			refs: refs,
			material: map[string]GroupRuntimeAccount{pinned: {
				CredentialType: "oauth_account", ExpiresAt: now + 3600,
				WindowStatus: "exhausted_current_window", WindowResetAt: &future,
			}},
			override: pinned,
			want:     OverrideQuotaExhausted,
		},
		{
			name: "7d window exhausted and not reset yet",
			refs: refs,
			material: map[string]GroupRuntimeAccount{pinned: {
				CredentialType: "oauth_account", ExpiresAt: now + 3600,
				Window7dStatus: "exhausted_current_window", Window7dResetAt: &future,
			}},
			override: pinned,
			want:     OverrideQuotaExhausted,
		},
		{
			// The half-open boundary the pool already relies on: past the
			// authoritative reset a stale exhausted value must not keep the
			// account out (MaterialWindowBlockedAt, bugfix 2026-08-27).
			name: "window exhausted but the authoritative reset already passed",
			refs: refs,
			material: map[string]GroupRuntimeAccount{pinned: {
				CredentialType: "oauth_account", ExpiresAt: now + 3600,
				WindowStatus: "exhausted_current_window", WindowResetAt: &past,
			}},
			override: pinned,
			want:     OverrideUsable,
		},
		{
			name:        "cooling AND hard-revoked reports the credential, not the quota",
			refs:        refs,
			material:    map[string]GroupRuntimeAccount{pinned: healthy},
			override:    pinned,
			cooling:     set(pinned),
			authRevoked: set(pinned),
			want:        OverrideCredentialUnusable,
		},
		{
			name:        "missing material outranks a hard revoke",
			refs:        refs,
			material:    map[string]GroupRuntimeAccount{other: healthy},
			override:    pinned,
			authRevoked: set(pinned),
			want:        OverrideMaterialNotReady,
		},
		{
			name:        "another account's cooldown or revoke never touches the pinned one",
			refs:        refs,
			material:    map[string]GroupRuntimeAccount{pinned: healthy, other: healthy},
			override:    pinned,
			cooling:     set(other),
			authRevoked: set(other),
			want:        OverrideUsable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyOverride(tc.refs, tc.material, tc.override, tc.cooling, tc.authRevoked, now)
			if got != tc.want {
				t.Fatalf("ClassifyOverride = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClassifyOverride_StateValuesAreTheWireReasons keeps the two states that
// ride the client-facing body from drifting away from the documented `reason`
// vocabulary. The 503 body carries the state verbatim, so a rename here is a
// wire change — there is deliberately no enum→string mapping table to keep in
// sync (error-code contract: design §4b.2).
func TestClassifyOverride_StateValuesAreTheWireReasons(t *testing.T) {
	if string(OverrideMaterialNotReady) != "material_not_ready" {
		t.Fatalf("OverrideMaterialNotReady = %q, want material_not_ready", OverrideMaterialNotReady)
	}
	if string(OverrideCredentialUnusable) != "credential_unusable" {
		t.Fatalf("OverrideCredentialUnusable = %q, want credential_unusable", OverrideCredentialUnusable)
	}
}
