package vkeys

import (
	"testing"

	"github.com/AiKeyLabs/pkg/seatassign"
)

// PickRoutedAccount is the proxy-side single source of truth for "which account does
// this seat route to" — shared by the hot-path resolver AND the display stamp. These
// cases lock its contract. 2026-08-15 rule change (schedstress P04 decision): a
// needs_login candidate — override included — never blocks while a healthy candidate
// exists; LOGIN_REQUIRED is reserved for "no candidate serviceable" and then names
// the engine's target first. (Supersedes the 2026-07-01 owner rule that honored a
// needs_login override immediately.)
func TestPickRoutedAccount(t *testing.T) {
	refs := []GroupAccountRef{
		{AccountID: "acc-a", Priority: 1},
		{AccountID: "acc-b", Priority: 1},
	}
	fresh := GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: 9_000_000_000}
	needsLogin := GroupRuntimeAccount{CredentialType: "oauth_account", NeedsLogin: true}
	now := int64(1_000_000)
	hrw := seatassign.Primary("seat-1", []seatassign.Account{{AccountID: "acc-a", Priority: 1}, {AccountID: "acc-b", Priority: 1}})
	other := "acc-a"
	if hrw == "acc-a" {
		other = "acc-b"
	}

	t.Run("needs_login override must NOT block while a healthy sibling serves (2026-08-15)", func(t *testing.T) {
		mat := map[string]GroupRuntimeAccount{hrw: fresh, other: needsLogin}
		acc, oc := PickRoutedAccount("seat-1", refs, mat, other, nil, now)
		if acc != hrw || oc != PickOK {
			t.Fatalf("hard-revoked/not-logged-in override must fall through to healthy %q: got (%q, %v)", hrw, acc, oc)
		}
	})

	t.Run("all candidates needs_login → prompt names the ENGINE's target first", func(t *testing.T) {
		mat := map[string]GroupRuntimeAccount{hrw: needsLogin, other: needsLogin}
		acc, oc := PickRoutedAccount("seat-1", refs, mat, other, nil, now)
		if acc != other || oc != PickNeedsLogin {
			t.Fatalf("login prompt must name the override target %q: got (%q, %v)", other, acc, oc)
		}
	})

	t.Run("usable override redirects off the HRW pick", func(t *testing.T) {
		mat := map[string]GroupRuntimeAccount{hrw: fresh, other: fresh}
		if acc, oc := PickRoutedAccount("seat-1", refs, mat, other, nil, now); acc != other || oc != PickOK {
			t.Fatalf("want (%q, OK), got (%q, %v)", other, acc, oc)
		}
	})

	t.Run("genuinely unusable override falls through (expired / not-a-candidate / cooled)", func(t *testing.T) {
		expired := GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: now - 1}
		mat := map[string]GroupRuntimeAccount{hrw: fresh, other: expired}
		if acc, oc := PickRoutedAccount("seat-1", refs, mat, other, nil, now); acc != hrw || oc != PickOK {
			t.Fatalf("expired override must fall through to HRW %q, got (%q, %v)", hrw, acc, oc)
		}
		if acc, _ := PickRoutedAccount("seat-1", refs, mat, "ghost", nil, now); acc != hrw {
			t.Fatalf("non-candidate override must fall through, got %q", acc)
		}
		mat[other] = fresh
		if acc, _ := PickRoutedAccount("seat-1", refs, mat, other, map[string]bool{other: true}, now); acc != hrw {
			t.Fatalf("cooled override must fall through, got %q", acc)
		}
	})

	t.Run("needs_login rank-0 falls through to the logged-in sibling (2026-08-15)", func(t *testing.T) {
		mat := map[string]GroupRuntimeAccount{hrw: needsLogin, other: fresh}
		if acc, oc := PickRoutedAccount("seat-1", refs, mat, "", nil, now); acc != other || oc != PickOK {
			t.Fatalf("needs_login rank-0 %q must not block; want healthy %q, got (%q, %v)", hrw, other, acc, oc)
		}
	})

	t.Run("no override, all candidates needs_login → prompt names rank-0", func(t *testing.T) {
		mat := map[string]GroupRuntimeAccount{hrw: needsLogin, other: needsLogin}
		if acc, oc := PickRoutedAccount("seat-1", refs, mat, "", nil, now); acc != hrw || oc != PickNeedsLogin {
			t.Fatalf("want rank-0 login prompt (%q, NeedsLogin), got (%q, %v)", hrw, acc, oc)
		}
	})

	t.Run("globally skipped account routes to the next needs_login account", func(t *testing.T) {
		mat := map[string]GroupRuntimeAccount{hrw: fresh, other: needsLogin}
		if acc, oc := PickRoutedAccount("seat-1", refs, mat, "", map[string]bool{hrw: true}, now); acc != other || oc != PickNeedsLogin {
			t.Fatalf("cooled rank-0 must converge on needs-login successor %q, got (%q, %v)", other, acc, oc)
		}
	})

	t.Run("no-material candidate is a retryable skip, not a login prompt", func(t *testing.T) {
		mat := map[string]GroupRuntimeAccount{other: fresh} // hrw's material not delivered yet
		if acc, oc := PickRoutedAccount("seat-1", refs, mat, "", nil, now); acc != other || oc != PickOK {
			t.Fatalf("undelivered rank-0 must be skipped to %q, got (%q, %v)", other, acc, oc)
		}
	})

	t.Run("blind mode (empty material): rank/override-only, for pre-poll display", func(t *testing.T) {
		if acc, oc := PickRoutedAccount("seat-1", refs, nil, "", nil, now); acc != hrw || oc != PickOK {
			t.Fatalf("blind rank-0: want %q, got (%q, %v)", hrw, acc, oc)
		}
		if acc, _ := PickRoutedAccount("seat-1", refs, nil, other, nil, now); acc != other {
			t.Fatalf("blind override: want %q, got %q", other, acc)
		}
	})

	t.Run("all unusable → PickNone", func(t *testing.T) {
		mat := map[string]GroupRuntimeAccount{
			"acc-a": {CredentialType: "oauth_account", ExpiresAt: now - 1},
			"acc-b": {CredentialType: "oauth_account", WindowStatus: "exhausted"},
		}
		if acc, oc := PickRoutedAccount("seat-1", refs, mat, "", nil, now); oc != PickNone {
			t.Fatalf("want PickNone, got (%q, %v)", acc, oc)
		}
	})

	t.Run("weekly exhausted is as unroutable as 5h exhausted", func(t *testing.T) {
		mat := map[string]GroupRuntimeAccount{
			hrw:   {CredentialType: "oauth_account", Window7dStatus: "exhausted_current_window"},
			other: fresh,
		}
		if acc, oc := PickRoutedAccount("seat-1", refs, mat, "", nil, now); acc != other || oc != PickOK {
			t.Fatalf("weekly-exhausted primary must route to %q, got (%q,%v)", other, acc, oc)
		}
	})
}

// Fence for quota-state convergence: a stale Master exhausted snapshot must
// block before reset, but must not deadlock the first recovery probe at reset.
// The sibling window remains an independent gate, and reset-less legacy state
// remains fail-closed.
func TestMaterialUsable_ExhaustedWindowResetBoundary(t *testing.T) {
	now := int64(1_000_000)
	future := now + 1
	past := now - 1
	fresh := GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: now + 3600}

	tests := []struct {
		name string
		mat  GroupRuntimeAccount
		want bool
	}{
		{
			name: "5h exhausted blocks before reset",
			mat:  withWindowState(fresh, "exhausted_current_window", &future, "active", nil),
			want: false,
		},
		{
			name: "5h exhausted admits half-open probe exactly at reset",
			mat:  withWindowState(fresh, "exhausted_current_window", &now, "active", nil),
			want: true,
		},
		{
			name: "expired 5h does not override live 7d exhaustion",
			mat:  withWindowState(fresh, "exhausted_current_window", &past, "exhausted_current_window", &future),
			want: false,
		},
		{
			name: "legacy exhausted without reset stays fail closed",
			mat:  withWindowState(fresh, "exhausted", nil, "active", nil),
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MaterialUsable(tc.mat, now); got != tc.want {
				t.Fatalf("MaterialUsable()=%v, want %v; material=%+v", got, tc.want, tc.mat)
			}
		})
	}
}

// Fence for the ONE exit of "until when does the master-delivered window state
// keep this account out" (spec: R-oauth-account-pool-4.2.S1 /
// R-oauth-account-pool-4.2.S2; rule R4.2 in workflow/CI/requirements/
// 2026-06-23-oauth-account-pool.md, scenarios in roadmap20260320/技术实现/update/
// 20260924-Codex冷却例外补全与提示显示恢复时间.md). Each row pins the WHOLE
// verdict — the state, and RecoversAt, which must stay 0 outside QuotaExhausted —
// and asserts that the verdict's "blocked" equals MaterialWindowBlockedAt, the
// picker's gate: the recovery time members are told must be the time the picker
// releases the account. Combining with the Worker's local cooldown is the
// proxy's job and is not covered here.
func TestMaterialWindowBlockedUntil_LaterWallAndParity(t *testing.T) {
	now := int64(1_000_000)
	in1h := now + 3600
	in3h := now + 3*3600
	in3d := now + 3*24*3600
	past := now - 1
	zero := int64(0)
	fresh := GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: in3d}
	available := QuotaVerdict{State: QuotaAvailable}
	resetUnknown := QuotaVerdict{State: QuotaResetUnknown}
	exhaustedUntil := func(at int64) QuotaVerdict { return QuotaVerdict{State: QuotaExhausted, RecoversAt: at} }

	tests := []struct {
		name string
		mat  GroupRuntimeAccount
		want QuotaVerdict
	}{
		// One window exhausted.
		{
			name: "S1 delivered half: 5h exhausted, resets in 3 h -> blocked until that reset",
			mat:  withWindowState(fresh, "exhausted_current_window", &in3h, "active", nil),
			want: exhaustedUntil(in3h),
		},
		{
			name: "7d exhausted alone -> blocked until its reset",
			mat:  withWindowState(fresh, "active", nil, "exhausted_current_window", &in3d),
			want: exhaustedUntil(in3d),
		},
		// Both exhausted: the later wall wins, whichever window it is.
		{
			name: "S2-1 5h resets in 1 h, 7d in 3 d -> 3 d, never 1 h",
			mat:  withWindowState(fresh, "exhausted_current_window", &in1h, "exhausted_current_window", &in3d),
			want: exhaustedUntil(in3d),
		},
		{
			name: "both exhausted, 5h is the later wall -> 5h reset",
			mat:  withWindowState(fresh, "exhausted_current_window", &in3h, "exhausted_current_window", &in1h),
			want: exhaustedUntil(in3h),
		},
		// One exhausted, the other already past its reset.
		{
			name: "5h past its reset, 7d still exhausted -> 7d reset",
			mat:  withWindowState(fresh, "exhausted_current_window", &past, "exhausted_current_window", &in3d),
			want: exhaustedUntil(in3d),
		},
		{
			name: "exactly at reset the half-open probe is admitted -> not blocked",
			mat:  withWindowState(fresh, "exhausted_current_window", &now, "active", nil),
			want: available,
		},
		// Exhausted without a reset: blocked, deadline unknown, never invented.
		{
			name: "S2-2 legacy exhausted without reset -> blocked, deadline unknown",
			mat:  withWindowState(fresh, "exhausted", nil, "active", nil),
			want: resetUnknown,
		},
		{
			name: "non-positive reset counts as missing -> blocked, deadline unknown",
			mat:  withWindowState(fresh, "exhausted_current_window", &zero, "active", nil),
			want: resetUnknown,
		},
		{
			// The reset-less window still blocks after the 7d reset passes (until
			// the control plane delivers a new state), so "in 3 d" would promise a
			// release the gate will not perform then.
			name: "reset-less exhausted window outlasts a known wall -> deadline unknown",
			mat:  withWindowState(fresh, "exhausted_current_window", nil, "exhausted_current_window", &in3d),
			want: resetUnknown,
		},
		{
			// Ruling-65 is symmetric: the same holds with the windows swapped.
			name: "mirror: 7d reset-less outlasts a known 5h wall -> deadline unknown",
			mat:  withWindowState(fresh, "exhausted_current_window", &in3h, "exhausted_current_window", nil),
			want: resetUnknown,
		},
		{
			// A recovered window carries its NEXT reset (Master active/R3, Worker
			// vault R3), so this input is the common case, not a corner.
			name: "an active window's later reset is not a wall -> exhausted 5h reset",
			mat:  withWindowState(fresh, "exhausted_current_window", &in1h, "active", &in3d),
			want: exhaustedUntil(in1h),
		},
		// Neither exhausted.
		{
			name: "neither window exhausted, resets present -> not blocked",
			mat:  withWindowState(fresh, "active", &in1h, "active", &in3d),
			want: available,
		},
		{
			name: "no window state at all -> not blocked",
			mat:  fresh,
			want: available,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MaterialWindowBlockedUntil(tc.mat, now)
			if got != tc.want {
				t.Fatalf("MaterialWindowBlockedUntil()=%+v, want %+v", got, tc.want)
			}
			if gate := MaterialWindowBlockedAt(tc.mat, now); gate != (got.State != QuotaAvailable) {
				t.Fatalf("parity broken: verdict %+v, MaterialWindowBlockedAt=%v", got, gate)
			}
		})
	}
}

func withWindowState(mat GroupRuntimeAccount, status5h string, reset5h *int64, status7d string, reset7d *int64) GroupRuntimeAccount {
	mat.WindowStatus = status5h
	mat.WindowResetAt = reset5h
	mat.Window7dStatus = status7d
	mat.Window7dResetAt = reset7d
	return mat
}
