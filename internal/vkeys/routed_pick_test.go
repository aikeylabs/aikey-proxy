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
