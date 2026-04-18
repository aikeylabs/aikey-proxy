package events

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// deriveKeyLabel's contract is the single place where RouteSource mis-population
// bites the UI: a route built without the right RouteSource falls through the
// `oauth/team/personal/personal_byok` switch and lands in the VK-id-prefix
// fallback, producing labels like `oauth:sessio` or `personal:my` instead of
// the user's email or alias. These tests pin each branch so a future caller
// forgetting the field gets loud feedback rather than a silent UI regression.
// (Historical prior art: bugfix/20260418-third-party-review-fixes.md and the
// re-review that caught the personal/team startup paths.)

func TestDeriveKeyLabel_OAuth_UsesIdentity(t *testing.T) {
	r := &vkeys.ResolvedRoute{
		RouteSource:   "oauth",
		VirtualKeyID:  "oauth:session_abcdef12345678",
		OAuthIdentity: "user@example.com",
		KeyAlias:      "__oauth__",
	}
	if got := deriveKeyLabel(r); got != "user@example.com" {
		t.Fatalf("oauth: want email label, got %q", got)
	}
}

func TestDeriveKeyLabel_OAuth_FallsBackWhenIdentityMissing(t *testing.T) {
	// OAuth branch only hits the fallback when identity is empty — rare but
	// possible when the broker lookup raced with token creation.
	r := &vkeys.ResolvedRoute{
		RouteSource:  "oauth",
		VirtualKeyID: "oauth:session_abcdef12345678",
		KeyAlias:     "__oauth__",
	}
	if got := deriveKeyLabel(r); got != "oauth:sessio" {
		t.Fatalf("oauth-missing-identity: want VK prefix, got %q", got)
	}
}

func TestDeriveKeyLabel_Team_UsesAlias(t *testing.T) {
	r := &vkeys.ResolvedRoute{
		RouteSource:  "team",
		VirtualKeyID: "vk_team_12345",
		KeyAlias:     "prod-shared",
	}
	if got := deriveKeyLabel(r); got != "prod-shared" {
		t.Fatalf("team: want alias, got %q", got)
	}
}

func TestDeriveKeyLabel_Personal_UsesAlias(t *testing.T) {
	r := &vkeys.ResolvedRoute{
		RouteSource:  "personal",
		VirtualKeyID: "personal:my-anthropic-key",
		KeyAlias:     "my-anthropic-key",
	}
	if got := deriveKeyLabel(r); got != "my-anthropic-key" {
		t.Fatalf("personal: want alias, got %q", got)
	}
}

func TestDeriveKeyLabel_PersonalBYOK_UsesAlias(t *testing.T) {
	r := &vkeys.ResolvedRoute{
		RouteSource:  "personal_byok",
		VirtualKeyID: "aikey_vk_xxx",
		KeyAlias:     "anthropic-dev",
	}
	if got := deriveKeyLabel(r); got != "anthropic-dev" {
		t.Fatalf("personal_byok: want alias, got %q", got)
	}
}

// Regression guard: an empty RouteSource is the footprint of the bug class
// the third-party review found twice (OAuth first, then personal/team
// startup paths). When this fires in CI, the fix is at the ResolvedRoute
// *construction site*, not here — search for `&vkeys.ResolvedRoute{` under
// supervisor.go / proxy.go and ensure every literal sets RouteSource.
func TestDeriveKeyLabel_EmptyRouteSource_FallsThrough(t *testing.T) {
	r := &vkeys.ResolvedRoute{
		// RouteSource deliberately empty — simulates a caller that forgot
		// to populate it. Should land in the VK-id-prefix fallback, *not*
		// silently use KeyAlias/OAuthIdentity (which would hide the bug).
		VirtualKeyID:  "personal:alias",
		KeyAlias:      "alias",
		OAuthIdentity: "would-be-email@example.com",
	}
	got := deriveKeyLabel(r)
	if got == "alias" || got == "would-be-email@example.com" {
		t.Fatalf("empty RouteSource should not unlock alias/identity path; got %q — "+
			"this means some caller is populating KeyAlias/OAuthIdentity without "+
			"RouteSource, which is the bug class we're guarding against", got)
	}
	if got != "personal:ali" {
		t.Fatalf("want VK prefix fallback, got %q", got)
	}
}

func TestDeriveKeyLabel_NilRoute_Empty(t *testing.T) {
	if got := deriveKeyLabel(nil); got != "" {
		t.Fatalf("nil route: want empty, got %q", got)
	}
}

// Verifies the prefix truncation handles short VK ids without panicking.
func TestDeriveKeyLabel_ShortVK_NoTruncation(t *testing.T) {
	r := &vkeys.ResolvedRoute{
		RouteSource:  "oauth",
		VirtualKeyID: "short",
		// OAuthIdentity empty → fallback path
	}
	if got := deriveKeyLabel(r); got != "short" {
		t.Fatalf("short vk: want verbatim, got %q", got)
	}
}
