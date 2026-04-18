package supervisor

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// These tests pin the `RouteSource` each builder assigns so a future
// refactor can't silently drop the field — which was the bug class the
// third-party reviews caught twice in 2026-04. Together with the
// event-side contract tests in `internal/events/reportable_test.go`, they
// cover the full "construction → deriveKeyLabel" path. See
// `workflow/CI/bugfix/2026-04-18-third-party-review-fixes.md` for context.

func TestManagedKeyToRoute_SetsTeamSource(t *testing.T) {
	mk := vault.ManagedKey{
		VirtualKeyID: "vk_team_xyz",
		ProtocolType: "openai",
		BaseURL:      "https://api.example.com/v1",
		PlaintextKey: "sk-xxx",
		OrgID:        "org-abc",
		ProviderCode: "openai",
	}
	r := managedKeyToRoute(mk)
	if r == nil {
		t.Fatal("expected non-nil route")
	}
	if r.RouteSource != "team" {
		t.Errorf("RouteSource = %q, want \"team\"", r.RouteSource)
	}
	if r.VirtualKeyID != "vk_team_xyz" {
		t.Errorf("VirtualKeyID passthrough wrong: %q", r.VirtualKeyID)
	}
	if r.OrgID != "org-abc" {
		t.Errorf("OrgID passthrough wrong: %q", r.OrgID)
	}
	if r.PlaintextKey != "sk-xxx" {
		t.Errorf("PlaintextKey passthrough wrong")
	}
}

func TestPersonalTokenToRoute_SetsPersonalSource(t *testing.T) {
	pt := vault.PersonalRouteToken{
		RouteToken:   "aikey_vk_personal_abc",
		Alias:        "anthropic-dev",
		ProviderCode: "anthropic",
		BaseURL:      "https://api.anthropic.com",
	}
	r := personalTokenToRoute(pt)
	if r == nil {
		t.Fatal("expected non-nil route")
	}
	if r.RouteSource != "personal" {
		t.Errorf("RouteSource = %q, want \"personal\"", r.RouteSource)
	}
	if r.KeyAlias != "anthropic-dev" {
		t.Errorf("KeyAlias = %q, want the alias (deriveKeyLabel reads this)", r.KeyAlias)
	}
	if r.VirtualKeyID != "personal:anthropic-dev" {
		t.Errorf("VirtualKeyID prefix wrong: %q", r.VirtualKeyID)
	}
	if r.BaseURL != "https://api.anthropic.com" {
		t.Errorf("BaseURL passthrough wrong: %q", r.BaseURL)
	}
}

func TestOAuthTokenToRoute_SetsOAuthSource(t *testing.T) {
	ot := vault.OAuthRouteToken{
		RouteToken: "aikey_vk_oauth_xyz",
		AccountID:  "session_abcdef",
		Provider:   "anthropic",
		Identity:   "user@example.com",
	}
	r := oauthTokenToRoute(ot)
	if r == nil {
		t.Fatal("expected non-nil route")
	}
	if r.RouteSource != "oauth" {
		t.Errorf("RouteSource = %q, want \"oauth\"", r.RouteSource)
	}
	if r.OAuthIdentity != "user@example.com" {
		t.Errorf("OAuthIdentity passthrough wrong: %q (deriveKeyLabel uses this for the email label)", r.OAuthIdentity)
	}
	if r.KeyAlias != "__oauth__" {
		t.Errorf("KeyAlias should be the sentinel \"__oauth__\" (signals broker credential injection), got %q", r.KeyAlias)
	}
	if r.AccountID != "session_abcdef" {
		t.Errorf("AccountID passthrough wrong: %q", r.AccountID)
	}
	if r.VirtualKeyID != "oauth:session_abcdef" {
		t.Errorf("VirtualKeyID prefix wrong: %q", r.VirtualKeyID)
	}
}

// Belt-and-suspenders coverage: if someone adds a 4th route type, this
// test doesn't directly fail — but the next time they run `rg -n
// '&vkeys.ResolvedRoute{'` they'll see the convention that inline
// construction is disallowed. The route_builders.go comment block
// documents the rule.
func TestAllBuildersSetRouteSource(t *testing.T) {
	managed := managedKeyToRoute(vault.ManagedKey{VirtualKeyID: "x", ProtocolType: "openai"})
	personal := personalTokenToRoute(vault.PersonalRouteToken{Alias: "a", ProviderCode: "anthropic"})
	oauth := oauthTokenToRoute(vault.OAuthRouteToken{AccountID: "x", Provider: "anthropic"})

	for label, r := range map[string]struct{ Got, Want string }{
		"managed":  {managed.RouteSource, "team"},
		"personal": {personal.RouteSource, "personal"},
		"oauth":    {oauth.RouteSource, "oauth"},
	} {
		if r.Got != r.Want {
			t.Errorf("%s builder RouteSource = %q, want %q (if this fails, check route_builders.go)",
				label, r.Got, r.Want)
		}
	}
}
