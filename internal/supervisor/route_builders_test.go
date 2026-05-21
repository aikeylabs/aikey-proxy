package supervisor

import (
	"errors"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
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
		RouteToken:   "aikey_personal_abc",
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
		RouteToken: "aikey_personal_xyz_oauth",
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
// ── Shared filter+build helpers (review #5 [中], 2026-04-29) ─────────────
//
// These tests pin the registry-eligibility contract for both the startup
// (`buildGeneration`) path and the reload (`syncManagedKeys`) path: only
// strict `aikey_personal_<64-lowercase-hex>` route tokens land in the
// registry; everything else gets WARN-skipped. Both paths now route
// through the same helpers, so a single regression test covers both.

const hex64Strict = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestBuildPersonalRoutesFiltered_KeepsStrictAndDropsLegacy(t *testing.T) {
	in := []vault.PersonalRouteToken{
		{Alias: "keyA", RouteToken: "aikey_personal_" + hex64Strict, ProviderCode: "anthropic"},
		// Legacy aikey_vk_ prefix — must drop.
		{Alias: "keyB-legacy", RouteToken: "aikey_vk_" + hex64Strict, ProviderCode: "anthropic"},
		// Legacy alias-shaped suffix — must drop.
		{Alias: "keyC-alias", RouteToken: "aikey_personal_my-claude", ProviderCode: "anthropic"},
		// 63-hex (off-by-one) — must drop.
		{Alias: "keyD-63hex", RouteToken: "aikey_personal_" + hex64Strict[:63], ProviderCode: "anthropic"},
		// Different strict token — must keep.
		{Alias: "keyE-strict",
			RouteToken:   "aikey_personal_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			ProviderCode: "openai"},
	}

	got := buildPersonalRoutesFiltered(in)

	if len(got) != 2 {
		t.Fatalf("want 2 strict routes, got %d (map=%v)", len(got), keysOf(got))
	}
	if _, ok := got["aikey_personal_"+hex64Strict]; !ok {
		t.Errorf("strict keyA missing from result")
	}
	if _, ok := got["aikey_personal_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"]; !ok {
		t.Errorf("strict keyE missing from result")
	}
	// Spot-check that none of the legacy / malformed bearers leaked through
	// under any encoding.
	for _, bad := range []string{
		"aikey_vk_" + hex64Strict,
		"aikey_personal_my-claude",
		"aikey_personal_" + hex64Strict[:63],
	} {
		if _, leaked := got[bad]; leaked {
			t.Errorf("legacy/malformed bearer %q must not land in registry", bad)
		}
	}
}

func TestBuildOAuthRoutesFiltered_KeepsStrictAndDropsLegacy(t *testing.T) {
	in := []vault.OAuthRouteToken{
		{AccountID: "accA", RouteToken: "aikey_personal_" + hex64Strict, Provider: "anthropic"},
		// Legacy UUID-shaped suffix from early OAuth — must drop.
		{AccountID: "accB-uuid", RouteToken: "aikey_personal_a1b2c3d4-5678-90ab-cdef-1234567890ab", Provider: "anthropic"},
		// Legacy aikey_vk_ — must drop.
		{AccountID: "accC-vk", RouteToken: "aikey_vk_" + hex64Strict, Provider: "anthropic"},
	}

	got := buildOAuthRoutesFiltered(in)

	if len(got) != 1 {
		t.Fatalf("want 1 strict OAuth route, got %d (map=%v)", len(got), keysOf(got))
	}
	if _, ok := got["aikey_personal_"+hex64Strict]; !ok {
		t.Errorf("strict accA missing from result")
	}
}

// ── Startup-path wiring evidence (loadVaultRoutesIntoRegistry) ────────────
//
// These tests prove that buildGeneration's startup load path (which calls
// loadVaultRoutesIntoRegistry) actually applies the strict-form filter —
// not just that the helper functions exist in isolation. Reviewers can
// read this fake-vault test to confirm "yes, when proxy starts up with a
// pre-migration vault containing aikey_vk_<64-hex>, those tokens do NOT
// land in the registry". Without this test, the wiring evidence is only
// visible through source reading. See review #5 [中] second pass.

// fakeVaultRouteTokenReader implements vaultRouteTokenReader for tests.
// It returns whatever the test caller seeds — including legacy /
// malformed shapes — so we can verify the filter at the real call site.
type fakeVaultRouteTokenReader struct {
	personal    []vault.PersonalRouteToken
	oauth       []vault.OAuthRouteToken
	app         []vault.AppRouteToken
	personalErr error
	oauthErr    error
	appErr      error
}

func (f *fakeVaultRouteTokenReader) GetAllPersonalRouteTokens() ([]vault.PersonalRouteToken, error) {
	return f.personal, f.personalErr
}

func (f *fakeVaultRouteTokenReader) GetAllOAuthRouteTokens() ([]vault.OAuthRouteToken, error) {
	return f.oauth, f.oauthErr
}

func (f *fakeVaultRouteTokenReader) GetAllAppRouteTokens() ([]vault.AppRouteToken, error) {
	return f.app, f.appErr
}

// TestLoadVaultRoutesIntoRegistry_StartupPathFiltersLegacy is the smoke
// test reviewer should look at to confirm: at the entrypoint
// buildGeneration uses (loadVaultRoutesIntoRegistry), legacy shapes do
// NOT enter the registry. If a future regression removes the filter
// from either the personal or OAuth load step, this test fails.
func TestLoadVaultRoutesIntoRegistry_StartupPathFiltersLegacy(t *testing.T) {
	const strictA = "aikey_personal_" + hex64Strict
	const strictB = "aikey_personal_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	const legacyVk = "aikey_vk_" + hex64Strict
	const legacyAlias = "aikey_personal_my-claude"
	const legacyOAuthUUID = "aikey_personal_a1b2c3d4-5678-90ab-cdef-1234567890ab"

	reader := &fakeVaultRouteTokenReader{
		personal: []vault.PersonalRouteToken{
			{Alias: "good-A", RouteToken: strictA, ProviderCode: "anthropic"},
			{Alias: "legacy-vk", RouteToken: legacyVk, ProviderCode: "anthropic"},
			{Alias: "legacy-alias", RouteToken: legacyAlias, ProviderCode: "anthropic"},
			{Alias: "good-B", RouteToken: strictB, ProviderCode: "openai"},
		},
		oauth: []vault.OAuthRouteToken{
			// Strict OAuth bearer — must land. We use a different strict
			// hex to avoid collision with the personal map's strictA.
			{AccountID: "oauth-strict",
				RouteToken: "aikey_personal_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Provider:   "anthropic"},
			// Legacy OAuth UUID-shaped suffix — must drop.
			{AccountID: "oauth-legacy", RouteToken: legacyOAuthUUID, Provider: "anthropic"},
		},
	}

	reg := vkeys.NewRegistry()
	loadVaultRoutesIntoRegistry(reg, reader)

	// Strict tokens must be resolvable.
	if reg.Resolve(strictA) == nil {
		t.Errorf("strict personal bearer %q must land in registry at startup", strictA)
	}
	if reg.Resolve(strictB) == nil {
		t.Errorf("strict personal bearer %q must land in registry at startup", strictB)
	}
	if reg.Resolve("aikey_personal_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == nil {
		t.Errorf("strict OAuth bearer must land in registry at startup")
	}

	// Legacy / malformed tokens MUST NOT be resolvable. This is the
	// regression the reviewer is asking us to pin: with the pre-fix
	// buildGeneration, all of these would resolve.
	for _, bad := range []string{legacyVk, legacyAlias, legacyOAuthUUID} {
		if reg.Resolve(bad) != nil {
			t.Errorf("legacy/malformed bearer %q must NOT be in registry after startup load — "+
				"buildGeneration's wiring is broken", bad)
		}
	}
}

// TestLoadVaultRoutesIntoRegistry_HandlesMissingColumnGracefully pins the
// "vault hasn't been migrated by CLI yet" path: GetAllPersonalRouteTokens
// returns ErrMissingRouteTokenColumn, the loader logs and skips without
// blowing up the proxy startup. Important for v1.0.3-and-earlier vaults
// that get carried into v1.0.5-alpha proxy without `aikey db upgrade`
// having run first.
func TestLoadVaultRoutesIntoRegistry_HandlesMissingColumnGracefully(t *testing.T) {
	reader := &fakeVaultRouteTokenReader{
		personalErr: vault.ErrMissingRouteTokenColumn,
		oauthErr:    vault.ErrMissingRouteTokenColumn,
	}

	reg := vkeys.NewRegistry()
	// Must not panic.
	loadVaultRoutesIntoRegistry(reg, reader)
}

// TestLoadVaultRoutesIntoRegistry_NilSafety covers the defensive
// nil-arg branches so a future caller mishap doesn't panic the proxy.
func TestLoadVaultRoutesIntoRegistry_NilSafety(t *testing.T) {
	loadVaultRoutesIntoRegistry(nil, nil)         // both nil
	loadVaultRoutesIntoRegistry(vkeys.NewRegistry(), nil)  // nil reader
	loadVaultRoutesIntoRegistry(nil, &fakeVaultRouteTokenReader{}) // nil reg
	// No assertions beyond "did not panic".
}

// TestBuildPersonalRoutesFiltered_EmptyInputYieldsEmptyMap pins the no-op
// case so callers can safely pass `len(in) == 0` without nil checks.
func TestBuildPersonalRoutesFiltered_EmptyInputYieldsEmptyMap(t *testing.T) {
	got := buildPersonalRoutesFiltered(nil)
	if got == nil {
		t.Fatal("nil input must yield empty (not nil) map")
	}
	if len(got) != 0 {
		t.Errorf("nil input should yield empty map, got %d entries", len(got))
	}
}

func keysOf(m map[string]*vkeys.ResolvedRoute) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestAllBuildersSetRouteSource(t *testing.T) {
	managed := managedKeyToRoute(vault.ManagedKey{VirtualKeyID: "x", ProtocolType: "openai"})
	personal := personalTokenToRoute(vault.PersonalRouteToken{Alias: "a", ProviderCode: "anthropic"})
	oauth := oauthTokenToRoute(vault.OAuthRouteToken{AccountID: "x", Provider: "anthropic"})
	app := appRouteTokenToRoute(vault.AppRouteToken{KeyID: "k", AppSlug: "x", AppKind: "third-party"})

	for label, r := range map[string]struct{ Got, Want string }{
		"managed":  {managed.RouteSource, "team"},
		"personal": {personal.RouteSource, "personal"},
		"oauth":    {oauth.RouteSource, "oauth"},
		"app":      {app.RouteSource, "app"},
	} {
		if r.Got != r.Want {
			t.Errorf("%s builder RouteSource = %q, want %q (if this fails, check route_builders.go)",
				label, r.Got, r.Want)
		}
	}
}

// ── App pipeline route loading (AKL-202, 2026-05-20) ──────────────────────
//
// Phase 4 introduced a third route source: app tokens (aikey_app_<64hex>).
// These tests pin the same invariants the personal/oauth tests pin:
//   - The builder sets every app-specific field correctly.
//   - The filter rejects malformed shapes (writer-side bug protection).
//   - The startup loader feeds app tokens into the registry alongside
//     personal/oauth without disturbing their loading.
//   - Pre-Phase-4 vaults (no app_records table) return empty without error.

// Strict app bearer fixtures (74 chars total: "aikey_app_" + 64-hex).
const appHex64A = "aikey_app_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const appHex64B = "aikey_app_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestAppRouteTokenToRoute_SetsAppFields(t *testing.T) {
	at := vault.AppRouteToken{
		KeyID:            "uuid-12345",
		AppSlug:          "degrade-detector",
		RouteToken:       appHex64A,
		Status:           "active",
		AppKind:          "first-party",
		FollowUserActive: true,
		AllowedUpstreams: []string{"openai", "anthropic"},
	}
	r := appRouteTokenToRoute(at)
	if r == nil {
		t.Fatal("expected non-nil route")
	}
	if r.RouteSource != "app" {
		t.Errorf("RouteSource = %q, want \"app\"", r.RouteSource)
	}
	if r.AppSlug != "degrade-detector" {
		t.Errorf("AppSlug passthrough wrong: %q", r.AppSlug)
	}
	if r.AppKind != "first-party" {
		t.Errorf("AppKind passthrough wrong: %q", r.AppKind)
	}
	if r.AppKeyID != "uuid-12345" {
		t.Errorf("AppKeyID passthrough wrong: %q", r.AppKeyID)
	}
	if !r.FollowUserActive {
		t.Error("FollowUserActive passthrough wrong: false, want true")
	}
	if r.VirtualKeyID != "app:degrade-detector" {
		t.Errorf("VirtualKeyID prefix wrong: %q (deriveKeyLabel reads this)", r.VirtualKeyID)
	}
	// Provider / BaseURL / KeyAlias intentionally empty — resolution
	// happens per-request in the App pipeline. Pin the zero-value contract.
	if r.Provider != "" {
		t.Errorf("Provider should be empty (resolved per-request), got %q", r.Provider)
	}
	if r.BaseURL != "" {
		t.Errorf("BaseURL should be empty (resolved per-request), got %q", r.BaseURL)
	}
	if r.KeyAlias != "" {
		t.Errorf("KeyAlias should be empty (resolved per-request), got %q", r.KeyAlias)
	}
}

func TestBuildAppRoutesFiltered_KeepsStrictAndDropsLegacy(t *testing.T) {
	tokens := []vault.AppRouteToken{
		{KeyID: "k1", AppSlug: "agent-a", RouteToken: appHex64A, AppKind: "third-party"},
		{KeyID: "k2", AppSlug: "agent-b", RouteToken: appHex64B, AppKind: "third-party"},
		// Malformed shapes that MUST be filtered out:
		{KeyID: "k-bad1", AppSlug: "agent-c", RouteToken: "aikey_app_tooshort", AppKind: "third-party"},
		{KeyID: "k-bad2", AppSlug: "agent-d", RouteToken: "aikey_personal_" + hex64Strict, AppKind: "third-party"}, // wrong prefix
		{KeyID: "k-bad3", AppSlug: "agent-e", RouteToken: "aikey_app_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", AppKind: "third-party"}, // uppercase
	}

	got := buildAppRoutesFiltered(tokens)
	if len(got) != 2 {
		t.Errorf("expected 2 strict tokens to land, got %d; keys=%v", len(got), keysOf(got))
	}
	if got[appHex64A] == nil {
		t.Errorf("strict %s must land", appHex64A)
	}
	if got[appHex64B] == nil {
		t.Errorf("strict %s must land", appHex64B)
	}
	// Ensure the malformed bearer plaintexts are NOT registered under any key.
	for _, bad := range []string{
		"aikey_app_tooshort",
		"aikey_personal_" + hex64Strict,
	} {
		if got[bad] != nil {
			t.Errorf("malformed bearer %q must NOT land in map", bad)
		}
	}
}

func TestBuildAppRoutesFiltered_EmptyInputYieldsEmptyMap(t *testing.T) {
	got := buildAppRoutesFiltered(nil)
	if got == nil {
		t.Fatal("nil input must yield empty (not nil) map")
	}
	if len(got) != 0 {
		t.Errorf("nil input should yield empty map, got %d entries", len(got))
	}
}

// TestLoadVaultRoutesIntoRegistry_LoadsAppTokensAlongsideOthers verifies
// the startup path wires app tokens into the same registry as personal +
// oauth, without disturbing their loading. The dispatch-side identity
// (RouteSource == "app") is preserved so downstream consumers
// (deriveKeyLabel, App pipeline auth) can branch on it.
func TestLoadVaultRoutesIntoRegistry_LoadsAppTokensAlongsideOthers(t *testing.T) {
	const personalStrict = "aikey_personal_" + hex64Strict

	reader := &fakeVaultRouteTokenReader{
		personal: []vault.PersonalRouteToken{
			{Alias: "personal-A", RouteToken: personalStrict, ProviderCode: "anthropic"},
		},
		app: []vault.AppRouteToken{
			{KeyID: "uuid-1", AppSlug: "agent-a", RouteToken: appHex64A, AppKind: "third-party"},
			{KeyID: "uuid-2", AppSlug: "degrade-detector", RouteToken: appHex64B, AppKind: "first-party", FollowUserActive: true},
		},
	}

	reg := vkeys.NewRegistry()
	loadVaultRoutesIntoRegistry(reg, reader)

	// Personal still landed.
	if reg.Resolve(personalStrict) == nil {
		t.Error("personal token must still land when app loading is added")
	}

	// App tokens landed and carry RouteSource="app" + app-identity fields.
	a := reg.Resolve(appHex64A)
	if a == nil {
		t.Fatalf("app token %s must land", appHex64A)
	}
	if a.RouteSource != "app" {
		t.Errorf("RouteSource = %q, want app", a.RouteSource)
	}
	if a.AppSlug != "agent-a" || a.AppKeyID != "uuid-1" {
		t.Errorf("agent-a app fields wrong: %+v", a)
	}
	b := reg.Resolve(appHex64B)
	if b == nil {
		t.Fatalf("first-party app token %s must land", appHex64B)
	}
	if !b.FollowUserActive || b.AppKind != "first-party" {
		t.Errorf("first-party + follow_user_active not propagated: %+v", b)
	}
}

// TestLoadVaultRoutesIntoRegistry_AppErrorDoesNotAbortStartup pins
// degradation: if GetAllAppRouteTokens returns an error (e.g. transient
// SQLite I/O failure, schema mismatch), the loader must log + skip app
// routes WITHOUT killing the personal/oauth load path. App tokens missing
// is a Phase 4 feature regression; personal/oauth missing is a v1.0
// regression — they can't share blast radius.
func TestLoadVaultRoutesIntoRegistry_AppErrorDoesNotAbortStartup(t *testing.T) {
	const personalStrict = "aikey_personal_" + hex64Strict
	reader := &fakeVaultRouteTokenReader{
		personal: []vault.PersonalRouteToken{
			{Alias: "personal-A", RouteToken: personalStrict, ProviderCode: "anthropic"},
		},
		appErr: errors.New("transient sqlite IO failure"),
	}

	reg := vkeys.NewRegistry()
	loadVaultRoutesIntoRegistry(reg, reader)

	if reg.Resolve(personalStrict) == nil {
		t.Error("personal token loading must survive app loader error (degradation contract)")
	}
}

// TestLoadVaultRoutesIntoRegistry_NoAppsIsNotAnError pins the
// pre-Phase-4 vault case: vault.GetAllAppRouteTokens returns nil + nil
// when app_records doesn't exist. The loader must treat that as
// "0 apps to register" without WARN spam.
func TestLoadVaultRoutesIntoRegistry_NoAppsIsNotAnError(t *testing.T) {
	reader := &fakeVaultRouteTokenReader{
		// Everything empty / no error — pre-Phase-4 vault shape.
	}

	reg := vkeys.NewRegistry()
	loadVaultRoutesIntoRegistry(reg, reader)

	if reg.Count() != 0 {
		t.Errorf("expected empty registry from pre-Phase-4 vault, got %d entries", reg.Count())
	}
}

// TestIsStrictAppRouteToken pins the form predicate directly. Mirrors
// TestIsStrictPersonalRouteToken in team_token_normalize_test.go.
func TestIsStrictAppRouteToken(t *testing.T) {
	cases := []struct {
		token string
		want  bool
	}{
		{appHex64A, true},
		{appHex64B, true},
		{"aikey_app_" + hex64Strict, true},
		// Length variants.
		{"aikey_app_" + hex64Strict[:63], false},
		{"aikey_app_" + hex64Strict + "x", false},
		{"aikey_app_", false},
		// Case sensitivity.
		{"aikey_app_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
		// Wrong prefix.
		{"aikey_personal_" + hex64Strict, false},
		{"aikey_team_" + hex64Strict, false},
		{"aikey_vk_" + hex64Strict, false},
		// Native non-aikey tokens.
		{"sk-1234567890", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isStrictAppRouteToken(c.token); got != c.want {
			t.Errorf("isStrictAppRouteToken(%q) = %v, want %v", c.token, got, c.want)
		}
	}
}
