package proxy

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// freshOAuth is a fully-usable OAuth material entry (far-future expiry, active
// window) for the oauth-group resolver tests below.
func freshOAuth(t *testing.T, key []byte, token string) vkeys.GroupRuntimeAccount {
	return encMat(t, key, vkeys.GroupRuntimeAccount{
		CredentialType: "oauth_account", ExpiresAt: 9_000_000_000, WindowStatus: "active",
	}, token)
}

// threeAccountRoute builds a 3-candidate group route where every account has
// fresh, usable material. Returns the route + the seatassign rank order so a test
// can name the local primary and a distinct override target.
func threeAccountRoute(t *testing.T, key []byte, seat string) (*vkeys.ResolvedRoute, []string) {
	t.Helper()
	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-a", ProviderCode: "anthropic"},
		{AccountID: "acc-b", ProviderCode: "anthropic"},
		{AccountID: "acc-c", ProviderCode: "anthropic"},
	}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-a": freshOAuth(t, key, "tok-acc-a"),
		"acc-b": freshOAuth(t, key, "tok-acc-b"),
		"acc-c": freshOAuth(t, key, "tok-acc-c"),
	}
	route := &vkeys.ResolvedRoute{SeatID: seat, OauthGroupID: "grp", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}
	return route, rankOrder(seat, "acc-a", "acc-b", "acc-c")
}

// A valid engine override (override account IS a serving candidate) redirects the
// seat off its local primary to the engine's healthy pick.
func TestResolveGroup_OverrideValidCandidateRedirects(t *testing.T) {
	key := grKey()
	seat := "seat-ovr-1"
	route, order := threeAccountRoute(t, key, seat)
	primary := order[0]
	override := order[len(order)-1] // a different, valid candidate

	if override == primary {
		t.Fatalf("test setup: override %q must differ from primary %q", override, primary)
	}

	// Feed the override through the cache exactly like the hot path does.
	cache := NewRoutingOverrideCache()
	cache.Store(7, map[string]string{routeKey(seat, route.OauthGroupID): override})

	res, err := resolveGroupCredential(route, key, 1_000_000, nil, cache.lookup(seat, route.OauthGroupID))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.AccountID != override {
		t.Fatalf("engine override should redirect to %q, got %q", override, res.AccountID)
	}
	if res.OAuth == nil || res.OAuth.AccessToken != "tok-"+override {
		t.Fatalf("override resolution wrong token: %+v", res.OAuth)
	}
	// The local rank-0 primary is still reported so the switch is audited (N9 #8).
	if res.Primary != primary {
		t.Fatalf("Primary must stay the local rank-0 %q for audit, got %q", primary, res.Primary)
	}
	if res.Primary == res.AccountID {
		t.Fatal("an applied override must differ from the local primary (switch case)")
	}
}

// A STALE override (the account is no longer a candidate in this group's set) is
// ignored — the §6.5 member-validity re-check falls back to the local pick rather
// than routing to an account the proxy has no material for.
func TestResolveGroup_StaleOverrideFallsBackToLocal(t *testing.T) {
	key := grKey()
	seat := "seat-ovr-2"
	route, order := threeAccountRoute(t, key, seat)
	primary := order[0]

	cache := NewRoutingOverrideCache()
	cache.Store(3, map[string]string{routeKey(seat, route.OauthGroupID): "ghost-account"}) // not in the candidate set

	res, err := resolveGroupCredential(route, key, 1_000_000, nil, cache.lookup(seat, route.OauthGroupID))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.AccountID != primary {
		t.Fatalf("stale override must fall back to local primary %q, got %q", primary, res.AccountID)
	}
	if res.Primary != res.AccountID {
		t.Fatalf("local pick → no switch: Primary(%q) must equal pick(%q)", res.Primary, res.AccountID)
	}
}

// OWNER RULE (2026-07-01): the engine MAY route a member to an account they have NOT
// logged into — an override naming a needs_login account is HONORED: the hot path stops
// there with LOGIN_REQUIRED for THAT account (matching what vault/virtual-keys/team-oauth
// display as the routed account), it does NOT silently fall through to a logged-in local
// pick. 能红: make the picker treat a needs_login override as unusable (fall through) →
// this resolves the local pick instead of erroring → fails.
func TestResolveGroup_NeedsLoginOverridePromptsLoginForThatAccount(t *testing.T) {
	key := grKey()
	seat := "seat-ovr-nl"
	now := int64(1_000_000)

	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-a", ProviderCode: "anthropic"},
		{AccountID: "acc-b", ProviderCode: "anthropic"},
	}
	order := rankOrder(seat, "acc-a", "acc-b")
	primary := order[0]  // logged in + usable — the fall-through would serve this
	override := order[1] // the ENGINE's pick — member not logged in
	mat := map[string]vkeys.GroupRuntimeAccount{
		primary:  freshOAuth(t, key, "tok-primary"),
		override: {CredentialType: "oauth_account", NeedsLogin: true},
	}
	route := &vkeys.ResolvedRoute{SeatID: seat, OauthGroupID: "grp", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}

	_, err := resolveGroupCredential(route, key, now, nil, override)
	if err == nil {
		t.Fatal("needs_login override must NOT silently serve the local pick — want LOGIN_REQUIRED")
	}
	ge, ok := err.(*groupResolveError)
	if !ok || ge.Code != groupErrLoginRequired {
		t.Fatalf("want LOGIN_REQUIRED, got %v", err)
	}
	if ge.Account != override {
		t.Fatalf("login prompt must name the ENGINE-routed account %q (the one all pages display), got %q", override, ge.Account)
	}
}

// An override pointing at a candidate ref WITHOUT usable material (expired) is also
// ignored: the override path runs the SAME usability gate as the ranked loop, so it
// never routes to an unusable account — it falls back to the local pick.
func TestResolveGroup_OverrideWithoutUsableMaterialFallsBack(t *testing.T) {
	key := grKey()
	seat := "seat-ovr-3"
	now := int64(1_000_000)

	refs := []vkeys.GroupAccountRef{
		{AccountID: "acc-a", ProviderCode: "anthropic"},
		{AccountID: "acc-b", ProviderCode: "anthropic"},
	}
	order := rankOrder(seat, "acc-a", "acc-b")
	primary := order[0]
	// The override target is a candidate ref but its token is expired (no usable
	// material) — engine picked it before it expired locally.
	expired := order[1]
	mat := map[string]vkeys.GroupRuntimeAccount{
		primary: freshOAuth(t, key, "tok-primary"),
		expired: encMat(t, key, vkeys.GroupRuntimeAccount{CredentialType: "oauth_account", ExpiresAt: now - 1}, "tok-expired"),
	}
	route := &vkeys.ResolvedRoute{SeatID: seat, GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}

	res, err := resolveGroupCredential(route, key, now, nil, expired)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.AccountID != primary {
		t.Fatalf("override-without-material must fall back to local primary %q, got %q", primary, res.AccountID)
	}
}

// No override ("") leaves the local seatassign pick unchanged.
func TestResolveGroup_NoOverrideUsesLocalPick(t *testing.T) {
	key := grKey()
	seat := "seat-ovr-4"
	route, order := threeAccountRoute(t, key, seat)
	primary := order[0]

	res, err := resolveGroupCredential(route, key, 1_000_000, nil, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.AccountID != primary {
		t.Fatalf("no override → local primary %q, got %q", primary, res.AccountID)
	}
}

// §11.1 invariant WITH the override layer present: when the engine is down (poll
// never succeeded → empty cache), serving still resolves via local seatassign.
func TestResolveGroup_EngineDownEmptyCacheLocalPick(t *testing.T) {
	key := grKey()
	seat := "seat-ovr-5"
	route, order := threeAccountRoute(t, key, seat)
	primary := order[0]

	cache := NewRoutingOverrideCache() // never Stored — engine down
	if got := cache.lookup(seat, route.OauthGroupID); got != "" {
		t.Fatalf("empty cache must miss, got %q", got)
	}
	res, err := resolveGroupCredential(route, key, 1_000_000, nil, cache.lookup(seat, route.OauthGroupID))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.AccountID != primary {
		t.Fatalf("engine down → local primary %q, got %q", primary, res.AccountID)
	}
}

// The cache is nil-safe and keep-last-known: a nil receiver / unset cache misses;
// Store replaces the whole map; Version gates re-apply.
func TestRoutingOverrideCache_NilSafeAndStore(t *testing.T) {
	var nilCache *RoutingOverrideCache
	if got := nilCache.lookup("seat", "g"); got != "" {
		t.Fatalf("nil cache lookup must be empty, got %q", got)
	}
	if v := nilCache.Version(); v != 0 {
		t.Fatalf("nil cache version must be 0, got %d", v)
	}
	nilCache.Store(1, map[string]string{routeKey("seat", "g"): "x"}) // must not panic

	c := NewRoutingOverrideCache()
	if got := c.lookup("seat", "g"); got != "" {
		t.Fatalf("fresh cache must miss, got %q", got)
	}
	c.Store(5, map[string]string{routeKey("seat-1", "g"): "acc-1"})
	if got := c.lookup("seat-1", "g"); got != "acc-1" {
		t.Fatalf("lookup after store: got %q", got)
	}
	if got := c.lookup("seat-unknown", "g"); got != "" {
		t.Fatalf("unknown seat must miss, got %q", got)
	}
	// Multi-pool (2026-07-01): the SAME seat in TWO groups keeps DISTINCT overrides —
	// keying by seat alone (the old bug) would collapse them to one.
	c.Store(5, map[string]string{routeKey("seat-1", "g1"): "acc-g1", routeKey("seat-1", "g2"): "acc-g2"})
	if got := c.lookup("seat-1", "g1"); got != "acc-g1" {
		t.Fatalf("seat-1/g1 override: got %q", got)
	}
	if got := c.lookup("seat-1", "g2"); got != "acc-g2" {
		t.Fatalf("seat-1/g2 override (multi-pool, distinct per group): got %q", got)
	}
	if v := c.Version(); v != 5 {
		t.Fatalf("version: got %d", v)
	}
	// A later store replaces the whole map (old key gone, new key present).
	c.Store(6, map[string]string{routeKey("seat-2", "g"): "acc-2"})
	if got := c.lookup("seat-1", "g1"); got != "" {
		t.Fatalf("replaced map must drop seat-1/g1, got %q", got)
	}
	if got := c.lookup("seat-2", "g"); got != "acc-2" {
		t.Fatalf("replaced map must carry seat-2, got %q", got)
	}
	// A nil map normalizes to empty (no panic, all lookups miss).
	c.Store(7, nil)
	if got := c.lookup("seat-2", "g"); got != "" {
		t.Fatalf("nil-map store must clear, got %q", got)
	}
}

// TestRoutingOverrideCache_StoredDistinguishesVersionZero is the regression for the
// first-pull-at-version-0 skip hole (review HIGH): the cache's version atomic is
// zero-valued, so the poll cannot treat Version()==0 alone as "unchanged" — master's
// first non-empty payload at routing_version 0 must still be applied. Stored() makes
// the "never pulled" vs "pulled at 0" distinction the poll's skip guard now relies on.
func TestRoutingOverrideCache_StoredDistinguishesVersionZero(t *testing.T) {
	c := NewRoutingOverrideCache()
	if c.Stored() {
		t.Fatal("fresh cache must report Stored()==false (never pulled)")
	}
	if c.Version() != 0 {
		t.Fatalf("fresh cache Version() must be 0, got %d", c.Version())
	}
	// First pull: a non-empty assignment map carrying routing_version 0.
	c.Store(0, map[string]string{routeKey("seat-1", "g"): "acct-1"})
	if !c.Stored() {
		t.Fatal("after Store(0,...) Stored() must be true — else the poll skips it forever")
	}
	if got := c.lookup("seat-1", "g"); got != "acct-1" {
		t.Fatalf("version-0 non-empty payload must be applied, lookup got %q want acct-1", got)
	}
}
