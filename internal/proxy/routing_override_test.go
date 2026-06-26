package proxy

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// freshOAuth is a fully-usable OAuth material entry (far-future expiry, active
// window) for the seat-group resolver tests below.
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
	route := &vkeys.ResolvedRoute{SeatID: seat, SeatGroupID: "grp", GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat)}
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
	cache.Store(7, map[string]string{seat: override})

	res, err := resolveGroupCredential(route, key, 1_000_000, nil, cache.lookup(seat))
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
	cache.Store(3, map[string]string{seat: "ghost-account"}) // not in the candidate set

	res, err := resolveGroupCredential(route, key, 1_000_000, nil, cache.lookup(seat))
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
	if got := cache.lookup(seat); got != "" {
		t.Fatalf("empty cache must miss, got %q", got)
	}
	res, err := resolveGroupCredential(route, key, 1_000_000, nil, cache.lookup(seat))
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
	if got := nilCache.lookup("seat"); got != "" {
		t.Fatalf("nil cache lookup must be empty, got %q", got)
	}
	if v := nilCache.Version(); v != 0 {
		t.Fatalf("nil cache version must be 0, got %d", v)
	}
	nilCache.Store(1, map[string]string{"seat": "x"}) // must not panic

	c := NewRoutingOverrideCache()
	if got := c.lookup("seat"); got != "" {
		t.Fatalf("fresh cache must miss, got %q", got)
	}
	c.Store(5, map[string]string{"seat-1": "acc-1"})
	if got := c.lookup("seat-1"); got != "acc-1" {
		t.Fatalf("lookup after store: got %q", got)
	}
	if got := c.lookup("seat-unknown"); got != "" {
		t.Fatalf("unknown seat must miss, got %q", got)
	}
	if v := c.Version(); v != 5 {
		t.Fatalf("version: got %d", v)
	}
	// A later store replaces the whole map (old seat gone, new seat present).
	c.Store(6, map[string]string{"seat-2": "acc-2"})
	if got := c.lookup("seat-1"); got != "" {
		t.Fatalf("replaced map must drop seat-1, got %q", got)
	}
	if got := c.lookup("seat-2"); got != "acc-2" {
		t.Fatalf("replaced map must carry seat-2, got %q", got)
	}
	// A nil map normalizes to empty (no panic, all lookups miss).
	c.Store(7, nil)
	if got := c.lookup("seat-2"); got != "" {
		t.Fatalf("nil-map store must clear, got %q", got)
	}
}
