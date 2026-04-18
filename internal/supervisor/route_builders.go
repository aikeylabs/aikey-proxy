package supervisor

import (
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// Route builders — single source of truth for how vault records become
// `vkeys.ResolvedRoute` values.
//
// Why these helpers exist
//
// Historically the route-building logic was inlined at two different places
// for each kind of route (one in `buildGeneration` at startup, another in
// the managed-key-sync goroutine). Twice in 2026-04 the two paths drifted
// — different `RouteSource` literals ended up on one side but not the
// other, which surfaced as `deriveKeyLabel()` producing opaque truncated
// VK ids in the UI (`oauth:sessio`, `personal:ab`). The fix was to set the
// missing field, but as long as the two paths remain duplicated, a future
// contributor can silently introduce the same class of bug a third time.
//
// These helpers collapse the two paths into one: every caller must route
// through the same function, so forgetting to set `RouteSource` becomes a
// compile error rather than a subtle UI regression. See
// `workflow/CI/bugfix/2026-04-18-third-party-review-fixes.md` for the
// history and regression tests (`route_builders_test.go` +
// `internal/events/reportable_test.go`) that pin the invariants.

// managedKeyToRoute builds a team-managed virtual-key route from a vault
// record. Used by both the startup sync in `buildGeneration` and the
// periodic managed-key sync goroutine.
func managedKeyToRoute(mk vault.ManagedKey) *vkeys.ResolvedRoute {
	return &vkeys.ResolvedRoute{
		// Provider points at the provider *adapter* (protocol), while
		// ProviderCode retains the canonical provider identifier.
		VirtualKeyID:       mk.VirtualKeyID,
		Provider:           mk.ProtocolType,
		BaseURL:            mk.BaseURL,
		PlaintextKey:       mk.PlaintextKey,
		OrgID:              mk.OrgID,
		AccountID:          mk.OwnerAccountID,
		SeatID:             mk.SeatID,
		ProviderCode:       mk.ProviderCode,
		ProtocolType:       mk.ProtocolType,
		CredentialID:       mk.CredentialID,
		CredentialRevision: mk.CredentialRevision,
		VirtualKeyRevision: mk.VirtualKeyRevision,
		RouteSource:        "team",
	}
}

// personalTokenToRoute builds a personal BYOK route from a vault personal
// route-token record. Called at proxy startup and again on managed-key sync
// (the personal table can change via CLI between reloads).
func personalTokenToRoute(pt vault.PersonalRouteToken) *vkeys.ResolvedRoute {
	return &vkeys.ResolvedRoute{
		VirtualKeyID: "personal:" + pt.Alias,
		Provider:     pt.ProviderCode,
		BaseURL:      pt.BaseURL,
		KeyAlias:     pt.Alias,
		ProviderCode: pt.ProviderCode,
		ProtocolType: providerToProtocol(pt.ProviderCode),
		RouteSource:  "personal",
	}
}

// oauthTokenToRoute builds an OAuth-account route from a vault OAuth
// route-token record. `KeyAlias = "__oauth__"` is the sentinel the proxy
// uses to know it must go through the OAuth broker for credential
// injection at request time rather than a direct vault lookup.
func oauthTokenToRoute(ot vault.OAuthRouteToken) *vkeys.ResolvedRoute {
	return &vkeys.ResolvedRoute{
		VirtualKeyID:  "oauth:" + ot.AccountID,
		Provider:      ot.Provider,
		BaseURL:       providerDefaultBaseURL(ot.Provider),
		KeyAlias:      "__oauth__",
		ProviderCode:  ot.Provider,
		ProtocolType:  providerToProtocol(ot.Provider),
		AccountID:     ot.AccountID,
		OAuthIdentity: ot.Identity,
		RouteSource:   "oauth",
	}
}
