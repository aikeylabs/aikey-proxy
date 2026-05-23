package supervisor

import (
	"errors"
	"log/slog"

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
		VirtualKeyID: mk.VirtualKeyID,
		Provider:     mk.ProtocolType,
		BaseURL:      mk.BaseURL,
		// 2026-05-09: surface the user-facing alias (e.g. `key-335923591-0011-1`)
		// onto the route so deriveKeyLabel uses it for receipt / WAL `key_label`
		// instead of falling back to the vk_id tail. Empty for legacy rows that
		// pre-date the `local_alias` column add — in that case deriveKeyLabel
		// still falls back to the vk_id tail (no regression).
		KeyAlias:           mk.LocalAlias,
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

// appRouteTokenToRoute builds an App pipeline route from a vault app
// route-token record (Phase 4 third-party Agent接入).
//
// Why Provider / BaseURL / KeyAlias are intentionally empty: app routes
// resolve their upstream credential per-request via the App pipeline (see
// vault.GetProviderBindingWithScope("app:<slug>", protocol)), not at load
// time. Pinning a static Provider here would lock the app to one upstream
// and defeat the point of the binding indirection (which lets the user
// switch which underlying account the app uses without rotating the
// app's token).
//
// VirtualKeyID prefix is "app:" mirroring "personal:" / "oauth:" so the
// existing deriveKeyLabel observability codepath produces a sensible
// label without special-casing.
func appRouteTokenToRoute(at vault.AppRouteToken) *vkeys.ResolvedRoute {
	return &vkeys.ResolvedRoute{
		VirtualKeyID:     "app:" + at.AppSlug,
		RouteSource:      "app",
		AppSlug:          at.AppSlug,
		AppKind:          at.AppKind,
		AppKeyID:         at.KeyID,
		FollowUserActive: at.FollowUserActive,
	}
}

// ── Filtered route-set builders (single source of truth for both startup
//    `buildGeneration` and reload `syncManagedKeys` paths) ─────────────────
//
// Why these wrappers exist (third-party review #5 [中], 2026-04-29):
// Initial-load and sync paths previously had different filter logic — sync
// rejected non-strict `aikey_personal_<64-hex>` route tokens with a WARN,
// but `buildGeneration` blindly registered whatever the loader returned.
// The vault-layer filter (review #4 [低]) catches most cases, but the two
// supervisor paths LOOKED different at the source level — exactly the
// drift this file's header docstring warns against. Centralizing here
// makes "skip non-strict + WARN with hint" a compile-time-shared shape;
// any future contributor adding a third call site gets the same behavior
// for free.

// buildPersonalRoutesFiltered converts personal-key route-token records
// into a `route → ResolvedRoute` map, skipping (with WARN) any record
// whose `RouteToken` is not a strict `aikey_personal_<64-lowercase-hex>`.
// Used by both startup and sync paths.
func buildPersonalRoutesFiltered(tokens []vault.PersonalRouteToken) map[string]*vkeys.ResolvedRoute {
	out := make(map[string]*vkeys.ResolvedRoute, len(tokens))
	for _, pt := range tokens {
		if !isStrictPersonalRouteToken(pt.RouteToken) {
			slog.Warn("registry load: skipping legacy/malformed personal route token; run `aikey db upgrade` to migrate",
				"alias", pt.Alias,
				"token_prefix", tokenPrefixForLog(pt.RouteToken))
			continue
		}
		out[pt.RouteToken] = personalTokenToRoute(pt)
	}
	return out
}

// buildOAuthRoutesFiltered is the OAuth-table counterpart to
// buildPersonalRoutesFiltered. Same form filter (post-2026-04-29 personal
// /OAuth bearer is `aikey_personal_<64-lowercase-hex>` regardless of
// credential source).
func buildOAuthRoutesFiltered(tokens []vault.OAuthRouteToken) map[string]*vkeys.ResolvedRoute {
	out := make(map[string]*vkeys.ResolvedRoute, len(tokens))
	for _, ot := range tokens {
		if !isStrictPersonalRouteToken(ot.RouteToken) {
			slog.Warn("registry load: skipping legacy/malformed oauth route token; run `aikey db upgrade` to migrate",
				"account_id", ot.AccountID,
				"token_prefix", tokenPrefixForLog(ot.RouteToken))
			continue
		}
		out[ot.RouteToken] = oauthTokenToRoute(ot)
	}
	return out
}

// buildAppRoutesFiltered converts app-pipeline route-token records into a
// `route → ResolvedRoute` map, skipping (with WARN) any record whose
// `RouteToken` is not a strict `aikey_app_<64-lowercase-hex>`. Mirrors the
// personal / OAuth filters; same eligibility rule, different form prefix.
//
// Vault-side filter already enforces this (vault/route_token_form.go +
// vault.GetAllAppRouteTokens), so this layer is belt-and-suspenders for
// the same reason the personal/OAuth filters duplicate the check —
// supervisor MUST NOT trust vault-side filtering alone, since a future
// vault implementation (or a test fixture / hand-crafted vault row) could
// bypass it. Registry's invariant "byToken only ever holds strict Tier1
// forms" stays true regardless.
func buildAppRoutesFiltered(tokens []vault.AppRouteToken) map[string]*vkeys.ResolvedRoute {
	out := make(map[string]*vkeys.ResolvedRoute, len(tokens))
	for _, at := range tokens {
		if !isStrictAppRouteToken(at.RouteToken) && !isFirstPartyAppBearer(at.RouteToken) {
			slog.Warn("registry load: skipping legacy/malformed app route token",
				"app_slug", at.AppSlug,
				"key_id", at.KeyID,
				"token_prefix", tokenPrefixForLog(at.RouteToken),
				"hint", "expected aikey_app_<64 lowercase hex> or first-party whitelist entry")
			continue
		}
		out[at.RouteToken] = appRouteTokenToRoute(at)
	}
	return out
}

// vaultRouteTokenReader is the minimal vault-reader surface that
// loadVaultRoutesIntoRegistry depends on. Defined as an interface so
// tests can inject a fake without spinning up a real vault file —
// `*vault.Reader` satisfies this naturally.
type vaultRouteTokenReader interface {
	GetAllPersonalRouteTokens() ([]vault.PersonalRouteToken, error)
	GetAllOAuthRouteTokens() ([]vault.OAuthRouteToken, error)
	GetAllAppRouteTokens() ([]vault.AppRouteToken, error)
}

// loadVaultRoutesIntoRegistry merges all strict-form personal + OAuth
// route tokens from a vault into the given registry. Non-strict / legacy
// (`aikey_vk_*` and similar) shapes are WARN-skipped via the shared
// build*RoutesFiltered helpers — same eligibility rule as the reload
// (syncManagedKeys) path.
//
// Why this exists as its own function (third-party review #5 [中],
// 2026-04-29 — second pass): factoring the startup load step out of
// `buildGeneration` makes the filter wiring directly testable. Reviewers
// can read this 20-line function instead of scanning a 200-line
// `buildGeneration` to confirm "yes, the startup path filters legacy".
//
// Returns silently on nil registry / nil reader (defensive — exercised
// only in tests). `ErrMissingRouteTokenColumn` is logged with the
// established hint text (CLI hasn't migrated the vault yet) so operators
// see a clear escalation path rather than an opaque silent skip.
func loadVaultRoutesIntoRegistry(reg *vkeys.Registry, vaultReader vaultRouteTokenReader) {
	if reg == nil || vaultReader == nil {
		return
	}

	// Personal-key bearers (entries.route_token).
	personalTokens, perr := vaultReader.GetAllPersonalRouteTokens()
	switch {
	case errors.Is(perr, vault.ErrMissingRouteTokenColumn):
		slog.Warn("vault missing route_token column, personal key routing disabled. Run any aikey CLI command to migrate.")
	case perr != nil:
		slog.Warn("could not load personal route tokens", "error", perr)
	case len(personalTokens) > 0:
		if routes := buildPersonalRoutesFiltered(personalTokens); len(routes) > 0 {
			reg.Merge(routes)
		}
	}

	// OAuth bearers (provider_accounts.route_token). Same shared filter.
	oauthTokens, oerr := vaultReader.GetAllOAuthRouteTokens()
	switch {
	case errors.Is(oerr, vault.ErrMissingRouteTokenColumn):
		slog.Warn("vault missing route_token column, oauth routing disabled. Run any aikey CLI command to migrate.")
	case oerr != nil:
		slog.Warn("could not load oauth route tokens", "error", oerr)
	case len(oauthTokens) > 0:
		if routes := buildOAuthRoutesFiltered(oauthTokens); len(routes) > 0 {
			reg.Merge(routes)
		}
	}

	// App pipeline bearers (app_keys.route_token, Phase 4). vault.GetAllAppRouteTokens
	// returns nil (no error) on pre-Phase-4 vaults that don't have the
	// app_records / app_keys tables — so a non-error empty result is
	// treated identically to "no apps registered". Any unexpected error
	// is logged but does NOT abort the startup load (preserves
	// personal/team/oauth routing even if app loading regressed).
	appTokens, aerr := vaultReader.GetAllAppRouteTokens()
	switch {
	case aerr != nil:
		slog.Warn("could not load app route tokens", "error", aerr)
	case len(appTokens) > 0:
		if routes := buildAppRoutesFiltered(appTokens); len(routes) > 0 {
			reg.Merge(routes)
		}
	}
}
