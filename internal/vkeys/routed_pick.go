// routed_pick.go — the SINGLE SOURCE OF TRUTH for "which pool account does this seat
// route to right now" on the PROXY side (2026-07-01, owner-approved unification).
//
// Consumers (both import this ONE function — never re-derive the pick):
//   - proxy.resolveGroupCredential  — the HOT PATH (what the request actually forwards to)
//   - supervisor.computeRoutedAccountID — the is_current_routed DISPLAY stamp
//     (/user/vault + /user/virtual-keys read it as current_routed)
//
// Together with the master side (poolroute.Resolve → the engine ledger feeding both the
// team-oauth page AND GET /accounts/me/routing → RoutingOverrideCache → the `override`
// input here), all four surfaces — proxy forwarding, vault, virtual-keys, team-oauth —
// resolve the SAME account by construction.
//
// OWNER RULE (2026-07-01): the engine is ALLOWED to route a member to an account they
// have NOT logged into. So an override naming a needs_login account is HONORED
// (PickNeedsLogin → the hot path returns LOGIN_REQUIRED for THAT account, the pages show
// that account with a "log in" prompt) — it is NOT treated as a stale redirect to fall
// through. Only a genuinely unusable override (not a candidate / no material / expired /
// window-exhausted / cooling) falls through to the local ranked pick.
package vkeys

import "github.com/AiKeyLabs/pkg/seatassign"

// PickOutcome is the 3-way result of picking a routed account.
type PickOutcome int

const (
	// PickNone: no candidate is usable (all skipped/expired/exhausted/absent).
	PickNone PickOutcome = iota
	// PickOK: the returned account is usable right now (has deliverable material).
	PickOK
	// PickNeedsLogin: the returned account IS the routed account but the member has
	// no token for it — callers prompt login for it (hot path: LOGIN_REQUIRED; display:
	// stamp it, the login badge explains).
	PickNeedsLogin
)

// PickRoutedAccount resolves the ONE account a seat routes to within a group.
//
//	refs      — the group's candidate set (key-sync snapshot shape).
//	material  — the group_runtime material map (per-account, PLAINTEXT flags only are
//	            read; secrets untouched). EMPTY map = "material unknown" (the proxy
//	            hasn't pulled yet) → gates degrade to rank/override-only (blind mode),
//	            so the display can still stamp a nominal pick pre-poll. The hot path
//	            never passes an empty map (it errors NO_MATERIAL before picking).
//	override  — the engine's (seat,group) routing override ("" = none). Honored when
//	            the account is a candidate and not skipped — INCLUDING needs_login
//	            (owner rule above). Falls through when genuinely unusable.
//	skip      — accounts to route around (cooldown / this-request retries). nil ok.
//	nowUnix   — clock for the expiry gate (injected for deterministic tests).
//
// The ranked loop STOPS at the first non-skipped needs_login candidate (strict HRW —
// never silently hop past an account the member merely needs to log into; RW2/D2).
func PickRoutedAccount(seatID string, refs []GroupAccountRef, material map[string]GroupRuntimeAccount, override string, skip map[string]bool, nowUnix int64) (string, PickOutcome) {
	if len(refs) == 0 {
		return "", PickNone
	}
	accounts := make([]seatassign.Account, 0, len(refs))
	inSet := make(map[string]bool, len(refs))
	for _, r := range refs {
		accounts = append(accounts, seatassign.Account{AccountID: r.AccountID, Priority: r.Priority})
		inSet[r.AccountID] = true
	}
	blind := len(material) == 0 // pre-poll display mode: no usability info yet

	gate := func(accountID string) PickOutcome {
		if !inSet[accountID] || skip[accountID] {
			return PickNone
		}
		if blind {
			return PickOK
		}
		mat, ok := material[accountID]
		if !ok {
			return PickNone // material not delivered (yet) — retryable skip, not a login prompt
		}
		if mat.NeedsLogin {
			return PickNeedsLogin
		}
		if !MaterialUsable(mat, nowUnix) {
			return PickNone // expired / window-exhausted
		}
		return PickOK
	}

	// Engine override first (owner rule: needs_login is a valid, honored destination).
	if override != "" {
		if oc := gate(override); oc != PickNone {
			return override, oc
		}
	}
	// Local ranked pick — stop at the first usable OR needs_login candidate.
	for _, a := range seatassign.Rank(seatID, accounts) {
		if oc := gate(a.AccountID); oc != PickNone {
			return a.AccountID, oc
		}
	}
	return "", PickNone
}

// MaterialUsable reports whether an account's material can serve a request now.
// OAuth: not past expiry and quota window not exhausted. API key: always usable if
// present (no expiry/window in the contract). Shared by the pick gate above and the
// hot path's post-pick sanity.
func MaterialUsable(mat GroupRuntimeAccount, nowUnix int64) bool {
	if mat.CredentialType == "api_key" {
		return true
	}
	if mat.ExpiresAt > 0 && mat.ExpiresAt <= nowUnix {
		return false // access_token expired (refresh is master's job — N7b)
	}
	if mat.WindowStatus == "exhausted" {
		return false // oauth-group quota window used up — route around it
	}
	return true
}

// MaterialExpired reports whether an OAuth account's material is stale
// SPECIFICALLY because the member's access token passed its expiry. R36
// (2026-07-04): expiry is MEMBER-fixable — re-logging in mints a new token — so
// the resolver's dead-end classification uses this to prompt a 401 re-login
// instead of the admin-facing ALL_UNUSABLE 503. Window-exhausted is deliberately
// NOT this: only routing around (or waiting) fixes it. API keys never expire.
func MaterialExpired(mat GroupRuntimeAccount, nowUnix int64) bool {
	return mat.CredentialType != "api_key" && mat.ExpiresAt > 0 && mat.ExpiresAt <= nowUnix
}
