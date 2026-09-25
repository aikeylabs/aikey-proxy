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
// have NOT logged into. Therefore the first non-skipped needs_login account is a valid
// destination (PickNeedsLogin): the hot path returns LOGIN_REQUIRED for THAT account and
// the pages show the same account with a login prompt. The caller, which owns the meaning
// of its skip set, decides whether a request-local failure may expose that prompt. This
// keeps the pure picker shared by forwarding and display without letting transient 5xx
// failures rewrite the client-visible error (the hot path preserves those separately).
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
//	            the account is a candidate, not skipped, and serviceable. A
//	            needs_login override no longer blocks (2026-08-15 rule change, see
//	            below): it becomes the preferred login-prompt target while any
//	            healthy candidate keeps serving.
//	skip      — accounts to route around (cooldown / this-request retries). nil ok.
//	nowUnix   — clock for the expiry gate (injected for deterministic tests).
//
// PickNeedsLogin is returned only when NO candidate is serviceable and at least
// one is waiting on a member login — the actionable prompt names the engine's
// override target first, else the highest-ranked needs_login account.
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
	ordered := seatassign.Rank(seatID, accounts)
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

	// 2026-08-15 rule change (decision: 硬吊销/未登录不阻塞用户流程 — supersedes the
	// 2026-07-01 owner rule "a needs_login override is honored immediately"):
	// a needs_login candidate is remembered as the ACTIONABLE login target but no
	// longer blocks the request while a healthy candidate exists. LOGIN_REQUIRED
	// therefore only surfaces when NO candidate is serviceable — matching the
	// spec's three-state table ("候选 token 都失效 → LOGIN_REQUIRED"). WHY: a hard
	// revoke marks the pinned account's token needs_login; under the old rule the
	// member was fully blocked until they re-logged in even though a healthy
	// sibling sat in the same pool (schedstress P04, live-measured). The engine's
	// target still wins as the login PROMPT (pendingLogin prefers the override),
	// and the display stamp shares this exact pick, so UI and hot path agree.
	pendingLogin := ""
	if override != "" {
		switch gate(override) {
		case PickOK:
			return override, PickOK
		case PickNeedsLogin:
			pendingLogin = override // remembered prompt target; keep searching for service
		case PickNone:
			// An unusable/stale override is not authoritative; try ranked candidates.
		}
	}
	for _, a := range ordered {
		switch gate(a.AccountID) {
		case PickOK:
			return a.AccountID, PickOK
		case PickNeedsLogin:
			if pendingLogin == "" {
				pendingLogin = a.AccountID
			}
		case PickNone:
			continue
		}
	}
	if pendingLogin != "" {
		return pendingLogin, PickNeedsLogin
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
	if MaterialWindowBlockedAt(mat, nowUnix) {
		return false // oauth-group quota window used up — route around it
	}
	return true
}

// WindowExhausted accepts the canonical master value plus the pre-canonical
// legacy value already present in older local vault rows. Writers must emit
// exhausted_current_window; the compatibility read keeps online upgrades safe.
func WindowExhausted(status string) bool {
	return status == "exhausted_current_window" || status == "exhausted"
}

func MaterialWindowExhausted(mat GroupRuntimeAccount) bool {
	return WindowExhausted(mat.WindowStatus) || WindowExhausted(mat.Window7dStatus)
}

// QuotaState is the verdict of MaterialWindowBlockedUntil — a closed set. The
// names and strings are the control plane's devicerouting.QuotaState verbatim
// (aikey-control-master service/internal/devicerouting/quota.go): both
// processes judge the same two window columns, so they share one vocabulary and
// one precedence, and a log line reads the same on either side.
type QuotaState string

const (
	// QuotaAvailable — no delivered window blocks the account right now.
	QuotaAvailable QuotaState = "available"
	// QuotaExhausted — an exhausted window blocks it until
	// QuotaVerdict.RecoversAt.
	QuotaExhausted QuotaState = "exhausted"
	// QuotaResetUnknown — an exhausted window blocks it and carries no reset
	// time, so nobody can say when it recovers. Blocked (fail-closed), and
	// never a time.
	QuotaResetUnknown QuotaState = "reset_unknown"
)

// QuotaVerdict is one account's delivered-window verdict at one instant.
//
// Callers branch on State; State is the only answer to "is it blocked".
// RecoversAt is 0 unless State is QuotaExhausted, so never test
// RecoversAt == 0 to mean "not blocked" (QuotaResetUnknown is blocked with
// RecoversAt 0), and never turn a 0 into a time. Combined with another
// deadline (the Worker's local cooldown), unknown stays unknown: the later of
// "in 1 h" and "unknown" is "unknown".
//
// Unlike the control plane's verdict it carries no UnknownWindows: no proxy
// caller reports which window lacks a reset.
type QuotaVerdict struct {
	State QuotaState
	// RecoversAt is unix seconds on the same clock as nowUnix, set only for
	// QuotaExhausted: the moment every exhausted window has reset — the LATER
	// reset when both are (R-oauth-account-pool-52.1).
	RecoversAt int64
}

// MaterialWindowBlockedAt applies an exhausted status only until that same
// window's authoritative reset. Master snapshots are eventually consistent:
// after reset_at, the old exhausted value can still be present in a Worker's
// group_runtime cache. Allowing one lazy half-open request at that boundary is
// what observes the provider's new window and lets Path Z converge Master back
// to active. A legacy exhausted value without a reset stays fail-closed.
//
// It delegates to MaterialWindowBlockedUntil so the picker's gate and the
// recovery time members are told remain ONE judgment and cannot drift apart.
//
// Contract: workflow/CI/bugfix/2026-08-27-oauth-pool-quota-state-convergence.md
func MaterialWindowBlockedAt(mat GroupRuntimeAccount, nowUnix int64) bool {
	return MaterialWindowBlockedUntil(mat, nowUnix).State != QuotaAvailable
}

// MaterialWindowBlockedUntil is the single exit for "until when does the
// master-delivered window state keep this account out". Every caller that
// needs the recovery time must go through it; a second derivation is how the
// device path came to report the EARLIER reset while the picker waited for the
// later one.
//
// The verdict folds the two windows with the control plane's precedence
// (devicerouting.PoolAccount.QuotaAt):
//
//   - an exhausted window with no reset → QuotaResetUnknown, even when the
//     other window has a known reset: it keeps blocking after that reset
//     passes, until the control plane delivers a new state, so a time would
//     promise a release the gate will not perform then;
//   - else an exhausted window before its reset → QuotaExhausted, RecoversAt =
//     the LATEST such reset. A window that is not exhausted is no wall,
//     however late its next reset;
//   - else QuotaAvailable.
//
// MaterialWindowBlockedAt is exactly State != QuotaAvailable. The Worker's
// local cooldown is not an input; QuotaVerdict says how a caller combines it.
//
// spec: R-oauth-account-pool-4.2.S1 the later wall wins (delivered half)
// spec: R-oauth-account-pool-4.2.S2 a missing reset is never a made-up time
// Rule R4.2: workflow/CI/requirements/2026-06-23-oauth-account-pool.md;
// scenarios: roadmap20260320/技术实现/update/20260924-Codex冷却例外补全与提示显示恢复时间.md
func MaterialWindowBlockedUntil(mat GroupRuntimeAccount, nowUnix int64) QuotaVerdict {
	var recoversAt int64
	var resetUnknown bool
	for _, w := range [...]struct {
		status  string
		resetAt *int64
	}{
		{mat.WindowStatus, mat.WindowResetAt},
		{mat.Window7dStatus, mat.Window7dResetAt},
	} {
		switch v := windowQuotaVerdict(w.status, w.resetAt, nowUnix); v.State {
		case QuotaResetUnknown:
			resetUnknown = true
		case QuotaExhausted:
			recoversAt = max(recoversAt, v.RecoversAt)
		case QuotaAvailable:
			// No wall, whatever reset the window carries.
		}
	}
	switch {
	case resetUnknown:
		return QuotaVerdict{State: QuotaResetUnknown}
	case recoversAt > 0:
		return QuotaVerdict{State: QuotaExhausted, RecoversAt: recoversAt}
	default:
		return QuotaVerdict{State: QuotaAvailable}
	}
}

// windowQuotaVerdict judges ONE window. An exhausted window blocks until its own
// reset, exclusive: at the reset second the lazy half-open probe is admitted. A
// reset-less (or non-positive) exhausted value blocks with no known end.
func windowQuotaVerdict(status string, resetAt *int64, nowUnix int64) QuotaVerdict {
	switch {
	case !WindowExhausted(status):
		return QuotaVerdict{State: QuotaAvailable}
	case resetAt == nil || *resetAt <= 0:
		return QuotaVerdict{State: QuotaResetUnknown}
	case nowUnix < *resetAt:
		return QuotaVerdict{State: QuotaExhausted, RecoversAt: *resetAt}
	default:
		return QuotaVerdict{State: QuotaAvailable}
	}
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
