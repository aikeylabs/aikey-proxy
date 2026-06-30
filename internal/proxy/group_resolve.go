// group_resolve.go — N8a: oauth-group credential resolver (pure, no I/O).
//
// Given a resolved group VK route (route.OauthGroupID != ""), this picks one
// candidate account for the request and produces the credential to inject:
//
//	route.GroupAccounts  (candidate set, ranking inputs + identity, NO secrets)
//	route.GroupRuntime   (per-account encrypted material, written by N7c-2)
//	        │
//	        ├─ seatassign.Rank(route.SeatID, candidates)   ← byte-identical to master
//	        ├─ first usable candidate (has material, not expired/exhausted)
//	        ├─ base64-decode + vault.Decrypt the secret with the vault key
//	        └─ build *groupResolution (OAuthCredential | plaintext key)
//
// This function is deliberately side-effect free (no vault read, no HTTP, no
// header mutation) so it is fully unit-testable. The hot-path wiring that calls
// it + mutates the request lives in N8b (handle_dispatch), behind the
// oauth-group feature flag. Direct-bind / personal routes never reach here.
//
// SECURITY: the decrypted secret exists only in the returned struct's memory;
// it is never logged. Ranking MUST match master's snapshot.GroupAccountRef
// ordering (seatassign.Account{AccountID, Priority}, Weight unset = 1).
package proxy

import (
	"encoding/base64"
	"encoding/json"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/seatassign"
)

// Credential types in the group material contract (match master + N7c-2 writer).
const (
	credTypeOAuth = "oauth_account"
	credTypeKey   = "api_key"
)

// Resolution failure codes (mapped to HTTP responses by the N8b caller).
const (
	groupErrNoCandidates = "GROUP_NO_CANDIDATES" // route has no parseable candidate set
	groupErrNoMaterial   = "GROUP_NO_MATERIAL"   // group_runtime empty/unparseable (not pulled yet)
	groupErrAllUnusable  = "GROUP_ALL_UNUSABLE"  // every candidate expired / exhausted / undecryptable
	// groupErrLoginRequired (RW2, per-member): the HRW-selected account has no
	// token for THIS member (they haven't logged into it). Per D2 the walk stops
	// here — it does NOT skip to a later already-logged-in account (that would
	// break the HRW load allocation) — and the caller returns a structured login
	// prompt naming groupResolveError.Account so the member logs into THAT account.
	groupErrLoginRequired = "OAUTH_GROUP_MEMBER_LOGIN_REQUIRED"
)

// candOutcome is the 3-way result of evaluating one candidate: usable now, skip
// (expired/exhausted/corrupt → continue fallback), or needs-login (no member
// token → stop + prompt, RW2/D2).
type candOutcome int

const (
	candOK candOutcome = iota
	candSkip
	candNeedsLogin
)

// groupResolveError is a typed resolver failure so the caller can map a precise
// HTTP status + error code without string matching.
type groupResolveError struct {
	Code   string
	Reason string
	// Account is set for groupErrLoginRequired: the account the member must log
	// into (the caller builds the login URL from it).
	Account string
}

func (e *groupResolveError) Error() string { return e.Code + ": " + e.Reason }

// groupResolution is the chosen account + its decrypted credential for one
// request. Exactly one of OAuth / PlaintextKey is meaningful, per CredentialType.
type groupResolution struct {
	AccountID      string
	CredentialID   string // real credential_id of the chosen account → route.CredentialID for I5 signal reporting (T2 uplink)
	CredentialType string // "oauth_account" | "api_key"
	ProviderCode   string // candidate's resolved provider code (oauthInject dispatch)
	Identity       string // display / audit only — never sent upstream
	// Primary is the seat's rank-0 account (seatassign top pick). When it differs
	// from AccountID, a fallback happened (the primary was cooled / exhausted /
	// expired / has no material) — the caller audits the switch (N9 #8).
	Primary string

	// oauth_account: header injection via oauthInject(req, OAuth, ProviderCode).
	OAuth *OAuthCredential
	// api_key: realKey + optional per-account upstream base URL.
	PlaintextKey string
	BaseURL      string
	Revision     string
	// WindowMaxUtilPct is master's randomized pre-cut cap (95-99) for this
	// account's quota window (N11). When the upstream response says utilization
	// ≥ this/100, N10 pre-cuts the account before it hits 100% (which looks like
	// abuse). nil → no cap delivered → proxy uses 100% (natural exhaustion only).
	WindowMaxUtilPct *int
}

// resolveGroupCredential ranks the route's group candidates for route.SeatID and
// returns the first usable account's decrypted credential. `nowUnix` is the
// caller's clock (injected for deterministic tests); `derivedKey` is the vault
// key used to decrypt the at-rest material. `skip` (may be nil) names accounts
// the caller already tried this request — used by N8c fallback to advance past a
// candidate the upstream just rejected. `overrideAccountID` (may be "") is the
// allocation engine's seat→account routing override (I-side §6.5): when the
// engine has redirected this seat off an unhealthy default, the caller passes the
// engine's healthy pick here.
//
// A candidate is skipped when: it has no material in group_runtime (not pulled
// yet), its OAuth token is expired, its quota window is exhausted, or its secret
// fails to decrypt (corrupt). If every candidate is skipped → GROUP_ALL_UNUSABLE.
func resolveGroupCredential(route *vkeys.ResolvedRoute, derivedKey []byte, nowUnix int64, skip map[string]bool, overrideAccountID string) (*groupResolution, error) {
	var refs []vkeys.GroupAccountRef
	if route.GroupAccounts == "" || json.Unmarshal([]byte(route.GroupAccounts), &refs) != nil || len(refs) == 0 {
		return nil, &groupResolveError{Code: groupErrNoCandidates, Reason: "no parseable group candidates on route"}
	}

	var material map[string]vkeys.GroupRuntimeAccount
	if route.GroupRuntime == "" || json.Unmarshal([]byte(route.GroupRuntime), &material) != nil || len(material) == 0 {
		// Material not pulled yet (N7c-2 poll hasn't landed) or unparseable.
		return nil, &groupResolveError{Code: groupErrNoMaterial, Reason: "group_runtime is empty — material not delivered yet"}
	}

	// Rank exactly as master does: Account{AccountID, Priority}, Weight unset.
	accounts := make([]seatassign.Account, 0, len(refs))
	refByID := make(map[string]vkeys.GroupAccountRef, len(refs))
	for _, r := range refs {
		accounts = append(accounts, seatassign.Account{AccountID: r.AccountID, Priority: r.Priority})
		refByID[r.AccountID] = r
	}
	ordered := seatassign.Rank(route.SeatID, accounts)
	primary := ordered[0].AccountID // rank-0; audited when the actual pick differs

	// §6.5 allocation-engine routing override (I-side keystone). The engine
	// re-ran seatassign over only the HEALTHY accounts and named the override as
	// this seat's healthy pick. Apply it ONLY when it is STILL a valid, serving
	// candidate in THIS group right now — member-validity re-check: the account
	// may have been removed/disabled since the engine computed it. resolveCandidate
	// runs the SAME validity gate the ranked loop below uses (candidate ref present
	// + material delivered + usable + decryptable), so the override can never route
	// to an account the proxy has no material for. Any miss (stale / no material /
	// expired / exhausted / undecryptable / in skip) falls through to the local
	// ranked pick — the existing path stays the default.
	if overrideAccountID != "" && !skip[overrideAccountID] {
		// Override only takes effect when its account is usable RIGHT NOW. A
		// needs-login/expired/exhausted override falls through to the local ranked
		// pick (don't force a login on a stale engine redirect).
		if res, oc := resolveCandidate(overrideAccountID, refByID, material, derivedKey, nowUnix); oc == candOK {
			res.Primary = primary // engine redirect audited as a switch (primary != pick)
			return res, nil
		}
	}

	for _, a := range ordered {
		if skip[a.AccountID] {
			continue
		}
		res, oc := resolveCandidate(a.AccountID, refByID, material, derivedKey, nowUnix)
		switch oc {
		case candOK:
			res.Primary = primary
			return res, nil
		case candNeedsLogin:
			// RW2/D2: stop at the first account this member hasn't logged into and
			// prompt — do NOT skip to a later logged-in account (preserves HRW
			// allocation). Quota fallback (candSkip) still advances past it.
			return nil, &groupResolveError{Code: groupErrLoginRequired,
				Reason: "member has no token for the routed account — login required", Account: a.AccountID}
		case candSkip:
			continue
		}
	}

	return nil, &groupResolveError{Code: groupErrAllUnusable, Reason: "all group candidates expired, exhausted, or undecryptable"}
}

// resolveCandidate resolves ONE account to its injectable credential, applying
// the single validity gate shared by the ranked loop and the §6.5 engine-override
// path: the account must be a candidate ref in THIS group, have delivered material,
// be usable (not expired/exhausted), and decrypt cleanly. ok=false on any miss so
// the caller skips it (loop) or falls back to the local pick (override). Sharing
// one gate is the whole point — the override's "is this still a valid candidate"
// re-check can never drift from what the loop considers usable.
func resolveCandidate(accountID string, refByID map[string]vkeys.GroupAccountRef, material map[string]vkeys.GroupRuntimeAccount, derivedKey []byte, nowUnix int64) (*groupResolution, candOutcome) {
	ref, ok := refByID[accountID]
	if !ok {
		return nil, candSkip // not a candidate in this group's set (stale/unknown override)
	}
	mat, ok := material[accountID]
	if !ok {
		// No delivered material at all = the proxy hasn't PULLED this account's
		// material yet (channel-③ race / cold start), NOT "member needs login"
		// (master delivers an explicit needs_login marker for that). Treat as a
		// retryable skip → quota fallback to the next candidate, NOT a hard
		// LOGIN_REQUIRED (P1).
		return nil, candSkip
	}
	if mat.NeedsLogin {
		// Master explicitly says the member has no token for this account → prompt
		// login for THIS account (RW2/D2, strict HRW — don't skip past it).
		return nil, candNeedsLogin
	}
	if !materialUsable(mat, nowUnix) {
		return nil, candSkip // expired / quota-exhausted → fall back to next account
	}
	secret, err := decryptGroupSecret(derivedKey, mat)
	if err != nil {
		return nil, candSkip // corrupt material — try the next candidate, don't fail the request
	}
	return buildGroupResolution(accountID, ref, mat, secret), candOK
}

// materialUsable reports whether an account's material can serve a request now.
// OAuth: not past expiry and quota window not exhausted. API key: always usable
// if present (no expiry/window in the contract).
func materialUsable(mat vkeys.GroupRuntimeAccount, nowUnix int64) bool {
	if mat.CredentialType == credTypeKey {
		return true
	}
	if mat.ExpiresAt > 0 && mat.ExpiresAt <= nowUnix {
		return false // access_token expired (refresh is master's job — N7b)
	}
	if mat.WindowStatus == "exhausted" {
		return false // oauth-group quota window used up — fall back to next account
	}
	return true
}

// decryptGroupSecret base64-decodes the nonce + ciphertext and AES-GCM decrypts
// the secret with the vault key.
func decryptGroupSecret(derivedKey []byte, mat vkeys.GroupRuntimeAccount) (string, error) {
	nonce, err := base64.StdEncoding.DecodeString(mat.SecretNonce)
	if err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(mat.SecretCiphertext)
	if err != nil {
		return "", err
	}
	pt, err := vault.Decrypt(derivedKey, nonce, ct)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// buildGroupResolution assembles the injectable credential for the chosen account.
func buildGroupResolution(accountID string, ref vkeys.GroupAccountRef, mat vkeys.GroupRuntimeAccount, secret string) *groupResolution {
	res := &groupResolution{
		AccountID:        accountID,
		CredentialID:     ref.CredentialID,
		CredentialType:   mat.CredentialType,
		ProviderCode:     ref.ProviderCode,
		Identity:         ref.Identity,
		WindowMaxUtilPct: mat.WindowMaxUtilPct, // master's pre-cut cap (N10)
	}
	if mat.CredentialType == credTypeKey {
		res.PlaintextKey = secret
		res.BaseURL = mat.BaseURL
		res.Revision = mat.Revision
		return res
	}
	// oauth_account → build the credential oauthInject consumes. The real client
	// identity flows upstream unchanged (transparent proxy); the former per-account
	// AccountPersona normalization was removed 2026-06-29 (see oauth_inject.go).
	res.OAuth = &OAuthCredential{
		AccessToken: secret,
		Provider:    ref.ProviderCode,
		AccountID:   accountID,
		ExternalID:  mat.ExternalID, // Claude metadata.user_id (empty until master N7a fills it)
		Identity:    ref.Identity,
		ExpiresAt:   mat.ExpiresAt,
	}
	return res
}
