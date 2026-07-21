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
	// EgressProxyURL is the chosen account's optional per-account egress proxy
	// (§11.7, P7). "" → node-level egress applies. Non-secret; carried so the
	// caller can pin this account's outbound to its own exit IP.
	EgressProxyURL string
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

	// Distinguish "not pulled yet" from "pulled → nothing for this seat" (2026-06-30):
	//   ""       → the channel-③ poll hasn't landed → NO_MATERIAL (retry DOES help).
	//   bad JSON → treat as not-ready → NO_MATERIAL (retry).
	//   "{}"     → the proxy DID pull and this seat's group delivered NO accounts:
	//              the member was unbound/removed (access gate wiped it to "{}"), or
	//              the group has no enabled accounts → NO_CANDIDATES: retrying will
	//              NOT help, the member must contact an admin. The candidate snapshot
	//              (group_accounts) may still be STALE with entries — the material rail
	//              (proxy 60s) is fresher than on-demand key sync, so trust "{}" over
	//              stale candidates here. WHY: a removed member was shown "credentials
	//              still syncing, retry shortly" forever — the message told them to
	//              retry when only an admin re-adding the seat can fix it.
	if route.GroupRuntime == "" {
		return nil, &groupResolveError{Code: groupErrNoMaterial, Reason: "group_runtime not pulled yet"}
	}
	var material map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(route.GroupRuntime), &material); err != nil {
		return nil, &groupResolveError{Code: groupErrNoMaterial, Reason: "group_runtime unparseable — treat as not-ready"}
	}
	if len(material) == 0 {
		return nil, &groupResolveError{Code: groupErrNoCandidates, Reason: "group_runtime delivered no accounts for this seat (unbound/removed member or empty group)"}
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
	assigned := primary
	if overrideAccountID != "" {
		if _, ok := refByID[overrideAccountID]; ok {
			assigned = overrideAccountID
		}
	}

	// SINGLE SOURCE OF TRUTH (2026-07-01): the pick — engine override first (§6.5,
	// member-validity re-checked; needs_login overrides are HONORED per the owner rule
	// "the engine may route a member to an account they haven't logged into"), else the
	// local ranked pick — is vkeys.PickRoutedAccount, the SAME function the display
	// stamp (supervisor.computeRoutedAccountID → /user/vault current_routed) uses. Do
	// NOT re-derive routing here; forwarding and display must agree by construction.
	//
	// The only hot-path-extra gate is DECRYPT (needs the vault key, so it can't be in
	// the pure picker): a corrupt secret adds the account to the skip set and re-picks,
	// preserving the old "corrupt material never fails the request" resilience.
	localSkip, cloned := skip, false
	for {
		acc, oc := vkeys.PickRoutedAccount(route.SeatID, refs, material, overrideAccountID, localSkip, nowUnix)
		switch oc {
		case vkeys.PickNeedsLogin:
			// RW2/D2: PickRoutedAccount only emits this for THE assigned account
			// (engine override or strict-HRW rank 0). A needs-login row reached only
			// during request failover is skipped inside the shared picker, because the
			// member page cannot act on that non-current account.
			return nil, &groupResolveError{Code: groupErrLoginRequired,
				Reason: "member has no token for the routed account — login required", Account: acc}
		case vkeys.PickOK:
			mat := material[acc]
			secret, err := decryptGroupSecret(derivedKey, mat)
			if err != nil {
				// corrupt material — route around it, don't fail the request. Clone the
				// caller's skip set once (never mutate the shared cooldown view).
				if !cloned {
					clone := make(map[string]bool, len(skip)+1)
					for k, v := range skip {
						clone[k] = v
					}
					localSkip, cloned = clone, true
				}
				localSkip[acc] = true
				continue
			}
			res := buildGroupResolution(acc, refByID[acc], mat, secret)
			res.Primary = primary
			return res, nil
		default: // PickNone
			// R36 (2026-07-04, codex pools): expiry is member-fixable, but only the
			// assigned account is an actionable re-login target. Never promote an
			// expired request-level fallback to LOGIN_REQUIRED.
			if !localSkip[assigned] {
				m, ok := material[assigned]
				if ok && vkeys.MaterialExpired(m, nowUnix) && m.WindowStatus != "exhausted" {
					return nil, &groupResolveError{Code: groupErrLoginRequired,
						Reason: "member token for the routed account expired — re-login required", Account: assigned}
				}
			}
			return nil, &groupResolveError{Code: groupErrAllUnusable, Reason: "all group candidates expired, exhausted, or undecryptable"}
		}
	}
}

// (resolveCandidate / materialUsable were absorbed into vkeys.PickRoutedAccount /
// vkeys.MaterialUsable — the shared pure pick used by BOTH this hot path and the
// supervisor's display stamp. 2026-07-01 single-source-of-truth unification.)

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
		EgressProxyURL:   mat.EgressProxyURL,   // per-account egress (§11.7, P7)
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
