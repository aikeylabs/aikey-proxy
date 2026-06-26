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
)

// groupResolveError is a typed resolver failure so the caller can map a precise
// HTTP status + error code without string matching.
type groupResolveError struct {
	Code   string
	Reason string
}

func (e *groupResolveError) Error() string { return e.Code + ": " + e.Reason }

// groupResolution is the chosen account + its decrypted credential for one
// request. Exactly one of OAuth / PlaintextKey is meaningful, per CredentialType.
type groupResolution struct {
	AccountID      string
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
// candidate the upstream just rejected.
//
// A candidate is skipped when: it has no material in group_runtime (not pulled
// yet), its OAuth token is expired, its quota window is exhausted, or its secret
// fails to decrypt (corrupt). If every candidate is skipped → GROUP_ALL_UNUSABLE.
func resolveGroupCredential(route *vkeys.ResolvedRoute, derivedKey []byte, nowUnix int64, skip map[string]bool) (*groupResolution, error) {
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

	for _, a := range ordered {
		if skip[a.AccountID] {
			continue
		}
		mat, ok := material[a.AccountID]
		if !ok {
			continue // candidate has no delivered material yet
		}
		if !materialUsable(mat, nowUnix) {
			continue // expired / quota-exhausted
		}
		secret, err := decryptGroupSecret(derivedKey, mat)
		if err != nil {
			continue // corrupt material — try the next candidate, don't fail the request
		}
		ref := refByID[a.AccountID]
		res := buildGroupResolution(a.AccountID, ref, mat, secret)
		res.Primary = primary
		return res, nil
	}

	return nil, &groupResolveError{Code: groupErrAllUnusable, Reason: "all group candidates expired, exhausted, or undecryptable"}
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
	// oauth_account → build the credential oauthInject consumes. The pool identity
	// disguise is NOT set here; the serve site stashes it (stashPoolPersona) so
	// the Director applies it to the outbound clone only (NP-4) — keeping the real
	// identity on r for internal attribution.
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
