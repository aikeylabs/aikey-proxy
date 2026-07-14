// group_runtime.go — shared oauth-group routing contracts (N8).
//
// Two JSON shapes the oauth-group feature passes between components live here,
// in vkeys (the bottom of the proxy dependency graph), so the WRITER
// (supervisor.group_runtime_policy — pulls + encrypts) and the READER
// (proxy.group_resolve — ranks + decrypts + injects) share ONE definition
// instead of two structs that can silently drift. Per project rule
// "source-of-truth 不要分裂".
//
// Neither struct carries logic or non-stdlib imports — they are pure wire/at-
// rest data, so keeping them in vkeys does not pull new dependencies into the
// bottom layer.
package vkeys

// GroupAccountRef is one candidate account in a seat group's routing set. It is
// the proxy-side mirror of master's snapshot.GroupAccountRef (JSON tags MUST
// match byte-for-byte) and arrives in ResolvedRoute.GroupAccounts, projected by
// master's RefreshSnapshot (N5). It carries only ranking inputs + display
// identity — NEVER secrets. The matching material (token/key) is in
// GroupRuntime, keyed by AccountID.
//
// NOTE on Weight: master ranks with seatassign.Account{AccountID, Priority}
// and leaves Weight unset (treated as 1 by seatassign). The proxy MUST do the
// same so its local ranking is byte-identical to master's — hence there is no
// Weight field to carry here.
type GroupAccountRef struct {
	AccountID    string `json:"account_id"`
	Identity     string `json:"identity"`      // email / alias (display + audit only)
	ProviderCode string `json:"provider_code"` // resolved provider code (injection dispatch)
	Priority     int    `json:"priority"`      // deterministic tie-break (lower wins)
	Assigned     bool   `json:"assigned"`      // master's rank-0 pick (advisory; proxy re-ranks)
	// CredentialID is the account's real credential_id (same id the engine,
	// auth-gate, and static-key track use). The proxy stamps it onto the resolved
	// route so I5 usage signals enqueue keyed by credential_id instead of being
	// dropped at the empty-id guard. json tag MUST stay byte-identical to master's
	// snapshot.GroupAccountRef. Empty when talking to an old master (back-compat).
	// Bugfix 2026-06-30: T2 uplink credential_id identity split.
	CredentialID string `json:"credential_id,omitempty"`
}

// GroupRuntimeAccount is one account's AT-REST material inside a group VK's
// managed_virtual_keys_cache.group_runtime column. The group_runtime value is a
// JSON map[account_id]GroupRuntimeAccount. The secret (access_token for OAuth /
// key for an API key) is AES-GCM encrypted with the vault derivedKey; nonce +
// ciphertext are base64 in the JSON.
//
// SECURITY: there is intentionally NO refresh_token field — master never
// delivers it, and the at-rest secret is always encrypted (the plaintext only
// exists transiently in memory between TLS receipt and re-encryption).
//
// WRITER: supervisor.buildGroupRuntimeJSON (N7c-2). READER:
// proxy.resolveGroupCredential (N8a).
type GroupRuntimeAccount struct {
	CredentialType   string `json:"credential_type"` // oauth_account | api_key
	SecretNonce      string `json:"secret_nonce"`    // base64(nonce)
	SecretCiphertext string `json:"secret_ciphertext"` // base64(enc(access_token|key))
	// Display meta (non-secret, 2026-07-01): identity/provider_code/priority carried on
	// the fast rail so the client's candidate LIST membership refreshes here (a fast-rail-
	// only account renders with its email/provider, not a bare UUID) — the CLI's
	// merge_group_accounts_live treats this map as authoritative for membership. Priority
	// is NOT omitempty (0 is a valid priority).
	Identity     string `json:"identity,omitempty"`
	ProviderCode string `json:"provider_code,omitempty"`
	Priority     int    `json:"priority"`
	// NeedsLogin: the member has no token for this OAuth account (master said so) →
	// the resolver returns LOGIN_REQUIRED for it. No secret when true. P1.
	NeedsLogin bool `json:"needs_login,omitempty"`
	// IsCurrentRouted: DISPLAY-ONLY (C2, 2026-06-30) — true on the ONE account this
	// seat's traffic is currently routed to in steady state = routing-override ??
	// seatassign rank-0. NOT read by the resolver (which re-decides per request incl.
	// cooldown failover); it exists only so /user/vault can show "current routed"
	// distinct from the static "assigned" default. Recomputed on every material
	// refresh AND on every routing-override change (couples the two 60s rails, owner-
	// approved 2026-06-30). Per-VK (per-seat): the same group's VKs carry different
	// flags. Deliberately excludes transient per-request cooldown failover (would
	// flap; owner chose the stable pick).
	IsCurrentRouted bool `json:"is_current_routed,omitempty"`
	// OAuth meta:
	ExpiresAt        int64  `json:"expires_at,omitempty"`
	WindowMaxUtilPct *int   `json:"window_max_util_pct,omitempty"`
	WindowStatus     string `json:"window_status,omitempty"`
	WindowResetAt    *int64 `json:"window_reset_at,omitempty"`
	// ExternalID is the OAuth provider's account UUID (e.g. Claude account.uuid).
	// Claude's OAuth injection needs it to build a valid metadata.user_id;
	// without it Claude returns a 429 business rejection. Codex uses AccountID
	// instead and Kimi needs neither, so this is only load-bearing for Claude
	// OAuth group accounts. Empty until master's N7a producer populates it.
	ExternalID string `json:"external_id,omitempty"`
	// KEY meta:
	BaseURL  string `json:"base_url,omitempty"`
	Revision string `json:"revision,omitempty"`
}
