// group_runtime.go — shared seat-group routing contracts (N8).
//
// Two JSON shapes the seat-group feature passes between components live here,
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
