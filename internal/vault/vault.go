package vault

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	_ "modernc.org/sqlite"
)

// ErrSecretNotFound is returned (wrapped) by GetSecret when the alias does not
// exist in the vault — a business condition the caller maps to "Run: aikey add".
// It is distinct from infrastructure errors (SQLITE_BUSY / IO / decrypt), which
// GetSecret wraps without this sentinel so callers can use errors.Is to tell
// "key truly missing" apart from "vault temporarily unavailable". Why this
// matters: without the split, a transient lock (Trial runs cli+proxy+server on
// one SQLite) would falsely tell the user to re-add an existing key.
var ErrSecretNotFound = errors.New("secret not found in vault")

// providerCodeAliases returns all lowercase aliases for a given provider code so
// that vault lookups match regardless of how the server stored the code
// (e.g. "Claude", "claude", or "anthropic" all refer to the same provider).
func providerCodeAliases(code string) []string {
	switch strings.ToLower(code) {
	case "anthropic", "claude":
		return []string{"anthropic", "claude"}
	case "openai", "gpt", "chatgpt":
		return []string{"openai", "gpt", "chatgpt"}
	case "google", "gemini":
		return []string{"google", "gemini"}
	default:
		return []string{strings.ToLower(code)}
	}
}

// Reader provides read-only access to the Rust-compatible AiKey vault.
type Reader struct {
	db         *sql.DB
	cache      *cache
	derivedKey []byte
}

// WithBusyTimeoutDSN appends the busy_timeout pragma to a vault DB path.
// Exported so other packages that open the SAME vault DB file by path (e.g.
// internal/quota WriteLocalUsage/WriteSubjects, internal/events) reuse the one
// busy_timeout convention — single source of truth, no raw opens of the vault file.
// (original doc continues below)
// WithBusyTimeoutDSN appends the busy_timeout pragma to a vault DB path,
// preserving any query params the path already carries. modernc.org/sqlite
// accepts `?_pragma=busy_timeout(5000)` (and `&_pragma=...` when other params
// are present). The vault path is normally a bare filesystem path, but we
// detect an existing `?` so callers passing a DSN don't get a malformed string.
func WithBusyTimeoutDSN(dbPath string) string {
	const pragma = "_pragma=busy_timeout(5000)"
	if strings.Contains(dbPath, "?") {
		return dbPath + "&" + pragma
	}
	return dbPath + "?" + pragma
}

// Open opens the vault database and verifies the password.
func Open(dbPath, password string) (*Reader, error) {
	// Open in read-write mode so the WAL reader can see latest CLI writes.
	// aikey-proxy does not write to the vault, but read-only mode on WAL
	// databases may return stale data if the WAL has not been checkpointed.
	//
	// busy_timeout(5000): on Trial the cli + proxy + server share one SQLite
	// file, so a transient SQLITE_BUSY can occur when the CLI holds a write
	// lock. The default modernc busy_timeout is 0 (fail immediately, no retry);
	// 5s lets a momentary lock retry instead of bubbling up as a spurious
	// vault error. modernc.org/sqlite honors `_pragma` DSN query params.
	db, err := sql.Open("sqlite", WithBusyTimeoutDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("open vault db: %w", err)
	}

	// Verify the database is accessible.
	if pingErr := db.Ping(); pingErr != nil {
		db.Close()
		return nil, fmt.Errorf("ping vault db: %w", pingErr)
	}

	// Read salt: try 'master_salt' first, fall back to 'salt'.
	salt, err := readConfigBlob(db, "master_salt")
	if err != nil {
		salt, err = readConfigBlob(db, "salt")
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("salt not found in vault (tried master_salt, salt): %w", err)
		}
	}

	// Read KDF parameters (fall back to defaults if not stored).
	mCost := readU32LEOrDefault(db, "kdf_m_cost", Argon2Memory)
	tCost := readU32LEOrDefault(db, "kdf_t_cost", Argon2Iterations)
	pCost := readU32LEOrDefault(db, "kdf_p_cost", Argon2Parallelism)

	slog.Debug("vault KDF params", "m_cost", mCost, "t_cost", tCost, "p_cost", pCost)

	// Derive key using Argon2id.
	derivedKey := DeriveKeyWithParams([]byte(password), salt, mCost, tCost, uint8(pCost)) //nolint:gosec // Argon2 parallelism is 1..255 (written as uint8 at vault creation)

	// Verify against stored password_hash.
	storedHash, err := readConfigBlob(db, "password_hash")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("password_hash not found in vault: %w", err)
	}

	if !VerifyKey(derivedKey, storedHash) {
		db.Close()
		return nil, fmt.Errorf("invalid master password")
	}

	slog.Info("vault opened successfully", "path", dbPath)

	return &Reader{
		db:         db,
		derivedKey: derivedKey,
		cache:      newCache(),
	}, nil
}

// DB returns the underlying database connection for constructing broker stores.
// The caller must not close this connection — it is owned by the Reader.
func (r *Reader) DB() *sql.DB { return r.db }

// DerivedKey returns the AES-256 key derived from the master password.
// Used by VaultTokenStore for token encryption.
func (r *Reader) DerivedKey() []byte { return r.derivedKey }

// GetLoggedInAccountID returns the account_id of the currently logged-in user
// from the platform_account table, or empty string if not logged in.
func (r *Reader) GetLoggedInAccountID() string {
	var accountID string
	err := r.db.QueryRow("SELECT account_id FROM platform_account WHERE id = 1").Scan(&accountID)
	if err != nil {
		return ""
	}
	return accountID
}

// GetPlatformRefreshToken returns the long-lived OAuth refresh_token
// for the currently-logged-in user, or "" if not logged in / row missing.
//
// 2026-05-11 (B4 phase): proxy needs this to bootstrap RefreshableJWT
// at startup so the team-route reporter can auto-renew the user JWT
// without going through the CLI. The column is stored plaintext in the
// vault SQLite file (matching aikey-cli's storage_platform.rs::
// save_oauth_session) — the vault file's on-disk protection is OS-level
// (~/.aikey/data perms), the same trust boundary CLI itself relies on.
//
// Why not encrypted with derivedKey: changing the storage shape would
// require a coordinated CLI + vault migration; refresh_token's at-rest
// protection currently rests on filesystem permissions, same as the
// access_token sitting next to it (jwt_token column). B4 doesn't
// expand that trust boundary — it just reads what's already there.
//
// Empty return means "no platform_account row yet" (pre-login) — caller
// treats as "no team-route credential available; fall back to legacy
// service_token if any, otherwise no auth header on uploads".
func (r *Reader) GetPlatformRefreshToken() (string, error) {
	var token sql.NullString
	err := r.db.QueryRow(
		"SELECT refresh_token FROM platform_account WHERE id = 1",
	).Scan(&token)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("query platform_account.refresh_token: %w", err)
	}
	if !token.Valid {
		// Row exists but column is NULL (legacy rows from pre-refresh CLI
		// versions). Same caller semantics as "not logged in".
		return "", nil
	}
	return token.String, nil
}

// GetSecret retrieves and decrypts a secret by its alias.
// Results are cached in memory for subsequent calls.
func (r *Reader) GetSecret(alias string) (string, error) {
	// Check cache first.
	if secret, ok := r.cache.get(alias); ok {
		return secret, nil
	}

	// Query from database.
	var nonce, ciphertext []byte
	err := r.db.QueryRow(
		"SELECT nonce, ciphertext FROM entries WHERE alias = ?", alias,
	).Scan(&nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		// Wrap the sentinel so callers can errors.Is(err, ErrSecretNotFound)
		// to distinguish "key truly missing" (→ aikey add) from infra errors
		// (BUSY/IO/decrypt → retry) below.
		return "", fmt.Errorf("secret %q: %w", alias, ErrSecretNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("query secret %q: %w", alias, err)
	}

	// Decrypt.
	plaintext, err := Decrypt(r.derivedKey, nonce, ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt secret %q: %w", alias, err)
	}

	secret := string(plaintext)
	r.cache.set(alias, secret)
	return secret, nil
}

// ListAliases returns all alias names in the vault.
func (r *Reader) ListAliases() ([]string, error) {
	rows, err := r.db.Query("SELECT alias FROM entries ORDER BY alias")
	if err != nil {
		return nil, fmt.Errorf("list aliases: %w", err)
	}
	defer rows.Close()

	var aliases []string
	for rows.Next() {
		var alias string
		if err := rows.Scan(&alias); err != nil {
			return nil, fmt.Errorf("scan alias: %w", err)
		}
		aliases = append(aliases, alias)
	}
	return aliases, rows.Err()
}

// ManagedKey holds a team-managed virtual key resolved from managed_virtual_keys_cache.
// The PlaintextKey field contains the decrypted real provider key; it must be
// treated with the same care as a regular vault secret.
type ManagedKey struct {
	VirtualKeyID string
	// LocalAlias is the user-facing name shown in `aikey list` for this team
	// key (e.g. `key-335923591-0011-1`). Stored in the
	// `managed_virtual_keys_cache.local_alias` column. May be empty for
	// historical rows that pre-date the column add.
	// 2026-05-09: surfaced into ManagedKey so routes carry it as KeyAlias and
	// receipt / WAL `key_label` shows the alias instead of the vk_id tail.
	LocalAlias   string
	ProviderCode string
	ProtocolType string
	BaseURL      string
	PlaintextKey string
	// ProviderBaseURLs maps provider_code → admin-configured upstream base URL for each
	// provider slot in the delivery payload. Use for path-prefix routing to get the
	// correct per-provider URL instead of only the primary slot URL.
	ProviderBaseURLs map[string]string

	// Anchor fields for usage reporting (D3 naming).
	OrgID              string
	SeatID             string
	CredentialID       string
	CredentialRevision string
	VirtualKeyRevision string
	OwnerAccountID     string

	// ── Oauth-group (channel ③) fields (N7c) ───────────────────────────────
	// Populated only for group VKs (binding.target = oauth_group). For these,
	// PlaintextKey is EMPTY — the real per-account material lives in GroupRuntime
	// and the route resolver (N8) picks a candidate account + injects its token.
	//
	// OauthGroupID != "" is the discriminator: empty = direct-bind VK (existing
	// path, byte-unchanged); non-empty = group VK.
	OauthGroupID string
	// GroupAccounts: the candidate account list JSON (structural, CLI-synced) —
	// [{account_id, identity, provider_code, priority, assigned}].
	GroupAccounts string
	// GroupRuntime: per-account token/key material JSON (channel ③, proxy-pulled,
	// encrypted at rest) — {account_id:{access_token ciphertext, expires, window}/
	// {key ciphertext, base_url, revision}}. NEVER refresh_token.
	GroupRuntime string
	// RoutingConfig: the group's routing knobs JSON (exhaustion_signals/util_cap/
	// ratios), structural-synced; the resolver reads it for classification.
	RoutingConfig string
	// MyAssignmentOverride: the engine's persisted seat→account routing assignment
	// for THIS VK's (seat, group) — {"account_id","blocked","routing_version",
	// "synced_at"} JSON, written by the routing_override SyncRail after each
	// successful pull and hydrated into the in-memory override cache at startup
	// (N12's persistence leg, completed 2026-07-03: without it a proxy restart
	// forgot the engine assignment and the local ranked pick could demand login
	// for an account the engine had routed the seat away from). Empty = no
	// persisted assignment (local ranked pick). CLI never touches this column
	// (fenced in its structural sync).
	MyAssignmentOverride string
}

// GetActiveManagedKeys reads all team keys from managed_virtual_keys_cache that
// are usable for routing — i.e. server says active, ciphertext downloaded, and
// not explicitly disabled or stale on the client side. Decrypts each provider
// key using the vault AES key derived at Open time.
//
// Why no local_state='active' gate (2026-05-09): the CLI never promotes a
// downloaded key to local_state='active' (set_virtual_key_local_state is only
// ever called with "stale"). The historical filter `local_state='active'`
// therefore matched zero rows in production, leaving the proxy's Tier1Team
// registry empty and every `aikey_team_<vk_id>` bearer 401-ing — even though
// claude/codex worked because they go through the Tier3-active-sentinel path
// which reads `user_profile_provider_bindings` and calls `GetTeamKeyByID`
// (which never had the local_state gate). This widens the registry to all
// usable team keys so connectivity probes (`aikey test`) and any direct
// `aikey_team_<vk_id>` bearer succeed consistently with claude's path. Bugfix:
// workflow/CI/bugfix/20260509-team-key-tier1-registry-empty.md.
//
// Keys that fail to decrypt are skipped with a warning (e.g. written by a
// different master password or corrupted data) so a single bad entry does not
// block the proxy from starting.
func (r *Reader) GetActiveManagedKeys() ([]ManagedKey, error) {
	// Try the group-aware query first (reads the oauth_group columns added by
	// N0/N6). Fall back to the legacy query on error — an older vault that lacks
	// those columns must still load its direct-bind keys, never lose all keys
	// over a missing column. Mirrors the CLI's column-cascade (storage_platform.rs).
	keys, err := r.queryManagedKeys(true)
	if err != nil {
		keys, err = r.queryManagedKeys(false)
		if err != nil {
			// Table missing on very old vaults — treat as empty, not an error.
			return nil, nil //nolint:nilerr // missing table → empty result, not a failure
		}
	}
	return keys, nil
}

// queryManagedKeys reads active managed keys. withGroup=true also selects the
// oauth-group columns (group VKs); false is the legacy shape for older vaults.
//
// 2026-05-09 alias surfacing: COALESCE(local_alias, alias) — the cache has two
// alias-like columns (`alias` server-canonical NOT NULL, `local_alias` nullable
// per-client rename overlay). Use local_alias when set, fall back to alias.
func (r *Reader) queryManagedKeys(withGroup bool) ([]ManagedKey, error) {
	groupCols := ""
	// Direct-bind keys require provider_key_ciphertext; group VKs have NONE
	// (material rides group_runtime), so when reading group columns we also admit
	// rows whose only target is a oauth_group.
	targetFilter := "provider_key_ciphertext IS NOT NULL"
	if withGroup {
		groupCols = ", oauth_group_id, group_accounts, group_runtime, routing_config, my_assignment_override"
		targetFilter = "(provider_key_ciphertext IS NOT NULL OR oauth_group_id IS NOT NULL)"
	}
	rows, err := r.db.Query(`
		SELECT virtual_key_id, COALESCE(NULLIF(local_alias, ''), alias) AS effective_alias,
		       provider_code, protocol_type, base_url,
		       provider_key_nonce, provider_key_ciphertext, provider_base_urls,
		       org_id, seat_id, credential_id, credential_revision,
		       virtual_key_revision, owner_account_id` + groupCols + `
		FROM managed_virtual_keys_cache
		WHERE key_status = 'active'
		  AND ` + targetFilter + `
		  AND COALESCE(local_state, '') != 'stale'
		  AND COALESCE(local_state, '') NOT LIKE 'disabled_by_%'
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []ManagedKey
	for rows.Next() {
		var vkID, provCode, protType, baseURL string
		var localAlias *string // nullable column on historical rows
		var nonce, ciphertext []byte
		var providerBaseURLsJSON *string
		var orgID, seatID, credID, credRev, vkRev string
		var ownerAccountID *string
		var oauthGroupID, groupAccounts, groupRuntime, routingConfig, myAssignmentOverride *string // group cols (nullable)

		dest := []any{&vkID, &localAlias, &provCode, &protType, &baseURL, &nonce, &ciphertext, &providerBaseURLsJSON,
			&orgID, &seatID, &credID, &credRev, &vkRev, &ownerAccountID}
		if withGroup {
			dest = append(dest, &oauthGroupID, &groupAccounts, &groupRuntime, &routingConfig, &myAssignmentOverride)
		}
		if err := rows.Scan(dest...); err != nil {
			slog.Warn("managed key: scan error, skipping", "error", err)
			continue
		}

		sgID := derefStr(oauthGroupID)
		// Direct-bind keys decrypt their provider_key_ciphertext. Group VKs have
		// NO ciphertext (material rides group_runtime, per-account) → skip decrypt,
		// leave PlaintextKey empty; the route resolver (N8) picks an account.
		var plaintextKey string
		if len(ciphertext) > 0 {
			plaintext, err := Decrypt(r.derivedKey, nonce, ciphertext)
			if err != nil {
				// 2026-05-11: ERROR (not WARN). A decrypt failure means this team
				// key was written with a vault_key that no longer matches the
				// current password_hash — requests via aikey_team_<vk_id> 401 with
				// no actionable signal. See
				// workflow/CI/bugfix/2026-05-11-team-key-decrypt-inconsistent.md.
				slog.Error(
					"managed key ciphertext was written with an inconsistent vault_key — proxy cannot decrypt. Recovery: aikey key sync --force-reencrypt",
					"event.name", "vault.managed_key.decrypt_inconsistent",
					"error.code", "VAULT_MANAGED_KEY_DECRYPT_INCONSISTENT",
					"vk_id", vkID,
					"error.message", err.Error(),
				)
				continue
			}
			plaintextKey = string(plaintext)
		} else if sgID == "" {
			// No ciphertext AND not a group VK — shouldn't pass the WHERE, but
			// guard: skip rather than register an empty-key route.
			continue
		}

		providerBaseURLs := make(map[string]string)
		if providerBaseURLsJSON != nil && *providerBaseURLsJSON != "" {
			_ = json.Unmarshal([]byte(*providerBaseURLsJSON), &providerBaseURLs)
		}
		keys = append(keys, ManagedKey{
			VirtualKeyID:       vkID,
			LocalAlias:         derefStr(localAlias),
			ProviderCode:       provCode,
			ProtocolType:       protType,
			BaseURL:            baseURL,
			PlaintextKey:       plaintextKey,
			ProviderBaseURLs:   providerBaseURLs,
			OrgID:              orgID,
			SeatID:             seatID,
			CredentialID:       credID,
			CredentialRevision: credRev,
			VirtualKeyRevision: vkRev,
			OwnerAccountID:     derefStr(ownerAccountID),
			OauthGroupID:        sgID,
			GroupAccounts:      derefStr(groupAccounts),
			GroupRuntime:         derefStr(groupRuntime),
			RoutingConfig:        derefStr(routingConfig),
			MyAssignmentOverride: derefStr(myAssignmentOverride),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("managed keys scan: %w", err)
	}
	return keys, nil
}

// derefStr returns the pointed-at string, or "" when nil (nullable columns).
func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// GetPersonalKeyByAlias returns the plaintext key, provider_code, and custom base_url
// for a personal key stored in the `entries` table.  Uses the derivedKey already held
// in memory from vault.Open — no additional authentication is needed.
//
// baseURL is empty when the user did not set a custom URL (proxy uses provider default).
// Returns an error if the entry is not found or decryption fails.
func (r *Reader) GetPersonalKeyByAlias(alias string) (plaintext, providerCode, baseURL string, err error) {
	var nonce, ciphertext []byte
	var code, url *string
	// base_url column was added in v0.7 — use a fallback query for older vaults.
	err = r.db.QueryRow(
		"SELECT nonce, ciphertext, provider_code, base_url FROM entries WHERE alias = ?", alias,
	).Scan(&nonce, &ciphertext, &code, &url)
	if err == sql.ErrNoRows {
		return "", "", "", fmt.Errorf("personal key %q not found in vault", alias)
	}
	if err != nil {
		// Retry without base_url for vaults that predate the column migration.
		var code2 *string
		err2 := r.db.QueryRow(
			"SELECT nonce, ciphertext, provider_code FROM entries WHERE alias = ?", alias,
		).Scan(&nonce, &ciphertext, &code2)
		if err2 != nil {
			return "", "", "", fmt.Errorf("query personal key %q: %w", alias, err2)
		}
		code = code2
	}

	plain, decErr := Decrypt(r.derivedKey, nonce, ciphertext)
	if decErr != nil {
		return "", "", "", fmt.Errorf("decrypt personal key %q: %w", alias, decErr)
	}

	if code != nil {
		providerCode = *code
	}
	if url != nil {
		baseURL = *url
	}
	return string(plain), providerCode, baseURL, nil
}

// AliasCredential is the result of a Probe-pipeline alias lookup. It carries
// a synthetic ProviderBinding that downstream credential resolution
// (proxy.ResolveBindingCredential) can consume identically to a real binding
// returned by GetProviderBindingWithScope.
//
// AliasKind is a logging/audit field — callers must NOT use it for control
// flow (the synthesized Binding.KeySourceType is authoritative).
//
// Status mirrors provider_accounts.status for OAuth rows; personal entries
// have no status column, so the loader sets "active" when the row exists.
// Callers map non-"active" status to HTTP errors (typically 403 with
// ALIAS_REVOKED / ALIAS_PAUSED reason codes).
type AliasCredential struct {
	Binding   *ProviderBinding
	Status    string // "active" | "revoked" | "paused" | ...
	AliasKind string // "personal" | "oauth" — audit/log only, not control flow
}

// GetAliasCredential resolves a probe URL alias (`/probe/<alias>/...`) to a
// synthetic ProviderBinding. See SPEC
// `workflow/CI/requirements/2026-05-23-credential-mode-architecture.md` §1.3
// for the Probe pipeline contract.
//
// Lookup order, first match wins:
//  1. entries.alias                       → personal API key
//  2. provider_accounts.local_alias       → OAuth account (user-renamed)
//  3. provider_accounts.display_identity  → OAuth account (original identity)
//
// Returns (nil, nil) when no row matches — caller maps to 404 ALIAS_NOT_FOUND.
// Returns ac with Status != "active" when a row exists but is unusable.
// Returns error only for infrastructure failures (DB unreachable, etc.).
//
// Why a synthetic ProviderBinding instead of a probe-only credential struct:
// downstream resolution (proxy.ResolveBindingCredential) is keyed on
// (KeySourceType, KeySourceRef) pairs mirroring the provider_bindings
// schema. Reusing that machinery means OAuth WAF fingerprint / personal-key
// decrypt / managed-key fetch logic is shared — Probe and App pipelines
// diverge only in how the binding was sourced, not in how it resolves to a
// usable plaintext credential.
func (r *Reader) GetAliasCredential(name string) (*AliasCredential, error) {
	if name == "" {
		return nil, nil
	}

	// 1. Personal entries lookup.
	var providerCode sql.NullString
	err := r.db.QueryRow(
		"SELECT provider_code FROM entries WHERE alias = ?", name,
	).Scan(&providerCode)
	switch {
	case err == nil:
		code := ""
		if providerCode.Valid {
			code = providerCode.String
		}
		return &AliasCredential{
			Binding: &ProviderBinding{
				ProviderCode:  code,
				KeySourceType: "personal",
				KeySourceRef:  name,
			},
			Status:    "active",
			AliasKind: "personal",
		}, nil
	case err == sql.ErrNoRows:
		// fall through to OAuth lookup
	default:
		return nil, fmt.Errorf("personal alias lookup %q: %w", name, err)
	}

	// 2 + 3. OAuth lookup. provider_accounts may not exist on pre-v1.0.3
	// vaults — treat as "no match".
	if !hasColumn(r.db, "provider_accounts", "provider_account_id") {
		return nil, nil
	}

	var (
		acctID, provider, status string
		hasLocalAlias            = hasColumn(r.db, "provider_accounts", "local_alias")
	)

	if hasLocalAlias {
		err = r.db.QueryRow(
			`SELECT provider_account_id, provider, status
			   FROM provider_accounts
			  WHERE local_alias = ? AND local_alias IS NOT NULL AND local_alias != ''
			  LIMIT 1`,
			name,
		).Scan(&acctID, &provider, &status)
		switch {
		case err == nil:
			return &AliasCredential{
				Binding: &ProviderBinding{
					ProviderCode:  provider,
					KeySourceType: "personal_oauth_account",
					KeySourceRef:  acctID,
				},
				Status:    status,
				AliasKind: "oauth",
			}, nil
		case err == sql.ErrNoRows:
			// fall through to display_identity
		default:
			return nil, fmt.Errorf("oauth local_alias lookup %q: %w", name, err)
		}
	}

	err = r.db.QueryRow(
		`SELECT provider_account_id, provider, status
		   FROM provider_accounts
		  WHERE display_identity = ?
		  LIMIT 1`,
		name,
	).Scan(&acctID, &provider, &status)
	switch {
	case err == nil:
		return &AliasCredential{
			Binding: &ProviderBinding{
				ProviderCode:  provider,
				KeySourceType: "personal_oauth_account",
				KeySourceRef:  acctID,
			},
			Status:    status,
			AliasKind: "oauth",
		}, nil
	case err == sql.ErrNoRows:
		return nil, nil
	default:
		return nil, fmt.Errorf("oauth display_identity lookup %q: %w", name, err)
	}
}

// ActiveKeyConfig represents the globally-active key selection written by `aikey use`.
// It mirrors the three config table rows: active_key_type, active_key_ref, active_key_providers.
type ActiveKeyConfig struct {
	// KeyType is "team", "personal", or "" (nothing active).
	KeyType string
	// KeyRef is the virtual_key_id (team) or alias (personal) of the active key.
	KeyRef string
	// Providers is the list of provider codes the active key supports (e.g. ["anthropic"]).
	Providers []string
}

// GetActiveKeyConfig reads the active key configuration from the config table.
// Returns nil if no key is currently active (active_key_type is missing or empty).
func (r *Reader) GetActiveKeyConfig() (*ActiveKeyConfig, error) {
	readText := func(key string) (string, error) {
		row := r.db.QueryRow("SELECT CAST(value AS TEXT) FROM config WHERE key = ?", key)
		var val string
		if err := row.Scan(&val); err == sql.ErrNoRows {
			return "", nil
		} else if err != nil {
			return "", fmt.Errorf("read config %q: %w", key, err)
		}
		return val, nil
	}

	keyType, err := readText("active_key_type")
	if err != nil {
		return nil, err
	}
	if keyType == "" {
		return nil, nil // no active key
	}

	keyRef, err := readText("active_key_ref")
	if err != nil {
		return nil, err
	}

	providersJSON, err := readText("active_key_providers")
	if err != nil {
		return nil, err
	}

	var providers []string
	if providersJSON != "" {
		if err := json.Unmarshal([]byte(providersJSON), &providers); err != nil {
			slog.Warn("vault: failed to decode active_key_providers", "error", err)
			providers = nil
		}
	}

	return &ActiveKeyConfig{
		KeyType:   keyType,
		KeyRef:    keyRef,
		Providers: providers,
	}, nil
}

// GetActiveTeamKeyByProvider returns the first usable decrypted team key for the
// given provider code. Used as a legacy fallback by the Tier3 active-sentinel
// path when `user_profile_provider_bindings` has no entry (pre-v1.0.2 vaults).
//
// Why no local_state='active' gate (2026-05-09): same reason as
// GetActiveManagedKeys — the CLI never promotes keys to that state, so the
// historical filter selected zero rows in production. The post-v1.0.2 routing
// path uses provider bindings + GetTeamKeyByID (which has no local_state gate),
// and this fallback now matches that semantic. Bugfix:
// workflow/CI/bugfix/20260509-team-key-tier1-registry-empty.md.
//
// LIMIT 1 picks an arbitrary row when multiple usable team keys exist for the
// same provider — acceptable because real routing always goes through the
// binding table; this fallback only fires for legacy vaults with one team key.
//
// Returns nil if no usable team key exists for that provider.
func (r *Reader) GetActiveTeamKeyByProvider(providerCode string) (*ManagedKey, error) {
	// Expand the provider code to all known aliases so that e.g. "anthropic"
	// also matches rows stored as "Claude" or "claude" by the server.
	aliases := providerCodeAliases(providerCode)
	placeholders := make([]string, len(aliases))
	args := make([]any, len(aliases))
	for i, a := range aliases {
		placeholders[i] = "?"
		args[i] = a
	}
	// 2026-05-09: include effective alias (COALESCE local_alias / alias) for
	// receipt / WAL surfacing of team key alias.
	// The only dynamic part of the query is the placeholder list ("?,?,...")
	// derived from len(aliases); all real values are bound via args, so this
	// concatenation carries no SQL-injection risk.
	const queryPrefix = `
		SELECT virtual_key_id,
		       COALESCE(NULLIF(local_alias, ''), alias) AS effective_alias,
		       provider_code, protocol_type, base_url,
		       provider_key_nonce, provider_key_ciphertext, provider_base_urls,
		       org_id, seat_id, owner_account_id
		FROM managed_virtual_keys_cache
		WHERE key_status = 'active'
		  AND provider_key_ciphertext IS NOT NULL
		  AND COALESCE(local_state, '') != 'stale'
		  AND COALESCE(local_state, '') NOT LIKE 'disabled_by_%'
		  AND LOWER(provider_code) IN (`
	const querySuffix = `)
		LIMIT 1
	`
	query := queryPrefix + strings.Join(placeholders, ",") + querySuffix
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, nil //nolint:nilerr // table may not exist on older vaults
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, rows.Err()
	}

	var vkID, effectiveAlias, provCode, protType, baseURL string
	var nonce, ciphertext []byte
	var providerBaseURLsJSON *string
	var orgID, seatID string
	var ownerAccountID *string
	if scanErr := rows.Scan(&vkID, &effectiveAlias, &provCode, &protType, &baseURL, &nonce, &ciphertext, &providerBaseURLsJSON,
		&orgID, &seatID, &ownerAccountID); scanErr != nil {
		return nil, fmt.Errorf("scan managed key: %w", scanErr)
	}

	plaintext, err := Decrypt(r.derivedKey, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt managed key %s: %w", vkID, err)
	}

	providerBaseURLs := make(map[string]string)
	if providerBaseURLsJSON != nil && *providerBaseURLsJSON != "" {
		_ = json.Unmarshal([]byte(*providerBaseURLsJSON), &providerBaseURLs)
	}

	var accountID string
	if ownerAccountID != nil {
		accountID = *ownerAccountID
	}

	return &ManagedKey{
		VirtualKeyID:     vkID,
		LocalAlias:       effectiveAlias,
		ProviderCode:     provCode,
		ProtocolType:     protType,
		BaseURL:          baseURL,
		PlaintextKey:     string(plaintext),
		OrgID:            orgID,
		SeatID:           seatID,
		OwnerAccountID:   accountID,
		ProviderBaseURLs: providerBaseURLs,
	}, nil
}

// GetTeamKeyByID returns the decrypted team key for a specific virtual_key_id.
// Unlike GetActiveTeamKeyByProvider, this does not filter by local_state — the
// provider binding already tells us which key to use.
// Returns nil if the key is not found or has no ciphertext.
func (r *Reader) GetTeamKeyByID(virtualKeyID string) (*ManagedKey, error) {
	var provCode, protType, baseURL, effectiveAlias string
	var nonce, ciphertext []byte
	var providerBaseURLsJSON *string
	var orgID, seatID string
	var ownerAccountID *string

	// 2026-05-09: include effective alias (COALESCE local_alias / alias) so
	// route's KeyAlias surfaces in WAL `key_label` and statusline receipt.
	// Hot path (binding-driven team-key fetch) — without this column, the
	// receipt falls back to the vk_id tail.
	err := r.db.QueryRow(`
		SELECT provider_code, protocol_type, base_url,
		       COALESCE(NULLIF(local_alias, ''), alias) AS effective_alias,
		       provider_key_nonce, provider_key_ciphertext, provider_base_urls,
		       org_id, seat_id, owner_account_id
		FROM managed_virtual_keys_cache
		WHERE virtual_key_id = ?
		  AND key_status = 'active'
		  AND provider_key_ciphertext IS NOT NULL
	`, virtualKeyID).Scan(
		&provCode, &protType, &baseURL, &effectiveAlias, &nonce, &ciphertext, &providerBaseURLsJSON,
		&orgID, &seatID, &ownerAccountID,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		// Table may not exist on older vaults.
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, fmt.Errorf("query team key %q: %w", virtualKeyID, err)
	}

	plaintext, decErr := Decrypt(r.derivedKey, nonce, ciphertext)
	if decErr != nil {
		// 2026-05-11: binding-driven team-key path (proxy.go:760). Surface
		// an actionable ERROR so users hitting the path-prefix Tier-3
		// fallthrough (e.g. `claude` runtime via the wrapper) see how to
		// recover. The caller still receives an error so the higher-level
		// route resolution short-circuits as before — this log is purely
		// for visibility into a state that was previously silent.
		slog.Error(
			"managed key ciphertext was written with an inconsistent vault_key — proxy cannot decrypt. Recovery: aikey key sync --force-reencrypt",
			"event.name", "vault.managed_key.decrypt_inconsistent",
			"error.code", "VAULT_MANAGED_KEY_DECRYPT_INCONSISTENT",
			"vk_id", virtualKeyID,
			"error.message", decErr.Error(),
		)
		return nil, fmt.Errorf("decrypt team key %s: %w", virtualKeyID, decErr)
	}

	providerBaseURLs := make(map[string]string)
	if providerBaseURLsJSON != nil && *providerBaseURLsJSON != "" {
		_ = json.Unmarshal([]byte(*providerBaseURLsJSON), &providerBaseURLs)
	}

	var accountID string
	if ownerAccountID != nil {
		accountID = *ownerAccountID
	}

	return &ManagedKey{
		VirtualKeyID:     virtualKeyID,
		LocalAlias:       effectiveAlias,
		ProviderCode:     provCode,
		ProtocolType:     protType,
		BaseURL:          baseURL,
		PlaintextKey:     string(plaintext),
		OrgID:            orgID,
		SeatID:           seatID,
		OwnerAccountID:   accountID,
		ProviderBaseURLs: providerBaseURLs,
	}, nil
}

// ProviderBinding represents a row from user_profile_provider_bindings (v1.0.2).
// It maps a provider to the key source that is currently Primary for the
// addressed profile scope.
//
// Possible KeySourceType values (matches aikey-cli's CredentialType enum):
//   - "personal"               — entries.alias (API key)
//   - "team"                   — managed_virtual_keys_cache.virtual_key_id
//   - "personal_oauth_account" — provider_accounts.provider_account_id (OAuth)
//
// The legacy short forms ("personal" / "team") are the canonical strings
// written by the CLI; "personal_api_key" / "managed_virtual_key" are
// accepted on read but never produced.
type ProviderBinding struct {
	ProviderCode  string
	KeySourceType string
	KeySourceRef  string // alias (personal) / virtual_key_id (team) / provider_account_id (oauth)
}

// GetProviderBinding reads the current provider binding for the given
// provider in the implicit default profile (`profile_id = 'default'`).
// Returns nil if no binding exists or the table does not exist.
//
// Kept as a thin wrapper over GetProviderBindingWithScope so the three
// existing callers in the proxy package (proxy/proxy.go:702 and the
// dispatch/middleware references) don't need to change signature.
func (r *Reader) GetProviderBinding(providerCode string) (*ProviderBinding, error) {
	return r.GetProviderBindingWithScope("default", providerCode)
}

// GetProviderBindingWithScope reads the provider binding for the given
// (profileID, providerCode) tuple. Returns nil if no binding exists or
// the table does not exist (pre-v1.0.2 vaults).
//
// profileID is `"default"` for the implicit user profile (legacy default
// behavior) or `"app:<slug>"` for the third-party app pipeline (Phase 4).
// The schema for `user_profile_provider_bindings.profile_id` is TEXT with
// no enum constraint, so any string value is structurally valid — the
// `app:` prefix is a writer-side convention enforced by `aikey app
// authorize`, not by SQL.
func (r *Reader) GetProviderBindingWithScope(profileID, providerCode string) (*ProviderBinding, error) {
	var sourceType, sourceRef string
	err := r.db.QueryRow(
		`SELECT key_source_type, key_source_ref
		   FROM user_profile_provider_bindings
		  WHERE profile_id = ? AND provider_code = ?`,
		profileID, providerCode,
	).Scan(&sourceType, &sourceRef)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		// Table may not exist on pre-v1.0.2 vaults — treat as "no binding".
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, fmt.Errorf("read provider binding for profile=%q provider=%q: %w", profileID, providerCode, err)
	}
	return &ProviderBinding{
		ProviderCode:  providerCode,
		KeySourceType: sourceType,
		KeySourceRef:  sourceRef,
	}, nil
}

// Close releases resources and clears cached secrets.
func (r *Reader) Close() error {
	r.cache.clear()
	// Wipe the derived key.
	for i := range r.derivedKey {
		r.derivedKey[i] = 0
	}
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

// readConfigBlob reads a BLOB value from the config table.
func readConfigBlob(db *sql.DB, key string) ([]byte, error) {
	var value []byte
	err := db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&value)
	if err != nil {
		return nil, err
	}
	return value, nil
}

// readU32LEOrDefault reads a little-endian uint32 from config, or returns the default.
func readU32LEOrDefault(db *sql.DB, key string, defaultVal uint32) uint32 {
	b, err := readConfigBlob(db, key)
	if err != nil {
		return defaultVal
	}
	v, err := ParseU32LE(b)
	if err != nil {
		return defaultVal
	}
	return v
}

// ReadConfigU64LE reads a uint64 stored as an 8-byte little-endian BLOB from
// the vault config table.  Returns 0 if the key is absent or the vault does
// not yet exist.  Opens a fresh read-write connection so callers do not need
// an existing Reader (e.g. the Supervisor calling this before vault.Open).
func ReadConfigU64LE(dbPath, key string) (uint64, error) {
	db, err := sql.Open("sqlite", WithBusyTimeoutDSN(dbPath))
	if err != nil {
		return 0, fmt.Errorf("open vault db for config read: %w", err)
	}
	defer db.Close()

	var value []byte
	err = db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read config key %q: %w", key, err)
	}
	if len(value) != 8 {
		return 0, fmt.Errorf("config key %q has unexpected length %d", key, len(value))
	}
	v := uint64(value[0]) | uint64(value[1])<<8 | uint64(value[2])<<16 | uint64(value[3])<<24 |
		uint64(value[4])<<32 | uint64(value[5])<<40 | uint64(value[6])<<48 | uint64(value[7])<<56
	return v, nil
}

// ReadConfigString reads a string value (stored as a UTF-8 BLOB) from the vault
// config table. Returns "" if the key is absent or the vault does not yet
// exist. Opens a fresh connection so the Supervisor can call it before
// vault.Open (same contract as ReadConfigU64LE). Used to read
// runtime.source_identity for delivery-integrity event stamping — written by
// the CLI side (storage.rs SOURCE_IDENTITY_KEY).
func ReadConfigString(dbPath, key string) (string, error) {
	db, err := sql.Open("sqlite", WithBusyTimeoutDSN(dbPath))
	if err != nil {
		return "", fmt.Errorf("open vault db for config read: %w", err)
	}
	defer db.Close()

	var value string
	err = db.QueryRow("SELECT CAST(value AS TEXT) FROM config WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read config key %q: %w", key, err)
	}
	return value, nil
}

// ---------------------------------------------------------------------------
// Route token reading (personal keys and OAuth accounts)
// ---------------------------------------------------------------------------

// ErrMissingRouteTokenColumn indicates the vault has not been migrated to
// include the route_token column.  Callers should degrade gracefully (skip
// personal/OAuth route token loading) rather than failing.
var ErrMissingRouteTokenColumn = fmt.Errorf("vault: route_token column not found, run CLI to migrate")

// PersonalRouteToken represents a personal key's route token for Registry registration.
type PersonalRouteToken struct {
	Alias        string
	RouteToken   string
	ProviderCode string
	BaseURL      string // custom base URL (may be empty)
}

// OAuthRouteToken represents an OAuth account's route token for Registry registration.
type OAuthRouteToken struct {
	AccountID  string
	RouteToken string
	Provider   string
	Identity   string // display identity (email or display name)
}

// hasColumn checks if a column exists on a table (via PRAGMA table_info).
func hasColumn(db *sql.DB, table, column string) bool {
	var count int
	err := db.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name=?", table), column,
	).Scan(&count)
	return err == nil && count > 0
}

// GetAllPersonalRouteTokens returns all personal key entries that have a
// non-NULL route_token.  Returns ErrMissingRouteTokenColumn if the column
// does not exist (old vault not yet migrated by CLI).
//
// Form filter (third-party review #4 [低], 2026-04-29): rows whose route_token
// is NOT a strict `aikey_personal_<64-lowercase-hex>` are skipped with a
// warn log. Why: post-migration the registry must only contain new-form
// bearers; pre-migration vaults that haven't run the CLI's v1.0.5-alpha
// upgrade yet may still hold `aikey_vk_*` or other legacy strings. Without
// this filter those would land in the registry, where ClassifyToken would
// later reject them at request time — but that means the user sees
// inscrutable 401s instead of a clean startup warning. Filtering at load
// surfaces the issue early and keeps the registry's invariant intact:
// "after proxy startup the registry only sees aikey_team_* and
// aikey_personal_<64-hex>" (主方案 §validation).
func (r *Reader) GetAllPersonalRouteTokens() ([]PersonalRouteToken, error) {
	if !hasColumn(r.db, "entries", "route_token") {
		return nil, ErrMissingRouteTokenColumn
	}

	rows, err := r.db.Query(
		"SELECT alias, route_token, provider_code, base_url FROM entries WHERE route_token IS NOT NULL",
	)
	if err != nil {
		return nil, fmt.Errorf("query personal route tokens: %w", err)
	}
	defer rows.Close()

	var result []PersonalRouteToken
	for rows.Next() {
		var t PersonalRouteToken
		var code, url *string
		if err := rows.Scan(&t.Alias, &t.RouteToken, &code, &url); err != nil {
			slog.Warn("skip personal route token row", "error", err)
			continue
		}
		if !isStrictPersonalBearerForm(t.RouteToken) {
			slog.Warn("skip personal route token: non-strict form (likely legacy aikey_vk_* or pre-migration residue)",
				"alias", t.Alias,
				"route_token_prefix", routeTokenPrefixForLog(t.RouteToken),
				"hint", "run `aikey db upgrade` to migrate vault.db to v1.0.5-alpha")
			continue
		}
		if code != nil {
			t.ProviderCode = *code
		}
		if url != nil {
			t.BaseURL = *url
		}
		result = append(result, t)
	}
	return result, rows.Err()
}

// GetAllOAuthRouteTokens returns all active OAuth accounts that have a
// non-NULL route_token.  Returns ErrMissingRouteTokenColumn if the column
// does not exist.
func (r *Reader) GetAllOAuthRouteTokens() ([]OAuthRouteToken, error) {
	// provider_accounts table may not exist (v1.0.3+ only).
	if !hasColumn(r.db, "provider_accounts", "provider_account_id") {
		return nil, nil // no table = no accounts, not an error
	}
	if !hasColumn(r.db, "provider_accounts", "route_token") {
		return nil, ErrMissingRouteTokenColumn
	}

	rows, err := r.db.Query(
		"SELECT provider_account_id, route_token, provider, display_identity " +
			"FROM provider_accounts WHERE route_token IS NOT NULL AND status = 'active'",
	)
	if err != nil {
		return nil, fmt.Errorf("query oauth route tokens: %w", err)
	}
	defer rows.Close()

	var result []OAuthRouteToken
	for rows.Next() {
		var t OAuthRouteToken
		var identity *string
		if err := rows.Scan(&t.AccountID, &t.RouteToken, &t.Provider, &identity); err != nil {
			slog.Warn("skip oauth route token row", "error", err)
			continue
		}
		if !isStrictPersonalBearerForm(t.RouteToken) {
			// Same form filter as GetAllPersonalRouteTokens — see that
			// function's docstring for rationale (third-party review #4 [低]).
			slog.Warn("skip oauth route token: non-strict form (likely legacy aikey_vk_* or pre-migration residue)",
				"account_id", t.AccountID,
				"route_token_prefix", routeTokenPrefixForLog(t.RouteToken),
				"hint", "run `aikey db upgrade` to migrate vault.db to v1.0.5-alpha")
			continue
		}
		if identity != nil {
			t.Identity = *identity
		}
		result = append(result, t)
	}
	return result, rows.Err()
}

// ---------------------------------------------------------------------------
// App pipeline (third-party Agent 接入, Phase 4) — read paths.
// ---------------------------------------------------------------------------
//
// Two tables are added to the vault schema by aikey-cli's baseline migration
// (src/migrations.rs v1_0_0_baseline.upgrade() tail block, 2026-05-20):
//
//   - app_records — application metadata (slug / name / vendor / declared
//     protocol set / app_kind / follow_user_active). One row per installed
//     app. Written by `aikey app register`.
//
//   - app_keys — issued credentials (route_token plaintext, key_id, status,
//     timestamps). Multiple rows per slug allowed (rotation history). Written
//     by `aikey app authorize` / `rotate`.
//
// Why route_token is stored plaintext (not hash) — same rationale as
// entries.route_token and provider_accounts.route_token: aikey-proxy's
// vkeys.Registry byToken map keys by the plaintext bearer that arrives
// in the Authorization header, so any hash would prevent lookup. The
// vault file itself is Argon2id + AES-256-GCM encrypted, so plaintext
// inside the encrypted blob is the same protection envelope.
//
// Day 2 spike verified this against the existing Registry implementation:
// roadmap20260320/技术实现/阶段4-增值版/2026-05-20-Phase0-spike-day2.md §3.

// AppRecord represents a row from app_records — the metadata side of an
// installed third-party Agent. No credentials live here; tokens are in
// app_keys.
//
// B-mode fields (2026-05-23, credential-mode-architecture SPEC §3.1):
// BoundAlias + BoundAt carry the snapshotted credential identity for
// "init_from_user_active" mode. When BoundAlias is non-empty, the App
// pipeline resolves credentials via GetAliasCredential(BoundAlias)
// instead of looking up the user's current active binding — making the
// app's identity sticky across later `aikey use` changes. See SPEC §1.1
// for the A vs B mode contract; mutex with FollowUserActive is
// enforced at the writer side (aikey-cli migrations + `aikey app create`).
type AppRecord struct {
	Slug                 string
	Name                 string
	Vendor               string
	AppKind              string   // "third-party" | "first-party"
	BoundAlias           string   // "" = not in B mode (use FollowUserActive)
	Upstreams            []string // decoded from JSON column
	RequestedPermissions []string // decoded from JSON column (nil if NULL)
	BoundAt              int64    // 0 when BoundAlias is unset
	CreatedAt            int64
	UpdatedAt            int64
	FollowUserActive     bool
}

// GetSlug returns the app slug. Implemented as a method (not just a
// field accessor) so *AppRecord directly satisfies the anonymous
// `interface { GetSlug() string }` declared in the observer
// framework's pkg/observer.VaultGetter — letting the proxy pass
// *AppRecord through to the observer's enable-check predicate without
// a wrapper struct.
func (a *AppRecord) GetSlug() string { return a.Slug }

// AppRouteToken is the joined view of app_keys × app_records used by the
// supervisor to populate the registry. It carries both the credential
// (RouteToken) and the metadata fields the App pipeline needs at request
// time (AppKind / FollowUserActive / AllowedUpstreams) without forcing a
// second DB hit per request.
//
// RouteToken is plaintext — see package doc for the rationale. Callers
// MUST NOT log this struct via "%v" / "%+v" / fmt.Sprintf or pass it
// directly to slog; use the LogValue method or extract non-secret fields
// explicitly. The redaction is enforced by the LogValue receiver below.
type AppRouteToken struct {
	KeyID            string
	AppSlug          string
	RouteToken       string // ★ plaintext aikey_app_<64hex>
	Status           string // "active" (loader only returns active)
	AppKind          string
	AllowedUpstreams []string
	FollowUserActive bool
}

// LogValue implements slog.LogValuer to redact the plaintext RouteToken
// from any log line that uses this value (or a slice of it) as an
// attribute. Critical R6-mitigation per Day 3 spike report §6 — without
// this, the routine vault loader trace logging would dump every app
// token to disk.
func (t AppRouteToken) LogValue() slog.Value { //nolint:gocritic // value receiver required: a pointer receiver makes slog skip LogValuer on value attrs and leak the plaintext token (security)
	return slog.GroupValue(
		slog.String("key_id", t.KeyID),
		slog.String("app_slug", t.AppSlug),
		slog.String("route_token_prefix", routeTokenPrefixForLog(t.RouteToken)),
		slog.String("status", t.Status),
		slog.String("app_kind", t.AppKind),
		slog.Bool("follow_user_active", t.FollowUserActive),
		slog.Any("allowed_upstreams", t.AllowedUpstreams),
	)
}

// HasFilterAppsRegistered reports whether any row in `app_records` has a
// non-NULL `filter_stages` column — i.e. one or more apps declared the
// E-mode (sync_filter) contract. Used by the proxy at startup to decide
// whether to fail-loud (P3 step 5) since the actual filter dispatcher
// is not implemented until P4 (SPEC §1.5.7).
//
// Returns (false, nil) on pre-P3 vaults (column missing) — that's a
// "no filter apps" state, the proxy serves traffic normally.
func (r *Reader) HasFilterAppsRegistered() (bool, error) {
	if !hasColumn(r.db, "app_records", "filter_stages") {
		return false, nil
	}
	var n int
	err := r.db.QueryRow(
		`SELECT COUNT(*) FROM app_records WHERE filter_stages IS NOT NULL`,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("count filter_stages rows: %w", err)
	}
	return n > 0, nil
}

// GetFilterAppSlugs returns the slugs of apps that declared a non-NULL
// `filter_stages` (i.e. registered as a filter/DLP app via `aikey app install`).
// The supervisor resolves each slug's installed binary by convention
// (<apps_dir>/<slug>/bin/<slug>) and spawns it. Empty when none / the column is
// absent. Multiple rows per slug (rotation history) are de-duplicated.
func (r *Reader) GetFilterAppSlugs() ([]string, error) {
	if !hasColumn(r.db, "app_records", "filter_stages") {
		return nil, nil
	}
	rows, err := r.db.Query(
		`SELECT DISTINCT slug FROM app_records WHERE filter_stages IS NOT NULL`,
	)
	if err != nil {
		return nil, fmt.Errorf("query filter_stages slugs: %w", err)
	}
	defer rows.Close()
	var slugs []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan filter slug: %w", err)
		}
		if s != "" {
			slugs = append(slugs, s)
		}
	}
	return slugs, rows.Err()
}

// GetFilterRecordAllow reports whether the given filter app has
// filter_record_allow=1 — the settings-page "record allow events" toggle. The
// supervisor passes this to the detector child as AIKEY_COMPLIANCE_RECORD_ALLOW
// so it can drop clean "allow" scans at source. Returns false (the default) when
// the column is absent (pre-flag vaults) or the row is 0/NULL/missing.
func (r *Reader) GetFilterRecordAllow(slug string) (bool, error) {
	if !hasColumn(r.db, "app_records", "filter_record_allow") {
		return false, nil
	}
	var v sql.NullInt64
	err := r.db.QueryRow(
		`SELECT filter_record_allow FROM app_records WHERE slug = ? LIMIT 1`, slug,
	).Scan(&v)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read filter_record_allow for %q: %w", slug, err)
	}
	return v.Valid && v.Int64 != 0, nil
}

// ObserveSubscription is one parsed entry from `app_records.observe_streams`.
// SPEC §1.4.3 allows both simple-string and object-form JSON elements;
// this flat view normalises both:
//
//	["user_chat"]
//	  → ObserveSubscription{Slug:"...", Stream:"user_chat", PayloadLevel:"metadata"}
//
//	[{"stream":"user_chat","payload_level":"full"}]
//	  → ObserveSubscription{Slug:"...", Stream:"user_chat", PayloadLevel:"full"}
//
// PayloadLevel defaults to "metadata" when the input is a bare string
// (per SPEC §1.4.2: full is opt-in via object form + consent fields).
type ObserveSubscription struct {
	Slug         string
	Stream       string
	PayloadLevel string // "metadata" | "full"
}

// ListObserveSubscriptions scans `app_records` for non-NULL observe_streams
// and returns the flattened (slug, stream, level) view. Used by the
// ndjson-fanout observer at Build time to construct its per-subscriber
// routing table.
//
// Returns nil + nil on pre-P3 vaults (column missing) so the observer can
// noop gracefully. Per-row JSON decode failures are logged WARN and
// skipped — one malformed row must not silence the rest of the table.
func (r *Reader) ListObserveSubscriptions() ([]ObserveSubscription, error) {
	// Pre-P3 vault has no observe_streams column; treat as "no subscribers".
	if !hasColumn(r.db, "app_records", "observe_streams") {
		return nil, nil
	}

	rows, err := r.db.Query(
		`SELECT slug, observe_streams FROM app_records WHERE observe_streams IS NOT NULL`,
	)
	if err != nil {
		return nil, fmt.Errorf("list observe subscriptions: %w", err)
	}
	defer rows.Close()

	var out []ObserveSubscription
	for rows.Next() {
		var slug, raw string
		if err := rows.Scan(&slug, &raw); err != nil {
			slog.Warn("vault: skip observe_streams row (scan failed)",
				"error", err)
			continue
		}
		subs, err := parseObserveStreamsJSON(slug, raw)
		if err != nil {
			slog.Warn("vault: observe_streams JSON decode failed; row skipped",
				"slug", slug,
				"raw", raw,
				"error", err)
			continue
		}
		out = append(out, subs...)
	}
	return out, rows.Err()
}

// parseObserveStreamsJSON decodes one row's observe_streams column into
// flat ObserveSubscription entries. Handles both SPEC §1.4.3 shapes
// AND a mixed array (e.g. `["user_chat", {"stream":"probe","payload_level":"full"}]`)
// — we parse as []json.RawMessage and try string-then-object per element,
// so authoring tools that emit either form interop cleanly.
func parseObserveStreamsJSON(slug, raw string) ([]ObserveSubscription, error) {
	if raw == "" {
		return nil, nil
	}
	var elements []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &elements); err != nil {
		return nil, fmt.Errorf("not a JSON array: %w", err)
	}
	out := make([]ObserveSubscription, 0, len(elements))
	for _, el := range elements {
		// Try the simple-string form first (most common, set by
		// `aikey app create --observe <stream>` and by
		// ensure_first_party_app_keys for degrade-detector).
		var s string
		if err := json.Unmarshal(el, &s); err == nil {
			out = append(out, ObserveSubscription{
				Slug:         slug,
				Stream:       s,
				PayloadLevel: "metadata",
			})
			continue
		}
		// Fall back to object form (opt-in payload_level=full path).
		var obj struct {
			Stream       string `json:"stream"`
			PayloadLevel string `json:"payload_level"`
		}
		if err := json.Unmarshal(el, &obj); err != nil {
			return nil, fmt.Errorf("element neither string nor object: %s", string(el))
		}
		if obj.Stream == "" {
			return nil, fmt.Errorf("object element missing 'stream' field: %s", string(el))
		}
		level := obj.PayloadLevel
		if level == "" {
			level = "metadata"
		}
		out = append(out, ObserveSubscription{
			Slug:         slug,
			Stream:       obj.Stream,
			PayloadLevel: level,
		})
	}
	return out, nil
}

// GetAppRecord reads a single application's metadata by slug. Returns nil
// if the row does not exist or the app_records table is absent
// (pre-Phase-4 vault). Used by the App pipeline per request to enforce
// upstream-set whitelist (inferred upstream must be in app.Upstreams).
//
// Backward compat (2026-05-23): bound_alias / bound_at were added by the
// P2 migration; older vault files lack the columns. We attempt the
// extended SELECT first and fall back to the legacy 9-column SELECT
// when SQLite reports "no such column" — same pattern used by
// GetPersonalKeyByAlias for entries.base_url retrofit.
func (r *Reader) GetAppRecord(slug string) (*AppRecord, error) {
	var (
		rec                 AppRecord
		protocolsJSON       string
		requestedPermsJSON  *string
		vendor              *string
		followUserActiveInt int
		boundAlias          *string
		boundAt             *int64
	)
	err := r.db.QueryRow(
		`SELECT slug, name, vendor, upstreams, app_kind, follow_user_active,
		        bound_alias, bound_at,
		        requested_permissions, created_at, updated_at
		   FROM app_records
		  WHERE slug = ?`,
		slug,
	).Scan(
		&rec.Slug,
		&rec.Name,
		&vendor,
		&protocolsJSON,
		&rec.AppKind,
		&followUserActiveInt,
		&boundAlias,
		&boundAt,
		&requestedPermsJSON,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil // pre-Phase-4 vault — no apps
		}
		if strings.Contains(err.Error(), "no such column") {
			// Pre-2026-05-23 vault without bound_alias / bound_at. Fall back
			// to the legacy SELECT — BoundAlias stays "" so the App pipeline
			// keeps using A mode (follow_user_active) for these legacy rows.
			return r.getAppRecordLegacyShape(slug)
		}
		return nil, fmt.Errorf("read app record for slug=%q: %w", slug, err)
	}
	if vendor != nil {
		rec.Vendor = *vendor
	}
	rec.FollowUserActive = followUserActiveInt != 0
	if boundAlias != nil {
		rec.BoundAlias = *boundAlias
	}
	if boundAt != nil {
		rec.BoundAt = *boundAt
	}
	if err := json.Unmarshal([]byte(protocolsJSON), &rec.Upstreams); err != nil {
		return nil, fmt.Errorf("decode app_records.upstreams for slug=%q: %w", slug, err)
	}
	if requestedPermsJSON != nil && *requestedPermsJSON != "" {
		if err := json.Unmarshal([]byte(*requestedPermsJSON), &rec.RequestedPermissions); err != nil {
			// Soft fail — requested_permissions is informational only, not
			// runtime-enforced. Log + continue.
			slog.Warn("app_records.requested_permissions decode failed; treating as empty",
				"slug", slug, "error", err)
		}
	}
	return &rec, nil
}

// getAppRecordLegacyShape is the pre-2026-05-23 fallback when the vault
// hasn't been migrated to add bound_alias / bound_at columns yet. Mirrors
// the main reader, but selects the 9-column shape.
func (r *Reader) getAppRecordLegacyShape(slug string) (*AppRecord, error) {
	var (
		rec                 AppRecord
		protocolsJSON       string
		requestedPermsJSON  *string
		vendor              *string
		followUserActiveInt int
	)
	err := r.db.QueryRow(
		`SELECT slug, name, vendor, upstreams, app_kind, follow_user_active,
		        requested_permissions, created_at, updated_at
		   FROM app_records
		  WHERE slug = ?`,
		slug,
	).Scan(
		&rec.Slug,
		&rec.Name,
		&vendor,
		&protocolsJSON,
		&rec.AppKind,
		&followUserActiveInt,
		&requestedPermsJSON,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read app record (legacy shape) for slug=%q: %w", slug, err)
	}
	if vendor != nil {
		rec.Vendor = *vendor
	}
	rec.FollowUserActive = followUserActiveInt != 0
	if err := json.Unmarshal([]byte(protocolsJSON), &rec.Upstreams); err != nil {
		return nil, fmt.Errorf("decode app_records.upstreams for slug=%q: %w", slug, err)
	}
	if requestedPermsJSON != nil && *requestedPermsJSON != "" {
		if err := json.Unmarshal([]byte(*requestedPermsJSON), &rec.RequestedPermissions); err != nil {
			slog.Warn("app_records.requested_permissions decode failed; treating as empty",
				"slug", slug, "error", err)
		}
	}
	return &rec, nil
}

// GetAllAppRouteTokens returns all currently active app tokens joined with
// their app_records metadata. Used by the supervisor at startup / restart
// to populate vkeys.Registry's byToken map with app routes. Returns an
// empty slice (not an error) if either table is absent (pre-Phase-4 vault).
//
// Form filter mirrors the personal / OAuth loaders: rows whose route_token
// is not a strict `aikey_app_<64-hex>` are skipped with a WARN log rather
// than aborting the load. Why: surfaces malformed writer-side bugs early
// (clean startup warning instead of opaque 401s at request time) while
// keeping the registry's invariant intact (registry only ever sees strict
// Tier1 forms post-startup; see 主方案 §validation).
func (r *Reader) GetAllAppRouteTokens() ([]AppRouteToken, error) {
	// app_records may not exist on pre-Phase-4 vaults — treat as no apps.
	if !hasColumn(r.db, "app_records", "slug") {
		return nil, nil
	}
	if !hasColumn(r.db, "app_keys", "route_token") {
		return nil, nil
	}

	rows, err := r.db.Query(
		`SELECT k.key_id, k.app_slug, k.route_token, k.status,
		        r.app_kind, r.follow_user_active, r.upstreams
		   FROM app_keys k
		   JOIN app_records r ON r.slug = k.app_slug
		  WHERE k.status = 'active'
		    AND (k.expires_at IS NULL OR k.expires_at > strftime('%s','now'))`,
	)
	if err != nil {
		return nil, fmt.Errorf("query app route tokens: %w", err)
	}
	defer rows.Close()

	var result []AppRouteToken
	for rows.Next() {
		var (
			t                   AppRouteToken
			followUserActiveInt int
			protocolsJSON       string
		)
		if err := rows.Scan(
			&t.KeyID, &t.AppSlug, &t.RouteToken, &t.Status,
			&t.AppKind, &followUserActiveInt, &protocolsJSON,
		); err != nil {
			slog.Warn("skip app route token row", "error", err)
			continue
		}
		if !isStrictAppBearerForm(t.RouteToken) && !isFirstPartyAppBearer(t.RouteToken) {
			slog.Warn("skip app route token: non-strict form (writer-side bug or hand-crafted vault row)",
				"app_slug", t.AppSlug,
				"key_id", t.KeyID,
				"route_token_prefix", routeTokenPrefixForLog(t.RouteToken),
				"hint", "expected aikey_app_<64 lowercase hex> or first-party whitelist entry")
			continue
		}
		t.FollowUserActive = followUserActiveInt != 0
		if err := json.Unmarshal([]byte(protocolsJSON), &t.AllowedUpstreams); err != nil {
			slog.Warn("skip app route token: upstreams JSON decode failed",
				"app_slug", t.AppSlug, "key_id", t.KeyID, "error", err)
			continue
		}
		result = append(result, t)
	}
	return result, rows.Err()
}

// GetActiveAppKeysForSlug returns the count of currently-active app_keys
// rows for a given slug. "Active" = status='active' AND not expired.
// Returns (0, nil) for a non-existent slug or a pre-Phase-4 vault (no
// app_keys table) — both are valid steady states meaning "this app has
// no live keys", not errors.
//
// Used by the Phase 4 observer framework's DefaultVaultEnableCheck to
// decide at proxy startup whether to instantiate a first-party
// observer. The semantics chosen here ("at least one active key")
// match the user-visible meaning of `aikey app list`: an app shows up
// only when it has at least one issued, non-expired bearer.
func (r *Reader) GetActiveAppKeysForSlug(slug string) (int, error) {
	// Pre-Phase-4 vault: app_keys table doesn't exist yet. Treat as no
	// active keys rather than erroring — matches GetAppRecord's
	// "soft return nil on missing table" convention.
	if !hasColumn(r.db, "app_keys", "route_token") {
		return 0, nil
	}
	var n int
	err := r.db.QueryRow(
		`SELECT COUNT(*) FROM app_keys
		  WHERE app_slug = ?
		    AND status = 'active'
		    AND (expires_at IS NULL OR expires_at > strftime('%s','now'))`,
		slug,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count active app_keys for slug=%q: %w", slug, err)
	}
	return n, nil
}

// WriteConfigU64LE writes a uint64 as an 8-byte little-endian BLOB into the
// vault config table (INSERT OR REPLACE).  Opens its own connection so it can
// be called independently of an existing Reader.
func WriteConfigU64LE(dbPath, key string, value uint64) error {
	db, err := sql.Open("sqlite", WithBusyTimeoutDSN(dbPath))
	if err != nil {
		return fmt.Errorf("open vault db for config write: %w", err)
	}
	defer db.Close()

	b := [8]byte{
		byte(value), byte(value >> 8), byte(value >> 16), byte(value >> 24),
		byte(value >> 32), byte(value >> 40), byte(value >> 48), byte(value >> 56),
	}
	_, err = db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, b[:])
	if err != nil {
		return fmt.Errorf("write config key %q: %w", key, err)
	}
	return nil
}

// WriteConfigString writes a string value (UTF-8 BLOB) into the vault config
// table (INSERT OR REPLACE). Mirror of WriteConfigU64LE for non-numeric config
// such as compliance.master_policy JSON. Opens its own connection.
func WriteConfigString(dbPath, key, value string) error {
	db, err := sql.Open("sqlite", WithBusyTimeoutDSN(dbPath))
	if err != nil {
		return fmt.Errorf("open vault db for config write: %w", err)
	}
	defer db.Close()

	_, err = db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, []byte(value))
	if err != nil {
		return fmt.Errorf("write config key %q: %w", key, err)
	}
	return nil
}

// WriteGroupRuntime updates the group_runtime column for one group VK (N7c-2).
// jsonValue is the proxy-built per-account material JSON (token/key ciphertext +
// window/meta). Only managed_virtual_keys_cache.group_runtime is touched — never
// the CLI-owned structural columns (which the CLI's sync fences this out of). A
// separate write connection mirrors WriteConfigString's pattern.
//
// busy_timeout is MANDATORY here (2026-07-03, Ubuntu client-leg regression):
// modernc's default busy_timeout is 0 — the UPDATE fails instantly with
// SQLITE_BUSY whenever any reader (CLI vault poll, second proxy connection)
// briefly holds the lock. The supervisor's 60s pull cycle then aborts and
// group VKs 503 "credentials are still syncing" for minutes on Linux, where
// the lock timing loses far more often than on macOS. Same guard applied to
// the config read/write helpers above — do not reintroduce raw dbPath opens.
func WriteGroupRuntime(dbPath, virtualKeyID, jsonValue string) error {
	db, err := sql.Open("sqlite", WithBusyTimeoutDSN(dbPath))
	if err != nil {
		return fmt.Errorf("open vault db for group_runtime write: %w", err)
	}
	defer db.Close()

	_, err = db.Exec(
		"UPDATE managed_virtual_keys_cache SET group_runtime = ? WHERE virtual_key_id = ?",
		jsonValue, virtualKeyID)
	if err != nil {
		return fmt.Errorf("write group_runtime for vk %q: %w", virtualKeyID, err)
	}
	return nil
}

// WriteAssignmentOverride updates the my_assignment_override column for one
// group VK (the routing_override SyncRail's persistence leg, N12 completed
// 2026-07-03). jsonValue "" clears it (engine no longer overrides this seat).
// Only this proxy-owned column is touched — the CLI's structural sync fences it
// out, mirroring WriteGroupRuntime's ownership split.
func WriteAssignmentOverride(dbPath, virtualKeyID, jsonValue string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open vault db for my_assignment_override write: %w", err)
	}
	defer db.Close()

	_, err = db.Exec(
		"UPDATE managed_virtual_keys_cache SET my_assignment_override = ? WHERE virtual_key_id = ?",
		jsonValue, virtualKeyID)
	if err != nil {
		return fmt.Errorf("write my_assignment_override for vk %q: %w", virtualKeyID, err)
	}
	return nil
}
