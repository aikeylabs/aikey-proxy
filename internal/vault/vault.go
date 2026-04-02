package vault

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	_ "modernc.org/sqlite"
)

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
	derivedKey []byte
	cache      *cache
}

// Open opens the vault database and verifies the password.
func Open(dbPath string, password string) (*Reader, error) {
	// Open in read-only mode — aikey-proxy never writes to the vault.
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open vault db: %w", err)
	}

	// Verify the database is accessible.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping vault db: %w", err)
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
	derivedKey := DeriveKeyWithParams([]byte(password), salt, mCost, tCost, uint8(pCost))

	// Verify against stored password_hash.
	storedHash, err := readConfigBlob(db, "password_hash")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("password_hash not found in vault: %w", err)
	}

	if !VerifyKey(derivedKey, storedHash) {
		db.Close()
		return nil, fmt.Errorf("invalid vault password")
	}

	slog.Info("vault opened successfully", "path", dbPath)

	return &Reader{
		db:         db,
		derivedKey: derivedKey,
		cache:      newCache(),
	}, nil
}

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
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("secret %q not found in vault", alias)
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
}

// GetActiveManagedKeys reads all rows from managed_virtual_keys_cache where
// local_state = 'active' and provider_key_ciphertext IS NOT NULL, then decrypts
// each provider key using the vault AES key derived at Open time.
//
// Keys that fail to decrypt are skipped with a warning (e.g. written by a
// different vault password or corrupted data) so a single bad entry does not
// block the proxy from starting.
func (r *Reader) GetActiveManagedKeys() ([]ManagedKey, error) {
	rows, err := r.db.Query(`
		SELECT virtual_key_id, provider_code, protocol_type, base_url,
		       provider_key_nonce, provider_key_ciphertext, provider_base_urls,
		       org_id, seat_id, credential_id, credential_revision,
		       virtual_key_revision, owner_account_id
		FROM managed_virtual_keys_cache
		WHERE local_state = 'active'
		  AND key_status  = 'active'
		  AND provider_key_ciphertext IS NOT NULL
	`)
	if err != nil {
		// Table may not exist on older vaults — treat as empty, not an error.
		return nil, nil //nolint:nilerr
	}
	defer rows.Close()

	var keys []ManagedKey
	for rows.Next() {
		var vkID, provCode, protType, baseURL string
		var nonce, ciphertext []byte
		var providerBaseURLsJSON *string
		var orgID, seatID, credID, credRev, vkRev string
		var ownerAccountID *string
		if err := rows.Scan(&vkID, &provCode, &protType, &baseURL, &nonce, &ciphertext, &providerBaseURLsJSON,
			&orgID, &seatID, &credID, &credRev, &vkRev, &ownerAccountID); err != nil {
			slog.Warn("managed key: scan error, skipping", "error", err)
			continue
		}
		plaintext, err := Decrypt(r.derivedKey, nonce, ciphertext)
		if err != nil {
			slog.Warn("managed key: decryption failed, skipping", "vk_id", vkID, "error", err)
			continue
		}
		providerBaseURLs := make(map[string]string)
		if providerBaseURLsJSON != nil && *providerBaseURLsJSON != "" {
			_ = json.Unmarshal([]byte(*providerBaseURLsJSON), &providerBaseURLs)
		}
		var accountID string
		if ownerAccountID != nil {
			accountID = *ownerAccountID
		}
		keys = append(keys, ManagedKey{
			VirtualKeyID:       vkID,
			ProviderCode:       provCode,
			ProtocolType:       protType,
			BaseURL:            baseURL,
			PlaintextKey:       string(plaintext),
			ProviderBaseURLs:   providerBaseURLs,
			OrgID:              orgID,
			SeatID:             seatID,
			CredentialID:       credID,
			CredentialRevision: credRev,
			VirtualKeyRevision: vkRev,
			OwnerAccountID:     accountID,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("managed keys scan: %w", err)
	}
	return keys, nil
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

// GetActiveTeamKeyByProvider returns the decrypted team key for the given provider code.
//
// Matches on managed_virtual_keys_cache rows where local_state = 'active'
// AND provider_code = providerCode (case-insensitive prefix match on the first active entry).
// Returns nil if no active team key exists for that provider.
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
	query := fmt.Sprintf(`
		SELECT virtual_key_id, provider_code, protocol_type, base_url,
		       provider_key_nonce, provider_key_ciphertext, provider_base_urls
		FROM managed_virtual_keys_cache
		WHERE local_state = 'active'
		  AND key_status  = 'active'
		  AND provider_key_ciphertext IS NOT NULL
		  AND LOWER(provider_code) IN (%s)
		LIMIT 1
	`, strings.Join(placeholders, ","))
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, nil //nolint:nilerr // table may not exist on older vaults
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, rows.Err()
	}

	var vkID, provCode, protType, baseURL string
	var nonce, ciphertext []byte
	var providerBaseURLsJSON *string
	if err := rows.Scan(&vkID, &provCode, &protType, &baseURL, &nonce, &ciphertext, &providerBaseURLsJSON); err != nil {
		return nil, fmt.Errorf("scan managed key: %w", err)
	}

	plaintext, err := Decrypt(r.derivedKey, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt managed key %s: %w", vkID, err)
	}

	providerBaseURLs := make(map[string]string)
	if providerBaseURLsJSON != nil && *providerBaseURLsJSON != "" {
		_ = json.Unmarshal([]byte(*providerBaseURLsJSON), &providerBaseURLs)
	}

	return &ManagedKey{
		VirtualKeyID:     vkID,
		ProviderCode:     provCode,
		ProtocolType:     protType,
		BaseURL:          baseURL,
		PlaintextKey:     string(plaintext),
		ProviderBaseURLs: providerBaseURLs,
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
func ReadConfigU64LE(dbPath string, key string) (uint64, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, fmt.Errorf("open vault db for config read: %w", err)
	}
	defer db.Close()

	var value []byte
	err = db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
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

// WriteConfigU64LE writes a uint64 as an 8-byte little-endian BLOB into the
// vault config table (INSERT OR REPLACE).  Opens its own connection so it can
// be called independently of an existing Reader.
func WriteConfigU64LE(dbPath string, key string, value uint64) error {
	db, err := sql.Open("sqlite", dbPath)
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
