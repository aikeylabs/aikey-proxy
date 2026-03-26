package vault

import (
	"database/sql"
	"fmt"
	"log/slog"

	_ "modernc.org/sqlite"
)

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
