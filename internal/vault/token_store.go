package vault

import (
	"context"
	"database/sql"
	"fmt"

	broker "github.com/AiKeyLabs/aikey-auth-broker"
)

// VaultTokenStore implements broker.TokenStore using SQLite + AES-256-GCM.
// Tokens are encrypted at rest using the vault's derived key.
type VaultTokenStore struct {
	db  *sql.DB
	key []byte // AES-256-GCM key (derived from master password)
}

// NewTokenStore creates a VaultTokenStore.
// The db must have provider_account_tokens table (v1.0.3-alpha migration).
func NewTokenStore(db *sql.DB, derivedKey []byte) *VaultTokenStore {
	return &VaultTokenStore{db: db, key: derivedKey}
}

func (s *VaultTokenStore) GetAccessToken(_ context.Context, accountID string) (string, int64, error) {
	var nonce, ciphertext []byte
	var expiresAt int64
	err := s.db.QueryRow(
		"SELECT access_token_nonce, access_token_ciphertext, token_expires_at FROM provider_account_tokens WHERE provider_account_id = ?",
		accountID,
	).Scan(&nonce, &ciphertext, &expiresAt)
	if err == sql.ErrNoRows {
		return "", 0, fmt.Errorf("no token for account %s", accountID)
	}
	if err != nil {
		return "", 0, fmt.Errorf("query token: %w", err)
	}
	if nonce == nil || ciphertext == nil {
		return "", 0, fmt.Errorf("token data is nil for account %s", accountID)
	}

	plaintext, err := Decrypt(s.key, nonce, ciphertext)
	if err != nil {
		return "", 0, fmt.Errorf("decrypt access_token: %w", err)
	}
	return string(plaintext), expiresAt, nil
}

func (s *VaultTokenStore) GetRefreshToken(_ context.Context, accountID string) (string, error) {
	var nonce, ciphertext []byte
	err := s.db.QueryRow(
		"SELECT refresh_token_nonce, refresh_token_ciphertext FROM provider_account_tokens WHERE provider_account_id = ?",
		accountID,
	).Scan(&nonce, &ciphertext)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no token for account %s", accountID)
	}
	if err != nil {
		return "", fmt.Errorf("query refresh_token: %w", err)
	}
	if nonce == nil || ciphertext == nil {
		return "", fmt.Errorf("refresh_token is nil for account %s", accountID)
	}

	plaintext, err := Decrypt(s.key, nonce, ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt refresh_token: %w", err)
	}
	return string(plaintext), nil
}

func (s *VaultTokenStore) SaveTokens(_ context.Context, accountID, accessToken, refreshToken string, expiresAt int64) error {
	atNonce, atCipher, err := Encrypt(s.key, []byte(accessToken))
	if err != nil {
		return fmt.Errorf("encrypt access_token: %w", err)
	}
	rtNonce, rtCipher, err := Encrypt(s.key, []byte(refreshToken))
	if err != nil {
		return fmt.Errorf("encrypt refresh_token: %w", err)
	}

	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO provider_account_tokens
			(provider_account_id, access_token_nonce, access_token_ciphertext,
			 refresh_token_nonce, refresh_token_ciphertext, token_expires_at,
			 updated_at)
		VALUES (?, ?, ?, ?, ?, ?, strftime('%s', 'now'))`,
		accountID, atNonce, atCipher, rtNonce, rtCipher, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("save tokens: %w", err)
	}
	return nil
}

func (s *VaultTokenStore) DeleteTokens(_ context.Context, accountID string) error {
	_, err := s.db.Exec(
		"DELETE FROM provider_account_tokens WHERE provider_account_id = ?",
		accountID,
	)
	if err != nil {
		return fmt.Errorf("delete tokens: %w", err)
	}
	return nil
}

// Compile-time interface check.
var _ broker.TokenStore = (*VaultTokenStore)(nil)
