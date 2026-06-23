package vault

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	broker "github.com/AiKeyLabs/aikey-auth-broker"
)

// generateRouteToken mirrors aikey-cli's `storage::generate_route_token()`
// (aikey-cli/src/storage.rs:1423): "aikey_personal_" + 64 lowercase hex
// chars (256 bits via crypto/rand). The lowercase requirement comes from
// the proxy's `isTier1Personal` form check, which rejects uppercase —
// this is a hard contract documented in
// roadmap20260320/技术实现/update/20260429-token前缀按角色重命名.md §4.
//
// Defined here (not in a shared helper) because this file is the only Go
// site that needs to generate the token — broker.ProviderAccount struct
// has no RouteToken field (token is a vault-owned identifier, not a
// broker concept). See bugfix
// 20260525-vault-oauth-route-token-not-generated-by-web-broker.md.
func generateRouteToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return "aikey_personal_" + hex.EncodeToString(b[:]), nil
}

// VaultAccountStore implements broker.AccountStore using SQLite.
// Account metadata is stored in plaintext (not encrypted) — only tokens are encrypted.
type VaultAccountStore struct {
	db *sql.DB
}

// NewAccountStore creates a VaultAccountStore.
// The db must have provider_accounts table (v1.0.3-alpha migration).
func NewAccountStore(db *sql.DB) *VaultAccountStore {
	return &VaultAccountStore{db: db}
}

func (s *VaultAccountStore) Save(_ context.Context, acct *broker.ProviderAccount) error {
	// BR-rc.5 fix (2026-05-25): preserve / generate `route_token`.
	//
	// Pre-fix: this INSERT covered 12 columns NOT including route_token.
	// `INSERT OR REPLACE` semantics replace the entire row, so any
	// existing route_token (e.g. seeded later by `aikey route` or by an
	// earlier CLI `aikey auth login` against the same account) would be
	// nuked on every broker save. New OAuth accounts created via the
	// web OAuthBrokerCard ended up with route_token=NULL, which the
	// vault drawer UI rendered as "Unlock vault to reveal this token"
	// even when the vault was unlocked (UI assumes NULL=locked).
	//
	// CLI-side `aikey auth login` symmetric path called
	// `storage::ensure_provider_account_route_token(account_id)` right
	// after broker save (commands_auth/mod.rs:393), so CLI-added OAuth
	// happened to have route_token. Web path bypasses that — the broker
	// is the only writer for web-added accounts, so the broker's save
	// MUST itself manage route_token.
	//
	// Strategy:
	//   1. Read existing route_token for this account_id (could exist
	//      from a prior save or from CLI-side ensure).
	//   2. If empty / NULL, generate a fresh one matching CLI format
	//      ("aikey_personal_" + 64 lowercase hex).
	//   3. INSERT OR REPLACE with the resolved token in the value list.
	//
	// Wrapped in a transaction so the read + insert is atomic against
	// concurrent saves of the same account_id (rare but possible if the
	// user clicks "Connect" twice in the OAuthBrokerCard UI).
	//
	// See bugfix 20260525-vault-oauth-route-token-not-generated-by-web-
	// broker.md.

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("save provider account: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	var existing sql.NullString
	if qErr := tx.QueryRow(
		"SELECT route_token FROM provider_accounts WHERE provider_account_id = ?",
		acct.ProviderAccountID,
	).Scan(&existing); qErr != nil && qErr != sql.ErrNoRows {
		return fmt.Errorf("save provider account: read existing route_token: %w", qErr)
	}

	routeToken := existing.String
	if !existing.Valid || routeToken == "" {
		routeToken, err = generateRouteToken()
		if err != nil {
			return fmt.Errorf("save provider account: generate route_token: %w", err)
		}
	}

	if _, err := tx.Exec(
		`INSERT OR REPLACE INTO provider_accounts
			(provider_account_id, provider, auth_type, credential_type, status,
			 external_id, display_identity, org_uuid, account_tier,
			 created_at, last_used_at, owner_type, route_token)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		acct.ProviderAccountID,
		acct.Provider,
		acct.AuthType,
		string(acct.CredentialType),
		string(acct.Status),
		nullStr(acct.ExternalID),
		nullStr(acct.DisplayIdentity),
		nullStr(acct.OrgUUID),
		nullStr(acct.AccountTier),
		acct.CreatedAt.Unix(),
		nullTime(acct.LastUsedAt),
		"local_user",
		routeToken,
	); err != nil {
		return fmt.Errorf("save provider account: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("save provider account: commit: %w", err)
	}
	return nil
}

func (s *VaultAccountStore) GetByID(_ context.Context, accountID string) (*broker.ProviderAccount, error) {
	return s.queryOne(
		"SELECT "+accountCols+" FROM provider_accounts WHERE provider_account_id = ?",
		accountID,
	)
}

func (s *VaultAccountStore) GetByExternalID(_ context.Context, provider, externalID string) (*broker.ProviderAccount, error) {
	return s.queryOne(
		"SELECT "+accountCols+" FROM provider_accounts WHERE provider = ? AND external_id = ?",
		provider, externalID,
	)
}

func (s *VaultAccountStore) ListByProvider(_ context.Context, provider string) ([]*broker.ProviderAccount, error) {
	return s.queryMany(
		"SELECT "+accountCols+" FROM provider_accounts WHERE provider = ? ORDER BY created_at",
		provider,
	)
}

func (s *VaultAccountStore) ListAll(_ context.Context) ([]*broker.ProviderAccount, error) {
	return s.queryMany(
		"SELECT " + accountCols + " FROM provider_accounts ORDER BY provider, created_at",
	)
}

func (s *VaultAccountStore) UpdateStatus(_ context.Context, accountID string, status broker.AccountStatus) error {
	_, err := s.db.Exec(
		"UPDATE provider_accounts SET status = ? WHERE provider_account_id = ?",
		string(status), accountID,
	)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	return nil
}

func (s *VaultAccountStore) UpdateDisplayIdentity(_ context.Context, accountID, displayIdentity string) error {
	_, err := s.db.Exec(
		"UPDATE provider_accounts SET display_identity = ? WHERE provider_account_id = ?",
		displayIdentity, accountID,
	)
	if err != nil {
		return fmt.Errorf("update display_identity: %w", err)
	}
	return nil
}

func (s *VaultAccountStore) Delete(_ context.Context, accountID string) error {
	_, err := s.db.Exec(
		"DELETE FROM provider_accounts WHERE provider_account_id = ?",
		accountID,
	)
	if err != nil {
		return fmt.Errorf("delete provider account: %w", err)
	}
	return nil
}

// --- internal helpers ---

const accountCols = "provider_account_id, provider, auth_type, credential_type, status, " +
	"external_id, display_identity, org_uuid, account_tier, created_at, last_used_at"

func (s *VaultAccountStore) queryOne(query string, args ...any) (*broker.ProviderAccount, error) {
	row := s.db.QueryRow(query, args...)
	acct, err := scanAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query account: %w", err)
	}
	return acct, nil
}

func (s *VaultAccountStore) queryMany(query string, args ...any) ([]*broker.ProviderAccount, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query accounts: %w", err)
	}
	defer rows.Close()

	var result []*broker.ProviderAccount
	for rows.Next() {
		acct, err := scanAccountFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		result = append(result, acct)
	}
	return result, rows.Err()
}

func scanAccount(row *sql.Row) (*broker.ProviderAccount, error) {
	var (
		id, provider, authType, credType, status string
		extID, display, orgUUID, tier            sql.NullString
		createdAt                                int64
		lastUsedAt                               sql.NullInt64
	)
	err := row.Scan(&id, &provider, &authType, &credType, &status,
		&extID, &display, &orgUUID, &tier, &createdAt, &lastUsedAt)
	if err != nil {
		return nil, err
	}
	return buildAccount(id, provider, authType, credType, status,
		extID, display, orgUUID, tier, createdAt, lastUsedAt), nil
}

func scanAccountFromRows(rows *sql.Rows) (*broker.ProviderAccount, error) {
	var (
		id, provider, authType, credType, status string
		extID, display, orgUUID, tier            sql.NullString
		createdAt                                int64
		lastUsedAt                               sql.NullInt64
	)
	err := rows.Scan(&id, &provider, &authType, &credType, &status,
		&extID, &display, &orgUUID, &tier, &createdAt, &lastUsedAt)
	if err != nil {
		return nil, err
	}
	return buildAccount(id, provider, authType, credType, status,
		extID, display, orgUUID, tier, createdAt, lastUsedAt), nil
}

func buildAccount(id, provider, authType, credType, status string,
	extID, display, orgUUID, tier sql.NullString,
	createdAt int64, lastUsedAt sql.NullInt64) *broker.ProviderAccount {
	acct := &broker.ProviderAccount{
		ProviderAccountID: id,
		Provider:          provider,
		AuthType:          authType,
		CredentialType:    broker.CredentialType(credType),
		Status:            broker.AccountStatus(status),
		ExternalID:        extID.String,
		DisplayIdentity:   display.String,
		OrgUUID:           orgUUID.String,
		AccountTier:       tier.String,
		CreatedAt:         time.Unix(createdAt, 0),
	}
	if lastUsedAt.Valid {
		t := time.Unix(lastUsedAt.Int64, 0)
		acct.LastUsedAt = &t
	}
	return acct
}

func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullTime(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.Unix(), Valid: true}
}

// Compile-time interface check.
var _ broker.AccountStore = (*VaultAccountStore)(nil)
