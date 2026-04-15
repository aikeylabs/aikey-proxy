package vault

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	broker "github.com/AiKeyLabs/aikey-auth-broker"
)

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
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO provider_accounts
			(provider_account_id, provider, auth_type, credential_type, status,
			 external_id, display_identity, org_uuid, account_tier,
			 created_at, last_used_at, owner_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
	)
	if err != nil {
		return fmt.Errorf("save provider account: %w", err)
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
		"SELECT "+accountCols+" FROM provider_accounts ORDER BY provider, created_at",
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
	if err == sql.ErrNoRows {
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

// scannable is an interface satisfied by both *sql.Row and *sql.Rows.
type scannable interface {
	Scan(dest ...any) error
}

func scanAccount(row *sql.Row) (*broker.ProviderAccount, error) {
	var (
		id, provider, authType, credType, status string
		extID, display, orgUUID, tier             sql.NullString
		createdAt                                 int64
		lastUsedAt                                sql.NullInt64
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
		extID, display, orgUUID, tier             sql.NullString
		createdAt                                 int64
		lastUsedAt                                sql.NullInt64
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
