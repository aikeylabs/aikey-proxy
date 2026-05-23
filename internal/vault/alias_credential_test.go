package vault

// Tests for GetAliasCredential — the Probe pipeline's alias → synthetic
// ProviderBinding lookup. See vault.go::GetAliasCredential and SPEC
// `workflow/CI/requirements/2026-05-23-credential-mode-architecture.md` §1.3.
//
// Fixture approach mirrors app_vault_test.go: in-memory SQLite, schema
// scoped to only the columns the function SELECTs. We construct
// Reader{db: ...} directly instead of going through vault.Open because
// GetAliasCredential is pure SQL — no decryption involved.

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// newTestReaderWithAliasTables creates a Reader against an in-memory SQLite
// with `entries` (personal) + `provider_accounts` (OAuth) tables. Schema
// mirrors aikey-cli/src/migrations.rs v1_0_0_baseline.
func newTestReaderWithAliasTables(t *testing.T) *Reader {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	stmts := []string{
		`CREATE TABLE entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			alias TEXT NOT NULL UNIQUE,
			nonce BLOB NOT NULL,
			ciphertext BLOB NOT NULL,
			version_tag INTEGER NOT NULL DEFAULT 1,
			metadata TEXT,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			provider_code TEXT,
			base_url TEXT,
			route_token TEXT
		)`,
		`CREATE TABLE provider_accounts (
			provider_account_id  TEXT PRIMARY KEY,
			provider             TEXT NOT NULL,
			auth_type            TEXT NOT NULL,
			credential_type      TEXT NOT NULL DEFAULT 'personal_oauth_account',
			status               TEXT NOT NULL DEFAULT 'active',
			external_id          TEXT,
			display_identity     TEXT,
			local_alias          TEXT,
			org_uuid             TEXT,
			account_tier         TEXT,
			created_at           INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			last_used_at         INTEGER,
			owner_type           TEXT NOT NULL DEFAULT 'local_user',
			route_token          TEXT,
			use_count            INTEGER NOT NULL DEFAULT 0
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("schema setup failed: %v\nstmt: %s", err, s)
		}
	}
	return &Reader{db: db}
}

// TestGetAliasCredential_PersonalEntry covers the personal API key path:
// `entries.alias` match → personal binding, status="active".
func TestGetAliasCredential_PersonalEntry(t *testing.T) {
	r := newTestReaderWithAliasTables(t)
	_, err := r.db.Exec(
		`INSERT INTO entries (alias, nonce, ciphertext, provider_code) VALUES ('my-claude', X'00', X'00', 'anthropic')`,
	)
	if err != nil {
		t.Fatalf("seed entries: %v", err)
	}

	got, err := r.GetAliasCredential("my-claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected credential, got nil")
	}
	if got.Status != "active" {
		t.Errorf("status: got %q, want active", got.Status)
	}
	if got.AliasKind != "personal" {
		t.Errorf("alias_kind: got %q, want personal", got.AliasKind)
	}
	if got.Binding.KeySourceType != "personal" {
		t.Errorf("key_source_type: got %q, want personal", got.Binding.KeySourceType)
	}
	if got.Binding.KeySourceRef != "my-claude" {
		t.Errorf("key_source_ref: got %q, want my-claude", got.Binding.KeySourceRef)
	}
	if got.Binding.ProviderCode != "anthropic" {
		t.Errorf("provider_code: got %q, want anthropic", got.Binding.ProviderCode)
	}
}

// TestGetAliasCredential_OAuthByDisplayIdentity covers the OAuth path:
// alias matches `provider_accounts.display_identity` (the canonical email).
func TestGetAliasCredential_OAuthByDisplayIdentity(t *testing.T) {
	r := newTestReaderWithAliasTables(t)
	_, err := r.db.Exec(
		`INSERT INTO provider_accounts (provider_account_id, provider, auth_type, display_identity, status)
		 VALUES ('acct-abc', 'anthropic', 'oauth', 'user@host.com', 'active')`,
	)
	if err != nil {
		t.Fatalf("seed provider_accounts: %v", err)
	}

	got, err := r.GetAliasCredential("user@host.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected credential, got nil")
	}
	if got.Status != "active" {
		t.Errorf("status: got %q, want active", got.Status)
	}
	if got.AliasKind != "oauth" {
		t.Errorf("alias_kind: got %q, want oauth", got.AliasKind)
	}
	if got.Binding.KeySourceType != "personal_oauth_account" {
		t.Errorf("key_source_type: got %q, want personal_oauth_account", got.Binding.KeySourceType)
	}
	if got.Binding.KeySourceRef != "acct-abc" {
		t.Errorf("key_source_ref: got %q, want acct-abc", got.Binding.KeySourceRef)
	}
	if got.Binding.ProviderCode != "anthropic" {
		t.Errorf("provider_code: got %q, want anthropic", got.Binding.ProviderCode)
	}
}

// TestGetAliasCredential_OAuthByLocalAlias covers the rename path:
// `local_alias` match should win over `display_identity` (per SPEC §1.3
// lookup order — user's chosen label takes precedence over the raw email).
func TestGetAliasCredential_OAuthByLocalAlias(t *testing.T) {
	r := newTestReaderWithAliasTables(t)
	_, err := r.db.Exec(
		`INSERT INTO provider_accounts (provider_account_id, provider, auth_type, display_identity, local_alias, status)
		 VALUES ('acct-abc', 'anthropic', 'oauth', 'noisy@email.com', 'my-renamed-claude', 'active')`,
	)
	if err != nil {
		t.Fatalf("seed provider_accounts: %v", err)
	}

	got, err := r.GetAliasCredential("my-renamed-claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected credential, got nil")
	}
	if got.Binding.KeySourceRef != "acct-abc" {
		t.Errorf("key_source_ref: got %q, want acct-abc", got.Binding.KeySourceRef)
	}
	if got.AliasKind != "oauth" {
		t.Errorf("alias_kind: got %q, want oauth", got.AliasKind)
	}
}

// TestGetAliasCredential_PersonalPrecedesOAuth: if the same name happens to
// exist in both `entries` and `provider_accounts`, personal wins (matches
// the lookup-order doc in vault.go).
func TestGetAliasCredential_PersonalPrecedesOAuth(t *testing.T) {
	r := newTestReaderWithAliasTables(t)
	if _, err := r.db.Exec(
		`INSERT INTO entries (alias, nonce, ciphertext, provider_code) VALUES ('shared', X'00', X'00', 'openai')`,
	); err != nil {
		t.Fatalf("seed entries: %v", err)
	}
	if _, err := r.db.Exec(
		`INSERT INTO provider_accounts (provider_account_id, provider, auth_type, local_alias, status)
		 VALUES ('acct-other', 'anthropic', 'oauth', 'shared', 'active')`,
	); err != nil {
		t.Fatalf("seed provider_accounts: %v", err)
	}

	got, err := r.GetAliasCredential("shared")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AliasKind != "personal" {
		t.Errorf("alias_kind: got %q, want personal (precedence)", got.AliasKind)
	}
	if got.Binding.ProviderCode != "openai" {
		t.Errorf("provider_code: got %q, want openai (personal row)", got.Binding.ProviderCode)
	}
}

// TestGetAliasCredential_NotFound returns (nil, nil) — caller maps to 404.
func TestGetAliasCredential_NotFound(t *testing.T) {
	r := newTestReaderWithAliasTables(t)
	got, err := r.GetAliasCredential("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil credential, got %+v", got)
	}
}

// TestGetAliasCredential_RevokedOAuth surfaces non-active status through.
// The probepipe.Resolve layer is responsible for mapping it to 403; vault
// just reports the underlying state.
func TestGetAliasCredential_RevokedOAuth(t *testing.T) {
	r := newTestReaderWithAliasTables(t)
	if _, err := r.db.Exec(
		`INSERT INTO provider_accounts (provider_account_id, provider, auth_type, display_identity, status)
		 VALUES ('acct-rev', 'anthropic', 'oauth', 'revoked@example.com', 'revoked')`,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := r.GetAliasCredential("revoked@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected credential (with revoked status), got nil")
	}
	if got.Status != "revoked" {
		t.Errorf("status: got %q, want revoked", got.Status)
	}
}

// TestGetAliasCredential_EmptyName guards against an empty alias slipping
// through the URL parser charset check.
func TestGetAliasCredential_EmptyName(t *testing.T) {
	r := newTestReaderWithAliasTables(t)
	got, err := r.GetAliasCredential("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for empty name, got %+v", got)
	}
}

// TestGetAliasCredential_PreV103Vault simulates a vault without the
// provider_accounts table (the OAuth table was added in v1.0.3-alpha).
// Personal lookup should still work; OAuth lookup gracefully returns nil.
func TestGetAliasCredential_PreV103Vault(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		alias TEXT NOT NULL UNIQUE,
		nonce BLOB NOT NULL,
		ciphertext BLOB NOT NULL,
		provider_code TEXT
	)`)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	r := &Reader{db: db}

	// OAuth-only lookup on pre-v1.0.3 vault → nil (no error).
	got, err := r.GetAliasCredential("user@host.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on pre-v1.0.3 vault, got %+v", got)
	}
}
