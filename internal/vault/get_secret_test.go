package vault

// Tests for GetSecret error classification (GAP 5, 2026-06-09 proxy
// architecture review). A missing alias must return ErrSecretNotFound
// (errors.Is) so proxy call sites can tell "key truly missing" (→ aikey add)
// apart from transient infra errors (SQLITE_BUSY / IO / decrypt → retry).
//
// Schema mirrors aikey-cli/src/migrations.rs v1_0_0_baseline `entries` table,
// same approach as alias_credential_test.go: in-memory SQLite, Reader{db:...}
// constructed directly since the not-found path is pure SQL (no decryption).

import (
	"database/sql"
	"errors"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestReaderForGetSecret(t *testing.T) *Reader {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.Exec(`CREATE TABLE entries (
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
	)`); err != nil {
		t.Fatalf("schema setup failed: %v", err)
	}
	return &Reader{db: db, cache: newCache()}
}

// TestGetSecret_MissingAlias asserts a missing alias returns ErrSecretNotFound
// (via errors.Is) so callers map it to "Run: aikey add" rather than a retry.
func TestGetSecret_MissingAlias(t *testing.T) {
	r := newTestReaderForGetSecret(t)

	_, err := r.GetSecret("does-not-exist")
	if err == nil {
		t.Fatalf("expected error for missing alias, got nil")
	}
	if !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("errors.Is(err, ErrSecretNotFound) = false; err = %v", err)
	}
}

// TestGetSecret_InfraErrorNotMisclassified guards the negative direction: a
// non-ErrNoRows failure (here: the entries table is absent, i.e. a query
// failure standing in for SQLITE_BUSY/IO) must NOT report ErrSecretNotFound,
// so the proxy maps it to VAULT_UNAVAILABLE retry instead of "re-add the key".
func TestGetSecret_InfraErrorNotMisclassified(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	// Deliberately do NOT create the entries table → query fails with a
	// "no such table" error, which is an infra-class error, not ErrNoRows.
	r := &Reader{db: db, cache: newCache()}

	_, err = r.GetSecret("any")
	if err == nil {
		t.Fatalf("expected query error, got nil")
	}
	if errors.Is(err, ErrSecretNotFound) {
		t.Errorf("infra error misclassified as ErrSecretNotFound: %v", err)
	}
}

// TestWithBusyTimeoutDSN verifies the busy_timeout pragma is appended with the
// correct separator whether or not the path already carries query params.
func TestWithBusyTimeoutDSN(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/path/vault.db", "/path/vault.db?_pragma=busy_timeout(5000)"},
		{"/path/vault.db?cache=shared", "/path/vault.db?cache=shared&_pragma=busy_timeout(5000)"},
	}
	for _, c := range cases {
		if got := WithBusyTimeoutDSN(c.in); got != c.want {
			t.Errorf("WithBusyTimeoutDSN(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
