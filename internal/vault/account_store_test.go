package vault

// Tests for VaultAccountStore.Save — specifically the BR-rc.5 fix that
// generates `route_token` on first save and preserves it on subsequent
// saves. See bugfix
// 20260525-vault-oauth-route-token-not-generated-by-web-broker.md.
//
// Pre-fix: Save's INSERT covered 12 columns NOT including route_token,
// so every OAuth account written via the web OAuthBrokerCard ended up
// with route_token=NULL. The vault drawer UI then rendered "Unlock vault
// to reveal this token" even when the vault was unlocked (UI assumes
// NULL=locked). Re-saving the same account (broker re-sync) wiped any
// route_token that had been backfilled by CLI's `ensure_provider_account_
// route_token` because `INSERT OR REPLACE` replaces the whole row.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	broker "github.com/AiKeyLabs/aikey-auth-broker"
	_ "modernc.org/sqlite"
)

// newTestAccountStore creates a VaultAccountStore against an in-memory
// SQLite with the `provider_accounts` table schema mirroring
// aikey-cli/src/migrations.rs v1_0_0_baseline (incl. route_token column).
func newTestAccountStore(t *testing.T) *VaultAccountStore {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.Exec(`CREATE TABLE provider_accounts (
		provider_account_id  TEXT PRIMARY KEY,
		provider             TEXT NOT NULL,
		auth_type            TEXT NOT NULL,
		credential_type      TEXT NOT NULL DEFAULT 'personal_oauth_account',
		status               TEXT NOT NULL DEFAULT 'active',
		external_id          TEXT,
		display_identity     TEXT,
		org_uuid             TEXT,
		account_tier         TEXT,
		created_at           INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
		last_used_at         INTEGER,
		owner_type           TEXT NOT NULL DEFAULT 'local_user',
		route_token          TEXT,
		use_count            INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatalf("schema setup: %v", err)
	}
	return NewAccountStore(db)
}

func sampleAccount() *broker.ProviderAccount {
	return &broker.ProviderAccount{
		ProviderAccountID: "acct-test-1",
		Provider:          "claude",
		AuthType:          "oauth_auth_code",
		CredentialType:    broker.CredentialType("personal_oauth_account"),
		Status:            broker.AccountStatus("active"),
		ExternalID:        "user-ext-id-1",
		DisplayIdentity:   "test@example.com",
		CreatedAt:         time.Unix(1700000000, 0),
	}
}

func selectRouteToken(t *testing.T, store *VaultAccountStore, accountID string) sql.NullString {
	t.Helper()
	var tok sql.NullString
	if err := store.db.QueryRow(
		"SELECT route_token FROM provider_accounts WHERE provider_account_id = ?",
		accountID,
	).Scan(&tok); err != nil {
		t.Fatalf("read route_token: %v", err)
	}
	return tok
}

// TestSave_GeneratesRouteTokenOnFirstSave is the direct BR-rc.5
// regression pin: a freshly-saved OAuth account must have a non-null
// route_token immediately, before any CLI side-channel runs.
func TestSave_GeneratesRouteTokenOnFirstSave(t *testing.T) {
	store := newTestAccountStore(t)
	acct := sampleAccount()

	if err := store.Save(context.Background(), acct); err != nil {
		t.Fatalf("Save: %v", err)
	}

	tok := selectRouteToken(t, store, acct.ProviderAccountID)
	if !tok.Valid || tok.String == "" {
		t.Fatalf("route_token must be non-null after first Save; got: %+v", tok)
	}
	if !strings.HasPrefix(tok.String, "aikey_personal_") {
		t.Fatalf("route_token must start with `aikey_personal_` (matches CLI generate_route_token format); got: %s", tok.String)
	}
	// 256-bit hex = 64 chars; prefix "aikey_personal_" is 15 chars → total 79.
	if len(tok.String) != 79 {
		t.Fatalf("route_token must be exactly 79 chars (prefix 15 + 64 hex); got %d: %s", len(tok.String), tok.String)
	}
}

// TestSave_PreservesRouteTokenOnResave covers the `INSERT OR REPLACE`
// rowscape issue: re-saving the same account_id (broker re-sync, status
// update, display rename, etc) must NOT regenerate route_token.
// Otherwise existing clients holding the bearer would suddenly 401.
func TestSave_PreservesRouteTokenOnResave(t *testing.T) {
	store := newTestAccountStore(t)
	acct := sampleAccount()

	if err := store.Save(context.Background(), acct); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	first := selectRouteToken(t, store, acct.ProviderAccountID)
	if !first.Valid {
		t.Fatalf("first Save did not produce route_token")
	}

	// Re-save with a different display_identity (a common broker
	// behavior — user renamed the provider account).
	acct.DisplayIdentity = "renamed@example.com"
	if err := store.Save(context.Background(), acct); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	second := selectRouteToken(t, store, acct.ProviderAccountID)
	if !second.Valid {
		t.Fatalf("route_token must remain after re-Save; got null")
	}
	if first.String != second.String {
		t.Fatalf("route_token must be preserved across re-Save (bearer stability);\n  first:  %s\n  second: %s", first.String, second.String)
	}

	// Sanity: display_identity change actually took effect.
	var disp sql.NullString
	if err := store.db.QueryRow(
		"SELECT display_identity FROM provider_accounts WHERE provider_account_id = ?",
		acct.ProviderAccountID,
	).Scan(&disp); err != nil {
		t.Fatalf("read display_identity: %v", err)
	}
	if disp.String != "renamed@example.com" {
		t.Fatalf("display_identity should have updated; got: %s", disp.String)
	}
}

// TestSave_PreservesExternallySeededRouteToken covers the case where an
// existing row already has a route_token (seeded by CLI's
// `ensure_provider_account_route_token` from `aikey route` or an earlier
// `aikey auth login`). Save must NOT overwrite it with a freshly
// generated value — otherwise broker re-sync would silently invalidate
// every bearer the user is holding.
func TestSave_PreservesExternallySeededRouteToken(t *testing.T) {
	store := newTestAccountStore(t)
	const preExistingToken = "aikey_personal_deadbeef00000000000000000000000000000000000000000000000000000000beef"

	// Simulate CLI-side ensure_provider_account_route_token having
	// written a token before broker ever saved this account_id.
	if _, err := store.db.Exec(
		`INSERT INTO provider_accounts (provider_account_id, provider, auth_type, route_token)
		 VALUES ('acct-cli-seeded', 'claude', 'oauth_auth_code', ?)`,
		preExistingToken,
	); err != nil {
		t.Fatalf("seed pre-existing row: %v", err)
	}

	acct := sampleAccount()
	acct.ProviderAccountID = "acct-cli-seeded"
	if err := store.Save(context.Background(), acct); err != nil {
		t.Fatalf("Save: %v", err)
	}

	tok := selectRouteToken(t, store, acct.ProviderAccountID)
	if tok.String != preExistingToken {
		t.Fatalf("pre-existing route_token must be preserved across broker Save;\n  expected: %s\n  got:      %s", preExistingToken, tok.String)
	}
}

// TestGenerateRouteToken_FormatContract pins the generator output shape.
// CLI proxy's isTier1Personal form check (aikey-cli/src/storage.rs:1419-
// 1420) is documented as: 64 lowercase hex chars, "aikey_personal_"
// prefix. Any change here must match aikey-cli's storage.rs:1423
// `generate_route_token()` exactly.
func TestGenerateRouteToken_FormatContract(t *testing.T) {
	tok, err := generateRouteToken()
	if err != nil {
		t.Fatalf("generateRouteToken: %v", err)
	}
	if !strings.HasPrefix(tok, "aikey_personal_") {
		t.Fatalf("missing `aikey_personal_` prefix: %s", tok)
	}
	hexPart := strings.TrimPrefix(tok, "aikey_personal_")
	if len(hexPart) != 64 {
		t.Fatalf("hex suffix must be 64 chars (256 bits); got %d: %s", len(hexPart), hexPart)
	}
	for _, c := range hexPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("hex suffix must be all lowercase hex; bad char %q in: %s", c, hexPart)
		}
	}
}

// TestGenerateRouteToken_Unique sanity-checks that two consecutive
// generations don't collide (extremely high probability given 256 bits
// of entropy; this just catches a broken impl that returns a static
// string or seeds from a fixed source).
func TestGenerateRouteToken_Unique(t *testing.T) {
	a, err := generateRouteToken()
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := generateRouteToken()
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a == b {
		t.Fatalf("two generated tokens must differ; both = %s", a)
	}
}
