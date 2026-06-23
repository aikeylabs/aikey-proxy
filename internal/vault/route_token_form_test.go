package vault

// Tests for the registry-load form filter (third-party review #4 [低],
// 2026-04-29). Verifies that GetAllPersonalRouteTokens /
// GetAllOAuthRouteTokens skip rows whose route_token is NOT
// `aikey_personal_<64-lowercase-hex>` so the registry's invariant is
// maintained on pre-migration vaults too.
//
// Why we hand-build a Reader here instead of using vault.Open: Open
// requires a real Argon2id-keyed vault file. The filter under test is a
// pure SQL+predicate combo on the entries / provider_accounts tables;
// constructing a Reader{db: ...} directly with a fresh SQLite handle is
// the cleanest way to focus on the behavior we want to pin without
// dragging in the password-derived key path.

import (
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// newTestReaderWithEntries opens an in-memory SQLite DB, creates the
// entries + provider_accounts schemas with the columns the loaders need,
// and returns a Reader pointing at it. Cleanup is registered with t.
func newTestReaderWithEntries(t *testing.T) *Reader {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Minimal schema mirroring the columns the loaders SELECT. We don't
	// recreate the full vault schema; only what these two functions read.
	stmts := []string{
		`CREATE TABLE entries (
			alias TEXT PRIMARY KEY,
			route_token TEXT,
			provider_code TEXT,
			base_url TEXT
		)`,
		`CREATE TABLE provider_accounts (
			provider_account_id TEXT PRIMARY KEY,
			route_token TEXT,
			provider TEXT,
			display_identity TEXT,
			status TEXT
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("create schema: %v\nstmt: %s", err, s)
		}
	}
	return &Reader{db: db, cache: newCache()}
}

const (
	hex64A = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // strict — must pass
	hex64B = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" // strict — must pass
	hex63  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"  // 63-hex — must skip
	hex64U = "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef" // mixed case — must skip
)

// TestGetAllPersonalRouteTokens_FiltersNonStrictForms feeds the entries
// table a mix of strict + legacy / malformed route_tokens and asserts
// that only the strict ones land in the result. This is the core
// regression for review #4 finding [低].
func TestGetAllPersonalRouteTokens_FiltersNonStrictForms(t *testing.T) {
	r := newTestReaderWithEntries(t)

	// Insert one row per form. Aliases are unique per row; we'll inspect
	// the returned set's aliases to verify which rows passed the filter.
	rows := []struct {
		alias       string
		routeToken  string
		providerCD  string
		description string
		shouldPass  bool
	}{
		{alias: "keyA-strict", routeToken: "aikey_personal_" + hex64A, providerCD: "anthropic", shouldPass: true,
			description: "strict aikey_personal_<64-lowercase-hex>"},
		{alias: "keyB-strict", routeToken: "aikey_personal_" + hex64B, providerCD: "openai", shouldPass: true,
			description: "strict aikey_personal_<64-lowercase-hex> different value"},
		{alias: "keyC-legacy-vk", routeToken: "aikey_vk_" + hex64A, providerCD: "anthropic", shouldPass: false,
			description: "legacy aikey_vk_<64-hex> — pre-migration residue"},
		{alias: "keyD-old-alias", routeToken: "aikey_personal_my-claude-account", providerCD: "anthropic", shouldPass: false,
			description: "legacy aikey_personal_<alias> sentinel form"},
		{alias: "keyE-uuid", routeToken: "aikey_personal_54f8a3e1-b4d9-4e21-9fa0-0e3c5b7d8a91", providerCD: "anthropic", shouldPass: false,
			description: "legacy aikey_personal_<UUID> form (early OAuth)"},
		{alias: "keyF-63hex", routeToken: "aikey_personal_" + hex63, providerCD: "anthropic", shouldPass: false,
			description: "63-hex suffix — short by one"},
		{alias: "keyG-uppercase", routeToken: "aikey_personal_" + hex64U, providerCD: "anthropic", shouldPass: false,
			description: "uppercase hex — strict form rejects"},
		{alias: "keyH-empty-suffix", routeToken: "aikey_personal_", providerCD: "anthropic", shouldPass: false,
			description: "empty hex suffix"},
		{alias: "keyI-other-prefix", routeToken: "aikey_team_acc-1234", providerCD: "anthropic", shouldPass: false,
			description: "team form in entries.route_token (shape-wrong for personal table)"},
	}

	for _, row := range rows {
		_, err := r.db.Exec(
			"INSERT INTO entries (alias, route_token, provider_code, base_url) VALUES (?, ?, ?, ?)",
			row.alias, row.routeToken, row.providerCD, "")
		if err != nil {
			t.Fatalf("insert %s: %v", row.alias, err)
		}
	}

	got, err := r.GetAllPersonalRouteTokens()
	if err != nil {
		t.Fatalf("GetAllPersonalRouteTokens: %v", err)
	}

	gotAliases := make(map[string]bool, len(got))
	for _, t := range got {
		gotAliases[t.Alias] = true
	}

	for _, row := range rows {
		if row.shouldPass {
			if !gotAliases[row.alias] {
				t.Errorf("row %q (%s) should have passed filter but was skipped",
					row.alias, row.description)
			}
		} else {
			if gotAliases[row.alias] {
				t.Errorf("row %q (%s) should have been skipped but landed in result",
					row.alias, row.description)
			}
		}
	}

	wantPassCount := 0
	for _, row := range rows {
		if row.shouldPass {
			wantPassCount++
		}
	}
	if len(got) != wantPassCount {
		t.Errorf("result count = %d, want %d (only strict aikey_personal_<64-lowercase-hex> rows should pass)",
			len(got), wantPassCount)
	}
}

// TestGetAllOAuthRouteTokens_FiltersNonStrictForms is the OAuth-table
// counterpart. Same filter rule, applied at the provider_accounts.
func TestGetAllOAuthRouteTokens_FiltersNonStrictForms(t *testing.T) {
	r := newTestReaderWithEntries(t)

	rows := []struct {
		accountID   string
		routeToken  string
		description string
		shouldPass  bool
	}{
		{accountID: "acc-A", routeToken: "aikey_personal_" + hex64A, shouldPass: true,
			description: "strict aikey_personal_<64-lowercase-hex>"},
		{accountID: "acc-B-legacy-vk", routeToken: "aikey_vk_" + hex64B, shouldPass: false,
			description: "legacy aikey_vk_<64-hex> — pre-migration residue"},
		{accountID: "acc-C-uuid", routeToken: "aikey_personal_a1b2c3d4-5678-90ab-cdef-1234567890ab", shouldPass: false,
			description: "legacy UUID-shaped aikey_personal_ (pre-migration OAuth)"},
		{accountID: "acc-D-uppercase", routeToken: "aikey_personal_" + hex64U, shouldPass: false,
			description: "uppercase hex — strict form rejects"},
	}

	for _, row := range rows {
		_, err := r.db.Exec(
			"INSERT INTO provider_accounts "+
				"(provider_account_id, route_token, provider, display_identity, status) "+
				"VALUES (?, ?, ?, ?, ?)",
			row.accountID, row.routeToken, "anthropic", "test@example.com", "active")
		if err != nil {
			t.Fatalf("insert %s: %v", row.accountID, err)
		}
	}

	got, err := r.GetAllOAuthRouteTokens()
	if err != nil {
		t.Fatalf("GetAllOAuthRouteTokens: %v", err)
	}

	gotAccountIDs := make(map[string]bool, len(got))
	for _, t := range got {
		gotAccountIDs[t.AccountID] = true
	}

	for _, row := range rows {
		if row.shouldPass {
			if !gotAccountIDs[row.accountID] {
				t.Errorf("OAuth row %q (%s) should have passed filter but was skipped",
					row.accountID, row.description)
			}
		} else {
			if gotAccountIDs[row.accountID] {
				t.Errorf("OAuth row %q (%s) should have been skipped but landed in result",
					row.accountID, row.description)
			}
		}
	}
}

// TestGetAllOAuthRouteTokens_SkipsInactive pins the existing `status =
// 'active'` filter alongside the new form filter. Combined they prove
// inactive rows AND non-strict-form rows are both excluded — the
// registry only sees usable, current-form OAuth bearers.
func TestGetAllOAuthRouteTokens_SkipsInactive(t *testing.T) {
	r := newTestReaderWithEntries(t)

	_, err := r.db.Exec(
		"INSERT INTO provider_accounts "+
			"(provider_account_id, route_token, provider, display_identity, status) "+
			"VALUES (?, ?, ?, ?, ?), (?, ?, ?, ?, ?)",
		"active-strict", "aikey_personal_"+hex64A, "anthropic", "a@x", "active",
		"revoked-strict", "aikey_personal_"+hex64B, "anthropic", "b@x", "revoked",
	)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := r.GetAllOAuthRouteTokens()
	if err != nil {
		t.Fatalf("GetAllOAuthRouteTokens: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 row (only active-strict), got %d", len(got))
	}
	if got[0].AccountID != "active-strict" {
		t.Errorf("want active-strict, got %q", got[0].AccountID)
	}
}

// TestIsStrictPersonalBearerForm pins the form predicate directly.
func TestIsStrictPersonalBearerForm(t *testing.T) {
	cases := []struct {
		token string
		want  bool
	}{
		{"aikey_personal_" + hex64A, true},
		{"aikey_personal_" + hex64B, true},
		{"aikey_personal_" + strings.Repeat("0", 64), true},
		{"aikey_personal_" + strings.Repeat("f", 64), true},
		// Negatives.
		{"aikey_personal_" + hex63, false},                             // 63 hex
		{"aikey_personal_" + hex64A + "x", false},                      // 65 chars
		{"aikey_personal_" + hex64U, false},                            // mixed case
		{"aikey_personal_my-alias", false},                             // legacy alias
		{"aikey_personal_a1b2c3d4-5678-90ab-cdef-1234567890ab", false}, // legacy UUID
		{"aikey_personal_", false},                                     // empty
		{"aikey_vk_" + hex64A, false},                                  // legacy vk_ prefix
		{"aikey_team_acc-1234", false},                                 // team prefix
		{"aikey_active_anthropic", false},                              // active sentinel
		{"sk-1234", false},                                             // native
		{"", false},                                                    // empty string
	}
	for _, c := range cases {
		if got := isStrictPersonalBearerForm(c.token); got != c.want {
			t.Errorf("isStrictPersonalBearerForm(%q) = %v, want %v", c.token, got, c.want)
		}
	}
}

// TestRouteTokenPrefixForLog verifies the log redactor doesn't surface
// secret material. Used by the WARN log lines added for skipped rows.
func TestRouteTokenPrefixForLog(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"aikey_personal_" + hex64A, "aikey_personal_..."},
		{"aikey_vk_" + hex64A, "aikey_vk_..."},
		{"aikey_team_acc-1234", "aikey_team_..."},
		{"aikey_active_anthropic", "aikey_active_..."},
		{"sk-real-secret-leak", "<no-aikey-prefix>"},
		{"", "<empty>"},
	}
	for _, c := range cases {
		if got := routeTokenPrefixForLog(c.in); got != c.want {
			t.Errorf("routeTokenPrefixForLog(%q) = %q, want %q", c.in, got, c.want)
		}
		// Critical safety property: never leak the suffix material.
		got := routeTokenPrefixForLog(c.in)
		if c.in != "" && strings.Contains(c.in, hex64A) && strings.Contains(got, hex64A) {
			t.Errorf("routeTokenPrefixForLog leaked hex64 suffix: %q", got)
		}
	}
}
