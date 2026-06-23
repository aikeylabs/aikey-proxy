package vault

// Tests for the App pipeline read paths (Phase 4 third-party Agent 接入,
// 2026-05-20).
//
// Covers:
//   - GetProviderBindingWithScope: profile_id scope routing ('default' vs
//     'app:<slug>') and the legacy GetProviderBinding wrapper delegating
//     to default scope without behavior change.
//   - GetAppRecord: row read + JSON column decode + missing-row + missing-
//     table (pre-Phase-4 vault) graceful nil return.
//   - GetAllAppRouteTokens: JOIN with app_records + status / expiration /
//     strict form filtering + upstreams JSON decode + LogValue redaction.
//   - isStrictAppBearerForm: predicate symmetry with personal form (Tier1App).
//
// Fixture approach mirrors route_token_form_test.go — hand-built in-memory
// SQLite, schema scoped to only the columns the readers SELECT. We avoid
// vault.Open + Argon2id keying because the readers under test are pure
// SQL+predicate work; constructing a Reader{db: ...} directly is the
// cleanest path. This is the same trade-off documented in
// route_token_form_test.go's header comment.

import (
	"database/sql"
	"log/slog"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// newTestReaderWithAppTables creates a Reader against an in-memory SQLite
// that has the App pipeline tables (app_records, app_keys) +
// user_profile_provider_bindings (for the scope tests).
//
// The schema MUST mirror aikey-cli/src/migrations.rs v1_0_0_baseline
// (the canonical writer). If the migration changes its CREATE TABLE
// shape, this fixture's CREATE statements must follow — caught by
// app_pipeline_tables_created_by_baseline (Rust side) cross-check.
func newTestReaderWithAppTables(t *testing.T) *Reader {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Enable foreign keys so CASCADE semantics match real vault behavior
	// (set by aikey-cli storage.rs::open_connection in production).
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatalf("enable foreign_keys: %v", err)
	}

	// 2026-05-20 fix: includes the user_profiles table + FK from
	// user_profile_provider_bindings.profile_id → user_profiles(id),
	// matching the real baseline schema (aikey-cli/src/migrations.rs).
	// The prior fixture omitted the FK, which allowed binding writes for
	// arbitrary profile_id values to silently succeed in tests but FAIL
	// at runtime — caught by AKL-107's authorize_atomic test.
	stmts := []string{
		`CREATE TABLE user_profiles (
			id TEXT PRIMARY KEY,
			is_active INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		)`,
		`INSERT OR IGNORE INTO user_profiles (id, is_active) VALUES ('default', 1)`,
		`CREATE TABLE app_records (
			slug TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			vendor TEXT,
			upstreams TEXT NOT NULL,
			app_kind TEXT NOT NULL DEFAULT 'third-party',
			follow_user_active INTEGER NOT NULL DEFAULT 0,
			-- B-mode columns (2026-05-23, credential-mode-architecture SPEC §3.1).
			-- Must stay in lockstep with aikey-cli/src/migrations.rs baseline DDL.
			bound_alias TEXT,
			bound_at INTEGER,
			requested_permissions TEXT,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		)`,
		`CREATE TABLE app_keys (
			key_id TEXT PRIMARY KEY,
			app_slug TEXT NOT NULL REFERENCES app_records(slug) ON DELETE CASCADE,
			route_token TEXT NOT NULL UNIQUE,
			token_hash TEXT,
			status TEXT NOT NULL DEFAULT 'active',
			expires_at INTEGER,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			last_used_at INTEGER
		)`,
		`CREATE TABLE user_profile_provider_bindings (
			profile_id TEXT NOT NULL,
			provider_code TEXT NOT NULL,
			key_source_type TEXT NOT NULL,
			key_source_ref TEXT NOT NULL,
			updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			PRIMARY KEY (profile_id, provider_code),
			FOREIGN KEY (profile_id) REFERENCES user_profiles(id)
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
	// Strict app bearer fixtures (74 chars total: prefix + 64-hex).
	appHex64A = "aikey_app_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	appHex64B = "aikey_app_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

// ---------------------------------------------------------------------------
// GetProviderBindingWithScope + legacy GetProviderBinding wrapper.
// ---------------------------------------------------------------------------

func TestGetProviderBindingWithScope_DefaultProfile(t *testing.T) {
	r := newTestReaderWithAppTables(t)

	_, err := r.db.Exec(
		"INSERT INTO user_profile_provider_bindings (profile_id, provider_code, key_source_type, key_source_ref) VALUES (?, ?, ?, ?)",
		"default", "anthropic", "personal", "my-claude-alias",
	)
	if err != nil {
		t.Fatalf("seed default binding: %v", err)
	}

	got, err := r.GetProviderBindingWithScope("default", "anthropic")
	if err != nil {
		t.Fatalf("GetProviderBindingWithScope: %v", err)
	}
	if got == nil {
		t.Fatal("expected binding, got nil")
	}
	if got.KeySourceType != "personal" || got.KeySourceRef != "my-claude-alias" {
		t.Errorf("binding fields: got %+v, want type=personal ref=my-claude-alias", got)
	}
}

func TestGetProviderBindingWithScope_AppProfile(t *testing.T) {
	r := newTestReaderWithAppTables(t)

	// FK-prerequisite: bindings under 'app:<slug>' scope require a
	// matching user_profiles row (real CLI writer seeds this as part of
	// `aikey app authorize`; tests must mirror that behavior).
	if _, err := r.db.Exec(
		"INSERT INTO user_profiles (id, is_active) VALUES ('app:degrade-detector', 0)",
	); err != nil {
		t.Fatalf("seed app profile row: %v", err)
	}

	// Seed an app-scoped binding ('app:degrade-detector') alongside an
	// unrelated default binding to verify the scope key is honored, not
	// just any binding for that provider.
	_, err := r.db.Exec(
		"INSERT INTO user_profile_provider_bindings (profile_id, provider_code, key_source_type, key_source_ref) VALUES (?, ?, ?, ?), (?, ?, ?, ?)",
		"default", "anthropic", "personal", "default-alias",
		"app:degrade-detector", "anthropic", "personal_oauth_account", "oauth-acct-xyz",
	)
	if err != nil {
		t.Fatalf("seed bindings: %v", err)
	}

	got, err := r.GetProviderBindingWithScope("app:degrade-detector", "anthropic")
	if err != nil {
		t.Fatalf("GetProviderBindingWithScope: %v", err)
	}
	if got == nil {
		t.Fatal("expected app-scoped binding, got nil")
	}
	if got.KeySourceType != "personal_oauth_account" {
		t.Errorf("KeySourceType = %q, want personal_oauth_account (app-scoped row, not default)", got.KeySourceType)
	}
	if got.KeySourceRef != "oauth-acct-xyz" {
		t.Errorf("KeySourceRef = %q, want oauth-acct-xyz", got.KeySourceRef)
	}
}

func TestGetProviderBindingWithScope_MissReturnsNil(t *testing.T) {
	r := newTestReaderWithAppTables(t)

	got, err := r.GetProviderBindingWithScope("app:nonexistent", "anthropic")
	if err != nil {
		t.Fatalf("GetProviderBindingWithScope: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on miss, got %+v", got)
	}
}

func TestGetProviderBinding_LegacyWrapperDelegatesToDefault(t *testing.T) {
	r := newTestReaderWithAppTables(t)

	// FK-prerequisite seed for app:test-agent.
	if _, err := r.db.Exec(
		"INSERT INTO user_profiles (id, is_active) VALUES ('app:test-agent', 0)",
	); err != nil {
		t.Fatalf("seed app profile row: %v", err)
	}

	// Seed only an app-scoped binding (NOT default). The legacy wrapper
	// must NOT return this — it's hard-wired to profile_id='default'.
	_, err := r.db.Exec(
		"INSERT INTO user_profile_provider_bindings (profile_id, provider_code, key_source_type, key_source_ref) VALUES (?, ?, ?, ?)",
		"app:test-agent", "anthropic", "personal", "should-not-leak",
	)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := r.GetProviderBinding("anthropic")
	if err != nil {
		t.Fatalf("GetProviderBinding: %v", err)
	}
	if got != nil {
		t.Errorf("legacy wrapper leaked app-scoped binding: %+v (must only see profile_id='default')", got)
	}

	// Now seed default — wrapper must surface it.
	_, err = r.db.Exec(
		"INSERT INTO user_profile_provider_bindings (profile_id, provider_code, key_source_type, key_source_ref) VALUES (?, ?, ?, ?)",
		"default", "anthropic", "team", "vk_default_team",
	)
	if err != nil {
		t.Fatalf("seed default: %v", err)
	}
	got, err = r.GetProviderBinding("anthropic")
	if err != nil {
		t.Fatalf("GetProviderBinding: %v", err)
	}
	if got == nil || got.KeySourceRef != "vk_default_team" {
		t.Errorf("legacy wrapper failed to surface default binding: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// GetAppRecord — single-row lookup + JSON decode.
// ---------------------------------------------------------------------------

func TestGetAppRecord_HappyPath(t *testing.T) {
	r := newTestReaderWithAppTables(t)

	_, err := r.db.Exec(
		`INSERT INTO app_records (slug, name, vendor, upstreams, app_kind, follow_user_active, requested_permissions, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"degrade-detector",
		"Degrade Detector",
		"haoge-labs",
		`["openai","anthropic"]`,
		"first-party",
		1,
		`["cloud_models","oauth_accounts"]`,
		1716200000,
		1716210000,
	)
	if err != nil {
		t.Fatalf("seed app_records: %v", err)
	}

	rec, err := r.GetAppRecord("degrade-detector")
	if err != nil {
		t.Fatalf("GetAppRecord: %v", err)
	}
	if rec == nil {
		t.Fatal("expected record, got nil")
	}
	if rec.Slug != "degrade-detector" || rec.Name != "Degrade Detector" || rec.Vendor != "haoge-labs" {
		t.Errorf("metadata fields: %+v", rec)
	}
	if rec.AppKind != "first-party" {
		t.Errorf("AppKind = %q, want first-party", rec.AppKind)
	}
	if !rec.FollowUserActive {
		t.Error("FollowUserActive = false, want true (integer column 1 should decode to true)")
	}
	if len(rec.Upstreams) != 2 || rec.Upstreams[0] != "openai" || rec.Upstreams[1] != "anthropic" {
		t.Errorf("Upstreams = %v, want [openai anthropic]", rec.Upstreams)
	}
	if len(rec.RequestedPermissions) != 2 {
		t.Errorf("RequestedPermissions = %v, want 2 entries", rec.RequestedPermissions)
	}
	if rec.CreatedAt != 1716200000 || rec.UpdatedAt != 1716210000 {
		t.Errorf("timestamps: created=%d updated=%d", rec.CreatedAt, rec.UpdatedAt)
	}
}

func TestGetAppRecord_MissReturnsNil(t *testing.T) {
	r := newTestReaderWithAppTables(t)

	got, err := r.GetAppRecord("nonexistent")
	if err != nil {
		t.Fatalf("GetAppRecord: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on miss, got %+v", got)
	}
}

func TestGetAppRecord_PreFeatureVaultGracefulNil(t *testing.T) {
	// Reader against a vault that does NOT have app_records (pre-Phase-4).
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	r := &Reader{db: db, cache: newCache()}

	got, err := r.GetAppRecord("anything")
	if err != nil {
		t.Fatalf("GetAppRecord must not error on pre-feature vault: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on missing table, got %+v", got)
	}
}

// TestGetAppRecord_ReadsBoundAlias pins the B-mode field plumbing
// (2026-05-23, credential-mode-architecture SPEC §3.1 / §6.1). A row with
// non-NULL bound_alias must surface AppRecord.BoundAlias + BoundAt to the
// App pipeline so resolve.go's B-mode short-circuit fires.
func TestGetAppRecord_ReadsBoundAlias(t *testing.T) {
	r := newTestReaderWithAppTables(t)

	_, err := r.db.Exec(
		`INSERT INTO app_records
		   (slug, name, upstreams, app_kind, follow_user_active,
		    bound_alias, bound_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"degrade-detector",
		"Degrade Detector",
		`["anthropic"]`,
		"first-party",
		0, // B mode: follow_user_active=0
		"user@host.com",
		1716200000,
	)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec, err := r.GetAppRecord("degrade-detector")
	if err != nil {
		t.Fatalf("GetAppRecord: %v", err)
	}
	if rec == nil {
		t.Fatal("expected record, got nil")
	}
	if rec.FollowUserActive {
		t.Error("FollowUserActive = true, want false (B mode)")
	}
	if rec.BoundAlias != "user@host.com" {
		t.Errorf("BoundAlias = %q, want user@host.com", rec.BoundAlias)
	}
	if rec.BoundAt != 1716200000 {
		t.Errorf("BoundAt = %d, want 1716200000", rec.BoundAt)
	}
}

// TestGetAppRecord_PreP2VaultLegacyShape exercises the backward-compat path:
// a vault file from before the 2026-05-23 P2 migration lacks bound_alias /
// bound_at columns; the extended SELECT errors with "no such column" and
// GetAppRecord must fall back to the 9-column shape gracefully, leaving
// BoundAlias = "" so the App pipeline keeps using A mode for legacy rows.
func TestGetAppRecord_PreP2VaultLegacyShape(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Pre-P2 schema: no bound_alias / bound_at columns.
	_, err = db.Exec(`CREATE TABLE app_records (
		slug TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		vendor TEXT,
		upstreams TEXT NOT NULL,
		app_kind TEXT NOT NULL DEFAULT 'third-party',
		follow_user_active INTEGER NOT NULL DEFAULT 0,
		requested_permissions TEXT,
		created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
		updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
	)`)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	_, err = db.Exec(
		`INSERT INTO app_records (slug, name, upstreams, app_kind, follow_user_active) VALUES
		 ('legacy-agent', 'Legacy Agent', '["openai"]', 'third-party', 1)`,
	)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := &Reader{db: db}
	rec, err := r.GetAppRecord("legacy-agent")
	if err != nil {
		t.Fatalf("GetAppRecord must gracefully fall back on pre-P2 vault: %v", err)
	}
	if rec == nil {
		t.Fatal("expected record from legacy-shape SELECT, got nil")
	}
	if rec.Slug != "legacy-agent" || rec.AppKind != "third-party" {
		t.Errorf("legacy fields not decoded: %+v", rec)
	}
	if !rec.FollowUserActive {
		t.Error("FollowUserActive should still decode to true on legacy shape")
	}
	if rec.BoundAlias != "" {
		t.Errorf("BoundAlias = %q, want empty (legacy vault has no column)", rec.BoundAlias)
	}
	if rec.BoundAt != 0 {
		t.Errorf("BoundAt = %d, want 0 (legacy vault has no column)", rec.BoundAt)
	}
}

// ---------------------------------------------------------------------------
// GetAllAppRouteTokens — JOIN + filtering.
// ---------------------------------------------------------------------------

func TestGetAllAppRouteTokens_HappyJOIN(t *testing.T) {
	r := newTestReaderWithAppTables(t)

	_, err := r.db.Exec(
		`INSERT INTO app_records (slug, name, upstreams, app_kind, follow_user_active) VALUES
		 ('agent-a', 'Agent A', '["openai"]', 'third-party', 0),
		 ('agent-b', 'Agent B', '["openai","anthropic"]', 'first-party', 1)`,
	)
	if err != nil {
		t.Fatalf("seed app_records: %v", err)
	}
	_, err = r.db.Exec(
		`INSERT INTO app_keys (key_id, app_slug, route_token, status) VALUES
		 ('k-a', 'agent-a', ?, 'active'),
		 ('k-b', 'agent-b', ?, 'active')`,
		appHex64A, appHex64B,
	)
	if err != nil {
		t.Fatalf("seed app_keys: %v", err)
	}

	got, err := r.GetAllAppRouteTokens()
	if err != nil {
		t.Fatalf("GetAllAppRouteTokens: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d tokens, want 2", len(got))
	}

	byKeyID := map[string]AppRouteToken{}
	for _, t := range got {
		byKeyID[t.KeyID] = t
	}

	a := byKeyID["k-a"]
	if a.AppSlug != "agent-a" || a.RouteToken != appHex64A || a.AppKind != "third-party" || a.FollowUserActive {
		t.Errorf("agent-a join row wrong: %+v", a)
	}
	if len(a.AllowedUpstreams) != 1 || a.AllowedUpstreams[0] != "openai" {
		t.Errorf("agent-a upstreams = %v, want [openai]", a.AllowedUpstreams)
	}

	b := byKeyID["k-b"]
	if b.AppSlug != "agent-b" || b.RouteToken != appHex64B || b.AppKind != "first-party" || !b.FollowUserActive {
		t.Errorf("agent-b join row wrong: %+v", b)
	}
	if len(b.AllowedUpstreams) != 2 {
		t.Errorf("agent-b upstreams = %v, want [openai anthropic]", b.AllowedUpstreams)
	}
}

func TestGetAllAppRouteTokens_SkipsInactiveAndExpired(t *testing.T) {
	r := newTestReaderWithAppTables(t)

	_, err := r.db.Exec(
		`INSERT INTO app_records (slug, name, upstreams) VALUES ('agent-a', 'A', '["openai"]')`,
	)
	if err != nil {
		t.Fatalf("seed app_records: %v", err)
	}

	pastEpoch := time.Now().Add(-1 * time.Hour).Unix()
	futureEpoch := time.Now().Add(1 * time.Hour).Unix()

	_, err = r.db.Exec(
		`INSERT INTO app_keys (key_id, app_slug, route_token, status, expires_at) VALUES
		 ('k-active', 'agent-a', ?, 'active', NULL),
		 ('k-active-future', 'agent-a', ?, 'active', ?),
		 ('k-expired', 'agent-a', ?, 'active', ?),
		 ('k-revoked', 'agent-a', ?, 'revoked', NULL),
		 ('k-paused', 'agent-a', ?, 'paused', NULL)`,
		"aikey_app_"+strings.Repeat("a", 64),
		"aikey_app_"+strings.Repeat("b", 64),
		futureEpoch,
		"aikey_app_"+strings.Repeat("c", 64),
		pastEpoch,
		"aikey_app_"+strings.Repeat("d", 64),
		"aikey_app_"+strings.Repeat("e", 64),
	)
	if err != nil {
		t.Fatalf("seed app_keys: %v", err)
	}

	got, err := r.GetAllAppRouteTokens()
	if err != nil {
		t.Fatalf("GetAllAppRouteTokens: %v", err)
	}

	got_ids := map[string]bool{}
	for _, t := range got {
		got_ids[t.KeyID] = true
	}
	if !got_ids["k-active"] {
		t.Error("k-active (status=active, no expiry) should be included")
	}
	if !got_ids["k-active-future"] {
		t.Error("k-active-future (status=active, future expiry) should be included")
	}
	if got_ids["k-expired"] {
		t.Error("k-expired (expires_at in past) MUST be skipped")
	}
	if got_ids["k-revoked"] {
		t.Error("k-revoked (status=revoked) MUST be skipped")
	}
	if got_ids["k-paused"] {
		t.Error("k-paused (status=paused) MUST be skipped")
	}
}

func TestGetAllAppRouteTokens_SkipsNonStrictFormWithWarn(t *testing.T) {
	r := newTestReaderWithAppTables(t)

	_, err := r.db.Exec(
		`INSERT INTO app_records (slug, name, upstreams) VALUES ('agent-a', 'A', '["openai"]')`,
	)
	if err != nil {
		t.Fatalf("seed app_records: %v", err)
	}

	rows := []struct {
		keyID       string
		routeToken  string
		description string
		shouldPass  bool
	}{
		{keyID: "strict", routeToken: appHex64A, shouldPass: true, description: "strict aikey_app_<64 lowercase hex>"},
		{keyID: "too-short", routeToken: "aikey_app_" + strings.Repeat("0", 63), shouldPass: false, description: "63 hex suffix"},
		{keyID: "too-long", routeToken: "aikey_app_" + strings.Repeat("0", 65), shouldPass: false, description: "65 hex suffix"},
		{keyID: "uppercase", routeToken: "aikey_app_" + strings.Repeat("A", 64), shouldPass: false, description: "uppercase hex"},
		{keyID: "non-hex", routeToken: "aikey_app_" + strings.Repeat("g", 64), shouldPass: false, description: "non-hex char"},
		{keyID: "wrong-prefix", routeToken: "aikey_personal_" + strings.Repeat("0", 64), shouldPass: false, description: "personal prefix in app_keys.route_token (writer bug)"},
		{keyID: "alias-form", routeToken: "aikey_app_my-agent", shouldPass: false, description: "alias-shaped suffix"},
	}

	for _, row := range rows {
		_, insErr := r.db.Exec(
			`INSERT INTO app_keys (key_id, app_slug, route_token, status) VALUES (?, 'agent-a', ?, 'active')`,
			row.keyID, row.routeToken,
		)
		if insErr != nil {
			t.Fatalf("insert %s: %v", row.keyID, insErr)
		}
	}

	got, err := r.GetAllAppRouteTokens()
	if err != nil {
		t.Fatalf("GetAllAppRouteTokens: %v", err)
	}
	gotIDs := map[string]bool{}
	for _, tok := range got {
		gotIDs[tok.KeyID] = true
	}
	for _, row := range rows {
		passed := gotIDs[row.keyID]
		if row.shouldPass && !passed {
			t.Errorf("row %q (%s) should pass form filter but was skipped", row.keyID, row.description)
		}
		if !row.shouldPass && passed {
			t.Errorf("row %q (%s) should be skipped but landed in result", row.keyID, row.description)
		}
	}
}

func TestGetAllAppRouteTokens_PreFeatureVaultEmpty(t *testing.T) {
	// Reader against a vault that does NOT have app_records / app_keys
	// — pre-Phase-4 vaults must return empty slice, not error.
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	r := &Reader{db: db, cache: newCache()}

	got, err := r.GetAllAppRouteTokens()
	if err != nil {
		t.Fatalf("must not error on pre-Phase-4 vault: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice on missing tables, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// LogValue: R6 risk mitigation (plaintext route_token MUST NOT leak via
// log lines that take an AppRouteToken as an attribute).
// ---------------------------------------------------------------------------

func TestAppRouteToken_LogValueRedactsRouteToken(t *testing.T) {
	tok := AppRouteToken{
		KeyID:            "k-1",
		AppSlug:          "agent-a",
		RouteToken:       appHex64A,
		Status:           "active",
		AppKind:          "third-party",
		FollowUserActive: false,
		AllowedUpstreams: []string{"openai"},
	}

	lv := tok.LogValue()
	if lv.Kind() != slog.KindGroup {
		t.Fatalf("LogValue Kind = %v, want Group", lv.Kind())
	}

	// Render the group to a string by iterating attrs, verifying the
	// plaintext token NEVER appears in any value.
	var rendered strings.Builder
	for _, a := range lv.Group() {
		rendered.WriteString(a.Key)
		rendered.WriteString("=")
		rendered.WriteString(a.Value.String())
		rendered.WriteString(" ")
	}
	out := rendered.String()
	if strings.Contains(out, "0123456789abcdef") {
		t.Errorf("LogValue leaked plaintext route_token: %s", out)
	}
	if !strings.Contains(out, "aikey_app_...") {
		t.Errorf("LogValue should include redacted prefix 'aikey_app_...', got: %s", out)
	}
	// Non-secret fields should appear unredacted.
	if !strings.Contains(out, "agent-a") || !strings.Contains(out, "third-party") {
		t.Errorf("LogValue dropped non-secret fields: %s", out)
	}
}

// ---------------------------------------------------------------------------
// isStrictAppBearerForm predicate (symmetry with TestIsStrictPersonalBearerForm).
// ---------------------------------------------------------------------------

func TestIsStrictAppBearerForm(t *testing.T) {
	cases := []struct {
		token string
		want  bool
	}{
		{appHex64A, true},
		{appHex64B, true},
		{"aikey_app_" + strings.Repeat("0", 64), true},
		{"aikey_app_" + strings.Repeat("f", 64), true},
		// Negatives.
		{"aikey_app_" + strings.Repeat("0", 63), false},      // 63 hex
		{"aikey_app_" + strings.Repeat("0", 65), false},      // 65 hex
		{"aikey_app_" + strings.Repeat("A", 64), false},      // uppercase
		{"aikey_app_my-agent", false},                        // alias form
		{"aikey_app_", false},                                // empty
		{"aikey_personal_" + strings.Repeat("0", 64), false}, // personal prefix
		{"aikey_team_acc-1234", false},                       // team prefix
		{"", false},
	}
	for _, c := range cases {
		if got := isStrictAppBearerForm(c.token); got != c.want {
			t.Errorf("isStrictAppBearerForm(%q) = %v, want %v", c.token, got, c.want)
		}
	}
}
