package vault

// Tests for ListObserveSubscriptions + parseObserveStreamsJSON
// (credential-mode-architecture SPEC §1.4.3 / P3 step 1).

import (
	"database/sql"
	"reflect"
	"testing"
)

func newTestReaderWithObserveStreams(t *testing.T) *Reader {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	// Shape mirrors the credential-mode-architecture P3 baseline DDL.
	_, err = db.Exec(`CREATE TABLE app_records (
		slug TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		upstreams TEXT NOT NULL,
		app_kind TEXT NOT NULL DEFAULT 'third-party',
		follow_user_active INTEGER NOT NULL DEFAULT 0,
		bound_alias TEXT,
		bound_at INTEGER,
		observe_streams TEXT,
		observe_consent_at INTEGER,
		observe_consent_email TEXT,
		filter_stages TEXT,
		filter_priority INTEGER,
		filter_timeout_policy TEXT,
		requested_permissions TEXT,
		created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
		updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
	)`)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	return &Reader{db: db}
}

func seedAppRecord(t *testing.T, r *Reader, slug, observeStreams string) {
	t.Helper()
	var observeArg sql.NullString
	if observeStreams != "" {
		observeArg = sql.NullString{String: observeStreams, Valid: true}
	}
	_, err := r.db.Exec(
		`INSERT INTO app_records (slug, name, upstreams, app_kind, observe_streams)
		 VALUES (?, ?, ?, ?, ?)`,
		slug, slug, `["anthropic"]`, "first-party", observeArg,
	)
	if err != nil {
		t.Fatalf("seed %q: %v", slug, err)
	}
}

func TestListObserveSubscriptions_NoSubscribers(t *testing.T) {
	r := newTestReaderWithObserveStreams(t)
	subs, err := r.ListObserveSubscriptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("expected empty result, got %+v", subs)
	}
}

// TestListObserveSubscriptions_SimpleStringForm covers the most common
// case: degrade-detector's auto-injected `["user_chat"]` from
// ensure_first_party_app_keys.
func TestListObserveSubscriptions_SimpleStringForm(t *testing.T) {
	r := newTestReaderWithObserveStreams(t)
	seedAppRecord(t, r, "degrade-detector", `["user_chat"]`)

	subs, err := r.ListObserveSubscriptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []ObserveSubscription{
		{Slug: "degrade-detector", Stream: "user_chat", PayloadLevel: "metadata"},
	}
	if !reflect.DeepEqual(subs, want) {
		t.Errorf("got %+v, want %+v", subs, want)
	}
}

// TestListObserveSubscriptions_ObjectForm covers payload_level=full
// (opt-in, used by future compliance detection per SPEC §2 example).
func TestListObserveSubscriptions_ObjectForm(t *testing.T) {
	r := newTestReaderWithObserveStreams(t)
	seedAppRecord(t, r, "compliance-guard",
		`[{"stream":"user_chat","payload_level":"full"}]`)

	subs, err := r.ListObserveSubscriptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []ObserveSubscription{
		{Slug: "compliance-guard", Stream: "user_chat", PayloadLevel: "full"},
	}
	if !reflect.DeepEqual(subs, want) {
		t.Errorf("got %+v, want %+v", subs, want)
	}
}

// TestListObserveSubscriptions_MixedFormElementsCoexist verifies the
// per-element decode (string OR object) handles arrays that mix forms.
// Not strictly required by SPEC §1.4.3 but defensive — authoring tools
// shouldn't have to normalise before writing.
func TestListObserveSubscriptions_MixedFormElementsCoexist(t *testing.T) {
	r := newTestReaderWithObserveStreams(t)
	seedAppRecord(t, r, "mixed",
		`["user_chat", {"stream":"probe","payload_level":"full"}]`)

	subs, err := r.ListObserveSubscriptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []ObserveSubscription{
		{Slug: "mixed", Stream: "user_chat", PayloadLevel: "metadata"},
		{Slug: "mixed", Stream: "probe", PayloadLevel: "full"},
	}
	if !reflect.DeepEqual(subs, want) {
		t.Errorf("got %+v, want %+v", subs, want)
	}
}

// TestListObserveSubscriptions_MultipleSubscribers pins the multi-app
// case — ndjson-fanout will need to write per-(slug, stream) files.
func TestListObserveSubscriptions_MultipleSubscribers(t *testing.T) {
	r := newTestReaderWithObserveStreams(t)
	seedAppRecord(t, r, "degrade-detector", `["user_chat"]`)
	seedAppRecord(t, r, "billing-tracker", `["app_pipeline"]`)
	seedAppRecord(t, r, "audit-bot",
		`["user_chat","app_pipeline","probe"]`)

	subs, err := r.ListObserveSubscriptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subs) != 5 {
		t.Fatalf("expected 5 subscriptions (1+1+3), got %d: %+v", len(subs), subs)
	}
}

// TestListObserveSubscriptions_BadJSONRowSkipped pins the "one bad row
// must not silence the whole table" graceful-skip rule. Other rows
// should still surface.
func TestListObserveSubscriptions_BadJSONRowSkipped(t *testing.T) {
	r := newTestReaderWithObserveStreams(t)
	seedAppRecord(t, r, "good", `["user_chat"]`)
	seedAppRecord(t, r, "bad", `not valid JSON {{{`)
	seedAppRecord(t, r, "also-good", `["probe"]`)

	subs, err := r.ListObserveSubscriptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subs) != 2 {
		t.Errorf("expected 2 subscriptions (bad row skipped), got %d: %+v", len(subs), subs)
	}
	// Defensive: verify the GOOD slugs survived.
	got := map[string]bool{}
	for _, s := range subs {
		got[s.Slug] = true
	}
	if !got["good"] || !got["also-good"] {
		t.Errorf("expected both 'good' and 'also-good' to survive; got %+v", got)
	}
}

// TestListObserveSubscriptions_PreP3VaultReturnsNil — column absent on
// vaults predating P3. Must not crash; return (nil, nil) so the
// downstream ndjson-fanout observer noops gracefully.
func TestListObserveSubscriptions_PreP3VaultReturnsNil(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE app_records (
		slug TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		upstreams TEXT NOT NULL
		-- no observe_streams column — pre-P3 schema
	)`)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	r := &Reader{db: db}

	subs, err := r.ListObserveSubscriptions()
	if err != nil {
		t.Fatalf("pre-P3 vault must not error: %v", err)
	}
	if subs != nil {
		t.Errorf("expected nil slice for pre-P3 vault, got %+v", subs)
	}
}

// ---------------------------------------------------------------------------
// E-mode (sync_filter) — HasFilterAppsRegistered (SPEC §1.5.7 P3 stub).
// ---------------------------------------------------------------------------

func TestHasFilterAppsRegistered_FalseWhenAllNull(t *testing.T) {
	r := newTestReaderWithObserveStreams(t)
	_, err := r.db.Exec(
		`INSERT INTO app_records (slug, name, upstreams, app_kind) VALUES (?, ?, ?, ?)`,
		"plain", "Plain", `["anthropic"]`, "first-party",
	)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := r.HasFilterAppsRegistered()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Errorf("expected false (no filter_stages set), got true")
	}
}

func TestHasFilterAppsRegistered_TrueWhenAnyRowHasFilterStages(t *testing.T) {
	r := newTestReaderWithObserveStreams(t)
	_, err := r.db.Exec(
		`INSERT INTO app_records (slug, name, upstreams, app_kind, filter_stages) VALUES (?, ?, ?, ?, ?)`,
		"compliance", "Compliance", `["anthropic"]`, "first-party",
		`["pre_forward"]`,
	)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := r.HasFilterAppsRegistered()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Errorf("expected true (filter_stages declared), got false")
	}
}

func TestHasFilterAppsRegistered_FalseOnPreP3Vault(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE app_records (slug TEXT, name TEXT, upstreams TEXT)`)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	r := &Reader{db: db}

	got, err := r.HasFilterAppsRegistered()
	if err != nil {
		t.Fatalf("pre-P3 vault must not error: %v", err)
	}
	if got {
		t.Errorf("expected false on pre-P3 vault (no column), got true")
	}
}

// TestParseObserveStreamsJSON_RejectsMissingStreamField pins one of the
// few hard-fail cases: an object element without the required 'stream'
// key is a malformed declaration, surfaced as an error so the row gets
// skipped (caller logs WARN). Don't silently turn it into a no-op
// subscription (would mask config bugs).
func TestParseObserveStreamsJSON_RejectsMissingStreamField(t *testing.T) {
	_, err := parseObserveStreamsJSON("slug",
		`[{"payload_level":"full"}]`)
	if err == nil {
		t.Fatal("expected error for object missing stream field, got nil")
	}
}
