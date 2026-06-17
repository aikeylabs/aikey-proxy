package quota

import (
	"database/sql"
	"encoding/json"
	"testing"

	_ "modernc.org/sqlite"
)

// newQuotaCacheDB creates an in-file SQLite vault with the real quota_rules_cache
// schema (kept in lockstep with aikey-cli/src/migrations.rs — the proxy can't run
// the Rust migration). Returns the path so WriteSubjects (which opens by path) and
// LoadSubjects (which takes a *sql.DB) can both exercise the SAME schema.
func newQuotaCacheDB(t *testing.T) (string, *sql.DB) {
	t.Helper()
	path := t.TempDir() + "/vault.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE quota_rules_cache (
		subject_id   TEXT PRIMARY KEY,
		subject_kind TEXT NOT NULL,
		members      TEXT,
		rules        TEXT NOT NULL DEFAULT '[]',
		baseline     TEXT,
		synced_at    INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	return path, db
}

func TestWriteSubjects_RoundTripThroughLoadSubjects(t *testing.T) {
	path, db := newQuotaCacheDB(t)

	subjects := []PolicySubject{
		{
			SubjectID:   "seat-a",
			SubjectKind: "seat",
			Rules:       json.RawMessage(`[{"metric":"tokens","period":"daily","limit_amount":100,"thresholds":[{"pct":100,"action":"hard_block"}]}]`),
			Baselines:   json.RawMessage(`[{"metric":"tokens","period":"daily","used":42}]`),
		},
		{
			SubjectID:   "grp-1",
			SubjectKind: "group",
			Members:     []string{"seat-a", "seat-b"},
			Rules:       json.RawMessage(`[{"metric":"usd","period":"monthly","limit_amount":50}]`),
		},
	}
	if err := WriteSubjects(path, subjects); err != nil {
		t.Fatalf("WriteSubjects: %v", err)
	}

	subs, err := LoadSubjects(db)
	if err != nil {
		t.Fatalf("LoadSubjects: %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("want 2 subjects, got %d", len(subs))
	}
	byID := map[string]Subject{}
	for _, s := range subs {
		byID[s.SubjectID] = s
	}
	seat := byID["seat-a"]
	if seat.SubjectKind != "seat" || len(seat.Members) != 0 {
		t.Errorf("seat-a parse wrong: %+v", seat)
	}
	if len(seat.Rules) != 1 || seat.Rules[0].Metric != "tokens" || seat.Rules[0].LimitAmount != 100 {
		t.Errorf("seat-a rules wrong: %+v", seat.Rules)
	}
	if len(seat.Baselines) != 1 || seat.Baselines[0].Used != 42 {
		t.Errorf("seat-a baseline wrong: %+v", seat.Baselines)
	}
	grp := byID["grp-1"]
	if grp.SubjectKind != "group" || len(grp.Members) != 2 {
		t.Errorf("grp-1 parse wrong: %+v", grp)
	}
	if len(grp.Baselines) != 0 {
		t.Errorf("grp-1 should have no baseline, got %+v", grp.Baselines)
	}
}

func TestWriteSubjects_FullReplaceClearsDeletedRows(t *testing.T) {
	// The poll full-replaces: a subsequent write with fewer (or zero) subjects must
	// drop the rows that are gone — this is how "admin deleted the rule" reaches the
	// proxy and clears enforcement.
	path, db := newQuotaCacheDB(t)
	if err := WriteSubjects(path, []PolicySubject{
		{SubjectID: "seat-a", SubjectKind: "seat", Rules: json.RawMessage(`[{"metric":"tokens","period":"daily","limit_amount":1}]`)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := WriteSubjects(path, []PolicySubject{}); err != nil {
		t.Fatalf("empty WriteSubjects: %v", err)
	}
	subs, err := LoadSubjects(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 0 {
		t.Errorf("empty write must clear table, got %d subjects", len(subs))
	}
}

func TestWriteSubjects_MissingTableTolerated(t *testing.T) {
	// A pre-Phase-2 vault has no quota_rules_cache. The poll must not error it.
	path := t.TempDir() + "/empty.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := WriteSubjects(path, []PolicySubject{
		{SubjectID: "seat-a", SubjectKind: "seat", Rules: json.RawMessage(`[]`)},
	}); err != nil {
		t.Errorf("missing table must be tolerated, got %v", err)
	}
}
