package quota

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSnapshotReverseIndexAndSubjectsForSeat(t *testing.T) {
	s := NewSnapshot()
	s.ReplaceAll([]Subject{
		{SubjectID: "seat-a", SubjectKind: KindSeat, Rules: []Rule{{Metric: "usd", Period: "monthly", LimitAmount: 50}}},
		{SubjectID: "grp-1", SubjectKind: KindGroup, Members: []string{"seat-a", "seat-b"},
			Rules: []Rule{{Metric: "tokens", Period: "daily", LimitAmount: 1_000_000}}},
	})
	if s.Len() != 2 {
		t.Fatalf("len: want 2 got %d", s.Len())
	}

	// seat-a: own subject + grp-1 (via reverse index)
	subs := s.SubjectsForSeat("seat-a")
	if len(subs) != 2 {
		t.Fatalf("seat-a: want 2 subjects got %d", len(subs))
	}
	ids := map[string]bool{}
	for _, x := range subs {
		ids[x.SubjectID] = true
	}
	if !ids["seat-a"] || !ids["grp-1"] {
		t.Errorf("seat-a applicable subjects wrong: %v", ids)
	}

	// seat-b: only grp-1 (no own seat subject)
	subB := s.SubjectsForSeat("seat-b")
	if len(subB) != 1 || subB[0].SubjectID != "grp-1" {
		t.Errorf("seat-b: want only grp-1, got %+v", subB)
	}

	// seat-c: no quota at all
	if subC := s.SubjectsForSeat("seat-c"); subC != nil {
		t.Errorf("seat-c: want nil, got %+v", subC)
	}

	// ReplaceAll(nil) clears both the subject map and the reverse index.
	s.ReplaceAll(nil)
	if s.Len() != 0 || s.SubjectsForSeat("seat-a") != nil {
		t.Error("ReplaceAll(nil) must clear snapshot + index")
	}
}

func TestLoadPriceSummary(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Tolerance: no config table (pre-Phase-2 vault) → (nil, nil), not an error.
	if ps, lerr := LoadPriceSummary(db); lerr != nil || ps != nil {
		t.Fatalf("missing config table: want (nil,nil) got (%v,%v)", ps, lerr)
	}

	// config kv table mirrors aikey-cli vault (key TEXT PK, value BLOB).
	if _, cerr := db.Exec(`CREATE TABLE config (key TEXT PRIMARY KEY, value BLOB NOT NULL)`); cerr != nil {
		t.Fatal(cerr)
	}
	// Absent key → still (nil, nil) (fall back to floor, don't error).
	if ps, lerr := LoadPriceSummary(db); lerr != nil || ps != nil {
		t.Fatalf("absent key: want (nil,nil) got (%v,%v)", ps, lerr)
	}

	// Insert the summary exactly as the CLI persists it (key quota.price_summary).
	const summary = `{"version":"v1","models":{"claude-opus-4-8":{"input":5e-6,"output":2.5e-5,"cache_creation":6.25e-6,"cache_read":5e-7,"reasoning":2.5e-5}}}`
	if _, ierr := db.Exec(`INSERT INTO config (key, value) VALUES (?, ?)`, quotaPriceSummaryKey, []byte(summary)); ierr != nil {
		t.Fatal(ierr)
	}
	ps, err := LoadPriceSummary(db)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if ps == nil || ps.Version != "v1" {
		t.Fatalf("want version v1, got %+v", ps)
	}
	op, ok := ps.Models["claude-opus-4-8"]
	if !ok || op.Input != 5e-6 || op.Output != 2.5e-5 || op.CacheRead != 5e-7 {
		t.Fatalf("opus-4-8 rates wrong: %+v (ok=%v)", op, ok)
	}

	// Holder: atomic set/get round-trips.
	snap := NewSnapshot()
	if snap.PriceSummary() != nil {
		t.Error("fresh snapshot must have nil price summary")
	}
	snap.SetPriceSummary(ps)
	if got := snap.PriceSummary(); got == nil || got.Version != "v1" {
		t.Errorf("holder round-trip failed: %+v", got)
	}
}

func TestLoadSubjects(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Tolerance: a vault that predates the Phase 2 schema → empty, not an error.
	subs, err := LoadSubjects(db)
	if err != nil {
		t.Fatalf("missing table must not error, got %v", err)
	}
	if len(subs) != 0 {
		t.Fatalf("missing table: want 0 subjects got %d", len(subs))
	}

	// Schema MUST mirror aikey-cli/src/migrations.rs quota_rules_cache (the
	// proxy can't run the Rust migration; keep this in lockstep with it).
	if _, cerr := db.Exec(`CREATE TABLE quota_rules_cache (
		subject_id   TEXT PRIMARY KEY,
		subject_kind TEXT NOT NULL,
		members      TEXT,
		rules        TEXT NOT NULL DEFAULT '[]',
		baseline     TEXT,
		synced_at    INTEGER NOT NULL DEFAULT 0)`); cerr != nil {
		t.Fatal(cerr)
	}
	if _, ierr := db.Exec(`INSERT INTO quota_rules_cache (subject_id, subject_kind, members, rules, baseline, synced_at) VALUES
		('seat-a','seat',NULL,'[{"metric":"usd","period":"monthly","limit_amount":50,"thresholds":[{"pct":100,"action":"hard_block"}]}]','[{"metric":"tokens","period":"monthly","used":42}]',0),
		('grp-1','group','["seat-a","seat-b"]','[{"metric":"tokens","period":"daily","limit_amount":1000000}]',NULL,0)`); ierr != nil {
		t.Fatal(ierr)
	}

	subs, err = LoadSubjects(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 2 {
		t.Fatalf("want 2 subjects got %d", len(subs))
	}
	byID := map[string]Subject{}
	for _, s := range subs {
		byID[s.SubjectID] = s
	}
	seat := byID["seat-a"]
	if seat.SubjectKind != "seat" || len(seat.Members) != 0 {
		t.Errorf("seat parse wrong: %+v", seat)
	}
	if len(seat.Rules) != 1 || seat.Rules[0].Metric != "usd" || seat.Rules[0].LimitAmount != 50 {
		t.Errorf("seat rules parse wrong: %+v", seat.Rules)
	}
	if len(seat.Rules[0].Thresholds) != 1 || seat.Rules[0].Thresholds[0].Pct != 100 ||
		seat.Rules[0].Thresholds[0].Action != "hard_block" {
		t.Errorf("threshold parse wrong: %+v", seat.Rules[0].Thresholds)
	}
	grp := byID["grp-1"]
	if len(grp.Members) != 2 || grp.Members[0] != "seat-a" {
		t.Errorf("group members parse wrong: %v", grp.Members)
	}
	// Stage 4 baseline column parses.
	if len(seat.Baselines) != 1 || seat.Baselines[0].Metric != "tokens" || seat.Baselines[0].Used != 42 {
		t.Errorf("baseline parse wrong: %+v", seat.Baselines)
	}
	if len(grp.Baselines) != 0 {
		t.Errorf("grp baseline should be empty (NULL), got %+v", grp.Baselines)
	}
}
