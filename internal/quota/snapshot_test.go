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
	if _, err := db.Exec(`CREATE TABLE quota_rules_cache (
		subject_id   TEXT PRIMARY KEY,
		subject_kind TEXT NOT NULL,
		members      TEXT,
		rules        TEXT NOT NULL DEFAULT '[]',
		baseline     TEXT,
		synced_at    INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO quota_rules_cache (subject_id, subject_kind, members, rules, baseline, synced_at) VALUES
		('seat-a','seat',NULL,'[{"metric":"usd","period":"monthly","limit_amount":50,"thresholds":[{"pct":100,"action":"hard_block"}]}]','[{"metric":"tokens","period":"monthly","used":42}]',0),
		('grp-1','group','["seat-a","seat-b"]','[{"metric":"tokens","period":"daily","limit_amount":1000000}]',NULL,0)`); err != nil {
		t.Fatal(err)
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
