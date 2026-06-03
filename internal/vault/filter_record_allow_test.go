package vault

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// TestGetFilterRecordAllow covers the settings-page record-allow flag read:
// missing row / 0 / NULL → false (default off), 1 → true.
func TestGetFilterRecordAllow(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE app_records (
		slug TEXT PRIMARY KEY,
		filter_stages TEXT,
		filter_record_allow INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatal(err)
	}
	r := &Reader{db: db}

	if v, err := r.GetFilterRecordAllow("missing"); err != nil || v {
		t.Fatalf("missing row → false,nil; got %v,%v", v, err)
	}
	if _, err := db.Exec(`INSERT INTO app_records (slug, filter_record_allow) VALUES ('off', 0)`); err != nil {
		t.Fatal(err)
	}
	if v, _ := r.GetFilterRecordAllow("off"); v {
		t.Fatal("filter_record_allow=0 must read false")
	}
	if _, err := db.Exec(`INSERT INTO app_records (slug, filter_record_allow) VALUES ('on', 1)`); err != nil {
		t.Fatal(err)
	}
	if v, _ := r.GetFilterRecordAllow("on"); !v {
		t.Fatal("filter_record_allow=1 must read true")
	}
}

// TestGetFilterRecordAllow_ColumnAbsent: a pre-flag vault (no column) must
// default to false, not error — the hasColumn guard.
func TestGetFilterRecordAllow_ColumnAbsent(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE app_records (slug TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	r := &Reader{db: db}
	if v, err := r.GetFilterRecordAllow("x"); err != nil || v {
		t.Fatalf("absent column must default false,nil; got %v,%v", v, err)
	}
}
