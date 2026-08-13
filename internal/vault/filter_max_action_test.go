package vault

import (
	"database/sql"
	"testing"
)

func TestGetFilterMaxAction(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE app_records (
		slug TEXT PRIMARY KEY,
		filter_max_action TEXT NOT NULL DEFAULT 'full'
			CHECK (filter_max_action IN ('full','warn'))
	)`); err != nil {
		t.Fatal(err)
	}
	r := &Reader{db: db}
	if got, err := r.GetFilterMaxAction("missing"); err != nil || got != "full" {
		t.Fatalf("missing row = %q, %v; want full", got, err)
	}
	if _, err := db.Exec(`INSERT INTO app_records (slug) VALUES ('default')`); err != nil {
		t.Fatal(err)
	}
	if got, err := r.GetFilterMaxAction("default"); err != nil || got != "full" {
		t.Fatalf("default row = %q, %v; want full", got, err)
	}
	if _, err := db.Exec(`INSERT INTO app_records (slug, filter_max_action) VALUES ('rollback','warn')`); err != nil {
		t.Fatal(err)
	}
	if got, err := r.GetFilterMaxAction("rollback"); err != nil || got != "warn" {
		t.Fatalf("warn row = %q, %v; want warn", got, err)
	}
	if _, err := db.Exec(`INSERT INTO app_records (slug, filter_max_action) VALUES ('bad','allow')`); err == nil {
		t.Fatal("database CHECK accepted invalid filter_max_action")
	}
}

func TestGetFilterMaxActionOldVaultDefaultsFull(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE app_records (slug TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	got, err := (&Reader{db: db}).GetFilterMaxAction("legacy")
	if err != nil || got != "full" {
		t.Fatalf("legacy vault = %q, %v; want full", got, err)
	}
}
