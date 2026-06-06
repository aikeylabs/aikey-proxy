package quota

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// quota_local_usage DDL — MUST mirror aikey-cli/src/migrations.rs (the proxy
// can't run the Rust migration; keep in lockstep).
const localUsageDDL = `CREATE TABLE quota_local_usage (
	subject_id TEXT NOT NULL,
	metric     TEXT NOT NULL,
	period_key TEXT NOT NULL,
	increment  REAL NOT NULL DEFAULT 0,
	updated_at INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (subject_id, metric, period_key))`

func tempVault(t *testing.T) (string, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return path, db
}

func TestLocalUsage_RoundTripAndMissingTableTolerance(t *testing.T) {
	path, db := tempVault(t)

	// Missing table → load returns empty (pre-P0 vault), write is a no-op — neither errors.
	if rows, err := LoadLocalUsage(db); err != nil || len(rows) != 0 {
		t.Fatalf("missing table: want empty/no-error, got rows=%v err=%v", rows, err)
	}
	if err := WriteLocalUsage(path, []LocalUsageRow{{"seat-a", MetricUSD, "monthly:2026-06", 1.5}}); err != nil {
		t.Fatalf("missing table write must be a tolerant no-op, got %v", err)
	}

	if _, err := db.Exec(localUsageDDL); err != nil {
		t.Fatal(err)
	}

	// Write two rows, read them back.
	in := []LocalUsageRow{
		{"seat-a", MetricUSD, "monthly:2026-06", 0.42},
		{"seat-a", MetricTokens, "monthly:2026-06", 1000},
	}
	if err := WriteLocalUsage(path, in); err != nil {
		t.Fatal(err)
	}
	got, err := LoadLocalUsage(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 rows got %d: %+v", len(got), got)
	}

	// Upsert: same key with a new value overwrites (not duplicates).
	if err := WriteLocalUsage(path, []LocalUsageRow{{"seat-a", MetricUSD, "monthly:2026-06", 0.99}}); err != nil {
		t.Fatal(err)
	}
	got, _ = LoadLocalUsage(db)
	if len(got) != 2 {
		t.Fatalf("upsert must not duplicate; want 2 rows got %d", len(got))
	}
	for _, r := range got {
		if r.Metric == MetricUSD && r.Increment != 0.99 {
			t.Errorf("upsert: usd want 0.99 got %v", r.Increment)
		}
	}
}

func TestCounter_SeedIncrementAndRows(t *testing.T) {
	c := NewCounter()
	pk := "monthly:2026-06"

	// SeedIncrement SETs the increment; Get = baseline(0) + increment.
	c.SeedIncrement("seat-a", MetricUSD, pk, 0.42)
	if got := c.Get("seat-a", MetricUSD, pk); got != 0.42 {
		t.Fatalf("seeded increment: want 0.42 got %v", got)
	}

	// A zero-increment bucket (baseline only) must NOT appear in IncrementRows.
	c.SetBaseline("seat-b", MetricTokens, pk, 500)
	// A real accrual does appear.
	c.Add("seat-a", MetricTokens, pk, 1000)

	rows := c.IncrementRows()
	found := map[string]float64{}
	for _, r := range rows {
		found[r.SubjectID+"|"+r.Metric] = r.Increment
	}
	if found["seat-a|"+MetricUSD] != 0.42 || found["seat-a|"+MetricTokens] != 1000 {
		t.Errorf("IncrementRows missing/ wrong non-zero buckets: %+v", found)
	}
	if _, ok := found["seat-b|"+MetricTokens]; ok {
		t.Errorf("IncrementRows must skip zero-increment (baseline-only) buckets: %+v", found)
	}
}

// TestLocalUsage_RestartRecovery is the core P0 guarantee: usage accrued locally
// is persisted (write-behind) and an OFFLINE restart (new Counter, only the STALE
// baseline available) resumes from baseline + persisted increment, not zero.
func TestLocalUsage_RestartRecovery(t *testing.T) {
	path, db := tempVault(t)
	if _, err := db.Exec(localUsageDDL); err != nil {
		t.Fatal(err)
	}
	pk := "monthly:2026-06"

	// --- before crash --- baseline 5 (server) + local accrual 3 = used 8.
	a := NewCounter()
	a.SetBaseline("seat-a", MetricUSD, pk, 5)
	a.Add("seat-a", MetricUSD, pk, 3)
	if got := a.Get("seat-a", MetricUSD, pk); got != 8 {
		t.Fatalf("pre-crash used want 8 got %v", got)
	}
	// flush (write-behind)
	if err := WriteLocalUsage(path, a.IncrementRows()); err != nil {
		t.Fatal(err)
	}

	// --- OFFLINE restart --- new Counter; only the STALE baseline is re-seeded
	// (offline → no fresh snapshot), THEN the persisted increment is restored.
	b := NewCounter()
	b.SetBaseline("seat-a", MetricUSD, pk, 5) // stale baseline (offline, unchanged)
	rows, err := LoadLocalUsage(db)
	if err != nil {
		t.Fatal(err)
	}
	SeedLocalIncrements(b, rows)
	if got := b.Get("seat-a", MetricUSD, pk); got != 8 {
		t.Fatalf("offline restart must recover used=8 (not the stale baseline 5), got %v", got)
	}
}

// TestLocalUsage_P8NoDoubleCount: after recovery, when the server baseline finally
// catches up (it now includes the previously-local usage), P8 monotonic-max must
// absorb the increment to 0 — no double counting.
func TestLocalUsage_P8NoDoubleCount(t *testing.T) {
	pk := "monthly:2026-06"
	c := NewCounter()
	c.SetBaseline("seat-a", MetricUSD, pk, 5)
	c.SeedIncrement("seat-a", MetricUSD, pk, 3) // recovered increment → used 8

	// Server materializes the offline usage → baseline becomes 8 (>= used).
	c.SetBaseline("seat-a", MetricUSD, pk, 8)
	if got := c.Get("seat-a", MetricUSD, pk); got != 8 {
		t.Fatalf("baseline caught up: used must stay 8 (not 11), got %v", got)
	}
	// The increment is now absorbed → nothing left to persist.
	if rows := c.IncrementRows(); len(rows) != 0 {
		t.Errorf("absorbed increment must drop out of IncrementRows, got %+v", rows)
	}
}
