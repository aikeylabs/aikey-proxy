package events

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mkWALFile creates an empty WAL file named for the given age (days before now).
func mkWALFile(t *testing.T, dir string, now time.Time, ageDays int) string {
	t.Helper()
	name := "usage-" + now.UTC().AddDate(0, 0, -ageDays).Format("20060102-15") + ".jsonl"
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// TestRetentionSweep_ArchivesExpiresPrunes is the fence test for the 费用小票
// §11 retention design (2026-06-10 decision (a)): live WAL files past
// retention move to usage-wal-archive/, archived files past the archive
// window are deleted, fresh files are untouched, and usage_events rows past
// retention are pruned while fresh rows survive.
func TestRetentionSweep_ArchivesExpiresPrunes(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	fresh := mkWALFile(t, dir, now, 5)    // stays live
	expired := mkWALFile(t, dir, now, 40) // → archive
	// Pre-existing archive contents: one inside the window, one past it.
	archiveDir := filepath.Join(dir, WALArchiveSubdir)
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	archKeep := mkWALFile(t, archiveDir, now, 40)    // 40d < 90d → kept
	archDelete := mkWALFile(t, archiveDir, now, 100) // 100d > 90d → deleted
	// Malformed name: parser must skip, never guess.
	malformed := filepath.Join(dir, "usage-notadate.jsonl")
	if err := os.WriteFile(malformed, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := OpenStore(filepath.Join(dir, "events.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if insErr := store.Insert([]UsageEvent{
		{Timestamp: now.AddDate(0, 0, -40), VirtualKeyID: "vk_old", Provider: "anthropic"},
		{Timestamp: now.AddDate(0, 0, -5), VirtualKeyID: "vk_new", Provider: "anthropic"},
	}); insErr != nil {
		t.Fatalf("seed events: %v", insErr)
	}

	res := RunRetentionSweep(RetentionConfig{WALDir: dir, RetentionDays: 30, ArchiveDays: 90}, store, now)

	if len(res.Errors) != 0 {
		t.Fatalf("sweep errors: %v", res.Errors)
	}
	if res.WALArchived != 1 || res.ArchiveDeleted != 1 || res.EventsPruned != 1 {
		t.Fatalf("got archived=%d deleted=%d pruned=%d, want 1/1/1", res.WALArchived, res.ArchiveDeleted, res.EventsPruned)
	}
	assertExists(t, fresh, true)
	assertExists(t, expired, false)
	assertExists(t, filepath.Join(archiveDir, filepath.Base(expired)), true)
	assertExists(t, archKeep, true)
	assertExists(t, archDelete, false)
	assertExists(t, malformed, true)

	// The archived file must be invisible to every WAL reader path:
	// ListWALFiles is the shared lister (reporter / watch / statusline).
	live, err := ListWALFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range live {
		if filepath.Base(f) == filepath.Base(expired) {
			t.Fatalf("archived file still visible to ListWALFiles: %s", f)
		}
	}

	// Pruned table keeps only the fresh row.
	byVKey, _, err := store.QueryStats()
	if err != nil {
		t.Fatal(err)
	}
	if byVKey["vk_old"] != 0 || byVKey["vk_new"] != 1 {
		t.Fatalf("prune wrong rows: stats=%v (want vk_old gone, vk_new kept)", byVKey)
	}

	// Idempotency: a second sweep finds nothing to do.
	res2 := RunRetentionSweep(RetentionConfig{WALDir: dir, RetentionDays: 30, ArchiveDays: 90}, store, now)
	if res2.WALArchived != 0 || res2.ArchiveDeleted != 0 || res2.EventsPruned != 0 || len(res2.Errors) != 0 {
		t.Fatalf("second sweep not a no-op: %+v", res2)
	}
}

// TestRetentionSweep_NegativeArchiveDaysKeepsArchivesForever pins the
// operator opt-out: wal_archive_days < 0 means archived files are never
// deleted, while live-file archiving still runs.
func TestRetentionSweep_NegativeArchiveDaysKeepsArchivesForever(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	archiveDir := filepath.Join(dir, WALArchiveSubdir)
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ancient := mkWALFile(t, archiveDir, now, 400)

	res := RunRetentionSweep(RetentionConfig{WALDir: dir, RetentionDays: 30, ArchiveDays: -1}, nil, now)
	if res.ArchiveDeleted != 0 {
		t.Fatalf("ArchiveDays=-1 must never delete, got %d", res.ArchiveDeleted)
	}
	assertExists(t, ancient, true)
}

func assertExists(t *testing.T, path string, want bool) {
	t.Helper()
	_, err := os.Stat(path)
	got := err == nil
	if got != want {
		t.Fatalf("%s: exists=%v, want %v", path, got, want)
	}
}
