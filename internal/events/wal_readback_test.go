package events

import (
	"os"
	"path/filepath"
	"testing"
)

func i64(v int64) *int64 { return &v }

// TestWAL_AppendThenReadBack is the round-trip invariant: events appended with
// delivery-integrity fields come back through ReadAllWAL with source_id /
// source_seq intact and schema tagged v2.
func TestWAL_AppendThenReadBack(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWALWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	for seq := int64(1); seq <= 3; seq++ {
		w.Append(ReportableEvent{
			EventID:   "e" + string(rune('0'+seq)),
			SourceID:  "srcA",
			SourceSeq: i64(seq),
		})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := ReadAllWAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("read back %d entries, want 3", len(entries))
	}
	for idx, e := range entries {
		wantSeq := int64(idx + 1)
		if e.SourceID != "srcA" {
			t.Errorf("entry %d source_id=%q want srcA", idx, e.SourceID)
		}
		if e.SourceSeq != wantSeq {
			t.Errorf("entry %d source_seq=%d want %d", idx, e.SourceSeq, wantSeq)
		}
		if e.SchemaVersion != WALSchemaV2 {
			t.Errorf("entry %d schema=%d want v2 (%d)", idx, e.SchemaVersion, WALSchemaV2)
		}
		if e.EventJSON.SourceSeq == nil || *e.EventJSON.SourceSeq != wantSeq {
			t.Errorf("entry %d nested event source_seq mismatch", idx)
		}
	}
}

// TestWAL_V1EntryStaysV1 confirms an event with no SourceSeq writes a v1-shaped
// entry (no source_seq) so legacy/offline events remain readable and are
// distinguishable from v2 — the gap-detection-exclusion invariant.
func TestWAL_V1EntryStaysV1(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWALWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	w.Append(ReportableEvent{EventID: "legacy"}) // no SourceSeq
	w.Close()

	entries, err := ReadAllWAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if entries[0].SchemaVersion != 1 {
		t.Errorf("legacy entry schema=%d want 1", entries[0].SchemaVersion)
	}
	if entries[0].SourceSeq != 0 || entries[0].SourceID != "" {
		t.Errorf("legacy entry should have empty source fields, got id=%q seq=%d",
			entries[0].SourceID, entries[0].SourceSeq)
	}
}

// TestWAL_MalformedLineTolerated proves a torn/garbage line (e.g. a crash
// mid-write) is skipped, not fatal — everything before and after still replays.
func TestWAL_MalformedLineTolerated(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWALWriter(dir)
	w.Append(ReportableEvent{EventID: "good1", SourceID: "s", SourceSeq: i64(1)})
	w.Close()

	// Append a garbage line directly to the (single) WAL file.
	files, _ := ListWALFiles(dir)
	if len(files) != 1 {
		t.Fatalf("expected 1 wal file, got %d", len(files))
	}
	f, _ := os.OpenFile(files[0], os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("{this is not valid json\n")
	f.Close()

	// Re-open writer (same hour file) and append another good entry.
	w2, _ := NewWALWriter(dir)
	w2.Append(ReportableEvent{EventID: "good2", SourceID: "s", SourceSeq: i64(2)})
	w2.Close()

	entries, err := ReadAllWAL(dir)
	if err != nil {
		t.Fatalf("ReadAllWAL must tolerate the bad line, got err: %v", err)
	}
	// 2 good entries parsed, garbage skipped.
	if len(entries) != 2 {
		t.Fatalf("want 2 good entries (garbage skipped), got %d", len(entries))
	}
	if entries[0].EventJSON.EventID != "good1" || entries[1].EventJSON.EventID != "good2" {
		t.Errorf("good entries mis-parsed: %q, %q",
			entries[0].EventJSON.EventID, entries[1].EventJSON.EventID)
	}
}

// TestWAL_WriteFailureCountsAndTags proves a WAL write failure (here: the
// underlying file handle is closed out from under the writer, simulating
// disk/IO loss) increments appendFailed so the externally-readable
// usage_wal_append_failed_total counter reflects it. The failure log now also
// carries event.name=usage.wal.write_failed / error.code=WAL_WRITE_FAILED for
// central diagnosis (logging-conventions); see GAP 3.
func TestWAL_WriteFailureCountsAndTags(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWALWriter(dir)
	if err != nil {
		t.Fatal(err)
	}

	// First Append succeeds and opens the hour file.
	w.Append(ReportableEvent{EventID: "ok1", SourceID: "s", SourceSeq: i64(1)})
	if got := w.AppendFailedTotal(); got != 0 {
		t.Fatalf("after good append appendFailed=%d, want 0", got)
	}

	// Close the underlying *os.File directly (not via w.Close, which also nils
	// w.file). The writer still thinks the file is open and same-hour, so the
	// next Append's ensureFile is a no-op and Write hits a closed descriptor →
	// guaranteed write error without depending on filesystem state.
	w.mu.Lock()
	if w.file == nil {
		w.mu.Unlock()
		t.Fatal("expected an open wal file after first append")
	}
	_ = w.file.Close()
	w.mu.Unlock()

	w.Append(ReportableEvent{EventID: "fail1", SourceID: "s", SourceSeq: i64(2)})

	if got := w.AppendFailedTotal(); got != 1 {
		t.Fatalf("after write-on-closed-fd appendFailed=%d, want 1", got)
	}
}

// TestWAL_ListFilesChronological confirms multi-file read order is chronological
// (lexical filename order == time order) so cold-start replay resumes oldest-first.
func TestWAL_ListFilesChronological(t *testing.T) {
	dir := t.TempDir()
	// Hand-create two hour files out of natural order to prove sorting.
	for _, name := range []string{"usage-20260530-18.jsonl", "usage-20260530-09.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := ListWALFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 ||
		filepath.Base(files[0]) != "usage-20260530-09.jsonl" ||
		filepath.Base(files[1]) != "usage-20260530-18.jsonl" {
		t.Fatalf("files not chronological: %v", files)
	}
}
