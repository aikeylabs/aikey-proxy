package events

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestContentWAL_RollAndCapEvictsOldest(t *testing.T) {
	dir := t.TempDir()
	// Tiny caps to force frequent rotation: ~1 entry per ~150B file, keep ≤3 files.
	w, err := NewContentWAL(dir, 150, 3)
	if err != nil {
		t.Fatalf("new content wal: %v", err)
	}

	const n = 12
	for i := 1; i <= n; i++ {
		rec := json.RawMessage(fmt.Sprintf(`{"event":"ev%02d","pad":"xxxxxxxxxxxxxxxxxxxx"}`, i))
		w.Append("src1", int64(i), rec)
	}
	w.Sync()

	files, err := ListContentWALFiles(dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(files) > 3 {
		t.Fatalf("file count=%d want ≤3 (cap evicts oldest)", len(files))
	}
	if w.EvictedTotal() == 0 {
		t.Fatalf("evicted=0 — cap eviction never fired (expected after %d rotations)", n)
	}

	entries, err := ReadAllContentWAL(dir)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("readall returned 0 entries")
	}
	// Survivors are the NEWEST entries, ascending by wal_seq, and the very last
	// (current file) must always survive.
	for i := 1; i < len(entries); i++ {
		if entries[i].WALSeq <= entries[i-1].WALSeq {
			t.Fatalf("entries not ascending by wal_seq: %d after %d", entries[i].WALSeq, entries[i-1].WALSeq)
		}
	}
	if got := entries[len(entries)-1].WALSeq; got != n {
		t.Fatalf("newest surviving wal_seq=%d want %d (current file must survive eviction)", got, n)
	}
	if entries[0].SourceSeq == 0 {
		t.Fatalf("source_seq not preserved through WAL round-trip")
	}
	// Record JSON survives verbatim.
	if !strings.Contains(string(entries[len(entries)-1].Record), fmt.Sprintf("ev%02d", n)) {
		t.Fatalf("record payload not preserved: %s", entries[len(entries)-1].Record)
	}
}

// A single entry larger than maxBytes still gets written (its own file) — no
// infinite-rotation / silent drop.
func TestContentWAL_OversizeSingleEntry(t *testing.T) {
	dir := t.TempDir()
	w, err := NewContentWAL(dir, 64, 100)
	if err != nil {
		t.Fatalf("new content wal: %v", err)
	}
	big := json.RawMessage(`{"big":"` + strings.Repeat("A", 500) + `"}`)
	w.Append("src1", 1, big)
	w.Sync()

	entries, err := ReadAllContentWAL(dir)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%d want 1 (oversize entry must still be stored)", len(entries))
	}
	if !strings.Contains(string(entries[0].Record), strings.Repeat("A", 500)) {
		t.Fatalf("oversize record truncated/lost")
	}
}

func TestContentWAL_PruneConfirmed(t *testing.T) {
	dir := t.TempDir()
	w, err := NewContentWAL(dir, 150, 100) // ~1 entry/file; high cap → no eviction
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	for i := int64(1); i <= 5; i++ {
		w.Append("s1", i, json.RawMessage(fmt.Sprintf(`{"n":%d,"pad":"xxxxxxxxxxxxxxxxxxxx"}`, i)))
	}
	w.Sync()
	cur := w.CurrentFileName()

	// Server confirmed contiguous seq 3 for s1 → files holding only seq ≤3 prune.
	pruned, err := PruneConfirmedContentWAL(dir, map[string]int64{"s1": 3}, cur)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 3 {
		t.Fatalf("pruned=%d want 3 (seq 1,2,3 confirmed)", pruned)
	}
	entries, _ := ReadAllContentWAL(dir)
	if len(entries) != 2 || entries[0].SourceSeq != 4 || entries[1].SourceSeq != 5 {
		t.Fatalf("after prune got %d entries want [seq4, seq5] (4 unconfirmed, 5 is current)", len(entries))
	}

	// An unknown source in the confirmed map prunes nothing (conserve, never lose).
	if p, _ := PruneConfirmedContentWAL(dir, map[string]int64{"other": 99}, cur); p != 0 {
		t.Fatalf("pruned=%d want 0 (s1 absent from confirmed map)", p)
	}
}
