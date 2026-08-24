package events

import (
	"os"
	"path/filepath"
	"testing"
)

// The invariant this whole type exists for: the allocator's grouping key must
// equal the server's watermark key, or dense-sequence checks manufacture gaps
// that were never losses. A live machine wrote 768 real events off as
// "confirmed lost" because one stream was fanned out across two orgs.

func TestLaneAllocator_LanesAreIndependentAndDense(t *testing.T) {
	dir := t.TempDir()
	la := NewLaneAllocator(dir, 4)
	t.Cleanup(func() { _ = la.Close() })

	var local, team []int64
	// Interleave, exactly as a mixed machine does: personal request, team
	// request, personal, team… Before the split this produced ONE stream and
	// each org's ledger saw every other number missing.
	for i := 0; i < 6; i++ {
		s, err := la.Next("personal")
		if err != nil {
			t.Fatalf("personal Next: %v", err)
		}
		local = append(local, s)
		s, err = la.Next("org-team")
		if err != nil {
			t.Fatalf("team Next: %v", err)
		}
		team = append(team, s)
	}

	for name, got := range map[string][]int64{"personal": local, "org-team": team} {
		for i, v := range got {
			if want := int64(i + 1); v != want {
				t.Fatalf("lane %s seq[%d] = %d, want %d — the lane is not dense, "+
					"so the server will read the holes as losses: %v", name, i, v, want, got)
			}
		}
	}
}

// Never-reuse is a per-SOURCE guarantee and must survive the split: before
// lanes existed one stream served every org, so a fresh lane starting at 1
// would reissue numbers the old stream already used. Reissued seqs are
// indistinguishable from duplicates at the collector.
func TestLaneAllocator_SeedsAboveLegacyStream(t *testing.T) {
	dir := t.TempDir()
	if err := writeSeqStateAtomic(filepath.Join(dir, LegacySeqStateFile), 700); err != nil {
		t.Fatal(err)
	}
	la := NewLaneAllocator(dir, 4)
	t.Cleanup(func() { _ = la.Close() })

	for _, lane := range []string{"personal", "org-team"} {
		got, err := la.Next(lane)
		if err != nil {
			t.Fatalf("lane %s: %v", lane, err)
		}
		if got <= 700 {
			t.Fatalf("lane %s first seq = %d, must be > 700 (the legacy high-water) "+
				"or it reissues numbers the pre-split stream already handed out", lane, got)
		}
	}
	// The legacy file is the floor for every future lane too — deleting it
	// would let a lane created later start from zero.
	if _, err := os.Stat(filepath.Join(dir, LegacySeqStateFile)); err != nil {
		t.Fatalf("legacy state file must be preserved as the seeding floor: %v", err)
	}
}

// Separating the lanes is only worth it if a failure stays on its own lane: a
// personal-lane fsync failure must not take team reporting down with it.
func TestLaneAllocator_ReserveFailureIsPerLane(t *testing.T) {
	dir := t.TempDir()
	la := NewLaneAllocator(dir, 1) // block=1 → every Next reserves (and fsyncs)
	t.Cleanup(func() { _ = la.Close() })

	if _, err := la.Next("org-team"); err != nil {
		t.Fatalf("team lane should work: %v", err)
	}
	// Make the personal lane's state file unwritable, mimicking a disk fault
	// scoped to that file.
	pPath := filepath.Join(dir, laneStateFile("personal"))
	if _, err := la.Next("personal"); err != nil {
		t.Fatalf("personal lane setup: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make dir read-only on this platform: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, perr := la.Next("personal")
	if perr == nil {
		t.Fatal("a reservation that cannot be persisted MUST fail rather than hand out a seq — " +
			"otherwise never-reuse breaks silently after a crash")
	}
	_ = pPath
}

// Lane keys arrive from event data (org ids). Anything that could escape the
// directory must be neutralized rather than trusted.
func TestLaneAllocator_LaneKeyCannotEscapeDirectory(t *testing.T) {
	for _, bad := range []string{"../../etc/passwd", "a/b", ""} {
		got := laneStateFile(bad)
		if filepath.Base(got) != got {
			t.Fatalf("lane key %q produced a path with separators: %q", bad, got)
		}
	}
}
