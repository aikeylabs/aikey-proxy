package events

import (
	"path/filepath"
	"testing"
)

// Seeding a lane above the legacy single stream's high-water is what keeps
// never-reuse intact across the split — and it strands a bounded span the
// server will read as a gap until it is told that span is TERMINATED. The
// obligation to say so must be RECORDED at seeding time, or an upgraded machine
// silently accumulates a gap per lane and reconcile eventually ledgers it as
// loss: the upgrade would reproduce the defect it fixes.
//
// 能红: drop the `l.pendingFloor[lane] = legacyHi` line in For().
func TestLaneAllocator_SeedingOwesAStreamSwitchDeclaration(t *testing.T) {
	dir := t.TempDir()
	if err := writeSeqStateAtomic(filepath.Join(dir, LegacySeqStateFile), 700); err != nil {
		t.Fatal(err)
	}
	la := NewLaneAllocator(dir, 4)
	t.Cleanup(func() { _ = la.Close() })

	if _, err := la.Next("personal"); err != nil {
		t.Fatal(err)
	}
	if got := la.PendingFloor("personal"); got != 700 {
		t.Fatalf("seeded lane owes floor=%d, want 700 — without the declaration the "+
			"span below it becomes a gap and then a fabricated loss record", got)
	}

	// Cleared only after the server accepted it. Clearing on a failed send
	// would drop the obligation forever, which is why the reporter clears
	// AFTER a 2xx and not before.
	la.ClearPendingFloor("personal")
	if got := la.PendingFloor("personal"); got != 0 {
		t.Fatalf("floor still owed after clear: %d", got)
	}
}

// A machine with no legacy stream (fresh install) owes nothing — the
// declaration must not fire for every new lane forever.
func TestLaneAllocator_FreshInstallOwesNothing(t *testing.T) {
	la := NewLaneAllocator(t.TempDir(), 4)
	t.Cleanup(func() { _ = la.Close() })
	if _, err := la.Next("personal"); err != nil {
		t.Fatal(err)
	}
	if got := la.PendingFloor("personal"); got != 0 {
		t.Fatalf("a fresh install owes floor=%d, want 0 — declaring on every new lane "+
			"would turn a one-off upgrade step into permanent traffic", got)
	}
}
