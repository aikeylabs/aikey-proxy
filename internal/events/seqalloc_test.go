package events

import (
	"os"
	"path/filepath"
	"testing"
)

func statePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "seq.state")
}

// TestSeqAllocator_MonotonicNoReuse is the core invariant: handed-out seqs are
// strictly increasing and never repeat, across block boundaries.
func TestSeqAllocator_MonotonicNoReuse(t *testing.T) {
	p := statePath(t)
	a, err := NewSeqAllocator(p, 4)
	if err != nil {
		t.Fatal(err)
	}
	var got []int64
	for i := 0; i < 10; i++ {
		s, err := a.Next()
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		got = append(got, s)
	}
	want := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("seq[%d]=%d want %d (full: %v)", i, got[i], want[i], got)
		}
	}
}

// TestSeqAllocator_CrashResumesAboveReserved simulates a HARD crash (no Close):
// the reserved block boundary persists, so the next start resumes ABOVE it and
// never reuses a seq from the lost block — the burned tail becomes a gap, never
// a reuse.
func TestSeqAllocator_CrashResumesAboveReserved(t *testing.T) {
	p := statePath(t)
	a, err := NewSeqAllocator(p, 4)
	if err != nil {
		t.Fatal(err)
	}
	// Hand out 1,2 — reserves block to hi=4 (fsync'd). Simulate crash: drop `a`
	// WITHOUT Close, so seq.state stays at 4 even though only 1,2 were used.
	_, _ = a.Next()
	_, _ = a.Next()

	a2, err := NewSeqAllocator(p, 4)
	if err != nil {
		t.Fatal(err)
	}
	s, err := a2.Next()
	if err != nil {
		t.Fatal(err)
	}
	// Must resume at 5 (=reservedHi+1), burning 3,4 as known-loss gaps — must
	// NOT reuse 3 (which is what a naive "scan max + 1" would wrongly do).
	if s != 5 {
		t.Fatalf("after crash, first seq = %d, want 5 (burn 3,4 not reuse)", s)
	}
}

// TestSeqAllocator_GracefulCloseZeroBurn confirms a graceful Close shrinks the
// persisted hi to the actual last-used seq, so the next start resumes exactly
// there with NO burned seqs (the common restart path stays gap-free).
func TestSeqAllocator_GracefulCloseZeroBurn(t *testing.T) {
	p := statePath(t)
	a, err := NewSeqAllocator(p, 256) // large block — naive would burn 253
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.Next() // 1
	_, _ = a.Next() // 2
	_, _ = a.Next() // 3
	if cErr := a.Close(); cErr != nil {
		t.Fatalf("Close: %v", cErr)
	}

	a2, err := NewSeqAllocator(p, 256)
	if err != nil {
		t.Fatal(err)
	}
	s, err := a2.Next()
	if err != nil {
		t.Fatal(err)
	}
	if s != 4 {
		t.Fatalf("after graceful close, first seq = %d, want 4 (zero burn)", s)
	}
}

// TestSeqAllocator_AllocatedReportsActualNotReserved guards the wire-reporting
// invariant: client_allocated_seq must be the actual last handed-out seq, NOT
// the reserved block boundary — otherwise the server manufactures false tail
// gaps for the unused reservation tail.
func TestSeqAllocator_AllocatedReportsActualNotReserved(t *testing.T) {
	p := statePath(t)
	a, err := NewSeqAllocator(p, 256)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.Next() // 1
	_, _ = a.Next() // 2
	// reservedHi is now 256, but only 2 handed out.
	if got := a.Allocated(); got != 2 {
		t.Fatalf("Allocated() = %d, want 2 (actual handed-out, not reserved hi 256)", got)
	}
}

// TestSeqAllocator_ReserveFailureBlocksAllocation proves a failed durable
// reserve does NOT hand out a seq (returns error instead) — preserving the
// never-reuse guarantee under disk failure. Failure is injected by making the
// state directory read-only AFTER construction (load succeeds on the absent
// file → 0), so the reserve's temp-file create fails.
func TestSeqAllocator_ReserveFailureBlocksAllocation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "seq.state")
	a, err := NewSeqAllocator(p, 4)
	if err != nil {
		t.Fatal(err)
	}
	// Make the dir read-only so CreateTemp inside writeSeqStateAtomic fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // restore so TempDir cleanup works
	if _, err := a.Next(); err == nil {
		t.Fatal("Next() must error when the reserve cannot be persisted, got nil")
	}
}

// TestSeqAllocator_CorruptStateErrors ensures a garbage state file fails loud at
// construction rather than silently resetting to 0 (which would reuse seqs).
func TestSeqAllocator_CorruptStateErrors(t *testing.T) {
	p := statePath(t)
	if err := os.WriteFile(p, []byte("not-a-number"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSeqAllocator(p, 4); err == nil {
		t.Fatal("NewSeqAllocator must error on corrupt state, got nil")
	}
}
