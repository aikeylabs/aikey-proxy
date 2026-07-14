package proxy

import (
	"net/http"
	"testing"
)

func TestPoolResetStore_RecordKeepsMaxAndSnapshotIsCopy(t *testing.T) {
	s := newPoolResetStore()
	if s.snapshot() != nil {
		t.Fatal("empty store must snapshot nil")
	}
	s.record("acc-1", 100)
	s.record("acc-1", 50)  // older → ignored (monotonic: resets only advance)
	s.record("acc-1", 200) // newer → kept
	s.record("acc-2", 300)
	s.record("", 999)    // empty id → ignored
	s.record("acc-x", 0) // non-positive → ignored

	snap := s.snapshot()
	if snap["acc-1"] != 200 {
		t.Fatalf("acc-1=%d want 200 (max kept, stale 50 ignored)", snap["acc-1"])
	}
	if snap["acc-2"] != 300 {
		t.Fatalf("acc-2=%d want 300", snap["acc-2"])
	}
	if len(snap) != 2 {
		t.Fatalf("snapshot size=%d want 2 (empty id + zero epoch dropped)", len(snap))
	}

	// snapshot is a copy — mutating it must not affect the store.
	snap["acc-1"] = 1
	if s.snapshot()["acc-1"] != 200 {
		t.Fatal("snapshot must be a defensive copy")
	}
}

func TestObservedResetEpoch(t *testing.T) {
	// Unified reset preferred.
	h := http.Header{}
	h.Set("anthropic-ratelimit-unified-reset", "1750000000")
	if e, ok := observedResetEpoch(h); !ok || e != 1750000000 {
		t.Fatalf("unified reset: e=%d ok=%v", e, ok)
	}
	// Per-window fallback when unified absent.
	h2 := http.Header{}
	h2.Set("anthropic-ratelimit-unified-5h-reset", "1750000500")
	if e, ok := observedResetEpoch(h2); !ok || e != 1750000500 {
		t.Fatalf("5h reset fallback: e=%d ok=%v", e, ok)
	}
	// No reset header → false.
	if _, ok := observedResetEpoch(http.Header{}); ok {
		t.Fatal("absent reset → false")
	}
	// Garbage → false (not recorded).
	h3 := http.Header{}
	h3.Set("anthropic-ratelimit-unified-reset", "notanum")
	if _, ok := observedResetEpoch(h3); ok {
		t.Fatal("garbage epoch → false")
	}
}
