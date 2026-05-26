package apppipe

import (
	"sync"
	"testing"
	"time"
)

func TestHealthCache_RecordOverwritesPriorEntry(t *testing.T) {
	c := NewHealthCache()
	t1 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(5 * time.Minute)

	c.RecordCall("foo", 500, "internal_server_error", t1)
	c.RecordCall("foo", 200, "", t2)

	h, ok := c.Lookup("foo")
	if !ok {
		t.Fatalf("entry missing after RecordCall")
	}
	if h.StatusCode != 200 || h.ErrorType != "" {
		t.Fatalf("expected latest entry to overwrite prior; got %+v", h)
	}
	if !h.LastCallAt.Equal(t2) {
		t.Fatalf("expected LastCallAt=%v, got %v", t2, h.LastCallAt)
	}
}

func TestHealthCache_EmptySlugDropped(t *testing.T) {
	c := NewHealthCache()
	c.RecordCall("", 200, "", time.Now())
	if _, ok := c.Lookup(""); ok {
		t.Fatalf("empty slug should not produce an entry")
	}
	if got := len(c.Snapshot()); got != 0 {
		t.Fatalf("snapshot should be empty, got %d entries", got)
	}
}

func TestHealthCache_SnapshotIsStableSorted(t *testing.T) {
	c := NewHealthCache()
	now := time.Now()
	c.RecordCall("zeta", 200, "", now)
	c.RecordCall("alpha", 404, "not_found", now)
	c.RecordCall("mu", 500, "internal_server_error", now)

	snap := c.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(snap))
	}
	if snap[0].AppSlug != "alpha" || snap[1].AppSlug != "mu" || snap[2].AppSlug != "zeta" {
		t.Fatalf("expected sorted slugs alpha,mu,zeta; got %v %v %v",
			snap[0].AppSlug, snap[1].AppSlug, snap[2].AppSlug)
	}
}

func TestHealthCache_SnapshotIsCopy(t *testing.T) {
	c := NewHealthCache()
	c.RecordCall("foo", 200, "", time.Now())

	snap := c.Snapshot()
	snap[0].StatusCode = 999 // mutate caller-side copy

	h, _ := c.Lookup("foo")
	if h.StatusCode != 200 {
		t.Fatalf("snapshot must not share backing memory with cache; got mutated %d", h.StatusCode)
	}
}

func TestHealthCache_ConcurrentRecordCalls(t *testing.T) {
	// Stress the mutex: 16 goroutines × 1000 writes each, then verify the
	// snapshot has the right shape. Goal is to catch data races (run with
	// `go test -race`) rather than assert specific values.
	c := NewHealthCache()
	var wg sync.WaitGroup
	now := time.Now()
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				c.RecordCall("slug", 200, "", now)
			}
		}(g)
	}
	wg.Wait()

	if _, ok := c.Lookup("slug"); !ok {
		t.Fatalf("entry missing after concurrent writes")
	}
	if got := len(c.Snapshot()); got != 1 {
		t.Fatalf("expected single slug entry after concurrent writes, got %d", got)
	}
}
