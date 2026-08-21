package events

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/aikeytime"
)

// A proxy that uploads to more than one collector must not tell either of them
// about the other's sequence numbers, and must reconcile with BOTH.
//
// Before bugfix 2026-08-20 it did neither: every batch carried the allocator's
// GLOBAL high-water, and reconcile only ever talked to the legacy single
// CollectorURL. On a Personal install logged into a team that meant the LOCAL
// collector was told "I allocated up to N" for seqs uploaded to the REMOTE team
// collector, computed the difference as its own tail gap, and the reconcile
// loop ledgered them in the LOCAL known-loss ledger — 479 rows of fiction.

// routedEvent is v2Event with an explicit route source.
//
// src is uniform across today's cases, which is why unparam flags it, but it is
// part of the event identity this helper exists to vary. Dropping it would force
// the first multi-source case to re-thread it through every call site.
//
//nolint:unparam // see the note above
func routedEvent(id, src string, seq int64, routeSource string) ReportableEvent {
	e := v2Event(id, src, seq)
	e.RouteSource = routeSource
	return e
}

func TestAllocatedSeq_NotSharedAcrossDestinations(t *testing.T) {
	csA, csB := newCaptureServer(false), newCaptureServer(false)
	srvA := httptest.NewServer(csA.handler())
	srvB := httptest.NewServer(csB.handler())
	defer srvA.Close()
	defer srvB.Close()

	dir := t.TempDir()
	sa, err := NewSeqAllocator(filepath.Join(dir, "seq.state"), DefaultSeqBlockSize)
	if err != nil {
		t.Fatal(err)
	}
	defer sa.Close()
	for i := 0; i < 6; i++ {
		if _, nErr := sa.Next(); nErr != nil {
			t.Fatal(nErr)
		}
	}

	r, err := NewReporter(&ReporterConfig{
		CollectorURL: srvA.URL,
		CollectorRoutes: map[string]string{
			"personal": srvA.URL,
			"team":     srvB.URL,
		},
		WALDir:         dir,
		SeqAlloc:       sa,
		BatchSize:      10,
		UploadInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	// seqs 1..2 → A (personal), seqs 5..6 → B (team).
	for _, e := range []ReportableEvent{
		routedEvent("p1", "srcA", 1, "personal"),
		routedEvent("p2", "srcA", 2, "personal"),
		routedEvent("t5", "srcA", 5, "team"),
		routedEvent("t6", "srcA", 6, "team"),
	} {
		ev := e
		r.Report(&ev)
	}
	time.Sleep(250 * time.Millisecond)
	r.Close()

	read := func(c *captureServer) int64 {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.lastAllocated == nil {
			t.Fatal("collector saw no allocated_seq at all")
		}
		return *c.lastAllocated
	}
	if got := read(csA); got > 2 {
		t.Errorf("collector A was told allocated_seq=%d, but only seqs 1..2 were routed to it — "+
			"it will treat 3..%d as its own tail gap and the reconcile loop will write them off "+
			"as lost in A's ledger", got, got)
	}
	if got := read(csB); got > 6 || got < 5 {
		t.Errorf("collector B was told allocated_seq=%d, want the high-water routed to B (5..6)", got)
	}
}

// diagServer answers just enough of the diagnostics surface for ReconcileGaps,
// and records that it was asked at all.
type diagServer struct {
	mu       sync.Mutex
	asked    bool
	sourceID string
}

func (d *diagServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/diagnostics/completeness":
			d.mu.Lock()
			d.asked = true
			d.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sources": []map[string]string{{"org_id": "o", "source_id": d.sourceID}},
			})
		case "/v1/diagnostics/gaps":
			_ = json.NewEncoder(w).Encode(map[string]any{"missing_seqs": []int64{}, "truncated": false})
		default:
			_ = json.NewEncoder(w).Encode(batchResponse{Accepted: 0})
		}
	}
}

func (d *diagServer) wasAsked() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.asked
}

// 能红: point reconcile back at a single base (the removed collectorBase()) and
// the team collector is never asked, so its deliveries go unreconciled forever
// while its seqs are written off against the local ledger.
func TestReconcile_AsksEveryDestination(t *testing.T) {
	dA := &diagServer{sourceID: "srcA"}
	dB := &diagServer{sourceID: "srcA"}
	srvA := httptest.NewServer(dA.handler())
	srvB := httptest.NewServer(dB.handler())
	defer srvA.Close()
	defer srvB.Close()

	r, err := NewReporter(&ReporterConfig{
		CollectorURL: srvA.URL,
		CollectorRoutes: map[string]string{
			"personal": srvA.URL,
			"team":     srvB.URL,
		},
		WALDir:         t.TempDir(),
		SourceID:       "srcA",
		BatchSize:      10,
		UploadInterval: time.Hour, // no drain interference
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if _, err := r.ReconcileGaps(context.Background()); err != nil {
		t.Fatalf("ReconcileGaps: %v", err)
	}
	if !dA.wasAsked() {
		t.Error("the local collector was never asked for completeness")
	}
	if !dB.wasAsked() {
		t.Error("the team collector was never asked for completeness — its deliveries are " +
			"unreconciled, and reconcile only knows about the local ledger")
	}
}

var _ = aikeytime.Now
