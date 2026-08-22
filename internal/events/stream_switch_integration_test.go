package events

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// S4 proved the SERVER settles a terminated span correctly, but the declaration
// there was sent by hand. This proves the other half: an upgraded client sends
// it BY ITSELF, before the first batch of that lane, without anyone asking.
//
// That ordering is the whole point. A batch that lands before the declaration
// leaves the stranded span looking like a gap, and reconcile eventually writes
// it into the known-loss ledger — the upgrade reproducing the defect it fixes.

type switchRecorder struct {
	mu       sync.Mutex
	order    []string // "switch" / "batch", in arrival order
	floors   map[string]int64
	switches int
}

func (s *switchRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.URL.Path {
		case "/v1/diagnostics/stream-switch":
			var req struct {
				OrgID string `json:"org_id"`
				Floor int64  `json:"floor_seq"`
			}
			_ = json.Unmarshal(body, &req)
			s.floors[req.OrgID] = req.Floor
			s.switches++
			s.order = append(s.order, "switch")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"applied":true,"contiguous_seq":700}`))
		case "/v1/usage-events:batch":
			s.order = append(s.order, "batch")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"accepted":1,"duplicated":0,"rejected":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestUpgradedClient_DeclaresStreamSwitchBeforeFirstBatch(t *testing.T) {
	rec := &switchRecorder{floors: map[string]int64{}}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	dir := t.TempDir()
	// A machine that ran the single-stream build: its legacy high-water is 700.
	if err := writeSeqStateAtomic(filepath.Join(dir, LegacySeqStateFile), 700); err != nil {
		t.Fatal(err)
	}
	la := NewLaneAllocator(dir, DefaultSeqBlockSize)

	r, err := NewReporter(&ReporterConfig{
		CollectorURL:   srv.URL,
		WALDir:         dir,
		SourceID:       "srcUp",
		SeqAlloc:       la,
		BatchSize:      10,
		UploadInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	// One event on the personal lane, numbered by the (seeded) allocator —
	// exactly what the proxy does on the first request after an upgrade.
	seq, err := la.Next(PersonalOrgSentinel)
	if err != nil {
		t.Fatal(err)
	}
	if seq <= 700 {
		t.Fatalf("seeded lane handed out %d, which the pre-split stream already used", seq)
	}
	ev := v2Event("up1", "srcUp", seq)
	ev.OrgID = PersonalOrgSentinel
	ev.RouteSource = "personal"
	r.Report(&ev)

	time.Sleep(300 * time.Millisecond)
	_ = r.Close()

	rec.mu.Lock()
	defer rec.mu.Unlock()

	if rec.switches == 0 {
		t.Fatal("the upgraded client never declared its stream switch. The span below the " +
			"seeded floor stays a gap, and reconcile will ledger it as loss — the upgrade " +
			"reproducing the defect it fixes")
	}
	if got := rec.floors[PersonalOrgSentinel]; got != 700 {
		t.Errorf("declared floor=%d, want 700 (the legacy high-water)", got)
	}
	if len(rec.order) < 2 || rec.order[0] != "switch" {
		t.Fatalf("declaration must arrive BEFORE the first batch, got order %v — a batch that "+
			"lands first leaves the span looking like a gap", rec.order)
	}
	// Steady state: the obligation is settled once, not re-sent on every batch.
	if got := la.PendingFloor(PersonalOrgSentinel); got != 0 {
		t.Errorf("floor still owed after a successful declaration: %d", got)
	}
}
