package events

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// mockCollector serves the D3 reconciliation endpoints + the batch ingest, and
// records what the client re-sent / confirmed-lost.
type mockCollector struct {
	gaps          []int64 // what /gaps returns
	reSentSeqs    []int64 // source_seqs received on the batch endpoint (re-sends)
	confirmedSeqs []int64 // seqs received on /confirm-lost
	mu            sync.Mutex
}

func (m *mockCollector) mux(srcID string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/diagnostics/completeness", func(w http.ResponseWriter, r *http.Request) {
		// One source (mine). gap_count is 0 ON PURPOSE: a FRESH gap (< MiddleGapAge)
		// reports gap_count=0 because completeness is age-gated. ReconcileGaps must
		// still process it via /gaps (active reconcile resolves immediately) — if it
		// re-gated on gap_count this test would see resent/confirmed = 0 and fail.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sources": []map[string]any{{
				"org_id": "o", "source_id": srcID, "gap_count": int64(0), "tail_pending": int64(0),
			}},
		})
	})
	mux.HandleFunc("/v1/diagnostics/gaps", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		g := append([]int64(nil), m.gaps...)
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"missing_seqs": g, "truncated": false})
	})
	mux.HandleFunc("/v1/usage-events:batch", func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		m.mu.Lock()
		for _, e := range req.Events {
			if e.SourceSeq != nil {
				m.reSentSeqs = append(m.reSentSeqs, *e.SourceSeq)
			}
		}
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(batchResponse{Accepted: len(req.Events)})
	})
	mux.HandleFunc("/v1/diagnostics/confirm-lost", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Seqs []int64 `json:"seqs"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.mu.Lock()
		m.confirmedSeqs = append(m.confirmedSeqs, body.Seqs...)
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"promoted": len(body.Seqs), "contiguous_seq": int64(0)})
	})
	return mux
}

// TestReconcileGaps_ResendAndConfirmLost is the D3 client-confirmed loop: of the
// server-reported gaps, the ones still in the WAL are RE-SENT (recoverable) and
// the ones the WAL no longer has are CONFIRMED LOST. Here seq 2 is in the WAL
// (written) and seq 5 is not.
func TestReconcileGaps_ResendAndConfirmLost(t *testing.T) {
	mc := &mockCollector{gaps: []int64{2, 5}}
	srv := httptest.NewServer(mc.mux("srcR"))
	defer srv.Close()

	r, err := NewReporter(&ReporterConfig{
		CollectorURL:   srv.URL,
		WALDir:         t.TempDir(),
		SourceID:       "srcR",
		BatchSize:      10,
		UploadInterval: time.Hour, // keep the periodic drain out of the way
	})
	if err != nil {
		t.Fatal(err)
	}
	// WAL now holds seqs 1,2,3 for srcR (Report appends synchronously).
	for seq := int64(1); seq <= 3; seq++ {
		e := v2Event("e"+string(rune('0'+seq)), "srcR", seq)
		r.Report(&e)
	}

	res, err := r.ReconcileGaps(context.Background())
	if err != nil {
		t.Fatalf("ReconcileGaps: %v", err)
	}
	if res.Sources != 1 {
		t.Fatalf("sources=%d, want 1", res.Sources)
	}
	if res.Resent != 1 {
		t.Fatalf("resent=%d, want 1 (seq 2 is in the WAL)", res.Resent)
	}
	if res.ConfirmedLost != 1 {
		t.Fatalf("confirmed_lost=%d, want 1 (seq 5 not in WAL)", res.ConfirmedLost)
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()
	if !containsSeq(mc.reSentSeqs, 2) {
		t.Fatalf("re-sent seqs %v missing 2 (the WAL-present gap)", mc.reSentSeqs)
	}
	if len(mc.confirmedSeqs) != 1 || mc.confirmedSeqs[0] != 5 {
		t.Fatalf("confirmed-lost seqs %v, want [5] (the WAL-absent gap)", mc.confirmedSeqs)
	}
}

// TestAuditStatus_LocalState confirms AuditStatus surfaces the local-only signals.
func TestAuditStatus_LocalState(t *testing.T) {
	dir := t.TempDir()
	sa, err := NewSeqAllocator(dir+"/seq.state", DefaultSeqBlockSize)
	if err != nil {
		t.Fatal(err)
	}
	defer sa.Close()
	for i := 0; i < 4; i++ {
		_, _ = sa.Next()
	}
	r, err := NewReporter(&ReporterConfig{
		WALDir:   dir,
		SourceID: "srcA",
		SeqAlloc: sa,
	})
	if err != nil {
		t.Fatal(err)
	}
	e1 := v2Event("e1", "srcA", 1)
	r.Report(&e1)

	st := r.AuditStatus()
	if st.SourceID != "srcA" {
		t.Fatalf("source_id=%q, want srcA", st.SourceID)
	}
	if st.AllocatedSeq != 4 {
		t.Fatalf("allocated_seq=%d, want 4", st.AllocatedSeq)
	}
	if st.WALFiles < 1 {
		t.Fatalf("wal_files=%d, want >=1", st.WALFiles)
	}
}

func containsSeq(s []int64, v int64) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
