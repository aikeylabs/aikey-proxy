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
)

// A lane seeded above the legacy stream owes the server a stream-switch
// declaration. Until it lands the server enumerates the terminated span as
// missing — and if the client answers "not in my WAL, confirm lost", those
// never-issued numbers become permanent DATA LOSS records.
//
// That is the exact pollution this work removes, and it would strike hardest
// where the declaration CANNOT land: observed live on winpc2, whose team
// collector answers 401 because its reverse proxy does not route /v1/ yet.
//
// "We cannot account for this yet" and "this was lost" are different facts, and
// only one of them is reversible. Below an owed floor the client must say
// neither — it holds back.
//
// 能红: remove the `seq <= owedFloor` guard in reconcileAgainst.

type lostRecorder struct {
	mu        sync.Mutex
	confirmed []int64
}

func (l *lostRecorder) handler(missing []int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/diagnostics/completeness":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"sources": []map[string]any{{
				"org_id": PersonalOrgSentinel, "source_id": "srcHold",
				"contiguous_seq": 0, "max_seen_seq": 900, "client_allocated_seq": 900,
				"gap_count": len(missing), "known_loss_count": 0, "status": "middle_gap",
			}}})
		case "/v1/diagnostics/gaps":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"org_id": PersonalOrgSentinel, "source_id": "srcHold",
				"missing_seqs": missing, "truncated": false,
			})
		case "/v1/diagnostics/confirm-lost":
			var body struct {
				Seqs []int64 `json:"seqs"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			l.mu.Lock()
			l.confirmed = append(l.confirmed, body.Seqs...)
			l.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"promoted":0}`))
		case "/v1/diagnostics/stream-switch":
			// Stands in for the broken remote: the declaration can never land.
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	})
}

func TestReconcile_HoldsBackGapsBelowAnUndeclaredFloor(t *testing.T) {
	rec := &lostRecorder{}
	// 700 and 701 are below the owed floor (terminated); 900 is above it and a
	// genuine unaccounted seq that MUST still be reported.
	srv := httptest.NewServer(rec.handler([]int64{700, 701, 900}))
	defer srv.Close()

	dir := t.TempDir()
	if err := writeSeqStateAtomic(filepath.Join(dir, LegacySeqStateFile), 800); err != nil {
		t.Fatal(err)
	}
	la := NewLaneAllocator(dir, DefaultSeqBlockSize)
	if _, err := la.Next(PersonalOrgSentinel); err != nil { // seeds the lane → owes floor 800
		t.Fatal(err)
	}
	if la.PendingFloor(PersonalOrgSentinel) != 800 {
		t.Fatalf("test setup: expected an owed floor of 800")
	}

	r, err := NewReporter(&ReporterConfig{
		CollectorURL:   srv.URL,
		WALDir:         dir,
		SourceID:       "srcHold",
		SeqAlloc:       la,
		BatchSize:      10,
		UploadInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if _, err := r.ReconcileGaps(context.Background()); err != nil {
		t.Fatalf("ReconcileGaps: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, seq := range rec.confirmed {
		if seq <= 800 {
			t.Fatalf("seq %d sits below the owed floor (800) and was confirmed LOST. "+
				"It was never issued to any event — filing it as loss fabricates a "+
				"permanent, irreversible loss record. Confirmed set: %v", seq, rec.confirmed)
		}
	}
	// And the guard must not swallow real gaps above the floor.
	var sawReal bool
	for _, seq := range rec.confirmed {
		if seq == 900 {
			sawReal = true
		}
	}
	if !sawReal {
		t.Errorf("seq 900 is above the floor and genuinely unaccounted — holding it back too "+
			"would trade false losses for undetectable real ones. Confirmed set: %v", rec.confirmed)
	}
}
