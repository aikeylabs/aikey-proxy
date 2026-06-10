package events

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/aikeytime"
)

// TestReporter_RetryableFailure_WALDrivenRetry pins the B' delivery contract
// (2026-06-09 缺口2): a RETRYABLE upload failure (5xx/429/network) must NOT be
// dead-lettered and must NOT advance the outbox cursors — the events stay in the
// WAL and a later drain re-sends them. It also pins the non-blocking backoff
// gate: while armed, an (un-forced) drain skips the upload attempt instead of
// hammering a down collector every tick. The old behavior blocked the pump with
// in-line time.Sleep and dead-lettered on exhaustion; this test would fail
// against that model.
func TestReporter_RetryableFailure_WALDrivenRetry(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	var received atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			// 503 → classifyUploadError → retryableFailure
			http.Error(w, "collector down", http.StatusServiceUnavailable)
			return
		}
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		received.Add(int64(len(req.Events)))
		json.NewEncoder(w).Encode(batchResponse{Accepted: len(req.Events)})
	}))
	defer srv.Close()

	walDir := t.TempDir()
	reporter, err := NewReporter(ReporterConfig{
		CollectorURL: srv.URL,
		WALDir:       walDir,
		BatchSize:    10,
		// Long interval so the background ticker doesn't interfere while the test
		// drives drains explicitly; the initial Report poke still triggers the
		// first (un-gated) drain immediately.
		UploadInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()

	const n = 3
	for i := 0; i < n; i++ {
		reporter.Report(ReportableEvent{
			EventID:       "e" + string(rune('0'+i)),
			OrgID:         "org1",
			EventTime:     aikeytime.Now(),
			OccurredAt:    aikeytime.Now(),
			RequestStatus: "success",
			RequestCount:  1,
		})
	}

	// Let the first (un-gated) drain attempt + fail against the 503 server.
	time.Sleep(250 * time.Millisecond)

	// --- Phase 1: retryable failure must conserve, not dead-letter ---
	if got := received.Load(); got != 0 {
		t.Fatalf("phase1: server should have accepted 0 (it's failing), got %d", got)
	}
	dlPath := filepath.Join(walDir, "dead_letter.jsonl")
	if _, err := os.Stat(dlPath); !os.IsNotExist(err) {
		t.Fatalf("phase1: retryable failure must NOT dead-letter; dead_letter.jsonl exists (err=%v)", err)
	}
	if entries, _ := ReadAllWAL(walDir); len(entries) != n {
		t.Fatalf("phase1: all %d events must remain in the WAL for retry, got %d", n, len(entries))
	}
	m := reporter.Metrics()
	if m.UploadSuccess != 0 || m.UploadFailed < n {
		t.Fatalf("phase1: want uploadSuccess=0 uploadFailed>=%d, got success=%d failed=%d", n, m.UploadSuccess, m.UploadFailed)
	}
	if m.ConsecutiveFailures < 1 || m.LastUploadStatus != "retryable_failed" {
		t.Fatalf("phase1: want consecutiveFailures>=1 status=retryable_failed, got cf=%d status=%q", m.ConsecutiveFailures, m.LastUploadStatus)
	}

	// --- Phase 2: backoff gate suppresses an un-forced drain ---
	failing.Store(false) // collector recovered
	reporter.drainOnce(false)
	if got := received.Load(); got != 0 {
		t.Fatalf("phase2: gate should suppress the un-forced drain even though collector recovered; got %d delivered", got)
	}

	// --- Phase 3: forced drain bypasses the gate and re-sends from the WAL ---
	reporter.drainOnce(true)
	if got := received.Load(); got != n {
		t.Fatalf("phase3: forced drain must re-send all %d events from the WAL, got %d", n, got)
	}
	if _, err := os.Stat(dlPath); !os.IsNotExist(err) {
		t.Fatalf("phase3: successful recovery must leave no dead-letter; dead_letter.jsonl exists")
	}
	m = reporter.Metrics()
	if m.UploadSuccess != n {
		t.Fatalf("phase3: want uploadSuccess=%d, got %d", n, m.UploadSuccess)
	}
}

// TestBackoffForFailures pins the gate schedule ceiling (same as the old in-line
// backoff: 5s → 15s → 60s → 5min) so a refactor can't silently lengthen it.
func TestBackoffForFailures(t *testing.T) {
	cases := []struct {
		n    int
		want time.Duration
	}{
		{0, 5 * time.Second},
		{1, 5 * time.Second},
		{2, 15 * time.Second},
		{3, 60 * time.Second},
		{4, 5 * time.Minute},
		{99, 5 * time.Minute},
	}
	for _, c := range cases {
		if got := backoffForFailures(c.n); got != c.want {
			t.Errorf("backoffForFailures(%d)=%v, want %v", c.n, got, c.want)
		}
	}
}
