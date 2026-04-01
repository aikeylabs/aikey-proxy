package events

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestReporter_ReportAndUpload(t *testing.T) {
	var received atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
			http.Error(w, "bad", 400)
			return
		}
		received.Add(int64(len(req.Events)))
		json.NewEncoder(w).Encode(batchResponse{
			Accepted: len(req.Events),
		})
	}))
	defer srv.Close()

	reporter, err := NewReporter(ReporterConfig{
		CollectorURL:   srv.URL,
		QueueCapacity:  100,
		BatchSize:      5,
		UploadInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		reporter.Report(ReportableEvent{
			EventID:       "e" + string(rune('0'+i)),
			OrgID:         "org1",
			EventTime:     time.Now(),
			OccurredAt:    time.Now(),
			RequestStatus: "success",
			RequestCount:  1,
		})
	}

	// Wait for flush interval
	time.Sleep(200 * time.Millisecond)

	reporter.Close()

	if got := received.Load(); got != 3 {
		t.Errorf("expected 3 events received by server, got %d", got)
	}

	m := reporter.Metrics()
	if m.Generated != 3 {
		t.Errorf("generated=%d, want 3", m.Generated)
	}
	if m.Enqueued != 3 {
		t.Errorf("enqueued=%d, want 3", m.Enqueued)
	}
	if m.Dropped != 0 {
		t.Errorf("dropped=%d, want 0", m.Dropped)
	}
}

func TestReporter_DropWhenQueueFull(t *testing.T) {
	// No collector URL → upload loop not started, queue will fill up
	reporter, err := NewReporter(ReporterConfig{
		QueueCapacity: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()

	for i := 0; i < 5; i++ {
		reporter.Report(ReportableEvent{
			EventID:       "e" + string(rune('0'+i)),
			OrgID:         "org1",
			EventTime:     time.Now(),
			OccurredAt:    time.Now(),
			RequestStatus: "success",
			RequestCount:  1,
		})
	}

	m := reporter.Metrics()
	if m.Generated != 5 {
		t.Errorf("generated=%d, want 5", m.Generated)
	}
	if m.Dropped < 3 {
		t.Errorf("dropped=%d, want at least 3", m.Dropped)
	}
}

func TestWALWriter_Append(t *testing.T) {
	dir := t.TempDir()
	wal, err := NewWALWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()

	wal.Append(ReportableEvent{
		EventID:       "e1",
		OrgID:         "org1",
		EventTime:     time.Now(),
		OccurredAt:    time.Now(),
		RequestStatus: "success",
		RequestCount:  1,
	})

	wal.Append(ReportableEvent{
		EventID:       "e2",
		OrgID:         "org1",
		EventTime:     time.Now(),
		OccurredAt:    time.Now(),
		RequestStatus: "success",
		RequestCount:  1,
	})

	if wal.AppendFailedTotal() != 0 {
		t.Errorf("unexpected append failures: %d", wal.AppendFailedTotal())
	}
}
