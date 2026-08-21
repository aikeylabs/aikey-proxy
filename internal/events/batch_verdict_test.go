package events

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A 2xx from the collector and the EVENTS BEING STORED are different facts.
// uploadGroupTo used to conflate them: any 2xx counted len(batch) successes,
// advanced sentSeq and dropped the events from the outbox, whatever the body
// said. On 2026-08-20 that let usage_events_upload_success_total climb past 300
// on a machine where the collector was storing nothing — the counters read
// healthy in the wrong direction, and the only record of the truth was a
// slog.Debug.
//
// These pin the CONTRACT from 日志规范 ("HTTP 200 + 非空 body + 解析结果全 0/空
// 必须再打一条 WARN"), not the shape of the code: whatever noteBatchVerdict does
// internally, a batch the collector did not account for must be audible at WARN.
// 能红: delete the noteBatchVerdict call in uploadGroupTo and every case here
// that expects a warning fails.

func captureWarn(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	fn()
	return buf.String()
}

func TestBatchVerdict_WarnsWhenNothingWasStored(t *testing.T) {
	cases := []struct {
		name      string
		resp      *batchResponse
		sent      int
		wantEvent string
	}{
		{
			name:      "rows rejected inside a 200",
			resp:      &batchResponse{Accepted: 0, Duplicated: 0, Rejected: 5},
			sent:      5,
			wantEvent: "usage.reporter.batch_rejected_rows",
		},
		{
			name:      "partial reject still warns — the rejected ones are gone",
			resp:      &batchResponse{Accepted: 3, Duplicated: 0, Rejected: 2},
			sent:      5,
			wantEvent: "usage.reporter.batch_rejected_rows",
		},
		{
			name:      "200 that accounts for nothing at all",
			resp:      &batchResponse{Accepted: 0, Duplicated: 0, Rejected: 0},
			sent:      5,
			wantEvent: "usage.reporter.batch_stored_none",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &Reporter{}
			out := captureWarn(t, func() { r.noteBatchVerdict(c.resp, c.sent) })
			if !strings.Contains(out, c.wantEvent) {
				t.Fatalf("expected a WARN carrying event.name=%s, got:\n%s", c.wantEvent, out)
			}
		})
	}
}

func TestBatchVerdict_SilentWhenEventsAreAccountedFor(t *testing.T) {
	// Re-delivery after a restart is normal and must not cry wolf — a warning
	// on every duplicate would train operators to ignore this event name, which
	// is exactly how the Debug line got ignored in the first place.
	cases := []struct {
		name string
		resp *batchResponse
		sent int
	}{
		{"all accepted", &batchResponse{Accepted: 5}, 5},
		{"all duplicates (normal WAL re-read)", &batchResponse{Duplicated: 5}, 5},
		{"quarantined rows are stored, just held", &batchResponse{Quarantined: 5}, 5},
		{"unparseable body — older collector, doUpload already handled it", nil, 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &Reporter{}
			out := captureWarn(t, func() { r.noteBatchVerdict(c.resp, c.sent) })
			if strings.TrimSpace(out) != "" {
				t.Fatalf("expected no warning, got:\n%s", out)
			}
		})
	}
}

// --- wiring, not just the helper -------------------------------------------
//
// The first draft of this file called noteBatchVerdict directly and stayed
// green when the call was deleted from uploadGroupTo — a fence on a function
// nobody has to call. These drive a real upload against a collector stub, so
// they cover the LINK: 2xx body → warning. 能红: remove the noteBatchVerdict
// call in uploadGroupTo and TestUpload_RejectedRowsAreAudible fails.

// stubCollector answers /v1/usage-events:batch with a fixed verdict body.
func stubCollector(t *testing.T, verdict string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(verdict))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func uploadOneBatch(t *testing.T, verdict string) (string, uploadGroupResult) {
	t.Helper()
	r, err := NewReporter(&ReporterConfig{
		CollectorURL:   stubCollector(t, verdict),
		WALDir:         t.TempDir(),
		SourceID:       "srcV",
		BatchSize:      10,
		UploadInterval: time.Hour, // keep the periodic drain out of the way
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	batch := []ReportableEvent{v2Event("ev1", "srcV", 1), v2Event("ev2", "srcV", 2)}
	var out uploadGroupResult
	log := captureWarn(t, func() {
		out = r.uploadGroupTo(context.Background(), r.cfg.CollectorURL, nil, batch)
	})
	return log, out
}

func TestUpload_RejectedRowsAreAudible(t *testing.T) {
	log, res := uploadOneBatch(t, `{"accepted":0,"duplicated":0,"rejected":2}`)
	if !strings.Contains(log, "usage.reporter.batch_rejected_rows") {
		t.Fatalf("a 200 that rejected every row must warn; log was:\n%s", log)
	}
	// The delivery decision is deliberately unchanged — see noteBatchVerdict's
	// doc for why retrying a row-level reject is the worse failure.
	if res != groupDone {
		t.Errorf("a 2xx must still count as handed over, got %v", res)
	}
}

func TestUpload_EmptyVerdictIsAudible(t *testing.T) {
	log, _ := uploadOneBatch(t, `{"accepted":0,"duplicated":0,"rejected":0}`)
	if !strings.Contains(log, "usage.reporter.batch_stored_none") {
		t.Fatalf("a 200 accounting for nothing must warn; log was:\n%s", log)
	}
}

func TestUpload_AcceptedBatchStaysQuiet(t *testing.T) {
	log, _ := uploadOneBatch(t, `{"accepted":2,"duplicated":0,"rejected":0}`)
	if strings.TrimSpace(log) != "" {
		t.Fatalf("a fully accepted batch must not warn; log was:\n%s", log)
	}
}
