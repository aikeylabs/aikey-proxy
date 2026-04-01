package events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ReporterConfig configures the usage reporter.
type ReporterConfig struct {
	CollectorURL   string        // e.g. "http://localhost:27300"
	CollectorToken string        // Bearer token
	QueueCapacity  int           // bounded queue size (default 10000)
	BatchSize      int           // events per upload batch (default 100)
	UploadInterval time.Duration // max time between uploads (default 5s)
	WALDir         string        // JSONL WAL directory
	ProxyInstanceID string
}

// batchRequest mirrors the collector-service ingest API request body.
type batchRequest struct {
	Source          string            `json:"source"`
	SourceVersion   string            `json:"source_version"`
	ProxyInstanceID string            `json:"proxy_instance_id"`
	Events          []ReportableEvent `json:"events"`
}

type batchResponse struct {
	Accepted   int `json:"accepted"`
	Duplicated int `json:"duplicated"`
	Rejected   int `json:"rejected"`
}

// Reporter handles usage event reporting: WAL write + async upload to collector-service.
type Reporter struct {
	cfg    ReporterConfig
	wal    *WALWriter
	ch     chan ReportableEvent
	done   chan struct{}
	wg     sync.WaitGroup
	client *http.Client

	// metrics
	generated     atomic.Int64
	enqueued      atomic.Int64
	dropped       atomic.Int64
	uploadSuccess atomic.Int64
	uploadFailed  atomic.Int64
}

// NewReporter creates and starts a usage event reporter.
func NewReporter(cfg ReporterConfig) (*Reporter, error) {
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = 10000
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.UploadInterval <= 0 {
		cfg.UploadInterval = 5 * time.Second
	}

	var wal *WALWriter
	if cfg.WALDir != "" {
		var err error
		wal, err = NewWALWriter(cfg.WALDir)
		if err != nil {
			return nil, fmt.Errorf("init wal: %w", err)
		}
	}

	r := &Reporter{
		cfg:    cfg,
		wal:    wal,
		ch:     make(chan ReportableEvent, cfg.QueueCapacity),
		done:   make(chan struct{}),
		client: &http.Client{Timeout: 30 * time.Second},
	}

	if cfg.CollectorURL != "" {
		r.wg.Add(1)
		go r.uploadLoop()
	}

	return r, nil
}

// Report enqueues a reportable event for WAL write and upload.
// Non-blocking; drops event if queue is full (D9).
func (r *Reporter) Report(ev ReportableEvent) {
	r.generated.Add(1)

	// WAL append (best-effort, async-ish but under lock)
	if r.wal != nil {
		r.wal.Append(ev)
	}

	// Enqueue for upload
	select {
	case r.ch <- ev:
		r.enqueued.Add(1)
	default:
		r.dropped.Add(1)
		slog.Warn("reporter: queue full, dropping event", "event_id", ev.EventID)
	}
}

// Close stops the reporter, flushes remaining events, and closes WAL.
func (r *Reporter) Close() error {
	close(r.done)
	r.wg.Wait()
	if r.wal != nil {
		return r.wal.Close()
	}
	return nil
}

// Metrics returns current reporter counters.
func (r *Reporter) Metrics() ReporterMetrics {
	return ReporterMetrics{
		Generated:     r.generated.Load(),
		Enqueued:      r.enqueued.Load(),
		Dropped:       r.dropped.Load(),
		UploadSuccess: r.uploadSuccess.Load(),
		UploadFailed:  r.uploadFailed.Load(),
		QueueDepth:    int64(len(r.ch)),
		WALAppendFail: r.walAppendFailed(),
	}
}

// ReporterMetrics holds observable counters.
type ReporterMetrics struct {
	Generated     int64 `json:"usage_events_generated_total"`
	Enqueued      int64 `json:"usage_events_enqueued_total"`
	Dropped       int64 `json:"usage_events_dropped_total"`
	UploadSuccess int64 `json:"usage_events_upload_success_total"`
	UploadFailed  int64 `json:"usage_events_upload_failed_total"`
	QueueDepth    int64 `json:"usage_queue_depth"`
	WALAppendFail int64 `json:"usage_wal_append_failed_total"`
}

func (r *Reporter) walAppendFailed() int64 {
	if r.wal != nil {
		return r.wal.AppendFailedTotal()
	}
	return 0
}

func (r *Reporter) uploadLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.cfg.UploadInterval)
	defer ticker.Stop()

	var batch []ReportableEvent

	for {
		select {
		case ev := <-r.ch:
			batch = append(batch, ev)
			if len(batch) >= r.cfg.BatchSize {
				r.uploadBatch(batch)
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				r.uploadBatch(batch)
				batch = nil
			}
		case <-r.done:
			// Drain remaining
			for {
				select {
				case ev := <-r.ch:
					batch = append(batch, ev)
				default:
					if len(batch) > 0 {
						r.uploadBatch(batch)
					}
					return
				}
			}
		}
	}
}

func (r *Reporter) uploadBatch(batch []ReportableEvent) {
	req := batchRequest{
		Source:          "aikey-proxy",
		SourceVersion:   "0.1.0",
		ProxyInstanceID: r.cfg.ProxyInstanceID,
		Events:          batch,
	}

	body, err := json.Marshal(req)
	if err != nil {
		slog.Error("reporter: marshal batch", "error", err)
		r.uploadFailed.Add(int64(len(batch)))
		return
	}

	url := r.cfg.CollectorURL + "/v1/usage-events:batch"

	// Retry with exponential backoff: 5s, 15s, 60s, 5min
	delays := []time.Duration{0, 5 * time.Second, 15 * time.Second, 60 * time.Second, 5 * time.Minute}
	var lastErr error

	for attempt, delay := range delays {
		if attempt > 0 {
			slog.Debug("reporter: retrying upload", "attempt", attempt, "delay", delay)
			time.Sleep(delay)
		}

		if err := r.doUpload(url, body); err != nil {
			lastErr = err
			slog.Warn("reporter: upload failed", "attempt", attempt, "error", err)
			continue
		}
		r.uploadSuccess.Add(int64(len(batch)))
		return
	}

	slog.Error("reporter: upload exhausted retries", "count", len(batch), "error", lastErr)
	r.uploadFailed.Add(int64(len(batch)))
}

func (r *Reporter) doUpload(url string, body []byte) error {
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if r.cfg.CollectorToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.cfg.CollectorToken)
	}

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("auth failed: %d", resp.StatusCode)
	}
	if resp.StatusCode >= 500 {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("server error: %d", resp.StatusCode)
	}

	var result batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	slog.Debug("reporter: batch uploaded",
		"accepted", result.Accepted, "duplicated", result.Duplicated, "rejected", result.Rejected)
	return nil
}
