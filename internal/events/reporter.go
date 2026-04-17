package events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// ReporterConfig configures the usage reporter.
type ReporterConfig struct {
	CollectorURL    string        // e.g. "http://localhost:27300"
	CollectorToken  string        // Bearer token
	QueueCapacity   int           // bounded queue size (default 10000)
	BatchSize       int           // events per upload batch (default 100)
	UploadInterval  time.Duration // max time between uploads (default 5s)
	WALDir          string        // JSONL WAL directory (used only when SharedWAL is nil)
	ProxyInstanceID string
	ConfigHash      string // pipeline config hash for dead letter diagnostics
	DBPath          string // events DB path, used as dead letter fallback dir

	// SharedWAL, when non-nil, takes precedence over WALDir.  This lets the
	// supervisor create a single WALWriter shared with the proxy — so even
	// when the reporter is disabled (no collector_url) the proxy can still
	// append to the same WAL for local consumers (statusline / watch).
	SharedWAL *WALWriter
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
	dlw    *deadLetterWriter // dead letter writer for terminal failures
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

	// delivery state (memory only, not persisted)
	mu                  sync.RWMutex
	consecutiveFailures int
	lastUploadAt        time.Time
	lastUploadStatus    string // "ok" | "retryable_failed" | "terminal_failed"
	lastErrorCode       int
	lastErrorAt         time.Time
	lastBusinessEventAt time.Time
	lastCanaryEventAt   time.Time
	terminalFailCount   atomic.Int64
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

	// Prefer a shared writer owned by the caller.  Falls back to creating one
	// from WALDir to stay compatible with existing callers.
	var wal *WALWriter
	switch {
	case cfg.SharedWAL != nil:
		wal = cfg.SharedWAL
	case cfg.WALDir != "":
		var err error
		wal, err = NewWALWriter(cfg.WALDir)
		if err != nil {
			return nil, fmt.Errorf("init wal: %w", err)
		}
	}

	// dead_letter.jsonl is always enabled when collector is configured,
	// even if WAL is not. Dead letters are critical for diagnosing terminal
	// upload failures — they must not be silently dropped.
	var dlw *deadLetterWriter
	dlDir := cfg.WALDir
	if dlDir == "" {
		// Default: same directory as events DB, or ~/.aikey/data/
		if cfg.DBPath != "" {
			dlDir = filepath.Dir(cfg.DBPath)
		} else {
			home, _ := os.UserHomeDir()
			dlDir = filepath.Join(home, ".aikey", "data")
		}
	}
	if dlDir != "" {
		os.MkdirAll(dlDir, 0o755)
		dlw = newDeadLetterWriter(dlDir)
	}

	r := &Reporter{
		cfg:    cfg,
		wal:    wal,
		dlw:    dlw,
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

	// Track business vs canary event timestamps separately so canary events
	// (every 5min) don't pollute business watermark freshness indicators.
	now := time.Now()
	r.mu.Lock()
	if ev.OrgID == "__canary__" {
		r.lastCanaryEventAt = now
	} else {
		r.lastBusinessEventAt = now
	}
	r.mu.Unlock()

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

// Metrics returns current reporter counters and delivery state.
func (r *Reporter) Metrics() ReporterMetrics {
	r.mu.RLock()
	m := ReporterMetrics{
		Generated:     r.generated.Load(),
		Enqueued:      r.enqueued.Load(),
		Dropped:       r.dropped.Load(),
		UploadSuccess: r.uploadSuccess.Load(),
		UploadFailed:  r.uploadFailed.Load(),
		QueueDepth:    int64(len(r.ch)),
		WALAppendFail: r.walAppendFailed(),

		// delivery state
		ConsecutiveFailures: r.consecutiveFailures,
		LastUploadAt:        r.lastUploadAt,
		LastUploadStatus:    r.lastUploadStatus,
		LastErrorCode:       r.lastErrorCode,
		LastErrorAt:         r.lastErrorAt,
		TerminalFailCount:   r.terminalFailCount.Load(),
		LastBusinessEventAt: r.lastBusinessEventAt,
		LastCanaryEventAt:   r.lastCanaryEventAt,
	}
	r.mu.RUnlock()
	return m
}

// ReporterMetrics holds observable counters and delivery state.
type ReporterMetrics struct {
	// counters
	Generated     int64 `json:"usage_events_generated_total"`
	Enqueued      int64 `json:"usage_events_enqueued_total"`
	Dropped       int64 `json:"usage_events_dropped_total"`
	UploadSuccess int64 `json:"usage_events_upload_success_total"`
	UploadFailed  int64 `json:"usage_events_upload_failed_total"`
	QueueDepth    int64 `json:"usage_queue_depth"`
	WALAppendFail int64 `json:"usage_wal_append_failed_total"`

	// delivery state
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastUploadAt        time.Time `json:"last_upload_at,omitempty"`
	LastUploadStatus    string    `json:"last_upload_status,omitempty"`
	LastErrorCode       int       `json:"last_error_code,omitempty"`
	LastErrorAt         time.Time `json:"last_error_at,omitempty"`
	TerminalFailCount   int64     `json:"terminal_fail_count"`
	LastBusinessEventAt time.Time `json:"latest_business_event_at,omitempty"`
	LastCanaryEventAt   time.Time `json:"latest_canary_event_at,omitempty"`
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
	var lastUpErr *uploadError

	for attempt, delay := range delays {
		if attempt > 0 {
			slog.Debug("reporter: retrying upload", "attempt", attempt, "delay", delay)
			time.Sleep(delay)
		}

		upErr := r.doUpload(url, body)
		if upErr == nil {
			r.uploadSuccess.Add(int64(len(batch)))
			r.onUploadSuccess(len(batch))
			return
		}
		lastUpErr = upErr

		// Terminal failure (401/403/400): write to dead_letter.jsonl, don't retry.
		// Why not retry: 401 = token mismatch (won't self-heal), 400 = schema
		// incompatibility (needs code fix). Retrying wastes backoff budget.
		if classifyUploadError(upErr.StatusCode) == terminalFailure {
			r.writeDeadLetter(batch, "terminal", upErr, attempt+1)
			r.onUploadFail(len(batch), upErr, true)
			slog.Error("reporter: terminal failure, events dead-lettered",
				"count", len(batch),
				"status", upErr.StatusCode,
				"response", upErr.ResponseBody)
			return
		}

		slog.Warn("reporter: upload failed (retryable)",
			"attempt", attempt,
			"status", upErr.StatusCode,
			"error", upErr.Err)
	}

	// Retries exhausted → also dead-letter
	r.writeDeadLetter(batch, "exhausted", lastUpErr, len(delays))
	r.onUploadFail(len(batch), lastUpErr, false)
	slog.Error("reporter: retries exhausted, events dead-lettered",
		"count", len(batch),
		"last_status", lastUpErr.StatusCode,
		"last_error", lastUpErr.Err)
}

// onUploadSuccess updates delivery state after a successful upload.
func (r *Reporter) onUploadSuccess(count int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	wasRecovery := r.consecutiveFailures > 0
	r.consecutiveFailures = 0
	r.lastUploadAt = time.Now()
	r.lastUploadStatus = "ok"
	total := r.uploadSuccess.Load()
	// Log on recovery or every 50 successful uploads to avoid log spam.
	if wasRecovery || total%50 == 1 {
		slog.Info("reporter: upload ok",
			"accepted", count,
			"total", total,
			"recovered", wasRecovery)
	}
}

// onUploadFail updates delivery state after a failed upload.
func (r *Reporter) onUploadFail(count int, upErr *uploadError, terminal bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.consecutiveFailures++
	r.lastErrorCode = upErr.StatusCode
	r.lastErrorAt = time.Now()
	if terminal {
		r.lastUploadStatus = "terminal_failed"
		r.terminalFailCount.Add(int64(count))
	} else {
		r.lastUploadStatus = "retryable_failed"
	}
	r.uploadFailed.Add(int64(count))
}

// doUpload sends a batch to the collector. Returns *uploadError on failure (nil on success).
// All non-2xx responses are captured with response body for diagnostics.
// Why catch all non-2xx (not just 401/5xx): classifyUploadError needs to see 400
// to mark it as terminal. If we only catch specific codes, 400 would fall through
// to json.Decode and be misclassified as a success or decode error.
func (r *Reporter) doUpload(url string, body []byte) *uploadError {
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return &uploadError{Err: fmt.Errorf("build request: %w", err)}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if r.cfg.CollectorToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.cfg.CollectorToken)
	}

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return &uploadError{Err: fmt.Errorf("http: %w", err)}
	}
	defer resp.Body.Close()

	// Catch all non-2xx: read response body (truncated) for dead letter diagnostics.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody := readTruncated(resp.Body, 512)
		return &uploadError{
			StatusCode:   resp.StatusCode,
			ResponseBody: respBody,
			Err:          fmt.Errorf("collector error: %d", resp.StatusCode),
		}
	}

	var result batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return &uploadError{Err: fmt.Errorf("decode response: %w", err)}
	}

	slog.Debug("reporter: batch uploaded",
		"accepted", result.Accepted, "duplicated", result.Duplicated, "rejected", result.Rejected)
	return nil
}
