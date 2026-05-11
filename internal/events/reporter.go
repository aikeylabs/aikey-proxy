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

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/aikeycompat"
	"github.com/AiKeyLabs/pkg/aikeytime"
)

// ReporterConfig configures the usage reporter.
type ReporterConfig struct {
	CollectorURL    string        // e.g. "http://localhost:27300"
	CollectorToken  string        // Bearer token

	// CollectorRoutes maps RouteSource ("personal" / "team" / "oauth") →
	// upload URL. When ev.RouteSource has a non-empty mapping, that URL
	// is used for the event; misses fall through to CollectorURL.
	// Empty value disables upload for that route (event still WAL'd).
	//
	// Why per-route: personal-key events stay on local collector;
	// team-key events go to remote team collector after `aikey login`.
	// Single channel + grouped per-URL upload — see uploadBatch.
	CollectorRoutes map[string]string

	// CollectorRouteCredentials maps RouteSource → Credential (added
	// 2026-05-11 B-phase, see roadmap update
	// 20260511-user-jwt-collector-ingest.md). When ev.RouteSource has a
	// per-route credential the reporter uses its Bearer() for the upload
	// header; misses fall back to the legacy CollectorToken (which is
	// wrapped in a StaticTokenCredential at config-load time, see
	// supervisor wiring).
	//
	// Why split from CollectorRoutes (URL): a route's URL is config-
	// time fixed but its credential may be stateful (RefreshableJWT
	// holds a mutex + refresh state). Keeping them parallel maps lets
	// tests inject either independently and lets a future config field
	// (e.g. per-route mTLS material) follow the same pattern.
	CollectorRouteCredentials map[string]Credential

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
		// Stage 2.5 windows-compat: dead-letter contains failed event
		// payloads — harden NTFS ACL.
		_ = aikeycompat.EnforceOwnerOnly(dlDir)
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

	// Start upload loop if any destination is configured (legacy single
	// CollectorURL OR per-route CollectorRoutes with at least one
	// non-empty entry). With both unset, events still get WAL'd but
	// nothing uploads — same as the pre-CollectorRoutes behaviour when
	// CollectorURL was empty.
	hasAnyURL := cfg.CollectorURL != ""
	if !hasAnyURL {
		for _, u := range cfg.CollectorRoutes {
			if u != "" {
				hasAnyURL = true
				break
			}
		}
	}
	if hasAnyURL {
		r.wg.Add(1)
		// Fatal: reporter upload loop silently dying means usage events pile
		// up in the queue and get dropped — direct billing correctness risk.
		observability.GoSafe("events.reporter.upload_loop", observability.Fatal, r.uploadLoop)
	}

	return r, nil
}

// urlForEvent picks the upload URL for an event, honouring per-route
// overrides ahead of the legacy single-URL CollectorURL. Returns "" when
// no destination is configured for the event's RouteSource — caller must
// skip the upload (event is already WAL'd).
func (r *Reporter) urlForEvent(ev ReportableEvent) string {
	return r.urlForRouteSource(ev.RouteSource)
}

// urlForRouteSource is the route-source-keyed half of urlForEvent. Split
// out 2026-05-11 so uploadBatch can group by RouteSource (and thus also
// pick the right credential per group, not just per URL — two route
// sources COULD collide on the same URL with different credentials).
func (r *Reporter) urlForRouteSource(routeSource string) string {
	if r.cfg.CollectorRoutes != nil {
		if u, ok := r.cfg.CollectorRoutes[routeSource]; ok && u != "" {
			return u
		}
	}
	return r.cfg.CollectorURL
}

// credentialForRouteSource returns the bearer source for uploads tied
// to this RouteSource. Per-route credentials win; falls back to the
// legacy global CollectorToken wrapped in a StaticTokenCredential.
// Returns nil only when neither path is configured — caller (doUpload)
// then sends the upload with no Authorization header (matches pre-B
// behaviour when CollectorToken was "").
func (r *Reporter) credentialForRouteSource(routeSource string) Credential {
	if r.cfg.CollectorRouteCredentials != nil {
		if c, ok := r.cfg.CollectorRouteCredentials[routeSource]; ok && c != nil {
			return c
		}
	}
	if r.cfg.CollectorToken != "" {
		return &StaticTokenCredential{Token: r.cfg.CollectorToken}
	}
	return nil
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

		// delivery state — internal fields remain time.Time (hot-path
		// monotonic clock math is easier); converted to Millis at the
		// Metrics boundary so the JSON exposes int64.
		ConsecutiveFailures: r.consecutiveFailures,
		LastUploadAt:        aikeytime.FromTime(r.lastUploadAt),
		LastUploadStatus:    r.lastUploadStatus,
		LastErrorCode:       r.lastErrorCode,
		LastErrorAt:         aikeytime.FromTime(r.lastErrorAt),
		TerminalFailCount:   r.terminalFailCount.Load(),
		LastBusinessEventAt: aikeytime.FromTime(r.lastBusinessEventAt),
		LastCanaryEventAt:   aikeytime.FromTime(r.lastCanaryEventAt),
	}
	r.mu.RUnlock()
	return m
}

// ReporterMetrics holds observable counters and delivery state.
//
// All *At fields are int64 Unix epoch milliseconds (UTC). The metrics
// endpoint exposes them for monitoring — keeping them in the same
// format as every other pipeline timestamp lets automation parse
// once without a format-detection step (bugfix 20260424).
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
	ConsecutiveFailures int              `json:"consecutive_failures"`
	LastUploadAt        aikeytime.Millis `json:"last_upload_at,omitempty"`
	LastUploadStatus    string           `json:"last_upload_status,omitempty"`
	LastErrorCode       int              `json:"last_error_code,omitempty"`
	LastErrorAt         aikeytime.Millis `json:"last_error_at,omitempty"`
	TerminalFailCount   int64            `json:"terminal_fail_count"`
	LastBusinessEventAt aikeytime.Millis `json:"latest_business_event_at,omitempty"`
	LastCanaryEventAt   aikeytime.Millis `json:"latest_canary_event_at,omitempty"`
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

// uploadBatch groups the batch by RouteSource and delegates each group
// to uploadGroupTo. Events without a destination URL are dropped at
// this stage — they are already WAL'd locally for offline replay /
// debugging.
//
// Why per-RouteSource grouping (changed 2026-05-11 from per-URL):
// per-route credentials need RouteSource as the lookup key, not URL —
// two route sources COULD legitimately point at the same URL with
// different bearer credentials (e.g. a single collector accepting
// both user-JWT-bound team events and S2S personal events). Grouping
// by RouteSource keeps URL + credential paired correctly for the
// entire batch.
//
// Why per-group grouping at all: the input batch can mix RouteSources
// (a personal call and a team call may finish in the same 5s window).
// Each group gets its own retry / dead-letter cycle so a slow /
// failing destination can't penalise others.
func (r *Reporter) uploadBatch(batch []ReportableEvent) {
	if len(batch) == 0 {
		return
	}
	groups := make(map[string][]ReportableEvent, 1)
	skipped := 0
	for _, ev := range batch {
		if r.urlForEvent(ev) == "" {
			skipped++
			continue
		}
		groups[ev.RouteSource] = append(groups[ev.RouteSource], ev)
	}
	if skipped > 0 {
		// Routine miss when a route_source has no destination configured
		// (e.g. team route on a pure personal install). Counted as
		// dropped so metrics show backlog vs. discard split.
		r.dropped.Add(int64(skipped))
	}
	for routeSource, group := range groups {
		url := r.urlForRouteSource(routeSource)
		cred := r.credentialForRouteSource(routeSource)
		r.uploadGroupTo(url, cred, group)
	}
}

// uploadGroupTo handles one (url, credential, batch) triple including
// retry + dead-letter. Extracted from the old monolithic uploadBatch
// when per-route routing landed (2026-05-10); credential parameter
// added 2026-05-11 to thread per-RouteSource bearer through the retry
// loop. The retry/DLW logic itself is unchanged.
//
// cred may be nil — doUpload tolerates that by sending without an
// Authorization header (matches pre-CollectorToken behaviour).
func (r *Reporter) uploadGroupTo(collectorURL string, cred Credential, batch []ReportableEvent) {
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

	url := collectorURL + "/v1/usage-events:batch"

	// Retry with exponential backoff: 5s, 15s, 60s, 5min
	delays := []time.Duration{0, 5 * time.Second, 15 * time.Second, 60 * time.Second, 5 * time.Minute}
	var lastUpErr *uploadError

	for attempt, delay := range delays {
		if attempt > 0 {
			slog.Debug("reporter: retrying upload", "attempt", attempt, "delay", delay)
			time.Sleep(delay)
		}

		upErr := r.doUpload(url, body, cred)
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
//
// cred (added 2026-05-11) is the per-RouteSource credential resolved by
// uploadBatch. If nil, the request goes without an Authorization header —
// matches pre-CollectorToken behaviour for credential-free deployments.
// Bearer() failures are surfaced as a synthetic 401-class uploadError so
// the retry/dead-letter loop treats stale credentials the same as a
// server-side 401 (no infinite retry; lands in dead_letter.jsonl with
// the credential error message as response body).
func (r *Reporter) doUpload(url string, body []byte, cred Credential) *uploadError {
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return &uploadError{Err: fmt.Errorf("build request: %w", err)}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if cred != nil {
		// Bearer() may block briefly on refresh — bound by RefreshableJWT's
		// internal HTTPClient timeout (10s default). Use the request context
		// so a shutdown cancels the refresh attempt cleanly.
		bearer, berr := cred.Bearer(httpReq.Context())
		if berr != nil {
			return &uploadError{
				StatusCode:   http.StatusUnauthorized,
				ResponseBody: berr.Error(),
				Err:          fmt.Errorf("credential: %w", berr),
			}
		}
		if bearer != "" {
			httpReq.Header.Set("Authorization", "Bearer "+bearer)
		}
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
