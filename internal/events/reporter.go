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

	// SeqAlloc is the per-source reserve-ahead sequence allocator, shared with
	// the proxy (same instance the proxy stamps source_seq from). The reporter
	// only READS Allocated() from it to stamp batchRequest.AllocatedSeq for
	// tail-gap detection — it does NOT own its lifecycle (the supervisor's
	// generation.close() owns the zero-burn Close()). nil → batches carry no
	// allocated_seq (offline / degraded). Added 2026-05-30 (delivery integrity).
	SeqAlloc *SeqAllocator

	// SourceID is this vault's stable source identity (runtime.source_identity).
	// Used by ReconcileGaps/AuditStatus (D2.5/D3) to filter the collector's
	// per-source completeness to "my" source. Empty disables reconcile.
	SourceID string
}

// batchRequest mirrors the collector-service ingest API request body.
type batchRequest struct {
	Source          string            `json:"source"`
	SourceVersion   string            `json:"source_version"`
	ProxyInstanceID string            `json:"proxy_instance_id"`
	Events          []ReportableEvent `json:"events"`

	// AllocatedSeq carries this source's allocator high-water mark (the highest
	// source_seq ever handed out, reserve-ahead) so the server can detect a
	// TAIL gap — allocated > delivered-contiguous past a timeout ⇒ suspected
	// loss at the tail (events allocated but never delivered, e.g. lost before
	// WAL append). Read live from the SeqAllocator at batch-build time (it's
	// monotonic; the server takes MAX, so a fresh snapshot is safe and most
	// up-to-date). nil when no allocator is wired (degraded/offline) → server
	// omits tail detection for this source. Added 2026-05-30 (delivery
	// integrity, B'). See design doc 阶段6-企业定制/20260530-财务对账级用量审计.
	AllocatedSeq *int64 `json:"allocated_seq,omitempty"`
}

type batchResponse struct {
	Accepted   int `json:"accepted"`
	Duplicated int `json:"duplicated"`
	Rejected   int `json:"rejected"`
	// ContiguousSeq is the server's per-source connected-no-gap high-water mark
	// after ingesting this batch (delivery integrity, 2026-05-30). The uploader
	// advances confirmedSeq to this and prunes WAL files at/below it. A nil map
	// (older collector that doesn't return the field) means "don't advance /
	// don't prune" — conserve, never lose. Keyed by source_id.
	ContiguousSeq map[string]int64 `json:"contiguous_seq,omitempty"`
}

// Reporter handles usage event reporting: WAL write + async upload to collector-service.
//
// Delivery model (2026-05-30, design doc §5.1/§5.4): the WAL is the upload
// outbox / source of truth. Report only appends to the WAL and pokes `signal`;
// the upload loop reads UN-confirmed entries from the WAL, uploads them, and
// advances two IN-MEMORY cursors (not persisted — rebuilt on restart):
//
//   - sentSeq[source]:      highest source_seq this process has handed to an
//                           upload attempt. Filters "what to read next time".
//   - confirmedSeq[source]: highest server-acked contiguous seq. Used ONLY to
//                           prune WAL files (files whose max seq ≤ confirmed).
//
// On restart both cursors are empty, so the loop replays from the oldest
// un-pruned WAL file; the server's (org_id,event_id) dedup absorbs the overlap.
// Not persisting the cursors is deliberate (user decision): a little re-upload
// on restart, in exchange for zero persisted upload state and a model that
// CANNOT silently skip (conserve-on-uncertainty everywhere).
type Reporter struct {
	cfg    ReporterConfig
	wal    *WALWriter
	dlw    *deadLetterWriter // dead letter writer for terminal failures
	signal chan struct{}     // cap-1 wakeup poke from Report → uploadLoop
	done   chan struct{}
	wg     sync.WaitGroup
	client *http.Client

	// delivery-integrity cursors (memory only; see type doc). Guarded by mu.
	sentSeq      map[string]int64 // source_id → highest seq handed to upload
	confirmedSeq map[string]int64 // source_id → server contiguous high-water
	seenV1       map[string]bool  // event_id → uploaded; A1 one-shot for v1 entries

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
		cfg:          cfg,
		wal:          wal,
		dlw:          dlw,
		signal:       make(chan struct{}, 1),
		done:         make(chan struct{}),
		client:       &http.Client{Timeout: 30 * time.Second},
		sentSeq:      make(map[string]int64),
		confirmedSeq: make(map[string]int64),
		seenV1:       make(map[string]bool),
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

// Report records a reportable event. In the WAL-as-outbox model this only
// appends to the WAL (the durable upload source) and wakes the upload loop;
// there is no in-memory queue and thus no "queue full" drop — the WAL itself is
// the buffer (disk backpressure). If the WAL write fails it is counted in
// usage_wal_append_failed_total and the event is lost locally, which a hard
// crash would do anyway; reserve-ahead turns that into an auditable gap.
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

	if r.wal != nil {
		r.wal.Append(ev)
		r.enqueued.Add(1)
	}

	// Non-blocking wake. signal has cap 1, so concurrent Reports coalesce into
	// at most one pending poke — the loop picks up everything new on its next
	// WAL read regardless.
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

// Close stops the reporter: one final WAL upload pass to push anything not yet
// confirmed, then fsync+close the WAL. Drains the outbox, not an in-memory
// queue.
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
		// QueueDepth: the in-memory queue is gone (WAL is the buffer). Report
		// the per-source backlog instead — how far sent is behind allocated is
		// not known here, so expose 0 for now; B' surfaces real backlog via the
		// server watermark health endpoint. Kept in the struct for wire-compat.
		QueueDepth:    0,
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

// uploadLoop is the WAL-as-outbox pump. It wakes on the upload interval, on a
// Report poke, or on shutdown, and each time runs one drainOnce pass that reads
// un-confirmed events from the WAL and uploads them. On shutdown it runs a final
// pass so a graceful stop pushes everything still pending.
func (r *Reporter) uploadLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.cfg.UploadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.drainOnce()
		case <-r.signal:
			r.drainOnce()
		case <-r.done:
			r.drainOnce() // final flush
			return
		}
	}
}

// drainOnce reads the WAL, selects entries not yet handed to an upload
// (source_seq > sentSeq[source], plus a one-shot pass over legacy v1 entries),
// uploads them grouped by RouteSource, then prunes confirmed WAL files. One WAL
// read per pass keeps it simple; the BatchSize cap bounds a single HTTP body.
func (r *Reporter) drainOnce() {
	if r.wal == nil {
		return
	}
	entries, err := ReadAllWAL(r.wal.Dir())
	if err != nil {
		slog.Warn("reporter: wal read for upload failed",
			"event.name", "usage.reporter.wal_read_failed", "error", err)
		// Partial entries may still be returned; fall through to upload them.
	}

	var pending []ReportableEvent
	for i := range entries {
		e := &entries[i]
		ev := e.EventJSON
		if e.SchemaVersion >= WALSchemaV2 && e.SourceSeq > 0 {
			// v2 path: skip anything already handed to an upload attempt.
			r.mu.RLock()
			already := e.SourceSeq <= r.sentSeq[e.SourceID]
			r.mu.RUnlock()
			if already {
				continue
			}
			// Ensure the wire event carries the integrity fields even if an
			// older Append didn't round-trip them through event_json.
			if ev.SourceID == "" {
				ev.SourceID = e.SourceID
			}
			if ev.SourceSeq == nil {
				seq := e.SourceSeq
				ev.SourceSeq = &seq
			}
		} else {
			// A1: legacy v1 entry (no source_seq). Upload exactly once, keyed by
			// event_id, so the upgrade-window residue reaches the collector
			// (server dedup guards against any double send) without participating
			// in seq-based gap detection.
			r.mu.RLock()
			seen := r.seenV1[ev.EventID]
			r.mu.RUnlock()
			if seen || ev.EventID == "" {
				continue
			}
		}
		pending = append(pending, ev)
		if len(pending) >= r.cfg.BatchSize {
			r.uploadPending(pending)
			pending = pending[:0]
		}
	}
	if len(pending) > 0 {
		r.uploadPending(pending)
	}

	r.pruneConfirmedWAL()
}

// uploadPending groups events by RouteSource and uploads each group. On a
// processed group (success OR dead-letter — both mean "we're done with these
// locally") it advances sentSeq / seenV1 so the next pass won't re-read them.
// Confirmed-seq (for WAL pruning) is advanced separately from the server's
// response inside uploadGroupTo.
func (r *Reporter) uploadPending(batch []ReportableEvent) {
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
		// No destination for this route_source (e.g. team route on a pure
		// personal install). These stay in the WAL; counted as dropped so
		// metrics distinguish "no route" backlog from real discard.
		r.dropped.Add(int64(skipped))
	}
	for routeSource, group := range groups {
		url := r.urlForRouteSource(routeSource)
		cred := r.credentialForRouteSource(routeSource)
		r.uploadGroupTo(url, cred, group)
		r.markProcessed(group)
	}
}

// markProcessed advances the in-memory cursors after a group has been handed to
// an upload attempt (whether it succeeded or was dead-lettered): v2 events bump
// sentSeq[source] to their max seq; v1 events mark their event_id seen (A1).
func (r *Reporter) markProcessed(group []ReportableEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range group {
		if ev.SourceSeq != nil {
			if *ev.SourceSeq > r.sentSeq[ev.SourceID] {
				r.sentSeq[ev.SourceID] = *ev.SourceSeq
			}
		} else if ev.EventID != "" {
			r.seenV1[ev.EventID] = true
		}
	}
}

// pruneConfirmedWAL deletes rotated WAL files whose every entry's source_seq is
// ≤ the server-confirmed contiguous mark for its source. The currently-open
// file is never deleted. A file is pruned only when ALL its v2 entries are
// confirmed AND it has no un-uploaded v1 entries — conservative so nothing
// un-acked is ever lost. Files with no v2 entries at all (pure legacy) are left
// to the natural retention sweep (not deleted here, to avoid dropping v1 data
// the server hasn't acked via any seq mechanism).
func (r *Reporter) pruneConfirmedWAL() {
	if r.wal == nil {
		return
	}
	files, err := ListWALFiles(r.wal.Dir())
	if err != nil {
		return
	}
	current := r.wal.CurrentFileName()

	r.mu.RLock()
	confirmed := make(map[string]int64, len(r.confirmedSeq))
	for k, v := range r.confirmedSeq {
		confirmed[k] = v
	}
	r.mu.RUnlock()

	for _, path := range files {
		if filepath.Base(path) == current {
			continue // never delete the file we're appending to
		}
		entries, err := ReadWALFile(path)
		if err != nil || len(entries) == 0 {
			continue
		}
		prunable := true
		sawV2 := false
		for i := range entries {
			e := &entries[i]
			if e.SchemaVersion >= WALSchemaV2 && e.SourceSeq > 0 {
				sawV2 = true
				if e.SourceSeq > confirmed[e.SourceID] {
					prunable = false
					break
				}
			} else {
				// A v1 (or seq-less) entry: only prunable once uploaded (seenV1).
				if e.EventJSON.EventID == "" || !r.seenV1Locked(e.EventJSON.EventID) {
					prunable = false
					break
				}
			}
		}
		if prunable && sawV2 {
			if err := os.Remove(path); err != nil {
				slog.Warn("reporter: prune wal file failed",
					"event.name", "usage.reporter.wal_prune_failed", "file", path, "error", err)
			} else {
				slog.Debug("reporter: pruned confirmed wal file", "file", path)
			}
		}
	}
}

// seenV1Locked reports whether a v1 event_id has been uploaded. Takes the read
// lock itself so pruneConfirmedWAL can call it inside its file loop without
// holding mu across file IO.
func (r *Reporter) seenV1Locked(eventID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.seenV1[eventID]
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
	// Stamp the allocator high-water so the server can detect tail gaps (events
	// allocated but never delivered). Read live — it's monotonic and the server
	// MAXes it, so a fresh snapshot is safe. Skipped when no allocator is wired
	// (offline/degraded), leaving the field omitted (old-server compatible).
	if r.cfg.SeqAlloc != nil {
		allocated := r.cfg.SeqAlloc.Allocated()
		req.AllocatedSeq = &allocated
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

		resp, upErr := r.doUpload(url, body, cred)
		if upErr == nil {
			r.uploadSuccess.Add(int64(len(batch)))
			r.onUploadSuccess(len(batch))
			// Advance the server-confirmed contiguous high-water per source so
			// pruneConfirmedWAL can reclaim fully-acked files. A nil/absent map
			// (older collector) leaves confirmedSeq untouched → conserve, the
			// WAL isn't pruned (no silent loss, just more disk until upgrade).
			if resp != nil && resp.ContiguousSeq != nil {
				r.mu.Lock()
				for src, c := range resp.ContiguousSeq {
					if c > r.confirmedSeq[src] {
						r.confirmedSeq[src] = c
					}
				}
				r.mu.Unlock()
			}
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
func (r *Reporter) doUpload(url string, body []byte, cred Credential) (*batchResponse, *uploadError) {
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, &uploadError{Err: fmt.Errorf("build request: %w", err)}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if cred != nil {
		// Bearer() may block briefly on refresh — bound by RefreshableJWT's
		// internal HTTPClient timeout (10s default). Use the request context
		// so a shutdown cancels the refresh attempt cleanly.
		bearer, berr := cred.Bearer(httpReq.Context())
		if berr != nil {
			return nil, &uploadError{
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
		return nil, &uploadError{Err: fmt.Errorf("http: %w", err)}
	}
	defer resp.Body.Close()

	// Catch all non-2xx: read response body (truncated) for dead letter diagnostics.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody := readTruncated(resp.Body, 512)
		return nil, &uploadError{
			StatusCode:   resp.StatusCode,
			ResponseBody: respBody,
			Err:          fmt.Errorf("collector error: %d", resp.StatusCode),
		}
	}

	var result batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		// 2xx but unparseable/absent body — still success, just no contiguous
		// info (older collector). Return nil resp so the caller conserves
		// (doesn't advance confirmedSeq) rather than failing the upload.
		slog.Debug("reporter: batch uploaded (unparsed response)")
		return nil, nil
	}

	slog.Debug("reporter: batch uploaded",
		"accepted", result.Accepted, "duplicated", result.Duplicated, "rejected", result.Rejected)
	return &result, nil
}
