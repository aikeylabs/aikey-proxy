package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// ContentReporterConfig configures the conversation-audit content reporter.
type ContentReporterConfig struct {
	Credential   Credential
	SeqAlloc     *SeqAllocator // content stream reserve-ahead allocator (nil → omit allocated_seq)
	HTTPClient   *http.Client
	CollectorURL string // team collector base URL (control-master :3000 ingress)
	// CollectorToken is the legacy static bearer used when Credential is nil —
	// MIRRORS the usage Reporter. Cluster worker nodes have NO per-route
	// "team" credential (no Personal vault/login); they authenticate the
	// collector with this static service token (set from cluster-node.env via
	// s.cfg.Events.CollectorToken), exactly as the usage reporter does. Without
	// this, cluster-node content uploads hit 401 "invalid or missing service
	// token". Bugfix: 2026-06-17-conversation-audit-cluster-content-reporter-collector-token.md
	CollectorToken  string
	ProxyInstanceID string
	UploadInterval  time.Duration
	BatchSize       int
}

// contentBatchRequest / contentBatchResponse mirror the collector
// /v1/conversation-records:batch wire. The proxy and collector share the JSON
// shape, not Go types — Records are the raw conversation-record JSONs the capture
// hook marshaled into the WAL, forwarded verbatim.
type contentBatchRequest struct {
	AllocatedSeq    *int64            `json:"allocated_seq,omitempty"`
	Source          string            `json:"source"`
	SourceVersion   string            `json:"source_version,omitempty"`
	ProxyInstanceID string            `json:"proxy_instance_id,omitempty"`
	Records         []json.RawMessage `json:"records"`
}

type contentBatchResponse struct {
	ContiguousSeq map[string]int64 `json:"contiguous_seq,omitempty"`
	Accepted      int              `json:"accepted"`
	Duplicated    int              `json:"duplicated"`
	Quarantined   int              `json:"quarantined"`
	Rejected      int              `json:"rejected"`
}

// ContentReporter is the conversation-audit content WAL-as-outbox pump — SEPARATE
// from the usage Reporter (own goroutine, own WAL) so content churn never affects
// financial-grade usage delivery. Single-route (the enterprise team master) — no
// per-RouteSource grouping. Mirrors the usage Reporter's
// drain→upload→prune→non-blocking-backoff, including the cursor model:
//   - sentSeq[source]:      highest seq handed to an upload → skip on re-read.
//   - confirmedSeq[source]: server contiguous high-water → prune WAL files ≤ it.
//
// Retryable failures leave cursors untouched (re-sent next pass; the server's
// (org,event_id) dedup absorbs the overlap). Terminal (4xx) drops the batch
// (advances sentSeq, no retry) — the gap is server-detectable via source_seq.
type ContentReporter struct {
	nextUploadAttempt   time.Time
	lastOKUploadAt      time.Time
	wal                 *ContentWAL
	sentSeq             map[string]int64
	confirmedSeq        map[string]int64
	signal              chan struct{}
	done                chan struct{}
	cfg                 ContentReporterConfig
	wg                  sync.WaitGroup
	consecutiveFailures int
	mu                  sync.Mutex
}

// NewContentReporter builds the content reporter. Defaults: 5s interval, 100/batch,
// 30s HTTP timeout.
func NewContentReporter(in *ContentReporterConfig, wal *ContentWAL) *ContentReporter {
	cfg := *in // local copy so default-fills never mutate the caller's value
	if cfg.UploadInterval <= 0 {
		cfg.UploadInterval = 5 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &ContentReporter{
		cfg:          cfg,
		wal:          wal,
		sentSeq:      make(map[string]int64),
		confirmedSeq: make(map[string]int64),
		signal:       make(chan struct{}, 1),
		done:         make(chan struct{}),
	}
}

// Start launches the upload loop on an isolated goroutine (a content-reporter
// panic must NEVER take down the proxy — this is a bypass concern).
func (r *ContentReporter) Start() {
	r.wg.Add(1)
	observability.GoSafe("events.content_reporter.upload_loop", observability.Isolated, r.uploadLoop)
}

// Poke wakes the loop (the capture hook calls it after Append; cap-1 coalesces).
func (r *ContentReporter) Poke() {
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

// Close stops the loop after a final flush.
func (r *ContentReporter) Close() error {
	close(r.done)
	r.wg.Wait()
	return nil
}

// LastOKUploadAt is the last successful upload time (server-reachability signal).
func (r *ContentReporter) LastOKUploadAt() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastOKUploadAt
}

func (r *ContentReporter) uploadLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.cfg.UploadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.drainOnce(false)
		case <-r.signal:
			r.drainOnce(false)
		case <-r.done:
			r.drainOnce(true) // final flush bypasses the backoff gate
			return
		}
	}
}

// drainOnce reads the content WAL, uploads entries not yet sent (source_seq >
// sentSeq[source]) in batches, then prunes confirmed files. A non-blocking
// backoff gate (set after retryable failures) skips passes until it elapses;
// `force` (shutdown flush) bypasses it.
func (r *ContentReporter) drainOnce(force bool) {
	if r.wal == nil || r.cfg.CollectorURL == "" {
		return
	}
	if !force {
		r.mu.Lock()
		gated := !r.nextUploadAttempt.IsZero() && time.Now().Before(r.nextUploadAttempt)
		r.mu.Unlock()
		if gated {
			return
		}
	}

	entries, err := ReadAllContentWAL(r.wal.Dir())
	if err != nil {
		slog.Warn("content reporter: wal read failed",
			"event.name", "conversation.reporter.wal_read_failed", "error", err)
	}

	anyRetryable := false
	pending := make([]ContentWALEntry, 0, len(entries))
	flush := func() {
		if len(pending) == 0 {
			return
		}
		if r.uploadBatch(pending) {
			anyRetryable = true
		}
		pending = pending[:0]
	}
	for i := range entries {
		e := entries[i]
		if e.SourceID == "" || e.SourceSeq == 0 {
			continue // content entries always carry source identity
		}
		r.mu.Lock()
		already := e.SourceSeq <= r.sentSeq[e.SourceID]
		r.mu.Unlock()
		if already {
			continue
		}
		pending = append(pending, e)
		if len(pending) >= r.cfg.BatchSize {
			flush()
		}
	}
	flush()

	if _, perr := PruneConfirmedContentWAL(r.wal.Dir(), r.confirmedMapCopy(), r.wal.CurrentFileName()); perr != nil {
		slog.Warn("content reporter: prune failed",
			"event.name", "conversation.reporter.prune_failed", "error", perr)
	}

	r.mu.Lock()
	if anyRetryable {
		r.nextUploadAttempt = time.Now().Add(backoffForFailures(r.consecutiveFailures))
	} else {
		r.nextUploadAttempt = time.Time{}
	}
	r.mu.Unlock()
}

func (r *ContentReporter) confirmedMapCopy() map[string]int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int64, len(r.confirmedSeq))
	for k, v := range r.confirmedSeq {
		out[k] = v
	}
	return out
}

// uploadBatch POSTs one batch. Returns true on a RETRYABLE failure (caller arms
// backoff). Success → advance sentSeq (batch max per source) + confirmedSeq (from
// response). Terminal (4xx except 429) → advance sentSeq (drop, no retry) + WARN.
// Retryable (429/5xx/transport) → leave cursors (re-sent next pass).
func (r *ContentReporter) uploadBatch(batch []ContentWALEntry) (retryable bool) {
	if len(batch) == 0 {
		return false
	}
	req := contentBatchRequest{
		Source:          "aikey-proxy",
		ProxyInstanceID: r.cfg.ProxyInstanceID,
		Records:         make([]json.RawMessage, 0, len(batch)),
	}
	maxSeq := make(map[string]int64)
	for _, e := range batch {
		req.Records = append(req.Records, e.Record)
		if e.SourceSeq > maxSeq[e.SourceID] {
			maxSeq[e.SourceID] = e.SourceSeq
		}
	}
	if r.cfg.SeqAlloc != nil {
		a := r.cfg.SeqAlloc.Allocated()
		req.AllocatedSeq = &a
	}
	body, err := json.Marshal(req)
	if err != nil {
		slog.Error("content reporter: marshal batch",
			"event.name", "conversation.reporter.marshal_failed", "error", err)
		return false // our own encode error won't self-heal; don't spin
	}

	resp, status, upErr := r.doUpload(body)
	if upErr == nil {
		r.mu.Lock()
		for src, c := range maxSeq {
			if c > r.sentSeq[src] {
				r.sentSeq[src] = c
			}
		}
		if resp != nil {
			for src, c := range resp.ContiguousSeq {
				if c > r.confirmedSeq[src] {
					r.confirmedSeq[src] = c
				}
			}
		}
		r.consecutiveFailures = 0
		r.lastOKUploadAt = time.Now()
		r.mu.Unlock()
		return false
	}

	retryableStatus := status == 0 || status == http.StatusTooManyRequests || status >= 500
	if !retryableStatus {
		// Terminal (400/401/403/…): drop — advance sentSeq so we don't re-send a
		// permanently-rejected batch. The dropped source_seq becomes a
		// server-detectable gap (collector stale-gap promotion advances past it).
		r.mu.Lock()
		for src, c := range maxSeq {
			if c > r.sentSeq[src] {
				r.sentSeq[src] = c
			}
		}
		r.consecutiveFailures++
		r.mu.Unlock()
		slog.Error("content reporter: terminal upload failure, batch dropped",
			"event.name", "conversation.reporter.terminal_failure",
			"error.code", "CONTENT_UPLOAD_TERMINAL", "status", status, "count", len(batch), "error", upErr)
		return false
	}

	r.mu.Lock()
	r.consecutiveFailures++
	r.mu.Unlock()
	slog.Warn("content reporter: upload failed (retryable), will retry from WAL",
		"event.name", "conversation.reporter.retryable_failure",
		"error.code", "CONTENT_UPLOAD_RETRYABLE", "status", status, "count", len(batch), "error", upErr)
	return true
}

// doUpload POSTs the batch. Returns (response, statusCode, err); err non-nil on
// any non-2xx or transport error. statusCode is 0 on transport error (→ retryable).
// A stale credential is surfaced as a synthetic 401 so it lands as terminal (no
// infinite retry), matching the usage reporter.
func (r *ContentReporter) doUpload(body []byte) (*contentBatchResponse, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	url := r.cfg.CollectorURL + "/v1/conversation-records:batch"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Auth resolution mirrors the usage Reporter: prefer the per-route team
	// Credential (Personal/lobster vault JWT), else fall back to the static
	// CollectorToken (cluster worker nodes — no team credential, authenticate
	// the collector with the cluster service token). Either may be empty for a
	// network-trust deployment, in which case no Authorization header is sent.
	if r.cfg.Credential != nil {
		tok, berr := r.cfg.Credential.Bearer(ctx)
		if berr != nil {
			return nil, http.StatusUnauthorized, fmt.Errorf("credential bearer: %w", berr)
		}
		if tok != "" {
			httpReq.Header.Set("Authorization", "Bearer "+tok)
		}
	} else if r.cfg.CollectorToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.cfg.CollectorToken)
	}
	httpResp, err := r.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, 0, err // transport → retryable
	}
	defer httpResp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return nil, httpResp.StatusCode, fmt.Errorf("collector status %d: %s", httpResp.StatusCode, string(rb))
	}
	var resp contentBatchResponse
	if err := json.Unmarshal(rb, &resp); err != nil {
		// 2xx but unparseable body → accepted-without-contiguous: advance sentSeq
		// (server took it), conserve confirmedSeq (no prune). nil resp signals that.
		return nil, httpResp.StatusCode, nil
	}
	return &resp, httpResp.StatusCode, nil
}
