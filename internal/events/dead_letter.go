package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/AiKeyLabs/pkg/aikeytime"
	"github.com/AiKeyLabs/pkg/buildinfo"
)

// failureType classifies upload errors for retry vs dead-letter decisions.
type failureType int

const (
	retryableFailure failureType = iota // network error, 5xx, 429
	terminalFailure                     // 401/403 (token mismatch), 400 (schema incompatible)
)

// classifyUploadError determines whether an upload failure is retryable.
// Terminal failures are written to dead_letter.jsonl immediately without retry.
func classifyUploadError(statusCode int) failureType {
	switch {
	case statusCode == 401, statusCode == 403:
		return terminalFailure // token mismatch, retry is pointless
	case statusCode == 400:
		return terminalFailure // request format / schema error
	default:
		return retryableFailure
	}
}

// uploadError carries HTTP status code and response body for diagnostics.
// doUpload returns *uploadError (not plain error) so uploadBatch can access
// status code and response body for dead letter records.
type uploadError struct {
	Err          error
	ResponseBody string // truncated to 512 bytes
	StatusCode   int
}

func (e *uploadError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("upload error: %d", e.StatusCode)
}

// readTruncated reads up to maxBytes from r, drains the rest, and returns the string.
func readTruncated(r io.Reader, maxBytes int) string {
	buf := make([]byte, maxBytes)
	n, _ := io.ReadFull(r, buf)
	_, _ = io.Copy(io.Discard, r) // drain remaining
	return string(buf[:n])
}

// deadLetterEntry is a single record in dead_letter.jsonl.
// Contains full diagnostic context for remote troubleshooting.
//
// DeadAt is int64 Unix epoch milliseconds (UTC) — consistent with the
// rest of the usage pipeline's timestamp format (bugfix 20260424).
type deadLetterEntry struct {
	ConfigHash    string            `json:"config_hash"`
	Reason        string            `json:"reason"` // "terminal" or "exhausted"
	ErrorMsg      string            `json:"error_msg"`
	ResponseBody  string            `json:"response_body"`
	CollectorURL  string            `json:"collector_url"`
	ProxyBuildID  string            `json:"proxy_build_id"`
	EventIDs      []string          `json:"event_ids"`
	Events        []ReportableEvent `json:"events"`
	ErrorCode     int               `json:"error_code"`
	DeadAt        aikeytime.Millis  `json:"dead_at"`
	AttemptCount  int               `json:"attempt_count"`
	BatchSize     int               `json:"batch_size"`
	SchemaVersion int               `json:"schema_version"`
}

// deadLetterWriter appends failed batches to dead_letter.jsonl.
type deadLetterWriter struct {
	path string
	mu   sync.Mutex
}

func newDeadLetterWriter(walDir string) *deadLetterWriter {
	return &deadLetterWriter{
		path: filepath.Join(walDir, "dead_letter.jsonl"),
	}
}

// Count returns the number of dead-letter entries currently on disk (one JSON
// object per line). Best-effort for `aikey audit status` (D2.5) — a read error
// or absent file reports 0. Each line is one failed upload batch.
func (w *deadLetterWriter) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	data, err := os.ReadFile(w.path)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			n++
		}
	}
	return n
}

func (w *deadLetterWriter) write(entry *deadLetterEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		slog.Error("dead_letter: marshal failed", "error", err)
		return
	}
	data = append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		slog.Error("dead_letter: open failed", "path", w.path, "error", err)
		return
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		slog.Error("dead_letter: write failed", "error", err)
	}
}

// ReplayDeadLetterResult is the outcome of one ReplayDeadLetter() pass.
// Surfaced to operators via the admin endpoint so they can tell at a
// glance whether replay made progress.
type ReplayDeadLetterResult struct {
	// LastError is the most recent error message seen on a re-upload
	// (empty if all succeeded). Useful for one-line diagnostics.
	LastError string `json:"last_error,omitempty"`
	// EntriesScanned is the total number of records read from
	// dead_letter.jsonl (one per failed batch from the original
	// upload run).
	EntriesScanned int `json:"entries_scanned"`
	// EntriesReplayedOK is the number of records that were successfully
	// re-delivered to the collector this pass. These are removed from
	// dead_letter.jsonl on disk.
	EntriesReplayedOK int `json:"entries_replayed_ok"`
	// EntriesStillFailing is the number of records still rejected
	// (e.g. JWT still expired, collector still 401). These are kept in
	// dead_letter.jsonl for a future replay attempt.
	EntriesStillFailing int `json:"entries_still_failing"`
	// EventsReplayedOK / EventsStillFailing sum the per-entry batch
	// sizes — useful when batches are large (one entry, 100 events).
	EventsReplayedOK   int `json:"events_replayed_ok"`
	EventsStillFailing int `json:"events_still_failing"`
}

// ReplayDeadLetter scans dead_letter.jsonl line by line and tries to
// re-deliver each entry's batch to the collector using the *current*
// reporter configuration (current CollectorRoutes / CollectorRouteCredentials
// — which is the whole point: after a `aikey login` refresh or a
// collector-side service_token rotation, the proxy's in-memory config
// is up to date even though the file's stale `collector_url` field
// is recorded at write time).
//
// On success the entry is removed from the file. On failure it stays.
// The file is rewritten atomically (write to a sibling .tmp then
// rename) so a mid-flight crash never leaves dead_letter.jsonl in a
// half-truncated state.
//
// The function holds the deadLetterWriter mutex for the whole pass,
// blocking any concurrent writes from the normal upload path during
// replay. This is intentional — the proxy isn't expected to be
// generating many new dead-letter entries while we're re-delivering
// old ones, and the simpler exclusive-lock model avoids a more
// complex two-phase commit between writes and re-deliveries.
//
// Added 2026-05-11 per the B-phase design doc's "reporter 401 fire-and-forget"
// follow-up: previously, every terminal failure was permanently lost
// the moment it hit dead_letter.jsonl, so a brief JWT expiry or
// collector restart would silently lose hours of usage events. With
// replay, an operator can run `aikey proxy replay-dead-letter` after
// fixing the upstream cause and recover everything.
func (r *Reporter) ReplayDeadLetter(ctx context.Context) (ReplayDeadLetterResult, error) {
	if r.dlw == nil {
		return ReplayDeadLetterResult{}, fmt.Errorf("reporter: dead-letter writer not configured")
	}
	r.dlw.mu.Lock()
	defer r.dlw.mu.Unlock()

	path := r.dlw.path
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ReplayDeadLetterResult{}, nil // nothing to replay
		}
		return ReplayDeadLetterResult{}, fmt.Errorf("read dead_letter: %w", err)
	}

	var result ReplayDeadLetterResult
	var keepLines [][]byte

	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		result.EntriesScanned++

		var entry deadLetterEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			// Malformed line — keep it so the operator can inspect manually;
			// not our place to silently drop unparseable history.
			slog.Warn("dead_letter replay: skip malformed line",
				"event.name", "dead_letter.replay.malformed_line",
				"error", err.Error(),
			)
			keepLines = append(keepLines, line)
			continue
		}

		// Resolve URL + credential from current cfg, not entry.CollectorURL.
		// Entry's URL was recorded at write time and may be stale (e.g.
		// CLI re-logged in to a different control-url since then).
		// We assume all events in one entry share the same RouteSource.
		routeSource := ""
		if len(entry.Events) > 0 {
			routeSource = entry.Events[0].RouteSource
		}
		url := r.urlForRouteSource(routeSource)
		cred := r.credentialForRouteSource(routeSource)
		if url == "" {
			// No upload destination configured for this RouteSource —
			// keep entry in dead-letter and warn. Common case: team
			// route configured but user logged out and `team` URL is
			// now empty.
			result.EntriesStillFailing++
			result.EventsStillFailing += len(entry.Events)
			result.LastError = fmt.Sprintf("no destination for route_source=%q", routeSource)
			keepLines = append(keepLines, line)
			continue
		}

		req := batchRequest{
			Source:          "aikey-proxy",
			SourceVersion:   "0.1.0",
			ProxyInstanceID: r.cfg.ProxyInstanceID,
			Events:          entry.Events,
		}
		body, err := json.Marshal(req)
		if err != nil {
			result.EntriesStillFailing++
			result.EventsStillFailing += len(entry.Events)
			result.LastError = "marshal: " + err.Error()
			keepLines = append(keepLines, line)
			continue
		}

		uploadURL := url + "/v1/usage-events:batch"
		// Honor context cancellation between entries (long replay can be
		// interrupted by SIGTERM during a graceful shutdown).
		select {
		case <-ctx.Done():
			// Keep the rest of the file unread; rewrite preserves entries
			// after this point as-is.
			keepLines = append(keepLines, line)
			// Note: we don't break here — we still want to flush
			// keepLines before exit, so just count this as not-replayed
			// and continue the loop. But ctx.Done means we should stop
			// trying. Use a flag.
			result.EntriesStillFailing++
			result.EventsStillFailing += len(entry.Events)
			result.LastError = "context canceled"
			// Continue draining to keep remaining lines.
			continue
		default:
		}

		if _, upErr := r.doUpload(uploadURL, body, cred); upErr != nil {
			result.EntriesStillFailing++
			result.EventsStillFailing += len(entry.Events)
			result.LastError = fmt.Sprintf("HTTP %d: %s", upErr.StatusCode, upErr.Err)
			keepLines = append(keepLines, line)
			slog.Info("dead_letter replay: still failing, kept",
				"event.name", "dead_letter.replay.still_failing",
				"event_ids", entry.EventIDs,
				"status", upErr.StatusCode,
			)
			continue
		}

		result.EntriesReplayedOK++
		result.EventsReplayedOK += len(entry.Events)
		r.uploadSuccess.Add(int64(len(entry.Events)))
		slog.Info("dead_letter replay: re-delivered",
			"event.name", "dead_letter.replay.delivered",
			"event_ids", entry.EventIDs,
			"route_source", routeSource,
		)
	}

	// Rewrite the file atomically — write tmp + rename. If we replayed
	// every entry, write an empty file rather than os.Remove() so the
	// path keeps existing (operators may have file watchers on it).
	tmpPath := path + ".tmp"
	out := bytes.Join(keepLines, []byte("\n"))
	if len(keepLines) > 0 {
		out = append(out, '\n')
	}
	if err := os.WriteFile(tmpPath, out, 0o600); err != nil {
		return result, fmt.Errorf("write dead_letter.tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return result, fmt.Errorf("rename dead_letter.tmp: %w", err)
	}

	slog.Info("dead_letter replay: pass complete",
		"event.name", "dead_letter.replay.pass_complete",
		"scanned", result.EntriesScanned,
		"replayed_ok", result.EntriesReplayedOK,
		"still_failing", result.EntriesStillFailing,
	)
	return result, nil
}

// writeDeadLetter records a failed batch to dead_letter.jsonl with full diagnostic context.
func (r *Reporter) writeDeadLetter(batch []ReportableEvent, reason string, upErr *uploadError, attempts int) {
	if r.dlw == nil {
		return
	}

	eventIDs := make([]string, len(batch))
	schemaVersion := 0
	for i := range batch {
		ev := &batch[i]
		eventIDs[i] = ev.EventID
		if ev.SchemaVersion > schemaVersion {
			schemaVersion = ev.SchemaVersion
		}
	}

	entry := deadLetterEntry{
		DeadAt:        aikeytime.Now(),
		Reason:        reason,
		ErrorCode:     upErr.StatusCode,
		ErrorMsg:      upErr.Error(),
		ResponseBody:  upErr.ResponseBody,
		CollectorURL:  r.cfg.CollectorURL + "/v1/usage-events:batch",
		ConfigHash:    r.cfg.ConfigHash,
		ProxyBuildID:  buildinfo.Get().BuildID,
		AttemptCount:  attempts,
		BatchSize:     len(batch),
		SchemaVersion: schemaVersion,
		EventIDs:      eventIDs,
		Events:        batch,
	}

	r.dlw.write(&entry)
}
