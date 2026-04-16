package events

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

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
	StatusCode   int
	ResponseBody string // truncated to 512 bytes
	Err          error
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
	io.Copy(io.Discard, r) // drain remaining
	return string(buf[:n])
}

// deadLetterEntry is a single record in dead_letter.jsonl.
// Contains full diagnostic context for remote troubleshooting.
type deadLetterEntry struct {
	DeadAt       time.Time         `json:"dead_at"`
	Reason       string            `json:"reason"` // "terminal" or "exhausted"
	ErrorCode    int               `json:"error_code"`
	ErrorMsg     string            `json:"error_msg"`
	ResponseBody string            `json:"response_body"`
	CollectorURL string            `json:"collector_url"`
	ConfigHash   string            `json:"config_hash"`
	ProxyBuildID string            `json:"proxy_build_id"`
	AttemptCount int               `json:"attempt_count"`
	BatchSize    int               `json:"batch_size"`
	SchemaVersion int              `json:"schema_version"`
	EventIDs     []string          `json:"event_ids"`
	Events       []ReportableEvent `json:"events"`
}

// deadLetterWriter appends failed batches to dead_letter.jsonl.
type deadLetterWriter struct {
	mu   sync.Mutex
	path string
}

func newDeadLetterWriter(walDir string) *deadLetterWriter {
	return &deadLetterWriter{
		path: filepath.Join(walDir, "dead_letter.jsonl"),
	}
}

func (w *deadLetterWriter) write(entry deadLetterEntry) {
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

// writeDeadLetter records a failed batch to dead_letter.jsonl with full diagnostic context.
func (r *Reporter) writeDeadLetter(batch []ReportableEvent, reason string, upErr *uploadError, attempts int) {
	if r.dlw == nil {
		return
	}

	eventIDs := make([]string, len(batch))
	schemaVersion := 0
	for i, ev := range batch {
		eventIDs[i] = ev.EventID
		if ev.SchemaVersion > schemaVersion {
			schemaVersion = ev.SchemaVersion
		}
	}

	entry := deadLetterEntry{
		DeadAt:        time.Now(),
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

	r.dlw.write(entry)
}
