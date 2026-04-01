package events

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// WALEntry wraps a reportable event with WAL metadata.
type WALEntry struct {
	WALSeq        int64           `json:"wal_seq"`
	WrittenAt     time.Time       `json:"written_at"`
	SchemaVersion int             `json:"schema_version"`
	EventJSON     ReportableEvent `json:"event_json"`
}

// WALWriter appends usage events to JSONL files, rotated hourly.
// This is write-only in the current phase; read-back is planned for Phase 2.
type WALWriter struct {
	dir     string
	seq     atomic.Int64
	mu      sync.Mutex
	file    *os.File
	curHour string

	appendFailed atomic.Int64
}

// NewWALWriter creates a WAL writer that writes to the given directory.
func NewWALWriter(dir string) (*WALWriter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create wal dir %s: %w", dir, err)
	}
	return &WALWriter{dir: dir}, nil
}

// Append writes a single event to the WAL. Non-blocking best-effort.
func (w *WALWriter) Append(ev ReportableEvent) {
	entry := WALEntry{
		WALSeq:        w.seq.Add(1),
		WrittenAt:     time.Now(),
		SchemaVersion: 1,
		EventJSON:     ev,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		slog.Error("wal: marshal failed", "error", err)
		w.appendFailed.Add(1)
		return
	}
	data = append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ensureFile(); err != nil {
		slog.Error("wal: open file failed", "error", err)
		w.appendFailed.Add(1)
		return
	}

	if _, err := w.file.Write(data); err != nil {
		slog.Error("wal: write failed", "error", err)
		w.appendFailed.Add(1)
	}
}

// AppendFailedTotal returns the count of failed WAL appends.
func (w *WALWriter) AppendFailedTotal() int64 {
	return w.appendFailed.Load()
}

// Close flushes and closes the current WAL file.
func (w *WALWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

// ensureFile opens or rotates the WAL file based on current hour.
// Must be called with w.mu held.
func (w *WALWriter) ensureFile() error {
	hour := time.Now().UTC().Format("20060102-15")
	if w.file != nil && w.curHour == hour {
		return nil
	}
	// Rotate
	if w.file != nil {
		_ = w.file.Close()
	}
	name := filepath.Join(w.dir, fmt.Sprintf("usage-%s.jsonl", hour))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		w.file = nil
		return err
	}
	w.file = f
	w.curHour = hour
	return nil
}
