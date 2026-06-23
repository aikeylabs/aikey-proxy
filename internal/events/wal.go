package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/pkg/aikeycompat"
	"github.com/AiKeyLabs/pkg/aikeytime"
)

// WALEntry wraps a reportable event with WAL metadata.
//
// WrittenAt is int64 Unix epoch milliseconds (UTC) — same format as
// every other timestamp in the usage pipeline, so consumers that
// parse the WAL envelope (e.g. the CLI's usage_wal.rs) don't need a
// second format path. See bugfix 20260424 chain-consistency round.
type WALEntry struct {
	// Delivery-integrity fields (WAL schema v2, 2026-05-30). Populated only on
	// v2 entries; absent (omitempty) on legacy v1 entries which remain readable.
	//   SourceID:    this vault's stable source identity (runtime.source_identity).
	//   SourceSeq:   per-source, never-reused sequence from SeqAllocator. This is
	//                the integrity sequence the server uses for gap detection —
	//                distinct from WALSeq (a local, restart-resetting line counter
	//                kept only for the CLI watcher's turn-bounding watermark).
	//   ContentHash: hash of normalized metering fields (filled in phase C; "" now).
	// v1 entries (no SourceSeq) are shown locally by statusline/watch but do NOT
	// participate in upload gap detection — see design doc §5.2 / §6 invariant 6.
	SourceID      string           `json:"source_id,omitempty"`
	ContentHash   string           `json:"content_hash,omitempty"`
	EventJSON     ReportableEvent  `json:"event_json"`
	WALSeq        int64            `json:"wal_seq"`
	WrittenAt     aikeytime.Millis `json:"written_at"`
	SchemaVersion int              `json:"schema_version"`
	SourceSeq     int64            `json:"source_seq,omitempty"`
}

// WALSchemaV2 is the entry schema version that carries the delivery-integrity
// fields (source_id / source_seq / content_hash). v1 entries lack them.
const WALSchemaV2 = 2

// WALWriter appends usage events to JSONL files, rotated hourly. Read-back for
// the delivery-integrity outbox is provided by the package functions
// ListWALFiles / ReadWALFile / ReadAllWAL (the WAL is no longer write-only).
type WALWriter struct {
	file         *os.File
	dir          string
	curHour      string
	seq          atomic.Int64
	appendFailed atomic.Int64
	mu           sync.Mutex
}

// NewWALWriter creates a WAL writer that writes to the given directory.
func NewWALWriter(dir string) (*WALWriter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create wal dir %s: %w", dir, err)
	}
	// Stage 2.5 windows-compat: WAL contains usage-event payloads which
	// can include provider key fingerprints — harden NTFS ACL.
	_ = aikeycompat.EnforceOwnerOnly(dir)
	return &WALWriter{dir: dir}, nil
}

// Append writes a single event to the WAL. Non-blocking best-effort.
//
// The envelope mirrors the event's delivery-integrity fields
// (SourceID / SourceSeq / content hash) so read-back (ReadAll) can filter and
// order by source_seq WITHOUT deserializing the nested event_json. When the
// event carries a SourceSeq the entry is tagged WALSchemaV2; otherwise it stays
// v1-shaped (offline / pre-seqalloc path) and is shown locally but excluded
// from upload gap detection.
//
// fsync policy: durability is handled by the periodic group-commit fsync in the
// uploader/close path (design §5.3), not per-Append — keeping the hot path off
// a synchronous disk flush. Append remains best-effort; a hard crash may lose
// the last un-fsync'd group, which reserve-ahead turns into an auditable gap
// rather than silent loss (§6.1 H2).
func (w *WALWriter) Append(ev *ReportableEvent) {
	entry := WALEntry{
		WALSeq:      w.seq.Add(1),
		WrittenAt:   aikeytime.Now(),
		EventJSON:   *ev,
		SourceID:    ev.SourceID,
		ContentHash: ev.ContentHash, // stamped in BuildReportableEvent (stage C)
	}
	if ev.SourceSeq != nil {
		entry.SourceSeq = *ev.SourceSeq
		entry.SchemaVersion = WALSchemaV2
	} else {
		entry.SchemaVersion = 1
	}

	data, err := json.Marshal(entry)
	if err != nil {
		// Structured event.name/error.code so disk/serialization failures in the
		// usage outbox are diagnosable centrally, not just as free-text slog
		// (logging-conventions; matches sibling collector.go's literal style).
		slog.Error("wal: marshal failed",
			"event.name", "usage.wal.marshal_failed",
			"error.code", "WAL_MARSHAL_FAILED",
			"error", err)
		w.appendFailed.Add(1)
		return
	}
	data = append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ensureFile(); err != nil {
		// Disk full / permission / rotation failure opening the WAL file. This is
		// the primary disk-full diagnosis signal (logging-conventions).
		slog.Error("wal: open file failed",
			"event.name", "usage.wal.open_failed",
			"error.code", "WAL_OPEN_FAILED",
			"error", err)
		w.appendFailed.Add(1)
		return
	}

	if _, err := w.file.Write(data); err != nil {
		// Partial/failed write (e.g. disk full mid-append) — externally tracked via
		// the usage_wal_append_failed_total counter; tagged for central diagnosis.
		slog.Error("wal: write failed",
			"event.name", "usage.wal.write_failed",
			"error.code", "WAL_WRITE_FAILED",
			"error", err)
		w.appendFailed.Add(1)
	}
}

// Sync flushes the current WAL file's buffered writes to disk (group-commit
// point). Called periodically by the uploader and once on Close. Safe to call
// when no file is open (no-op). Best-effort: a Sync error is counted, not
// returned, so the caller's commit cadence isn't coupled to disk hiccups.
func (w *WALWriter) Sync() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		if err := w.file.Sync(); err != nil {
			// fsync failure at the group-commit point (e.g. disk full on flush).
			// Kept at WARN (durability is best-effort here, not hot-path) but
			// tagged so it's diagnosable centrally (logging-conventions).
			slog.Warn("wal: fsync failed",
				"event.name", "usage.wal.fsync_failed",
				"error.code", "WAL_FSYNC_FAILED",
				"error", err)
			w.appendFailed.Add(1)
		}
	}
}

// AppendFailedTotal returns the count of failed WAL appends.
func (w *WALWriter) AppendFailedTotal() int64 {
	return w.appendFailed.Load()
}

// Close flushes (fsync) and closes the current WAL file. The fsync on close
// makes a graceful shutdown lose nothing from the current group.
func (w *WALWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		_ = w.file.Sync()
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

// Dir returns the WAL directory, so the uploader can list/read/clean files
// without holding a separate copy of the path.
func (w *WALWriter) Dir() string { return w.dir }

// CurrentFileName returns the base name of the WAL file currently open for
// writing (e.g. "usage-20260530-18.jsonl"), or "" if none is open. Cleanup must
// never delete this file. Holds the writer lock so it races safely with rotation.
func (w *WALWriter) CurrentFileName() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return ""
	}
	return filepath.Base(w.file.Name())
}

// ListWALFiles returns the absolute paths of WAL files in dir, sorted
// ascending. Filenames embed a zero-padded UTC hour (usage-YYYYMMDD-HH.jsonl)
// so lexical order == chronological order — the order the uploader replays in.
func ListWALFiles(dir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "usage-*.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("glob wal dir %s: %w", dir, err)
	}
	sort.Strings(matches)
	return matches, nil
}

// ReadWALFile parses one WAL file into entries, tolerating malformed lines
// (logged and skipped, not fatal) so a single torn tail line — e.g. from a
// crash mid-write — never blocks replay of everything before it.
func ReadWALFile(path string) ([]WALEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wal file %s: %w", path, err)
	}
	defer f.Close()

	var out []WALEntry
	sc := bufio.NewScanner(f)
	// Usage events can be large (raw token breakdowns); raise the line cap well
	// above bufio's 64KB default so a big-but-valid line isn't dropped as "torn".
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var e WALEntry
		if err := json.Unmarshal(b, &e); err != nil {
			slog.Warn("wal: skip malformed line",
				"event.name", "usage.wal.malformed_line",
				"file", path, "line", line, "error", err)
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		// A scan error (e.g. a line exceeding the cap) returns what parsed so
		// far plus the error — caller decides whether partial replay is OK.
		return out, fmt.Errorf("scan wal file %s: %w", path, err)
	}
	return out, nil
}

// ReadAllWAL reads every WAL file in dir in chronological order and returns all
// entries concatenated. Used by the uploader for cold-start replay (resume from
// the oldest un-cleaned file). Malformed lines are skipped per ReadWALFile; an
// unreadable file is logged and skipped so one bad file doesn't block the rest.
func ReadAllWAL(dir string) ([]WALEntry, error) {
	files, err := ListWALFiles(dir)
	if err != nil {
		return nil, err
	}
	var all []WALEntry
	for _, p := range files {
		entries, err := ReadWALFile(p)
		if err != nil {
			slog.Warn("wal: partial/failed file read, continuing",
				"event.name", "usage.wal.file_read_error", "file", p, "error", err)
		}
		all = append(all, entries...)
	}
	return all, nil
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
