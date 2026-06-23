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

	"github.com/AiKeyLabs/pkg/aikeycompat"
	"github.com/AiKeyLabs/pkg/aikeytime"
)

// ContentWALEntry wraps one conversation record (the upload payload) with WAL
// metadata. Record is the marshaled conversation-record JSON — the proxy and
// collector share the WIRE format, not Go types (the proxy must not import the
// collector's internal package), so the typed record is opaque here. SourceSeq
// is the per-source reserve-ahead integrity sequence the server uses for gap
// detection and the reporter uses for contiguous-confirmed WAL pruning.
type ContentWALEntry struct {
	SourceID  string           `json:"source_id,omitempty"`
	Record    json.RawMessage  `json:"record"`
	WALSeq    int64            `json:"wal_seq"`
	WrittenAt aikeytime.Millis `json:"written_at"`
	SourceSeq int64            `json:"source_seq,omitempty"`
}

// Content WAL roll defaults (design decision ⑬): 20MB per file, ≤100 files (≈2GB).
const (
	DefaultContentWALMaxBytes int64 = 20 * 1024 * 1024
	DefaultContentWALMaxFiles       = 100
)

// ContentWAL is the conversation-audit content outbox — an append-only JSONL WAL
// SEPARATE from the usage WAL (its own conv-*.jsonl namespace + its own instance)
// so large content payloads never bloat or slow the financial-grade usage WAL.
//
// Rotation is by SIZE (maxBytes): content volume per hour is unpredictable, so a
// fixed file size keeps files bounded (usage rolls hourly instead). A file-count
// cap (maxFiles) bounds disk: when exceeded, the OLDEST file is dropped — the
// fail-open disk guard (the design's accepted loss under a sustained master
// outage). The dropped source_seq range becomes a SERVER-detectable gap that the
// collector's stale-gap promotion advances the watermark past, so the watermark
// never sticks (3rd-review #1 / known-loss ledger).
//
// Mirrors WALWriter's best-effort, lock-guarded, fsync-on-group-commit style.
type ContentWAL struct {
	file         *os.File
	dir          string
	maxBytes     int64
	maxFiles     int
	seq          atomic.Int64
	curBytes     int64
	rotCtr       int
	appendFailed atomic.Int64
	evicted      atomic.Int64
	mu           sync.Mutex
}

// NewContentWAL creates a content WAL writer. Zero maxBytes/maxFiles fall back to
// the 20MB / 100-file defaults.
func NewContentWAL(dir string, maxBytes int64, maxFiles int) (*ContentWAL, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultContentWALMaxBytes
	}
	if maxFiles <= 0 {
		maxFiles = DefaultContentWALMaxFiles
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create content wal dir %s: %w", dir, err)
	}
	// Content includes prompts (may carry source/secrets) — harden NTFS ACL like
	// the usage WAL does for key fingerprints.
	_ = aikeycompat.EnforceOwnerOnly(dir)
	return &ContentWAL{dir: dir, maxBytes: maxBytes, maxFiles: maxFiles}, nil
}

// Append writes one content entry. Non-blocking best-effort (mirrors WALWriter):
// a failure is counted + logged, never propagated to the caller's path — content
// capture must never disturb the proxy's forwarding hot path.
func (w *ContentWAL) Append(sourceID string, sourceSeq int64, record json.RawMessage) {
	entry := ContentWALEntry{
		WALSeq:    w.seq.Add(1),
		WrittenAt: aikeytime.Now(),
		SourceID:  sourceID,
		SourceSeq: sourceSeq,
		Record:    record,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		slog.Error("content wal: marshal failed",
			"event.name", "conversation.wal.marshal_failed",
			"error.code", "CONTENT_WAL_MARSHAL_FAILED", "error", err)
		w.appendFailed.Add(1)
		return
	}
	data = append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	if efErr := w.ensureFile(int64(len(data))); efErr != nil {
		slog.Error("content wal: open file failed",
			"event.name", "conversation.wal.open_failed",
			"error.code", "CONTENT_WAL_OPEN_FAILED", "error", efErr)
		w.appendFailed.Add(1)
		return
	}
	n, err := w.file.Write(data)
	if err != nil {
		slog.Error("content wal: write failed",
			"event.name", "conversation.wal.write_failed",
			"error.code", "CONTENT_WAL_WRITE_FAILED", "error", err)
		w.appendFailed.Add(1)
		return
	}
	w.curBytes += int64(n)
}

// ensureFile opens the first file, or rotates when the current file would exceed
// maxBytes, then evicts oldest files beyond maxFiles. Must hold w.mu. `incoming`
// is the size of the pending entry; a single entry larger than maxBytes still
// gets its own fresh file (no infinite rotation).
func (w *ContentWAL) ensureFile(incoming int64) error {
	if w.file != nil && w.curBytes > 0 && w.curBytes+incoming > w.maxBytes {
		_ = w.file.Sync()
		_ = w.file.Close()
		w.file = nil
	}
	if w.file != nil {
		return nil
	}
	// Filename: 13-digit open-millis + 4-digit per-process rotation counter.
	// Millis keeps lexical == chronological order across restarts; the counter
	// disambiguates same-millis rotations. Glob conv-*.jsonl, lexical sort.
	w.rotCtr++
	name := filepath.Join(w.dir, fmt.Sprintf("conv-%013d-%04d.jsonl", int64(aikeytime.Now()), w.rotCtr))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		w.file = nil
		return err
	}
	w.file = f
	w.curBytes = 0
	w.evictBeyondCap()
	return nil
}

// evictBeyondCap drops the oldest content WAL files when the count exceeds
// maxFiles, NEVER the current (just-opened) file. Fail-open disk guard: the
// dropped seqs become a server-detectable gap. Must hold w.mu.
func (w *ContentWAL) evictBeyondCap() {
	files, err := ListContentWALFiles(w.dir)
	if err != nil || len(files) <= w.maxFiles {
		return
	}
	cur := ""
	if w.file != nil {
		cur = w.file.Name()
	}
	over := len(files) - w.maxFiles
	for _, p := range files {
		if over <= 0 {
			break
		}
		if p == cur {
			continue // never delete the file we're writing to
		}
		if err := os.Remove(p); err != nil {
			continue
		}
		w.evicted.Add(1)
		over--
		slog.Warn("content wal: evicted oldest file (cap exceeded — bounded disk; dropped seqs are server-detectable)",
			"event.name", "conversation.wal.evicted",
			"error.code", "CONTENT_WAL_CAP_EVICTED", "file", filepath.Base(p))
	}
}

// Sync flushes the current file (group-commit point). No-op when no file open.
func (w *ContentWAL) Sync() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		if err := w.file.Sync(); err != nil {
			slog.Warn("content wal: fsync failed",
				"event.name", "conversation.wal.fsync_failed",
				"error.code", "CONTENT_WAL_FSYNC_FAILED", "error", err)
			w.appendFailed.Add(1)
		}
	}
}

// Close fsyncs + closes the current file.
func (w *ContentWAL) Close() error {
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

// Dir returns the WAL directory. CurrentFileName returns the open file's base
// name (or ""), so the reporter's prune never deletes the file being written.
func (w *ContentWAL) Dir() string { return w.dir }

func (w *ContentWAL) CurrentFileName() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return ""
	}
	return filepath.Base(w.file.Name())
}

func (w *ContentWAL) AppendFailedTotal() int64 { return w.appendFailed.Load() }
func (w *ContentWAL) EvictedTotal() int64      { return w.evicted.Load() }

// ListContentWALFiles returns absolute paths of conv-*.jsonl in dir, sorted
// ascending (lexical == chronological by the millis-prefixed name) — the order
// the reporter replays in.
func ListContentWALFiles(dir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "conv-*.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("glob content wal dir %s: %w", dir, err)
	}
	sort.Strings(matches)
	return matches, nil
}

// ReadContentWALFile parses one file, tolerating malformed/torn tail lines
// (logged + skipped) so a crash mid-write never blocks replay of prior lines.
func ReadContentWALFile(path string) ([]ContentWALEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open content wal file %s: %w", path, err)
	}
	defer f.Close()
	var out []ContentWALEntry
	sc := bufio.NewScanner(f)
	// Content lines can be large (full prompts) — raise the cap well above 64KB.
	sc.Buffer(make([]byte, 0, 64*1024), 32*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var e ContentWALEntry
		if err := json.Unmarshal(b, &e); err != nil {
			slog.Warn("content wal: skip malformed line",
				"event.name", "conversation.wal.malformed_line",
				"file", path, "line", line, "error", err)
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("scan content wal file %s: %w", path, err)
	}
	return out, nil
}

// ReadAllContentWAL reads every conv-*.jsonl in chronological order. Used by the
// reporter for cold-start replay. Malformed lines / unreadable files are skipped.
func ReadAllContentWAL(dir string) ([]ContentWALEntry, error) {
	files, err := ListContentWALFiles(dir)
	if err != nil {
		return nil, err
	}
	var all []ContentWALEntry
	for _, p := range files {
		entries, err := ReadContentWALFile(p)
		if err != nil {
			slog.Warn("content wal: partial/failed file read, continuing",
				"event.name", "conversation.wal.file_read_error", "file", p, "error", err)
		}
		all = append(all, entries...)
	}
	return all, nil
}

// PruneConfirmedContentWAL deletes content WAL files whose EVERY entry has been
// server-confirmed — i.e. for each entry, the server's contiguous high-water for
// that entry's source (confirmed[source_id]) is ≥ the entry's source_seq. A file
// with ANY unconfirmed entry is kept (the reporter re-reads it next pass; the
// server's (org,event_id) dedup absorbs the overlap — conserve, never lose). The
// currentFileBase (ContentWAL.CurrentFileName()) is NEVER deleted. Unreadable or
// empty files are kept (conservative). Returns the count pruned.
//
// This is the content side of the delivery contract: the reporter advances its
// confirmed map from each batch response's contiguous_seq, then calls this to
// reclaim disk for fully-delivered files. Mirrors the usage WAL prune.
func PruneConfirmedContentWAL(dir string, confirmed map[string]int64, currentFileBase string) (int, error) {
	files, err := ListContentWALFiles(dir)
	if err != nil {
		return 0, err
	}
	pruned := 0
	for _, p := range files {
		if filepath.Base(p) == currentFileBase {
			continue // never delete the file currently being written
		}
		entries, err := ReadContentWALFile(p)
		if err != nil || len(entries) == 0 {
			continue // unreadable / empty → keep (conserve)
		}
		allConfirmed := true
		for _, e := range entries {
			c, ok := confirmed[e.SourceID]
			// No source identity, unknown source, or seq beyond the confirmed
			// high-water ⇒ not (yet) safe to drop this file.
			if e.SourceID == "" || e.SourceSeq == 0 || !ok || e.SourceSeq > c {
				allConfirmed = false
				break
			}
		}
		if allConfirmed {
			if err := os.Remove(p); err == nil {
				pruned++
			}
		}
	}
	return pruned, nil
}
