package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
)

// walTailer reads a JSONL WAL directory INCREMENTALLY: it remembers, per file,
// how far the reporter has processed (commit cursor) and how far the in-memory
// index reaches, so a drain pass parses only bytes it has not handed over yet.
//
// Why this exists (bugfix: workflow/CI/bugfix/2026-09-23-reporter-wal-full-reread-cpu.md):
// both reporters used to call ReadAllWAL / ReadAllContentWAL on EVERY pass —
// a 5 s ticker plus one wake-up per new event — and pruneConfirmedWAL re-read
// every rotated file again. Cost per pass was O(bytes in the directory), not
// O(new events): with a 21 MB hourly file + 9 MB content WAL a production node
// spent 85% of its CPU in encoding/json (perf, 7238 samples) and the co-located
// tokenhub's whole-machine CPU guard turned customer requests into 503s.
// Reading from the K+1 position is what the original design asked for
// (20260530-财务对账级用量审计-完整技术方案 §5.4); the rewrite simplified it to a
// full read per pass and the file grew past what that could carry.
//
// What is deliberately unchanged:
//   - Zero persisted cursor state (rewrite decision): the tailer lives on the
//     Reporter, not on the shared writer, so a restart or a hot reload starts
//     with empty cursors and replays every unpruned file once — the server's
//     (org_id,event_id) dedup absorbs the overlap exactly as before.
//   - File format and naming (the Rust CLI reads the same files).
//   - "Advance on send": a group that fails RETRYABLY is not committed; its
//     bytes are re-read next pass (advance_on_send_contract_test.go).
//   - Recovery of server-side holes still comes from ReconcileGaps, which
//     refreshes the index from disk before answering (seqs land out of order:
//     a lower seq can be appended after a higher one was drained).
//
// Two offsets per file: `commit` moves only by commit-on-done; `indexed` is the
// high-water of bytes whose keys are in the index, so re-reading a held range
// never double-counts. The '\n' gate applies to GROWABLE files only (the
// writer's current file, or the lexically last file — a same-hour restart
// appends to the same name): an unterminated tail there is the writer
// mid-append and is left for the next pass. On a rotated file an unterminated
// tail is a crash-torn line: it is finalized once (parsed, or WARNed and
// skipped) exactly like ReadWALFile does today, otherwise it would be re-read
// forever and block the file's prune.
type walTailer[E any] struct {
	mu          sync.Mutex
	dir         string
	spec        tailerSpec[E]
	files       map[string]*fileState
	bytesRead   atomic.Int64 // cumulative bytes parsed; tests read deltas
	linesParsed atomic.Int64
}

// tailerSpec adapts the tailer to one WAL family (usage / content).
type tailerSpec[E any] struct {
	list  func(dir string) ([]string, error)
	parse func(path string, line int, b []byte) (E, bool) // false = malformed (already WARNed)
	key   func(*E) lineKey
	// maxLine mirrors the Scanner buffer cap of the family's ReadXFile.
	maxLine int
	// keepSeqs records every seq per source (usage: served to walSeqSet /
	// resendWALSeqs). Content has no reconcile and keeps prompts out of memory.
	keepSeqs bool
	// requireV2 mirrors pruneConfirmedWAL's "at least one v2 entry" rule
	// (pure-legacy files are left to the retention sweep).
	requireV2   bool
	eventPrefix string // "usage.wal" | "conversation.wal"
}

// lineKey is what the index keeps per parsed line.
type lineKey struct {
	src     string
	seq     int64
	v1ID    string
	isV2    bool // keyed by (source, seq)
	unkeyed bool // usage: v1 with empty event_id; content: no source identity
}

// walPos locates one line: [start,end) byte offsets and its 1-based line number.
type walPos struct {
	file  string
	start int64
	end   int64
	line  int
}

// tailed is a parsed entry with its position, so the caller can commit past it
// (or hold at it) once the upload outcome is known.
type tailed[E any] struct {
	entry E
	pos   walPos
}

type srcIdx struct {
	max  int64
	seqs map[int64]struct{}
}

type fileIndex struct {
	keyed   map[string]*srcIdx
	v1IDs   []string
	unkeyed bool
	sawV2   bool
	entries int
}

type fileState struct {
	commit       int64 // bytes handed over as processed (drain cursor)
	commitLines  int   // lines before commit (for line numbers in WARNs)
	indexed      int64 // bytes whose keys are in idx
	indexedLines int
	lastSize     int64
	broken       bool // ErrTooLong etc.: never re-read, never prunable (as today)
	idx          fileIndex
}

func newWALTailer[E any](dir string, spec tailerSpec[E]) *walTailer[E] {
	return &walTailer[E]{dir: dir, spec: spec, files: make(map[string]*fileState)}
}

// newUsageWALTailer reads usage-*.jsonl. The parse closure repeats the six
// lines of ReadWALFile's unmarshal+WARN so the log shape stays identical and
// wal.go itself stays byte-for-byte unchanged.
func newUsageWALTailer(dir string) *walTailer[WALEntry] {
	return newWALTailer(dir, tailerSpec[WALEntry]{
		list: ListWALFiles,
		parse: func(path string, line int, b []byte) (WALEntry, bool) {
			var e WALEntry
			if err := json.Unmarshal(b, &e); err != nil {
				slog.Warn("wal: skip malformed line",
					"event.name", "usage.wal.malformed_line",
					"file", path, "line", line, "error", err)
				return WALEntry{}, false
			}
			return e, true
		},
		key: func(e *WALEntry) lineKey {
			if e.SchemaVersion >= WALSchemaV2 && e.SourceSeq > 0 {
				return lineKey{src: e.SourceID, seq: e.SourceSeq, isV2: true}
			}
			if e.EventJSON.EventID == "" {
				return lineKey{unkeyed: true}
			}
			return lineKey{v1ID: e.EventJSON.EventID}
		},
		maxLine:     8 * 1024 * 1024,
		keepSeqs:    true,
		requireV2:   true,
		eventPrefix: "usage.wal",
	})
}

// newContentWALTailer reads conv-*.jsonl (mirror of ReadContentWALFile).
func newContentWALTailer(dir string) *walTailer[ContentWALEntry] {
	return newWALTailer(dir, tailerSpec[ContentWALEntry]{
		list: ListContentWALFiles,
		parse: func(path string, line int, b []byte) (ContentWALEntry, bool) {
			var e ContentWALEntry
			if err := json.Unmarshal(b, &e); err != nil {
				slog.Warn("content wal: skip malformed line",
					"event.name", "conversation.wal.malformed_line",
					"file", path, "line", line, "error", err)
				return ContentWALEntry{}, false
			}
			return e, true
		},
		key: func(e *ContentWALEntry) lineKey {
			if e.SourceID == "" || e.SourceSeq == 0 {
				return lineKey{unkeyed: true}
			}
			return lineKey{src: e.SourceID, seq: e.SourceSeq, isV2: true}
		},
		maxLine:     32 * 1024 * 1024,
		keepSeqs:    false,
		requireV2:   false,
		eventPrefix: "conversation.wal",
	})
}

// readNew returns every entry not yet committed as processed, in file order,
// reading only bytes past each file's commit cursor. ends reports, per file
// touched this pass, the position just past the last complete line read — the
// caller commits to it when nothing in that file was held back, or to the
// first held entry's start otherwise. current is the writer's open file name
// (its unterminated tail is the writer mid-append).
func (t *walTailer[E]) readNew(current string) (items []tailed[E], ends map[string]walPos, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	paths, lerr := t.spec.list(t.dir)
	if lerr != nil {
		return nil, nil, lerr
	}
	t.forgetUnlisted(paths)
	ends = make(map[string]walPos)
	last := ""
	if len(paths) > 0 {
		last = paths[len(paths)-1]
	}
	var firstErr error
	for _, p := range paths {
		st := t.stateFor(p)
		size, ok := t.refreshSize(p, st)
		if !ok || st.broken || size == st.commit {
			continue
		}
		growable := filepath.Base(p) == current || p == last
		got, end, serr := t.scan(p, st, st.commit, st.commitLines, size, growable, true)
		items = append(items, got...)
		ends[p] = end
		if serr != nil && firstErr == nil {
			firstErr = serr
		}
	}
	return items, ends, firstErr
}

// refreshIndex brings the index up to date with what is on disk (bytes past
// `indexed`) WITHOUT touching commit cursors or returning entries. ReconcileGaps
// calls it before asking which seqs the WAL holds: seqs are allocated before
// the append, so a lower seq can land after a higher one was drained.
func (t *walTailer[E]) refreshIndex(current string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	paths, err := t.spec.list(t.dir)
	if err != nil {
		return err
	}
	t.forgetUnlisted(paths)
	last := ""
	if len(paths) > 0 {
		last = paths[len(paths)-1]
	}
	var firstErr error
	for _, p := range paths {
		st := t.stateFor(p)
		size, ok := t.refreshSize(p, st)
		if !ok || st.broken || size == st.indexed {
			continue
		}
		growable := filepath.Base(p) == current || p == last
		if _, _, serr := t.scan(p, st, st.indexed, st.indexedLines, size, growable, false); serr != nil && firstErr == nil {
			firstErr = serr
		}
	}
	return firstErr
}

// commit marks bytes [0,offset) of file as processed. Monotonic: a lower offset
// is ignored, so an overlapping pass can never rewind a cursor.
func (t *walTailer[E]) commit(file string, offset int64, lines int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.files[file]
	if st == nil {
		return
	}
	if offset > st.commit {
		st.commit = offset
		st.commitLines = lines
	}
}

// forget drops a file's cursor and index (after prune / retention / eviction
// removed it). A file that reappears under the same name is read from 0.
func (t *walTailer[E]) forget(file string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.files, file)
}

// prunable answers pruneConfirmedWAL / PruneConfirmedContentWAL's question from
// the index instead of re-reading the file. The predicate is the one both
// prune functions apply line by line: fully indexed and readable, at least one
// entry, no entry without a key, (usage) at least one v2 entry, every keyed
// source's max seq ≤ confirmed[source] (an unknown source counts as 0 → keep),
// and every v1 entry already uploaded (seenV1). The caller excludes the
// writer's current file itself.
func (t *walTailer[E]) prunable(file string, confirmed map[string]int64, seenV1 map[string]bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.files[file]
	if st == nil || st.broken || st.lastSize == 0 || st.indexed != st.lastSize || st.idx.entries == 0 {
		return false
	}
	if st.idx.unkeyed || (t.spec.requireV2 && !st.idx.sawV2) {
		return false
	}
	for src, si := range st.idx.keyed {
		if si.max > confirmed[src] {
			return false
		}
	}
	for _, id := range st.idx.v1IDs {
		if !seenV1[id] {
			return false
		}
	}
	return true
}

// seqSet returns the seqs the WAL holds for one source (union over files).
// Callers refreshIndex first.
func (t *walTailer[E]) seqSet(source string) map[int64]bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[int64]bool)
	for _, st := range t.files {
		if si := st.idx.keyed[source]; si != nil {
			for s := range si.seqs {
				out[s] = true
			}
		}
	}
	return out
}

// filesHolding returns, in chronological order, the files that hold at least
// one of the wanted seqs for source — so a targeted re-send reads one file, not
// the directory.
func (t *walTailer[E]) filesHolding(source string, want map[int64]bool) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for p, st := range t.files {
		si := st.idx.keyed[source]
		if si == nil {
			continue
		}
		for s := range want {
			if _, ok := si.seqs[s]; ok {
				out = append(out, p)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// ── internals (callers hold t.mu) ────────────────────────────────────────────

func (t *walTailer[E]) stateFor(p string) *fileState {
	st := t.files[p]
	if st == nil {
		st = &fileState{}
		t.files[p] = st
	}
	return st
}

func (t *walTailer[E]) forgetUnlisted(paths []string) {
	if len(t.files) == 0 {
		return
	}
	keep := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		keep[p] = struct{}{}
	}
	for p := range t.files {
		if _, ok := keep[p]; !ok {
			delete(t.files, p)
		}
	}
}

// refreshSize stats the file and resets the cursor when the file got SHORTER
// than what was already consumed (rewritten / recreated under the same name):
// re-reading from 0 is idempotent through sentSeq / seenV1 / server dedup.
func (t *walTailer[E]) refreshSize(p string, st *fileState) (int64, bool) {
	info, err := os.Stat(p)
	if err != nil {
		return 0, false // vanished between list and stat; forgotten on the next list
	}
	size := info.Size()
	if size < st.commit || size < st.indexed {
		slog.Warn("wal: file shrank or was rewritten — re-reading it from the start",
			"event.name", t.spec.eventPrefix+".file_rewritten",
			"file", p, "size", size, "cursor", st.commit)
		*st = fileState{}
	}
	st.lastSize = size
	return size, true
}

// scan reads complete lines of p from byte offset `from` (whose line number is
// fromLines+1) up to size. Lines past st.indexed are added to the index; when
// collect is true every parsed line is also returned. Malformed lines are
// WARNed and skipped by spec.parse (consumed, never re-parsed once committed).
func (t *walTailer[E]) scan(p string, st *fileState, from int64, fromLines int, size int64, growable, collect bool) ([]tailed[E], walPos, error) {
	end := walPos{file: p, start: from, end: from, line: fromLines}
	f, err := os.Open(p)
	if err != nil {
		return nil, end, err
	}
	defer f.Close()
	if from > 0 {
		if _, err := f.Seek(from, io.SeekStart); err != nil {
			return nil, end, err
		}
	}
	rd := bufio.NewReaderSize(io.LimitReader(f, size-from), 64*1024)
	var items []tailed[E]
	off := from
	line := fromLines
	var acc []byte
	for {
		chunk, rerr := rd.ReadSlice('\n')
		acc = append(acc, chunk...)
		if errors.Is(rerr, bufio.ErrBufferFull) {
			if len(acc) > t.spec.maxLine {
				// Same outcome as ReadWALFile's ErrTooLong: the file is not
				// readable past this line and is never pruned; say so once.
				slog.Warn("wal: line exceeds the reader cap — file frozen, not prunable",
					"event.name", t.spec.eventPrefix+".line_too_long",
					"file", p, "line", line+1, "cap", t.spec.maxLine)
				st.broken = true
				st.commit, st.indexed = size, size
				return items, walPos{file: p, start: size, end: size, line: line}, fmt.Errorf("scan wal file %s: line %d exceeds %d bytes", p, line+1, t.spec.maxLine)
			}
			continue
		}
		terminated := rerr == nil
		if !terminated && !errors.Is(rerr, io.EOF) {
			return items, end, fmt.Errorf("read wal file %s: %w", p, rerr)
		}
		if len(acc) == 0 {
			break // clean EOF
		}
		if !terminated && growable {
			break // unterminated tail of a live file: the writer is mid-append
		}
		lineStart := off
		off += int64(len(acc))
		line++
		t.bytesRead.Add(int64(len(acc)))
		b := acc
		if terminated {
			b = b[:len(b)-1]
		}
		b = bytes.TrimSuffix(b, []byte{'\r'})
		pos := walPos{file: p, start: lineStart, end: off, line: line}
		if len(b) > 0 {
			e, ok := t.spec.parse(p, line, b)
			if ok {
				t.linesParsed.Add(1)
			}
			if off > st.indexed {
				if ok {
					t.index(st, &e)
				}
				st.indexed, st.indexedLines = off, line
			}
			if ok && collect {
				items = append(items, tailed[E]{entry: e, pos: pos})
			}
		} else if off > st.indexed {
			st.indexed, st.indexedLines = off, line // blank line: consumed, nothing to parse
		}
		end = pos
		acc = acc[:0]
		if !terminated {
			break
		}
	}
	return items, end, nil
}

func (t *walTailer[E]) index(st *fileState, e *E) {
	k := t.spec.key(e)
	st.idx.entries++
	switch {
	case k.unkeyed:
		st.idx.unkeyed = true
	case k.isV2:
		st.idx.sawV2 = true
		if st.idx.keyed == nil {
			st.idx.keyed = make(map[string]*srcIdx)
		}
		si := st.idx.keyed[k.src]
		if si == nil {
			si = &srcIdx{}
			if t.spec.keepSeqs {
				si.seqs = make(map[int64]struct{})
			}
			st.idx.keyed[k.src] = si
		}
		if k.seq > si.max {
			si.max = k.seq
		}
		if si.seqs != nil {
			si.seqs[k.seq] = struct{}{}
		}
	default:
		st.idx.v1IDs = append(st.idx.v1IDs, k.v1ID)
	}
}
