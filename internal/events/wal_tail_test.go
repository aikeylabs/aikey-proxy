package events

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/AiKeyLabs/pkg/aikeytime"
)

// Guards for the incremental WAL reader (bugfix 2026-09-23-reporter-wal-full-
// reread-cpu). These pin the NEW invariants the tailer introduces — cost is
// O(new bytes), cursors commit only past handed-over entries, a live file's
// torn tail is deferred, reconcile sees late appends, deleted files are
// forgotten — and complement the behavioral fences in
// wal_reread_fence_test.go (which also serve as the 能红 witness).

func commitAll[E any](tl *walTailer[E], ends map[string]walPos) {
	for f, end := range ends {
		tl.commit(f, end.end, end.line)
	}
}

// The second pass parses only the bytes appended since the last commit; a
// third pass with nothing new parses zero bytes and opens no file.
func TestTail_SecondPassParsesOnlyNewBytes(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWALWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	for seq := int64(1); seq <= 50; seq++ {
		e := v2Event("e", "srcB", seq)
		w.Append(&e)
	}
	tl := newUsageWALTailer(dir)
	items, ends, err := tl.readNew(w.CurrentFileName())
	if err != nil || len(items) != 50 {
		t.Fatalf("first pass: items=%d err=%v", len(items), err)
	}
	commitAll(tl, ends)
	before := tl.bytesRead.Load()
	files, _ := ListWALFiles(dir)
	st0, _ := os.Stat(files[0])
	e51 := v2Event("e51", "srcB", 51)
	w.Append(&e51)
	st1, _ := os.Stat(files[0])
	items, ends, _ = tl.readNew(w.CurrentFileName())
	if len(items) != 1 || items[0].entry.SourceSeq != 51 {
		t.Fatalf("second pass must return exactly the new entry, got %d items", len(items))
	}
	if got, want := tl.bytesRead.Load()-before, st1.Size()-st0.Size(); got != want {
		t.Fatalf("second pass parsed %d bytes, want exactly the appended %d", got, want)
	}
	commitAll(tl, ends)
	before = tl.bytesRead.Load()
	items, _, _ = tl.readNew(w.CurrentFileName())
	if len(items) != 0 || tl.bytesRead.Load() != before {
		t.Fatalf("third pass with nothing new must parse 0 bytes (got %d items, %d bytes)", len(items), tl.bytesRead.Load()-before)
	}

	// content family, same contract
	cdir := t.TempDir()
	cw, err := NewContentWAL(cdir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for seq := int64(1); seq <= 20; seq++ {
		cw.Append("p1", seq, json.RawMessage(`{"event_id":"c","pad":"xxxxxxxxxx"}`))
	}
	ct := newContentWALTailer(cdir)
	citems, cends, _ := ct.readNew(cw.CurrentFileName())
	if len(citems) != 20 {
		t.Fatalf("content first pass: %d items", len(citems))
	}
	commitAll(ct, cends)
	cw.Append("p1", 21, json.RawMessage(`{"event_id":"c21"}`))
	citems, cends, _ = ct.readNew(cw.CurrentFileName())
	if len(citems) != 1 || citems[0].entry.SourceSeq != 21 {
		t.Fatalf("content second pass must return the one new entry, got %d", len(citems))
	}
	commitAll(ct, cends)
	cb := ct.bytesRead.Load()
	if citems, _, _ = ct.readNew(cw.CurrentFileName()); len(citems) != 0 || ct.bytesRead.Load() != cb {
		t.Fatalf("content third pass must parse nothing")
	}
}

// A retryable group holds the cursor at its FIRST entry; the next pass re-reads
// from there and delivers each held event once, while the already-sent
// interleaved entry of another route is filtered by sentSeq, never re-sent.
func TestDrain_RetryableGroupReReadNextPass(t *testing.T) {
	var teamFailing atomic.Bool
	teamFailing.Store(true)
	team := newCaptureServer(false)
	teamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if teamFailing.Load() {
			http.Error(w, "team collector down", http.StatusServiceUnavailable)
			return
		}
		team.handler()(w, req)
	}))
	defer teamSrv.Close()
	personal := newCaptureServer(false)
	personalSrv := httptest.NewServer(personal.handler())
	defer personalSrv.Close()
	dir := t.TempDir()
	r := newIdleReporter(t, &ReporterConfig{
		CollectorRoutes: map[string]string{"team": teamSrv.URL, "personal": personalSrv.URL},
		WALDir:          dir,
	})
	t1 := v2Event("t1", "srcT", 1)
	t1.RouteSource = "team"
	p2 := v2Event("p2", "srcP", 1)
	p2.RouteSource = "personal"
	t3 := v2Event("t3", "srcT", 2)
	t3.RouteSource = "team"
	r.wal.Append(&t1)
	r.wal.Append(&p2)
	r.wal.Append(&t3)

	r.drainOnce(context.Background(), true) // team 503 → held at t1; personal delivered
	if personal.idCount("p2") != 1 || team.idCount("t1") != 0 {
		t.Fatalf("pass 1: personal=%d team=%d", personal.idCount("p2"), team.idCount("t1"))
	}
	teamFailing.Store(false)
	r.drainOnce(context.Background(), true) // re-read from t1; p2 filtered by sentSeq
	if team.idCount("t1") != 1 || team.idCount("t3") != 1 {
		t.Fatalf("pass 2: held team events must be delivered once each (t1=%d t3=%d)", team.idCount("t1"), team.idCount("t3"))
	}
	if personal.idCount("p2") != 1 {
		t.Fatalf("pass 2: p2 re-sent (%d deliveries) — sentSeq must filter the re-read interleaved entry", personal.idCount("p2"))
	}
	before := r.tail.bytesRead.Load()
	r.drainOnce(context.Background(), true)
	if r.tail.bytesRead.Load() != before {
		t.Fatalf("pass 3: everything handed over, yet %d bytes were re-parsed", r.tail.bytesRead.Load()-before)
	}
}

// A live file's unterminated tail is the writer mid-append: it is neither
// parsed nor WARNed, and once the line completes it is delivered exactly once.
func TestDrain_TornTailDeferredThenDelivered(t *testing.T) {
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()
	dir := t.TempDir()
	r := newIdleReporter(t, &ReporterConfig{CollectorURL: srv.URL, WALDir: dir})
	first := v2Event("first", "srcX", 1)
	r.wal.Append(&first)
	path := filepath.Join(dir, r.wal.CurrentFileName())
	second := v2Event("second", "srcX", 2)
	line, err := json.Marshal(WALEntry{SourceID: "srcX", EventJSON: second, WALSeq: 2, WrittenAt: aikeytime.Now(), SchemaVersion: WALSchemaV2, SourceSeq: 2})
	if err != nil {
		t.Fatal(err)
	}
	half := len(line) / 2
	appendRaw(t, path, string(line[:half])) // torn: no newline yet
	log := captureWarn(t, func() { r.drainOnce(context.Background(), true) })
	if n := countEvent(log, "usage.wal.malformed_line"); n != 0 {
		t.Fatalf("a live file's unterminated tail must not be parsed as malformed (WARNs=%d)", n)
	}
	if cs.idCount("first") != 1 || cs.idCount("second") != 0 {
		t.Fatalf("after the torn pass: first=%d second=%d", cs.idCount("first"), cs.idCount("second"))
	}
	appendRaw(t, path, string(line[half:])+"\n")
	r.drainOnce(context.Background(), true)
	r.drainOnce(context.Background(), true)
	if n := cs.idCount("second"); n != 1 {
		t.Fatalf("completed line delivered %d times, want exactly 1", n)
	}
}

// Seqs land out of order (allocated before the append): the WAL-presence check
// used by reconcile must see a seq appended AFTER the drain that passed it.
func TestReconcile_WalSeqSetSeesLateAppend(t *testing.T) {
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()
	dir := t.TempDir()
	r := newIdleReporter(t, &ReporterConfig{CollectorURL: srv.URL, WALDir: dir})
	a1 := v2Event("a1", "srcL", 1)
	a3 := v2Event("a3", "srcL", 3)
	r.wal.Append(&a1)
	r.wal.Append(&a3)
	r.drainOnce(context.Background(), true)
	a2 := v2Event("a2", "srcL", 2)
	r.wal.Append(&a2) // late arrival, no drain in between
	set := r.walSeqSet("srcL")
	if !set[2] {
		t.Fatalf("walSeqSet must refresh from disk and see the late seq 2, got %v — otherwise reconcile would confirm-lost a seq that IS in the WAL", set)
	}
	if !set[1] || !set[3] {
		t.Fatalf("walSeqSet lost already-indexed seqs: %v", set)
	}
}

// Pruned files are forgotten (no stale cursor), and a file recreated under the
// same name is read from byte 0.
func TestTail_ForgetsPrunedFilesAndRereadsRecreated(t *testing.T) {
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()
	dir := t.TempDir()
	old := writeRotatedWAL(t, dir, "usage-20200101-00.jsonl", "", v2Event("f1", "srcF", 1))
	r := newIdleReporter(t, &ReporterConfig{CollectorURL: srv.URL, WALDir: dir})
	f2 := v2Event("f2", "srcF", 2)
	r.wal.Append(&f2)
	r.drainOnce(context.Background(), true) // f1,f2 delivered → contiguous 2 → old file pruned
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old file must be pruned (err=%v)", err)
	}
	r.tail.mu.Lock()
	_, tracked := r.tail.files[old]
	r.tail.mu.Unlock()
	if tracked {
		t.Fatalf("pruned file must be forgotten by the tailer")
	}
	// same name reappears with new content → read from 0
	writeRotatedWAL(t, dir, "usage-20200101-00.jsonl", "", v2Event("f3", "srcF", 3))
	r.drainOnce(context.Background(), true)
	if n := cs.idCount("f3"); n != 1 {
		t.Fatalf("recreated file must be read from the start (f3 delivered %d times)", n)
	}
}

// A file that got SHORTER than the committed cursor (rewritten) is WARNed once
// and re-read from the start; the replay is idempotent through sentSeq.
func TestTail_RewrittenFileIsReReadFromZero(t *testing.T) {
	dir := t.TempDir()
	path := writeRotatedWAL(t, dir, "usage-20200101-00.jsonl", "", v2Event("w1", "srcW", 1), v2Event("w2", "srcW", 2))
	tl := newUsageWALTailer(dir)
	items, ends, _ := tl.readNew("")
	if len(items) != 2 {
		t.Fatalf("first read: %d items", len(items))
	}
	commitAll(tl, ends)
	writeRotatedWAL(t, dir, "usage-20200101-00.jsonl", "", v2Event("w9", "srcW", 9)) // shorter than the cursor
	log := captureWarn(t, func() { items, _, _ = tl.readNew("") })
	if countEvent(log, "usage.wal.file_rewritten") != 1 {
		t.Fatalf("rewritten file must be WARNed once, log=%s", log)
	}
	if len(items) != 1 || items[0].entry.SourceSeq != 9 {
		t.Fatalf("rewritten file must be re-read from 0, got %d items", len(items))
	}
	_ = path
}
