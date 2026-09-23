package events

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/aikeytime"
)

// Fences for bugfix 2026-09-23-reporter-wal-full-reread-cpu — the BEHAVIORAL
// half. They use only symbols that existed before the fix (NewReporter,
// drainOnce, walSeqSet, resendWALSeqs, the content reporter, captureWarn), so
// the very same file runs against the pre-fix tree as the 能红 witness: there
// every drain pass re-parsed the whole directory (and prune parsed every rotated
// file again), so a malformed line was WARNed on every pass and a no-route event
// was counted dropped on every pass. After the fix each byte is parsed at most
// until it is handed over.
//
// Why WARN counting: it needs no new counter, is observable on both trees, and
// pins exactly the property that mattered in production — how many times the
// same bytes go through encoding/json.

func appendRaw(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
	_ = f.Close()
}

func countEvent(log, event string) int { return strings.Count(log, `"event.name":"`+event+`"`) }

// writeRotatedWAL writes a lexically-older hourly WAL file (never the writer's
// current file) with the given v2 entries, then the raw trailer (e.g. a
// malformed line).
func writeRotatedWAL(t *testing.T, dir, name string, trailer string, evs ...ReportableEvent) string {
	t.Helper()
	path := filepath.Join(dir, name)
	var b strings.Builder
	for i, ev := range evs {
		entry := WALEntry{SourceID: ev.SourceID, EventJSON: ev, WALSeq: int64(i + 1), WrittenAt: aikeytime.Now(), SchemaVersion: WALSchemaV2, SourceSeq: *ev.SourceSeq}
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	b.WriteString(trailer)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func newIdleReporter(t *testing.T, cfg *ReporterConfig) *Reporter {
	t.Helper()
	if cfg.UploadInterval == 0 {
		cfg.UploadInterval = time.Hour // the test drives drainOnce explicitly
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 10
	}
	r, err := NewReporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// A malformed line in the current file is parsed (and WARNed) exactly once per
// process: the pass that consumed it commits past it.
func TestDrain_MalformedLineWarnedOncePerProcess(t *testing.T) {
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()
	dir := t.TempDir()
	r := newIdleReporter(t, &ReporterConfig{CollectorURL: srv.URL, WALDir: dir})
	good := v2Event("good", "srcM", 1)
	r.wal.Append(&good) // append without a poke: the loop stays idle
	files, _ := ListWALFiles(dir)
	if len(files) != 1 {
		t.Fatalf("want 1 wal file, got %d", len(files))
	}
	appendRaw(t, files[0], "this is not json\n")
	log := captureWarn(t, func() {
		r.drainOnce(context.Background(), true)
		r.drainOnce(context.Background(), true)
	})
	if n := countEvent(log, "usage.wal.malformed_line"); n != 1 {
		t.Fatalf("malformed line WARNed %d times over two passes, want 1 (bytes must be parsed at most until handed over)", n)
	}
	if n := cs.idCount("good"); n != 1 {
		t.Fatalf("good event delivered %d times, want 1", n)
	}
}

// Events whose route has no destination are held in the WAL and counted
// dropped ONCE per Reporter lifetime — not once per pass. (Before the fix the
// same two events were re-parsed and re-counted on every pass.)
func TestDrain_NoRouteEventsCountedOnce(t *testing.T) {
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()
	dir := t.TempDir()
	r := newIdleReporter(t, &ReporterConfig{
		CollectorURL:    srv.URL,
		CollectorRoutes: map[string]string{"team": ""}, // present + empty = no destination
		WALDir:          dir,
	})
	for seq := int64(1); seq <= 2; seq++ {
		e := v2Event("t"+string(rune('0'+seq)), "srcN", seq)
		e.RouteSource = "team"
		r.wal.Append(&e)
	}
	for i := 0; i < 3; i++ {
		r.drainOnce(context.Background(), true)
	}
	if d := r.Metrics().Dropped; d != 2 {
		t.Fatalf("no-route events counted dropped %d times over three passes, want 2 (once each)", d)
	}
	if entries, _ := ReadAllWAL(dir); len(entries) != 2 {
		t.Fatalf("held events must stay in the WAL, got %d entries", len(entries))
	}
}

// A rotated (older-hour) file is parsed once for upload and its prune decision
// is taken from the index — no second parse per pass.
func TestPrune_DoesNotReReadRotatedFiles(t *testing.T) {
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()
	dir := t.TempDir()
	old := writeRotatedWAL(t, dir, "usage-20200101-00.jsonl", "garbage line\n",
		v2Event("p1", "srcP", 1), v2Event("p2", "srcP", 2))
	r := newIdleReporter(t, &ReporterConfig{CollectorURL: srv.URL, WALDir: dir})
	p3 := v2Event("p3", "srcP", 3)
	r.wal.Append(&p3) // current hourly file
	log := captureWarn(t, func() {
		r.drainOnce(context.Background(), true)
		r.drainOnce(context.Background(), true)
	})
	if n := countEvent(log, "usage.wal.malformed_line"); n != 1 {
		t.Fatalf("rotated file parsed %d times (WARN count), want 1: prune must decide from the index", n)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("rotated file with every seq confirmed must be pruned (stat err=%v)", err)
	}
	for _, id := range []string{"p1", "p2", "p3"} {
		if n := cs.idCount(id); n != 1 {
			t.Fatalf("%s delivered %d times, want 1", id, n)
		}
	}
}

// Reconcile's targeted re-send reads only the file(s) holding the wanted seq;
// the WAL-presence check refreshes the index instead of re-parsing everything.
func TestReconcile_ResendReadsOnlyFilesHoldingSeq(t *testing.T) {
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()
	dir := t.TempDir()
	writeRotatedWAL(t, dir, "usage-20200101-00.jsonl", "garbage line\n",
		v2Event("r1", "srcR", 1), v2Event("r2", "srcR", 2))
	writeRotatedWAL(t, dir, "usage-20200101-01.jsonl", "",
		v2Event("r3", "srcR", 3))
	r := newIdleReporter(t, &ReporterConfig{CollectorURL: srv.URL, WALDir: dir})
	log := captureWarn(t, func() {
		set := r.walSeqSet("srcR")
		if !set[1] || !set[2] || !set[3] {
			t.Fatalf("walSeqSet must see every seq on disk, got %v", set)
		}
		delivered := r.resendWALSeqs("srcR", []int64{3})
		if len(delivered) != 1 || delivered[0] != 3 {
			t.Fatalf("resend must deliver seq 3, got %v", delivered)
		}
	})
	if n := countEvent(log, "usage.wal.malformed_line"); n != 1 {
		t.Fatalf("file A (with the malformed line) was parsed %d times during reconcile, want 1: the re-send must read only the file holding seq 3", n)
	}
	if n := cs.idCount("r3"); n != 1 {
		t.Fatalf("r3 delivered %d times, want 1", n)
	}
}

// Content side of the same property: a malformed line in a rotated content
// file is parsed once; prune decides from the index.
func TestContentDrain_MalformedLineWarnedOnce(t *testing.T) {
	m := newMockCollector(t, 200, map[string]int64{"p1": 3})
	wal := seedContentWAL(t, 3)
	files, _ := ListContentWALFiles(wal.Dir())
	if len(files) != 3 {
		t.Fatalf("want 3 content files, got %d", len(files))
	}
	appendRaw(t, files[0], "garbage line\n") // rotated, not the current file
	r := newTestContentReporter(m.srv.URL, wal)
	log := captureWarn(t, func() {
		r.drainOnce(context.Background(), true)
		r.drainOnce(context.Background(), true)
	})
	if n := countEvent(log, "conversation.wal.malformed_line"); n != 1 {
		t.Fatalf("content malformed line WARNed %d times over two passes, want 1", n)
	}
	if _, err := os.Stat(files[0]); !os.IsNotExist(err) {
		t.Fatalf("confirmed rotated content file must be pruned (stat err=%v)", err)
	}
}
