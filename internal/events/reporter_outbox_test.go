package events

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/aikeytime"
)

// captureServer records every event_id it receives and replies with a
// contiguous_seq map computed from the connected prefix of source_seqs seen so
// far (a minimal stand-in for the real collector). Lets outbox tests assert
// both delivery and WAL pruning.
type captureServer struct {
	mu            sync.Mutex
	seenSeqs      map[string]map[int64]bool // source -> set of seqs
	ids           []string
	dropV2        bool   // if true, omit contiguous_seq (simulates an older collector)
	lastAllocated *int64 // last batchRequest.AllocatedSeq seen (nil if never sent)
}

func newCaptureServer(dropV2 bool) *captureServer {
	return &captureServer{seenSeqs: map[string]map[int64]bool{}, dropV2: dropV2}
}

func (c *captureServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		c.mu.Lock()
		if req.AllocatedSeq != nil {
			v := *req.AllocatedSeq
			c.lastAllocated = &v
		}
		for _, e := range req.Events {
			c.ids = append(c.ids, e.EventID)
			if e.SourceSeq != nil {
				if c.seenSeqs[e.SourceID] == nil {
					c.seenSeqs[e.SourceID] = map[int64]bool{}
				}
				c.seenSeqs[e.SourceID][*e.SourceSeq] = true
			}
		}
		resp := batchResponse{Accepted: len(req.Events)}
		if !c.dropV2 {
			resp.ContiguousSeq = map[string]int64{}
			for src, set := range c.seenSeqs {
				var cont int64
				for set[cont+1] {
					cont++
				}
				resp.ContiguousSeq[src] = cont
			}
		}
		c.mu.Unlock()
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func (c *captureServer) idCount(id string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, got := range c.ids {
		if got == id {
			n++
		}
	}
	return n
}

func v2Event(id, src string, seq int64) ReportableEvent {
	s := seq
	now := aikeytime.Now()
	return ReportableEvent{
		EventID: id, OrgID: "o", SourceID: src, SourceSeq: &s,
		RouteSource: "personal", EventTime: now, OccurredAt: now,
		RequestStatus: "success", RequestCount: 1,
	}
}

// TestOutbox_UploadsFromWAL is the basic round-trip: events appended to the WAL
// are uploaded from it (not from any in-memory queue) and reach the collector
// with their integrity fields intact.
func TestOutbox_UploadsFromWAL(t *testing.T) {
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()

	r, err := NewReporter(ReporterConfig{
		CollectorURL:   srv.URL,
		WALDir:         t.TempDir(),
		BatchSize:      10,
		UploadInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	for seq := int64(1); seq <= 3; seq++ {
		r.Report(v2Event("e"+string(rune('0'+seq)), "srcA", seq))
	}
	time.Sleep(150 * time.Millisecond)
	r.Close()

	for seq := int64(1); seq <= 3; seq++ {
		if n := cs.idCount("e" + string(rune('0'+seq))); n != 1 {
			t.Errorf("event seq=%d delivered %d times, want 1", seq, n)
		}
	}
}

// TestOutbox_NoReSendWithinProcess proves the in-memory sentSeq cursor prevents
// re-uploading already-sent events on subsequent drain passes (so a steady WAL
// isn't re-shipped every interval).
func TestOutbox_NoReSendWithinProcess(t *testing.T) {
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()

	r, err := NewReporter(ReporterConfig{
		CollectorURL:   srv.URL,
		WALDir:         t.TempDir(),
		BatchSize:      10,
		UploadInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.Report(v2Event("only", "srcA", 1))
	// Let several drain intervals elapse — must still upload exactly once.
	time.Sleep(150 * time.Millisecond)
	r.Close()

	if n := cs.idCount("only"); n != 1 {
		t.Fatalf("event re-sent %d times across drain passes, want exactly 1", n)
	}
}

// TestOutbox_RestartReplaysUnconfirmed simulates a crash (new Reporter over the
// same WAL dir, cursors reset): the second reporter replays the WAL from the
// start, the server dedups, and every event is still ultimately delivered. This
// is the "restart resends, dedup absorbs" invariant — no loss across restart.
func TestOutbox_RestartReplaysUnconfirmed(t *testing.T) {
	dir := t.TempDir()

	// Reporter #1 with NO collector → events only WAL'd, never uploaded.
	r1, err := NewReporter(ReporterConfig{WALDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for seq := int64(1); seq <= 3; seq++ {
		r1.Report(v2Event("e"+string(rune('0'+seq)), "srcA", seq))
	}
	r1.Close() // graceful close, but no upload destination was set

	// Reporter #2 over the SAME WAL dir, now WITH a collector. Fresh cursors →
	// must replay everything in the WAL.
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()
	r2, err := NewReporter(ReporterConfig{
		CollectorURL:   srv.URL,
		WALDir:         dir,
		BatchSize:      10,
		UploadInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	r2.Close()

	for seq := int64(1); seq <= 3; seq++ {
		if n := cs.idCount("e" + string(rune('0'+seq))); n < 1 {
			t.Errorf("event seq=%d not delivered after restart-replay", seq)
		}
	}
}

// TestOutbox_PrunesConfirmedWAL confirms that once the server acks a contiguous
// high-water mark, fully-confirmed ROTATED WAL files are deleted. We can't
// easily force an hourly rotation in a unit test, so we assert the weaker but
// still meaningful invariant: with an old-server (no contiguous_seq) the WAL is
// NEVER pruned (conserve), and with a normal server confirmedSeq advances.
func TestOutbox_OldServerConservesWAL(t *testing.T) {
	cs := newCaptureServer(true) // drops contiguous_seq → looks like old collector
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()

	dir := t.TempDir()
	r, err := NewReporter(ReporterConfig{
		CollectorURL:   srv.URL,
		WALDir:         dir,
		BatchSize:      10,
		UploadInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.Report(v2Event("e1", "srcA", 1))
	time.Sleep(120 * time.Millisecond)

	// Event delivered, but confirmedSeq must NOT have advanced (no contiguous in
	// response) → nothing is eligible for pruning. WAL file still present.
	r.mu.RLock()
	conf := r.confirmedSeq["srcA"]
	r.mu.RUnlock()
	r.Close()

	if conf != 0 {
		t.Errorf("confirmedSeq advanced to %d against an old (no-contiguous) server; must stay 0 (conserve)", conf)
	}
	files, _ := ListWALFiles(dir)
	if len(files) == 0 {
		t.Error("WAL pruned against an old server — must conserve when unconfirmed")
	}
}

// TestOutbox_ConfirmedSeqAdvances asserts the happy path: a normal server's
// contiguous_seq is recorded into confirmedSeq so pruning can later reclaim
// space.
func TestOutbox_ConfirmedSeqAdvances(t *testing.T) {
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()

	r, err := NewReporter(ReporterConfig{
		CollectorURL:   srv.URL,
		WALDir:         t.TempDir(),
		BatchSize:      10,
		UploadInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	for seq := int64(1); seq <= 3; seq++ {
		r.Report(v2Event("e"+string(rune('0'+seq)), "srcA", seq))
	}
	time.Sleep(150 * time.Millisecond)

	r.mu.RLock()
	conf := r.confirmedSeq["srcA"]
	r.mu.RUnlock()
	r.Close()

	if conf != 3 {
		t.Fatalf("confirmedSeq=%d, want 3 (server acked contiguous 1..3)", conf)
	}
}

// TestOutbox_CarriesAllocatedSeq proves the reporter stamps the batch with the
// allocator's high-water mark so the server can detect tail gaps. The allocator
// is bumped ABOVE the delivered seqs (simulating events allocated but not yet /
// never delivered); the server must see allocated_seq == Allocated(), not the
// max delivered seq — that difference is exactly the tail-gap signal.
func TestOutbox_CarriesAllocatedSeq(t *testing.T) {
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()

	dir := t.TempDir()
	sa, err := NewSeqAllocator(filepath.Join(dir, "seq.state"), DefaultSeqBlockSize)
	if err != nil {
		t.Fatal(err)
	}
	defer sa.Close()
	// Hand out seqs 1..5 (allocator high-water = 5) but only deliver 1..3.
	for i := 0; i < 5; i++ {
		if _, err := sa.Next(); err != nil {
			t.Fatal(err)
		}
	}
	if got := sa.Allocated(); got != 5 {
		t.Fatalf("Allocated()=%d, want 5", got)
	}

	r, err := NewReporter(ReporterConfig{
		CollectorURL:   srv.URL,
		WALDir:         dir,
		SeqAlloc:       sa,
		BatchSize:      10,
		UploadInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	for seq := int64(1); seq <= 3; seq++ {
		r.Report(v2Event("e"+string(rune('0'+seq)), "srcA", seq))
	}
	time.Sleep(150 * time.Millisecond)
	r.Close()

	cs.mu.Lock()
	got := cs.lastAllocated
	cs.mu.Unlock()
	if got == nil {
		t.Fatal("server saw no allocated_seq (reporter did not stamp it)")
	}
	if *got != 5 {
		t.Fatalf("allocated_seq=%d, want 5 (allocator high-water, ABOVE delivered max=3 — the tail-gap signal)", *got)
	}
}

// TestOutbox_NoAllocatedSeqWithoutAllocator confirms that when no SeqAlloc is
// wired (offline / degraded), the batch omits allocated_seq entirely so an
// older server isn't confused and tail detection simply stays off.
func TestOutbox_NoAllocatedSeqWithoutAllocator(t *testing.T) {
	cs := newCaptureServer(false)
	srv := httptest.NewServer(cs.handler())
	defer srv.Close()

	r, err := NewReporter(ReporterConfig{
		CollectorURL:   srv.URL,
		WALDir:         t.TempDir(),
		BatchSize:      10,
		UploadInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.Report(v2Event("e1", "srcA", 1))
	time.Sleep(150 * time.Millisecond)
	r.Close()

	cs.mu.Lock()
	got := cs.lastAllocated
	cs.mu.Unlock()
	if got != nil {
		t.Fatalf("allocated_seq=%d sent without an allocator, want omitted (nil)", *got)
	}
}
