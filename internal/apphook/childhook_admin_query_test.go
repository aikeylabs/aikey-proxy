package apphook

// === Fence for TODO-144 — an operator's GET /admin/compliance/packs must never
// take a data-plane worker out of rotation ===
//
// 需求包: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// task-execution/TODO.md TODO-144 (user decision 2026-09-17: fix at the root —
// the admin query gets its own, longer deadline, and its failure neither marks
// the worker degraded nor retires its pipe). Evidence: task-execution/runs/
// todo-132-verify.md §1 and amplifier A in §4.
//
// Real ChildHook, real child process, real OS pipe — the child is this test
// binary re-executed (same pattern as TestHelperOversizeChild).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/pipewire"
)

// k1ChildEnv switches the test binary into "AIKEY_COMPLIANCE_WORKERS=1 detector"
// mode: ONE frame is handled at a time and the next frame is not read until the
// current one is answered — the shape of the real serve loop, which takes its
// single worker slot INSIDE the read loop (ai-compliance-detector
// cmd/detector/main.go, the `sem <- struct{}{}` in serve). A Detect whose prompt
// starts with k1SlowPrefix takes k1SlowDetect to answer; op=ListPacks is
// answered at once with k1PacksReport (on the real child it is a lock-free
// snapshot read — its latency is pure queueing behind the in-flight Detect).
const k1ChildEnv = "AIKEY_APPHOOK_K1_CHILD"

const (
	k1SlowPrefix  = "slow:"
	k1PacksReport = `{"built_in":[{"name":"k1-fixture","kind":"built-in"}],"pulled":[]}`
	// k1SlowDetect models one Detect that the CHILD keeps working on after the
	// proxy's 150ms Detect deadline gave up on it (a loaded box, a big piece):
	// the child does not abort on the proxy's deadline, so anything queued behind
	// it on a K=1 child waits for the whole of it.
	k1SlowDetect = 400 * time.Millisecond
	// productionDetectTimeout mirrors supervisor.filterDefaultTimeout (150ms,
	// internal/supervisor/filter_hook.go) — the per-Detect cfg.Timeout the
	// production filter hook is built with and that ListPacks used to inherit.
	// Not imported: supervisor depends on apphook, not the other way round.
	productionDetectTimeout = 150 * time.Millisecond
)

// TestHelperK1Child is not a test: it is the child process for the fences below.
// STDOUT IS THE PIPE, hence os.Exit instead of returning.
func TestHelperK1Child(t *testing.T) {
	if os.Getenv(k1ChildEnv) == "" {
		t.Skip("helper process; not a test")
	}
	fmt.Fprintln(os.Stderr, "ready k1-child")
	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	for {
		version, payload, err := pipewire.ReadFrame(in)
		if err != nil {
			os.Exit(0)
		}
		if version != pipewire.ProtocolVersion {
			os.Exit(1)
		}
		req, err := pipewire.DecodeRequest(payload)
		if err != nil {
			os.Exit(1)
		}
		res := &pipewire.Response{ReqID: req.ReqID, Action: pipewire.ActionAllow}
		switch {
		case req.Op == pipewire.OpListPacks:
			res.Findings = []byte(k1PacksReport)
		case req.Op == pipewire.OpDetect && strings.HasPrefix(req.Prompt, k1SlowPrefix):
			time.Sleep(k1SlowDetect) // the single worker slot is busy; stdin is not read
		}
		if err := pipewire.WriteFrame(out, pipewire.EncodeResponse(res)); err != nil {
			os.Exit(1)
		}
	}
}

func startK1Child(t *testing.T) *ChildHook {
	t.Helper()
	h := NewChildHook(&ChildHookConfig{
		Name:         "k1-child",
		BinaryPath:   os.Args[0],
		BinaryArgs:   []string{"-test.run", "^TestHelperK1Child$"},
		ExtraEnv:     []string{k1ChildEnv + "=1"},
		Timeout:      productionDetectTimeout,
		ReadyTimeout: 15 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("start k1 child: %v", err)
	}
	t.Cleanup(func() { _ = h.Shutdown(context.Background()) })
	// Let the content-version poll's immediate first ListPacks land before the
	// scenario starts, so it cannot be the frame queued behind the slow Detect.
	if !waitFor(5*time.Second, func() bool { _, ok := h.ContentVersion(); return ok }) {
		t.Fatal("the first content-version poll never landed")
	}
	return h
}

// TestChildHook_AdminListPacksBehindSlowDetectKeepsWorkerInRotation
//
// GIVEN a K=1 child that is still working on a Detect the proxy already gave up
// on (the child takes 400ms; the proxy's Detect deadline is 150ms)
// WHEN an operator asks GET /admin/compliance/packs (ListPacks) meanwhile
// THEN the query waits its turn and returns the report, the worker stays
// Healthy with no DegradedReason, its pipe session and child process are the
// same ones as before, and the next Detect is served normally
// BUT NOT: the query giving up at the Detect deadline and marking the worker
// degraded — which takes it out of the FilterPool's serving set and respawns it,
// i.e. an admin opening a page switches content inspection off on that worker.
func TestChildHook_AdminListPacksBehindSlowDetectKeepsWorkerInRotation(t *testing.T) {
	h := startK1Child(t)
	sessionBefore := h.session.Load()
	pidBefore := h.cmd.Process.Pid
	restartsBefore := h.Status().RestartCount

	slowDone := make(chan *Response, 1)
	go func() {
		slowDone <- h.Detect(context.Background(), &Request{Direction: DirectionInbound, Payload: []byte(k1SlowPrefix + "piece")})
	}()
	time.Sleep(30 * time.Millisecond) // the slow Detect is now occupying the child's only slot

	start := time.Now()
	report, err := h.ListPacks(context.Background()) // the admin handler passes r.Context(); no deadline of its own
	elapsed := time.Since(start)
	<-slowDone // the slow Detect itself fails open at 150ms; that is Detect's own, unchanged contract

	t.Logf("ListPacks behind a %s Detect: elapsed=%s err=%v", k1SlowDetect, elapsed, err)
	if err != nil {
		t.Errorf("the admin query must be able to wait out one in-flight Detect on a K=1 child; got %v after %s", err, elapsed)
	} else if string(report) != k1PacksReport {
		t.Errorf("report: got %q want %q", report, k1PacksReport)
	}
	st := h.Status()
	if !st.Healthy || st.DegradedReason != "" {
		t.Errorf("an admin query must not take the worker out of rotation: Healthy=%v DegradedReason=%q", st.Healthy, st.DegradedReason)
	}
	if h.session.Load() != sessionBefore {
		t.Error("the admin query retired the worker's pipe session")
	}
	if h.cmd == nil || h.cmd.Process.Pid != pidBefore || h.Status().RestartCount != restartsBefore {
		t.Error("the admin query caused the child process to be replaced")
	}
	res := h.Detect(context.Background(), &Request{Direction: DirectionInbound, Payload: []byte("next")})
	if res.Degraded || res.Action != ActionAllow {
		t.Errorf("the next Detect must be served by the same worker: Degraded=%v Action=%v Reason=%q", res.Degraded, res.Action, res.Reason)
	}
}

// TestChildHook_AdminListPacksFailureConcludesNothingAboutTheWorker
//
// GIVEN a K=1 child busy with a slow Detect
// WHEN the admin query's caller gives up first (here: its own ctx expires)
// THEN the caller gets an error, and the worker is exactly as healthy as it was
// BUT NOT: marking it degraded ("listpacks_failed: …") on the strength of an
// answer that was merely late.
func TestChildHook_AdminListPacksFailureConcludesNothingAboutTheWorker(t *testing.T) {
	h := startK1Child(t)
	sessionBefore := h.session.Load()

	go h.Detect(context.Background(), &Request{Direction: DirectionInbound, Payload: []byte(k1SlowPrefix + "piece")})
	time.Sleep(30 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.ListPacks(ctx); err == nil {
		t.Fatal("expected the admin query to fail: its caller's deadline expired first")
	}
	st := h.Status()
	if !st.Healthy || st.DegradedReason != "" {
		t.Errorf("a failed admin query must not relabel the worker: Healthy=%v DegradedReason=%q", st.Healthy, st.DegradedReason)
	}
	if h.session.Load() != sessionBefore {
		t.Error("a failed admin query retired the worker's pipe session")
	}
}

// heldPermitWorker is a worker whose pipe permit is held by another writer that
// never finishes — the state in which a caller's WRITE (not its reply wait)
// times out. Real production code from roundtrip down; only the far end is a
// drain and the permit holder is simulated by occupying writeSlot.
func heldPermitWorker(t *testing.T, name string) (*ChildHook, *pipeSession) {
	t.Helper()
	h := drainingChild(t, name)
	s := h.session.Load()
	s.writeSlot <- struct{}{}
	t.Cleanup(func() {
		select {
		case <-s.writeSlot:
		default:
		}
	})
	return h, s
}

// TestChildHook_AdminListPacksWriteTimeoutLeavesPipeAlone
//
// GIVEN a worker whose pipe permit is held by a stuck writer
// WHEN the admin query cannot get its frame out before its deadline
// THEN the query fails, and the session is neither marked broken nor closed and
// the worker is not degraded — the admin query wrote nothing, so it has learnt
// nothing about the stream that a Detect would not learn for itself.
// BUT NOT: the admin query retiring the pipe (that decision belongs to the data
// plane — see the companion assertion below, which is the unchanged invariant of
// bugfix 20260813-childhook-write-before-deadline-wedges-main-path).
func TestChildHook_AdminListPacksWriteTimeoutLeavesPipeAlone(t *testing.T) {
	h, s := heldPermitWorker(t, "admin-held-permit")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.ListPacks(ctx); !errors.Is(err, errWriteTimeout) {
		t.Fatalf("expected the admin query to time out on the write side, got %v", err)
	}
	if s.broken.Load() {
		t.Error("the admin query marked the pipe session broken")
	}
	if h.session.Load() != s {
		t.Error("the admin query replaced the pipe session")
	}
	if st := h.Status(); !st.Healthy || st.DegradedReason != "" {
		t.Errorf("the admin query degraded the worker: Healthy=%v DegradedReason=%q", st.Healthy, st.DegradedReason)
	}

	// Unchanged invariant (bugfix 20260813): the SAME condition on the Detect
	// path still retires the pipe and degrades the worker — a Detect that cannot
	// get its frame out within its deadline is the health signal for a wedge.
	res := h.Detect(context.Background(), &Request{Direction: DirectionInbound, Payload: []byte("x")})
	if !res.Degraded {
		t.Fatal("a Detect that cannot write must fail open (Degraded)")
	}
	if !s.broken.Load() {
		t.Error("bugfix 20260813 regressed: a Detect write timeout no longer retires the pipe")
	}
	if st := h.Status(); st.Healthy || st.DegradedReason != DegradeReasonWriteTimeout {
		t.Errorf("bugfix 20260813 regressed: want DegradedReason=%q, got Healthy=%v %q", DegradeReasonWriteTimeout, st.Healthy, st.DegradedReason)
	}
}
