package apphook

// === Fence F2 of TODO-120 — an oversize verdict frame fails CLOSED and the pipe
// stays in sync ===
//
// 需求包: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// task-execution/TODO.md TODO-120 (user decision 2026-09-15: D + A).
// Related rule (PROPOSAL layer, referenced by id rather than as a `spec:` anchor —
// same convention as canned_answer_carrier_test.go):
//
//	R-compliance-canned-answer-6  a verdict the proxy cannot read SHALL be handled
//	                              as ActionBlock; TODO-120 extends its reach to a
//	                              verdict frame larger than pipewire.MaxPayloadBytes.
//
// Real ChildHook, real child process, real OS pipe — no detector binary needed:
// the child is this test binary re-executed (same pattern as
// TestHelperCannedAnswerChild). 🔴 No real hit samples; the filler is 'x' bytes.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/pipewire"
)

// oversizeChildEnv switches the test binary into "misbehaving detector" mode:
//
//	pair       — a Detect whose prompt starts with oversizePromptPrefix is HELD
//	             until the next Detect arrives; then the held one is answered with
//	             an oversize frame and the next one with a normal allow frame, in
//	             that order. This is the shape that used to take every in-flight
//	             request down with it.
//	listpacks  — every op=ListPacks is answered with an oversize frame.
const oversizeChildEnv = "AIKEY_APPHOOK_OVERSIZE_CHILD"

const oversizePromptPrefix = "oversize:"

// ~100 KB — comfortably past pipewire.MaxPayloadBytes (64 KiB).
const oversizeFillerBytes = 100 * 1024

// TestHelperOversizeChild is not a test: it is the child process for the
// oversize fences below. STDOUT IS THE PIPE, hence os.Exit instead of returning.
func TestHelperOversizeChild(t *testing.T) {
	mode := os.Getenv(oversizeChildEnv)
	if mode == "" {
		t.Skip("helper process; not a test")
	}
	fmt.Fprintln(os.Stderr, "ready oversize-child")

	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	write := func(res *pipewire.Response) {
		if err := pipewire.WriteFrame(out, pipewire.EncodeResponse(res)); err != nil {
			os.Exit(1)
		}
	}
	oversize := func(reqID uint32) *pipewire.Response {
		return &pipewire.Response{ReqID: reqID, Action: pipewire.ActionMask, Findings: bytes.Repeat([]byte("x"), oversizeFillerBytes)}
	}
	var held *pipewire.Request
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
			continue
		}
		switch {
		case req.Op == pipewire.OpListPacks && mode == "listpacks":
			write(oversize(req.ReqID))
		case req.Op != pipewire.OpDetect:
			// The content-version poll's ListPacks in `pair` mode: unanswered on
			// purpose, so it can never land between the held pair.
		case mode == "pair" && held == nil && strings.HasPrefix(req.Prompt, oversizePromptPrefix):
			held = req
		case held != nil:
			write(oversize(held.ReqID))
			write(&pipewire.Response{ReqID: req.ReqID, Action: pipewire.ActionAllow})
			held = nil
		default:
			write(&pipewire.Response{ReqID: req.ReqID, Action: pipewire.ActionAllow})
		}
	}
}

func startOversizeChild(t *testing.T, mode string) *ChildHook {
	t.Helper()
	h := NewChildHook(&ChildHookConfig{
		Name:       "oversize-child",
		BinaryPath: os.Args[0],
		BinaryArgs: []string{"-test.run", "^TestHelperOversizeChild$"},
		ExtraEnv:   []string{oversizeChildEnv + "=" + mode},
		// Long enough that nothing here can pass or fail by hitting the deadline
		// except the pre-fix behavior, whose in-flight callers only ever return
		// via this deadline.
		Timeout:      3 * time.Second,
		ReadyTimeout: 15 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("start oversize child: %v", err)
	}
	t.Cleanup(func() { _ = h.Shutdown(context.Background()) })
	return h
}

// TestChildHook_OversizeFrameFailsClosedAndStreamStaysInSync
//
// GIVEN a child that answers req1 with a ~100 KB frame and req2 (in flight at the
// same time) with a normal frame
// WHEN the parent reads both
// THEN req1 is refused (ActionBlock, marked as an unreadable verdict, NOT
// Degraded), req2 gets its real verdict, the hook stays healthy, and a request
// sent afterwards is answered normally — the frame stream was resynchronised,
// not abandoned.
// BUT NOT: marking the child degraded and letting req1 and req2 fail OPEN.
func TestChildHook_OversizeFrameFailsClosedAndStreamStaysInSync(t *testing.T) {
	h := startOversizeChild(t, "pair")
	ctx := context.Background()

	var wg sync.WaitGroup
	var res1, res2 *Response
	wg.Add(2)
	go func() {
		defer wg.Done()
		res1 = h.Detect(ctx, &Request{Payload: []byte(oversizePromptPrefix + "req1")})
	}()
	// req1 must reach the child first so it is the one held; the child answers
	// nothing until req2 arrives, so this ordering cannot race the replies.
	time.Sleep(50 * time.Millisecond)
	go func() {
		defer wg.Done()
		res2 = h.Detect(ctx, &Request{Payload: []byte("req2")})
	}()
	wg.Wait()

	if res1.Action != ActionBlock || res1.Degraded {
		t.Errorf("req1 (oversize frame) = {action:%s degraded:%v reason:%q}, want {block, degraded:false} — "+
			"an oversize verdict is a verdict we cannot read, not a child we cannot reach",
			res1.Action, res1.Degraded, res1.Reason)
	}
	if !res1.VerdictUnreadable {
		t.Errorf("req1 must be flagged VerdictUnreadable so the dispatcher refuses it on the fail-closed branch")
	}
	if res2.Action != ActionAllow || res2.Degraded {
		t.Errorf("req2 (normal frame after the oversize one) = {action:%s degraded:%v reason:%q}, want {allow, degraded:false} — "+
			"the pipe desynced or was abandoned", res2.Action, res2.Degraded, res2.Reason)
	}
	if res2.VerdictUnreadable {
		t.Errorf("req2 was flagged VerdictUnreadable; only the oversize frame's own request may be")
	}
	if s := h.Status(); !s.Healthy {
		t.Errorf("Status().Healthy = false (reason %q) after one oversize frame", s.DegradedReason)
	}

	res3 := h.Detect(ctx, &Request{Payload: []byte("req3")})
	if res3.Action != ActionAllow || res3.Degraded {
		t.Errorf("req3 (after the pair) = {action:%s degraded:%v reason:%q}, want allow", res3.Action, res3.Degraded, res3.Reason)
	}
	if s := h.Status(); !s.Healthy || s.RestartCount != 0 {
		t.Errorf("after req3: healthy=%v restarts=%d reason=%q, want healthy with no restart", s.Healthy, s.RestartCount, s.DegradedReason)
	}
}

// TestChildHook_OversizeListPacksIsUnavailableNotDegraded — the same frame shape
// on op=ListPacks is "packs unavailable", never a reason to take a child that is
// serving Detect out of rotation.
func TestChildHook_OversizeListPacksIsUnavailableNotDegraded(t *testing.T) {
	h := startOversizeChild(t, "listpacks")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := h.ListPacks(ctx); !errors.Is(err, ErrPacksUnavailable) {
		t.Errorf("ListPacks on an oversize report: err = %v, want ErrPacksUnavailable", err)
	}
	if s := h.Status(); !s.Healthy {
		t.Errorf("Status().Healthy = false (reason %q) after an oversize ListPacks report", s.DegradedReason)
	}
	if res := h.Detect(ctx, &Request{Payload: []byte("after-listpacks")}); res.Action != ActionAllow || res.Degraded {
		t.Errorf("Detect after the oversize report = {action:%s degraded:%v reason:%q}, want allow", res.Action, res.Degraded, res.Reason)
	}
}
