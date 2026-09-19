package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/pipewire"
)

// stubHook is a configurable apphook.Hook for testing applyInboundFilter's
// verdict handling without spawning a real child.
type stubHook struct {
	resp         *apphook.Response
	gotPayload   []byte
	gotDirection apphook.Direction
	called       int
}

func (h *stubHook) Name() string { return "stub" }
func (h *stubHook) Detect(ctx context.Context, req *apphook.Request) *apphook.Response {
	h.called++
	h.gotPayload = append([]byte(nil), req.Payload...)
	h.gotDirection = req.Direction
	return h.resp
}
func (h *stubHook) Status() *apphook.Status { return &apphook.Status{Healthy: true} }

// TestApplyInboundFilter_TeamEventIsMirroredToLocalStore — a TEAM-routed
// compliance event must reach BOTH the team server (existing behavior) AND
// the local self-view store.
//
// spec: R-compliance-local-ledger-completeness-1.S1 团队路由事件同时到达团队服务端与本机库
// (workflow/CI/requirements/2026-09-03-compliance-local-ledger-completeness.md)
//
// 🔴 Why (user decision 2026-09-03, 「团队和个人的账号都需要记录本地的合规检测，
// 并且显示到本地 web」): until now team-routed events went to master only —
// the 2026-05-10 personal↔team isolation rule, written for USAGE data (billing
// projection). Applied to compliance events it produced a page at
// 127.0.0.1:8090/user/compliance with NOTHING on it while the member's own
// machine had detected and masked their phone number (winpc2 report). The
// isolation rule is reversed for compliance events only: the local copy is a
// best-effort mirror, stamped route_source=team, never dead-lettered, and its
// failure never touches the master upload. RED before the mirror existed:
// the local sink timed out.
func TestApplyInboundFilter_TeamEventIsMirroredToLocalStore(t *testing.T) {
	sink := func(ch chan<- []byte) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			ch <- b
			_, _ = w.Write([]byte(`{"accepted_ids":["e-team-1"]}`))
		}))
	}
	teamCh, localCh := make(chan []byte, 1), make(chan []byte, 1)
	teamSink, localSink := sink(teamCh), sink(localCh)
	defer teamSink.Close()
	defer localSink.Close()

	rep, err := events.NewReporter(&events.ReporterConfig{
		CollectorRoutes: map[string]string{"team": teamSink.URL, "personal": localSink.URL},
		CollectorRouteCredentials: map[string]events.Credential{
			"team":     &events.StaticTokenCredential{Token: "member-jwt"},
			"personal": &events.StaticTokenCredential{Token: "local-token"},
		},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	hook := &stubHook{resp: &apphook.Response{
		Action: apphook.ActionAllow,
		// 标记字段用 scenario,不用 event_id:2026-09-08 起 proxy 会把 event_id 改写成
		// 内容派生的审计单元 id(auditUnitID),detector 铸的原值不再出现在上报里,
		// 拿它当"事件到了没有"的标记会误红。本用例断言的是**镜像链路**,与 id 无关。
		Event: []byte(`{"event_id":"e-team-1","scenario":"mirror-marker","action_taken":"allow","prompt_length":10,"findings":[]}`),
	}}
	p := &Proxy{filterHook: hook, reporter: rep}
	r := newReq(`{"model":"m","messages":[{"role":"user","content":"hello team"}]}`)
	if !p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org", "vk", "seat", "", "", discardLogger()) {
		t.Fatal("expected proceed")
	}

	select {
	case b := <-teamCh:
		if !strings.Contains(string(b), "mirror-marker") {
			t.Fatalf("team sink got an envelope without the event: %s", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("team sink never received the event (existing behavior regressed)")
	}
	select {
	case b := <-localCh:
		if !strings.Contains(string(b), "mirror-marker") {
			t.Fatalf("local store got an envelope without the event: %s", b)
		}
		if !strings.Contains(string(b), `"route_source":"team"`) {
			t.Fatalf("mirrored event is not stamped route_source=team (the page cannot label it): %s", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("local store never received the mirrored team event — the member's own machine has no record of a detection it performed")
	}
}

// TestApplyInboundFilter_BodilessRequestIsNotAnUnfilteredForward — a request
// with NO body (GET / HEAD / OPTIONS, http.NoBody, Content-Length: 0) has
// nothing to scan. It must pass through without calling the detector and
// WITHOUT the WARN "no filterable content extracted; forwarded UNFILTERED".
//
// 🔴 Why (winpc2 2026-09-03): three team-oauth group-lane requests logged
// exactly that WARN with reason=body_not_json body_bytes=0 content_type="".
// The wording says "content went upstream unmasked" — read as a P0 PII leak
// during triage — while the truth was an empty request. A diagnostic that
// cries wolf on empty bodies hides the day it is right. RED before the
// short-circuit in applyInboundFilter: the old path ReadAll'd 0 bytes, failed
// the JSON parse, and emitted the WARN.
func TestApplyInboundFilter_BodilessRequestIsNotAnUnfilteredForward(t *testing.T) {
	cases := []struct {
		name string
		mk   func() *http.Request
	}{
		{"GET nil body", func() *http.Request { return httptest.NewRequest(http.MethodGet, "/v1/models", nil) }},
		{"POST http.NoBody", func() *http.Request { return httptest.NewRequest(http.MethodPost, "/v1/messages", http.NoBody) }},
		{"POST Content-Length 0", func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(nil))
			r.ContentLength = 0
			return r
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}
			p := &Proxy{filterHook: hook}
			logger, buf := captureLogger()
			if proceed := p.applyInboundFilter(httptest.NewRecorder(), tc.mk(), "m", "team", "", "", "", "", "", logger); !proceed {
				t.Fatal("expected proceed for a bodiless request")
			}
			if hook.called != 0 {
				t.Fatalf("detector invoked %d time(s) for a bodiless request", hook.called)
			}
			if strings.Contains(buf.String(), "UNFILTERED") {
				t.Fatalf("bodiless request reported as an unfiltered forward:\n%s", buf.String())
			}
		})
	}
}

func newReq(body string) *http.Request {
	r := httptest.NewRequest("POST", "/v1/messages", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func readReqBody(t *testing.T, r *http.Request) string {
	t.Helper()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestApplyInboundFilter_PipeCapAndSplice — B (2026-06-05): a content piece
// larger than pipeInputCap is capped before the pipe (the detector only scans
// the first 16KB anyway), and the untouched tail is re-attached after masking.
// Without the cap a huge prompt blocks the IPC for seconds and desyncs it.
func TestApplyInboundFilter_PipeCapAndSplice(t *testing.T) {
	head := strings.Repeat("A", pipeInputCap+5000) // > 16KB
	tail := strings.Repeat("B", 3000)
	full := head + tail
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionMask, MutatedPayload: []byte("[masked]")}}
	p := &Proxy{filterHook: hook}
	r := newReq(`{"model":"m","messages":[{"role":"user","content":"` + full + `"}]}`)
	w := httptest.NewRecorder()

	if proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", discardLogger()); !proceed {
		t.Fatal("expected proceed")
	}
	// 1. payload over the pipe is capped — the detector never sees the huge tail.
	if len(hook.gotPayload) > pipeInputCap {
		t.Errorf("payload not capped: %d bytes > cap %d", len(hook.gotPayload), pipeInputCap)
	}
	// 2. forwarded body = masked head + raw tail (the bytes beyond the cap).
	got := readReqBody(t, r)
	if !strings.Contains(got, "[masked]") {
		t.Error("masked head missing from forwarded body")
	}
	if !strings.Contains(got, tail) {
		t.Error("raw tail (beyond cap) not preserved in forwarded body")
	}
}

// No hook installed → proceed=true, body untouched, zero cost.
func TestApplyInboundFilter_NoHook_PassThrough(t *testing.T) {
	p := &Proxy{} // filterHook nil
	r := newReq(`{"model":"claude","messages":[{"role":"user","content":"hi"}]}`)
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "claude", "personal", "", "", "", "", "", discardLogger())
	if !proceed {
		t.Fatal("expected proceed=true with no hook")
	}
	if got := readReqBody(t, r); got != `{"model":"claude","messages":[{"role":"user","content":"hi"}]}` {
		t.Errorf("body mutated despite no hook: %s", got)
	}
}

// Allow verdict → proceed, body unchanged.
func TestApplyInboundFilter_Allow(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}
	p := &Proxy{filterHook: hook}
	body := `{"messages":[{"content":"hello"}]}`
	r := newReq(body)
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", discardLogger())
	if !proceed {
		t.Fatal("Allow should proceed")
	}
	if hook.called != 1 {
		t.Errorf("hook.Detect called %d times, want 1", hook.called)
	}
	if hook.gotDirection != apphook.DirectionInbound {
		t.Errorf("direction: got %v want inbound", hook.gotDirection)
	}
	// L1: the hook sees the extracted CONTENT ("hello"), never the JSON envelope.
	if string(hook.gotPayload) != "hello" {
		t.Errorf("hook got payload %q, want \"hello\" (content, not envelope)", hook.gotPayload)
	}
	if got := readReqBody(t, r); got != body {
		t.Errorf("Allow should not mutate body: %s", got)
	}
}

// Mask verdict → the masked CONTENT is written back into the envelope, which is
// otherwise preserved (L1: only content string values change, structure intact).
func TestApplyInboundFilter_Mask(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte("my id is [masked]"), // content-level mask
	}}
	p := &Proxy{filterHook: hook}
	r := newReq(`{"messages":[{"content":"my id is 110101199001011234"}]}`)
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", discardLogger())
	if !proceed {
		t.Fatal("Mask should proceed (forward masked)")
	}
	// Hook saw the content, not the envelope.
	if string(hook.gotPayload) != "my id is 110101199001011234" {
		t.Errorf("hook got payload %q, want the content string", hook.gotPayload)
	}
	got := readReqBody(t, r)
	// Masked content reinserted, raw id gone, envelope structure preserved + valid JSON.
	if !strings.Contains(got, `"my id is [masked]"`) {
		t.Errorf("masked content not reinserted:\n%s", got)
	}
	if strings.Contains(got, "110101199001011234") {
		t.Errorf("raw id survived in body:\n%s", got)
	}
	if !json.Valid([]byte(got)) || !strings.Contains(got, `"messages"`) {
		t.Errorf("envelope structure not preserved:\n%s", got)
	}
	if r.ContentLength != int64(len(got)) {
		t.Errorf("ContentLength: got %d want %d", r.ContentLength, len(got))
	}
	if r.Header.Get("Content-Length") != itoaInt64(int64(len(got))) {
		t.Errorf("Content-Length header not updated: %s", r.Header.Get("Content-Length"))
	}
}

// Mask verdict but empty payload → that piece is left unchanged (defensive); the
// body is not mutated.
func TestApplyInboundFilter_MaskEmptyPayload_LeavesUnchanged(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionMask}} // no MutatedPayload
	p := &Proxy{filterHook: hook}
	orig := `{"messages":[{"content":"x"}]}`
	r := newReq(orig)
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", discardLogger())
	if !proceed {
		t.Fatal("should proceed")
	}
	if got := readReqBody(t, r); got != orig {
		t.Errorf("empty-mask should leave body unchanged: %s", got)
	}
}

// Block verdict → proceed=false, 403 written with structured error.
func TestApplyInboundFilter_Block(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{
		Action: apphook.ActionBlock,
		Reason: "private key leak detected",
	}}
	p := &Proxy{filterHook: hook}
	r := newReq(`{"messages":[{"content":"key=sk-ant-secret"}]}`)
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", discardLogger())
	if proceed {
		t.Fatal("Block should NOT proceed")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d want 403", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	// writeJSONError shape: {"error": {"type":..., "code":..., "message":...}}
	errObj, _ := body["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("no error object in body: %s", w.Body.String())
	}
	if errObj["code"] != "COMPLIANCE_BLOCKED" {
		t.Errorf("code: got %v want COMPLIANCE_BLOCKED", errObj["code"])
	}
	if errObj["message"] != "AiKey: private key leak detected" {
		t.Errorf("message: got %v", errObj["message"])
	}
}

// Block with empty reason → default message.
func TestApplyInboundFilter_BlockDefaultMessage(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionBlock}}
	p := &Proxy{filterHook: hook}
	r := newReq(`{"messages":[{"content":"x"}]}`) // needs a content piece to inspect
	w := httptest.NewRecorder()

	p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", discardLogger())
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	errObj := body["error"].(map[string]any)
	if errObj["message"] != "AiKey: request blocked by compliance policy" {
		t.Errorf("default message: got %v", errObj["message"])
	}
}

// Warn verdict → proceed, body unchanged (passed through with warning).
func TestApplyInboundFilter_Warn(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionWarn, Reason: "soft signal"}}
	p := &Proxy{filterHook: hook}
	body := `{"messages":[{"content":"borderline"}]}`
	r := newReq(body)
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", discardLogger())
	if !proceed {
		t.Fatal("Warn should proceed")
	}
	if got := readReqBody(t, r); got != body {
		t.Errorf("Warn should not mutate body: %s", got)
	}
}

// Degraded (Action=Allow + Degraded=true) → fail-open, proceed, body unchanged.
func TestApplyInboundFilter_DegradedFailsOpen(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{
		Action:   apphook.ActionAllow,
		Degraded: true,
		Reason:   "child unreachable",
	}}
	p := &Proxy{filterHook: hook}
	body := `{"messages":[{"content":"anything"}]}`
	r := newReq(body)
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", discardLogger())
	if !proceed {
		t.Fatal("degraded must fail-open (proceed), NOT fail the request (§6 #11)")
	}
	if w.Code != 200 {
		t.Errorf("degraded should not write an error status, got %d", w.Code)
	}
	if got := readReqBody(t, r); got != body {
		t.Errorf("degraded should not mutate body: %s", got)
	}
}

// nil body → proceed (nothing to inspect).
func TestApplyInboundFilter_NilBody(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionBlock}} // would block if called
	p := &Proxy{filterHook: hook}
	r := httptest.NewRequest("GET", "/v1/models", nil)
	r.Body = nil
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", discardLogger())
	if !proceed {
		t.Fatal("nil body should proceed without calling hook")
	}
	if hook.called != 0 {
		t.Errorf("hook should not be called on nil body, called=%d", hook.called)
	}
}

func TestItoaInt64(t *testing.T) {
	cases := map[int64]string{0: "0", 5: "5", 42: "42", 1024: "1024", -7: "-7"}
	for in, want := range cases {
		if got := itoaInt64(in); got != want {
			t.Errorf("itoaInt64(%d): got %q want %q", in, got, want)
		}
	}
}

// TestApplyInboundFilter_UnknownAction_FailsClosedBlocked pins the observable
// half of R-compliance-canned-answer-6.S1: an action value this build cannot
// read is REFUSED (403 COMPLIANCE_BLOCKED, nothing forwarded), never forwarded.
//
// spec (PROPOSAL layer): 需求包 roadmap20260320/技术实现/阶段9-商业化版本/
// 博时基金合规能力融合/openspec/changes/add-compliance-grading-fusion/specs/
// compliance-canned-answer/spec.md — R-compliance-canned-answer-6 / .S1.
// Enum-level half: internal/apphook TestUnknownAction_TreatedAsBlock.
//
// 🔴 THIS REVERSES ITS OWN PREDECESSOR, deliberately. The test that stood here
// until 2026-09-13 was TestApplyInboundFilter_UnknownAction_FailsLoudDegraded,
// the 2026-06-22 third-party-review regression: an exhaustive-switch refactor
// had dropped the catch-all, and the fix restored it as a LOUD FAIL-OPEN (warn +
// count as degraded + forward). The "loud" half is kept verbatim. The "open"
// half is reversed, because the two cases it conflated are opposites:
//
//	child could not answer (timeout / crash / unreachable)  → fail-OPEN, §6 #11.
//	  Those paths return an explicit ActionAllow+Degraded from ChildHook.Detect
//	  (internal/apphook/childhook.go), so they never reach this branch and are
//	  byte-for-byte unaffected by the reversal.
//	child answered with a verdict we cannot read              → fail-CLOSED.
//	  The action value is policy handed down by the master. Not recognizing it
//	  means this proxy is older than the policy, or the policy was tampered
//	  with. Forwarding on either is "version skew silently switches the
//	  compliance policy off" — R-compliance-canned-answer-6 names exactly this.
func TestApplyInboundFilter_UnknownAction_FailsClosedBlocked(t *testing.T) {
	const unknownAction = apphook.Action(99) // outside the defined action set
	hook := &stubHook{resp: &apphook.Response{Action: unknownAction, Reason: "detector said something we cannot read"}}
	p := &Proxy{filterHook: hook}
	r := newReq(`{"model":"m","messages":[{"role":"user","content":"hello world"}]}`)
	w := httptest.NewRecorder()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", logger)

	// 1. fail-CLOSED. proceed=false IS the "upstream receives 0 requests" half of
	// .S1 at this layer: the sole caller returns immediately on false, before any
	// forwarding step (forward_and_resolve.go:510-512, read 2026-09-13).
	if proceed {
		t.Fatal("unrecognized action must fail-CLOSED (proceed=false); proceed=true forwards " +
			"the content upstream unscanned, which R-compliance-canned-answer-6 forbids")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "COMPLIANCE_BLOCKED") {
		t.Errorf("body must carry COMPLIANCE_BLOCKED, got %q", body)
	}
	// 2. The client gets the constant refusal, NOT the detector's Reason. On a
	// real Block the Reason is empty by construction (see guardrailVerbatimSources
	// in compliance_guardrail_response_fence_test.go); on THIS path it is a string
	// of unknown provenance from a verdict we already decided we cannot read, so
	// it must not be echoed back to the caller.
	if body := w.Body.String(); strings.Contains(body, "cannot read") {
		t.Errorf("the unreadable verdict's Reason leaked into the client response: %q", body)
	}
	// 3. fail-LOUD: the operator can tell a version skew from a policy block.
	if logs := logBuf.String(); !strings.Contains(logs, "proxy.filter.unknown_action") {
		t.Errorf("expected a WARN (proxy.filter.unknown_action) for the unrecognized action, got logs:\n%s", logs)
	}
}

// TestActionCeiling_ClampsAnswerLikeBlock keeps the new ActionAnswer rung under
// the block-type action ceiling (方案② 2026-08-10, 天花板只压不抬).
//
// WHY IT IS PART OF ADDING THE ENUM VALUE, not of implementing the canned answer:
// clamp() enumerates the intrusive verdicts by name. A rung that is not named
// there falls through its trailing `return a, false` and escapes the ceiling —
// so a tool_result pinned to the audit rung, which may not even be masked, could
// short-circuit the whole request with a canned answer. Answer is at least as
// intrusive as Block (same short-circuit, same `return false`), so it clamps
// with Block or the ceiling has a hole the day the value exists.
func TestActionCeiling_ClampsAnswerLikeBlock(t *testing.T) {
	for _, c := range []actionCeiling{ceilingAudit, ceilingOff} {
		got, capped := c.clamp(apphook.ActionAnswer)
		if got != apphook.ActionAllow || !capped {
			t.Errorf("ceiling %s: clamp(answer) = (%v, capped=%v), want (allow, capped=true) — "+
				"same as clamp(block) = %v", c, got, capped, mustClamp(c, apphook.ActionBlock))
		}
	}
	// ceilingFull is the pass-through rung: it must NOT cap anything.
	if got, capped := ceilingFull.clamp(apphook.ActionAnswer); got != apphook.ActionAnswer || capped {
		t.Errorf("ceilingFull.clamp(answer) = (%v, %v), want (answer, false)", got, capped)
	}
}

func mustClamp(c actionCeiling, a apphook.Action) apphook.Action {
	out, _ := c.clamp(a)
	return out
}

// TestInjectSeat pins the 2026-07-08 seat-attribution stamp: the compliance
// event must carry seat_id so the master audit page resolves the employee's
// alias instead of the raw detector user_id. Mirrors injectVirtualKey's
// fail-safe contract (empty seat / bad JSON → unchanged).
func TestInjectSeat(t *testing.T) {
	// stamps seat_id, preserves existing fields (incl. detector's user_id)
	out := injectSeat([]byte(`{"user_id":"claude-session-x","action":"block"}`), "seat-aa4c7f87")
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if m["seat_id"] != "seat-aa4c7f87" {
		t.Fatalf("seat_id = %v, want seat-aa4c7f87", m["seat_id"])
	}
	if m["user_id"] != "claude-session-x" {
		t.Fatalf("user_id clobbered = %v (must be preserved — decision A)", m["user_id"])
	}
	// empty seat → unchanged (personal key / legacy)
	if got := string(injectSeat([]byte(`{"action":"mask"}`), "")); got != `{"action":"mask"}` {
		t.Fatalf("empty seat mutated event: %s", got)
	}
	// non-JSON → unchanged (fail-safe)
	if got := string(injectSeat([]byte(`not json`), "s1")); got != `not json` {
		t.Fatalf("bad json mutated: %s", got)
	}
}

// TestInjectSession pins the 2026-07-08 cross-audit deep-link key: the
// compliance event carries session_id (same resolveSessionID source as the
// conversation-audit observer) so the drawer can open the exact conversation
// thread. Fail-safe contract mirrors injectSeat.
func TestInjectSession(t *testing.T) {
	out := injectSession([]byte(`{"event_id":"trace-1","seat_id":"s1"}`), "sess-9")
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if m["session_id"] != "sess-9" {
		t.Fatalf("session_id = %v, want sess-9", m["session_id"])
	}
	if m["event_id"] != "trace-1" || m["seat_id"] != "s1" {
		t.Fatalf("existing fields clobbered: %v", m)
	}
	// empty session (codex / no session header) → unchanged
	if got := string(injectSession([]byte(`{"event_id":"x"}`), "")); got != `{"event_id":"x"}` {
		t.Fatalf("empty session mutated: %s", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R-compliance-grading-10.S2 — detector timeout stays fail-open WITH grading on
// ─────────────────────────────────────────────────────────────────────────────

// timeoutChildGradingOutEnv tells the helper child where to record the grading
// document it was spawned with. Its presence is also what turns the helper test
// into a child process instead of a skipped test.
const timeoutChildGradingOutEnv = "AIKEY_TEST_TIMEOUT_CHILD_GRADING_OUT"

// complianceGradingEnvName MIRRORS the variable the supervisor bakes into the
// detector child (internal/supervisor/filter_hook.go `gradingEnv :=
// "AIKEY_COMPLIANCE_GRADING=" + ...`). It cannot be imported: supervisor imports
// this package. If the supervisor renames it, this fence keeps passing against
// a name no real detector reads — the supervisor-side wiring fence
// (compliance_escalation_wiring_fence_test.go) is what guards that half.
const complianceGradingEnvName = "AIKEY_COMPLIANCE_GRADING"

// fenceDetectTimeout is the "探测器 100ms 未返回" of 2.A5 / R-compliance-grading-10.S2.
// It is set on the REAL ChildHook, so the deadline that fires is production code
// (apphook.ChildHook.Detect → context.WithTimeout), not something this test does.
const fenceDetectTimeout = 100 * time.Millisecond

// TestHelperDetectorTimeoutChild is not a test: it is the detector child for
// TestApplyInboundFilter_DetectorTimeoutStaysFailOpenWithGrading, re-executed
// from this same binary (the os/exec TestHelperProcess pattern, see
// internal/apphook/canned_answer_carrier_test.go).
//
// It signals ready, records the grading env it was handed, and then reads every
// request frame and NEVER answers — a hung detector. STDOUT IS THE PIPE, so it
// never returns into the framework (which would print a summary onto it).
func TestHelperDetectorTimeoutChild(t *testing.T) {
	out := os.Getenv(timeoutChildGradingOutEnv)
	if out == "" {
		t.Skip("helper process; not a test")
	}
	if err := os.WriteFile(out, []byte(os.Getenv(complianceGradingEnvName)), 0o600); err != nil {
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "ready detector-timeout-child")
	in := bufio.NewReader(os.Stdin)
	for {
		if _, _, err := pipewire.ReadFrame(in); err != nil {
			os.Exit(0) // stdin closed: the parent shut us down
		}
		// Deliberately no response: every Detect must run into its deadline.
	}
}

// detectCallCounter wraps the real ChildHook so the fence can prove the verdict
// came from exactly one Detect call that actually waited out the deadline.
type detectCallCounter struct {
	inner apphook.Hook
	calls atomic.Int64
}

func (c *detectCallCounter) Name() string { return c.inner.Name() }
func (c *detectCallCounter) Detect(ctx context.Context, req *apphook.Request) *apphook.Response {
	c.calls.Add(1)
	return c.inner.Detect(ctx, req)
}
func (c *detectCallCounter) Status() *apphook.Status { return c.inner.Status() }

// TestApplyInboundFilter_DetectorTimeoutStaysFailOpenWithGrading pins
// R-compliance-grading-10.S2: `fail_closed_levels` only applies once detection
// has COMPLETED; when the detector cannot answer, the level is undecidable and
// the request SHALL stay fail-open + WARN.
//
// GIVEN 分级文档含 fail_closed_levels=[5] 且含一条 L5 block 的 escalation 规则;
// 同一份字节既装进 proxy (SetComplianceGrading) 又作为 AIKEY_COMPLIANCE_GRADING
// 交给探测器子进程 (与 supervisor/filter_hook.go 的装配方式一致)。
// WHEN 探测器 100ms 内未返回 (真实 ChildHook 超时, 不是 stub 直接给 Degraded)。
// THEN 原文透传 (proceed=true, 请求体不变)、WARN 恰好 1 条 (proxy.filter.degraded)、
// 5xx 0 次; 请求级升级判定照常执行且结论为「无升级」。
//
// spec (PROPOSAL layer): 需求包 roadmap20260320/技术实现/阶段9-商业化版本/
// 博时基金合规能力融合/openspec/changes/add-compliance-grading-fusion/specs/
// compliance-grading/spec.md — R-compliance-grading-10 / .S2; 验收细则 tasks.md 2.A5.
// rule: R-compliance-grading-10.S2
//
// WHY THIS IS NOT TestApplyInboundFilter_DegradedFailsOpen RENAMED: that test
// hands the proxy a ready-made Degraded=true from a stub, with no grading
// installed and no log assertion. This one (1) installs grading on both sides
// and PROVES it is installed (the anti-vacuous assertions below go red if the
// install step is removed), (2) lets the production ChildHook deadline fire
// against a child that really hangs, and (3) counts the WARN.
//
// 🔴 Future (阶段 B, tasks.md 11.x): once `fail_closed_on_detector_unavailable`
// exists, this fence is the SWITCH-OFF half and must stay green unchanged —
// do not rename it (tasks.md runs it by exact name).
func TestApplyInboundFilter_DetectorTimeoutStaysFailOpenWithGrading(t *testing.T) {
	gradingDoc := []byte(`{"escalation":[{"min_level":5,"min_count":1,"action":"block"}],"fail_closed_levels":[5]}`)

	// --- GIVEN: grading installed in the proxy through the production setter ---
	p := &Proxy{}
	applied, refused, err := p.SetComplianceGrading(gradingDoc)
	if err != nil || len(refused) > 0 || applied != 1 {
		t.Fatalf("SetComplianceGrading: applied=%d refused=%v err=%v", applied, refused, err)
	}

	// --- GIVEN: the same bytes handed to a detector child that never answers ---
	gradingSeen := filepath.Join(t.TempDir(), "grading-seen.json")
	child := apphook.NewChildHook(&apphook.ChildHookConfig{
		Name:       "detector-timeout-child",
		BinaryPath: os.Args[0],
		BinaryArgs: []string{"-test.run", "^TestHelperDetectorTimeoutChild$"},
		ExtraEnv: []string{
			timeoutChildGradingOutEnv + "=" + gradingSeen,
			complianceGradingEnvName + "=" + string(gradingDoc),
		},
		Timeout:      fenceDetectTimeout,
		ReadyTimeout: 15 * time.Second,
	})
	startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := child.Start(startCtx); err != nil {
		t.Fatalf("start detector-timeout child: %v", err)
	}
	t.Cleanup(func() {
		ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = child.Shutdown(ctx)
	})
	hook := &detectCallCounter{inner: child}
	p.SetFilterHook(hook)

	// --- Anti-vacuous: the grading GIVEN is really in force on both sides ------
	// Proxy side: the only member of the document the proxy models is
	// escalation[] (proxy.go SetComplianceGrading). fail_closed_levels lives in
	// the detector and is deliberately not held here — so the detector-side
	// assertion below is what proves fail_closed_levels was configured at all.
	if rules := p.ComplianceEscalationRules(); len(rules) != 1 || rules[0].MinLevel != 5 || rules[0].Action != "block" {
		t.Fatalf("anti-vacuous: proxy holds escalation rules %v, want exactly [level>=5,count>=1,action=block] — "+
			"without grading installed this fence proves nothing about R-compliance-grading-10", rules)
	}
	seenRaw, err := os.ReadFile(gradingSeen)
	if err != nil {
		t.Fatalf("anti-vacuous: detector child did not record its grading env: %v", err)
	}
	var seen struct {
		FailClosedLevels []int `json:"fail_closed_levels"`
	}
	if err := json.Unmarshal(seenRaw, &seen); err != nil || len(seen.FailClosedLevels) != 1 || seen.FailClosedLevels[0] != 5 {
		t.Fatalf("anti-vacuous: detector child received %s=%q (fail_closed_levels=%v, err=%v), want fail_closed_levels=[5] — "+
			"the scenario's GIVEN is not in force", complianceGradingEnvName, seenRaw, seen.FailClosedLevels, err)
	}

	// --- WHEN: one request whose only piece hits the hung detector -------------
	const body = `{"model":"m","messages":[{"role":"user","content":"please summarize the attached quarterly fund report"}]}`
	r := newReq(body)
	w := httptest.NewRecorder()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	t0 := time.Now()
	proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", logger)
	elapsed := time.Since(t0)

	// It really was a timeout: one Detect, and it waited out the deadline.
	if got := hook.calls.Load(); got != 1 {
		t.Fatalf("Detect calls = %d, want 1", got)
	}
	if elapsed < fenceDetectTimeout {
		t.Fatalf("applyInboundFilter returned in %s, before the %s detect deadline — this was not a real timeout "+
			"(e.g. the hook was already degraded), so the fence would not be testing the timeout path", elapsed, fenceDetectTimeout)
	}
	if elapsed > 5*time.Second {
		t.Errorf("applyInboundFilter took %s; a timed-out detector must not hold the request (§6 #11)", elapsed)
	}

	// --- THEN: fail-open, verbatim, no 5xx --------------------------------------
	if !proceed {
		t.Fatalf("proceed=false: a detector timeout was turned into a refusal (status %d, body %q). "+
			"R-compliance-grading-10 — fail_closed_levels only applies after detection COMPLETED; "+
			"a timeout SHALL stay fail-open", w.Code, w.Body.String())
	}
	if w.Code >= 500 {
		t.Errorf("status = %d, want no 5xx on detector timeout", w.Code)
	}
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Errorf("filter wrote a response on the fail-open path: status=%d body=%q", w.Code, w.Body.String())
	}
	if got := readReqBody(t, r); got != body {
		t.Errorf("request body changed on the fail-open path:\n got: %s\nwant: %s", got, body)
	}

	// --- THEN: exactly one WARN, and it is the degraded one ---------------------
	logs := logBuf.String()
	if n := strings.Count(logs, "level=ERROR"); n != 0 {
		t.Errorf("ERROR lines = %d on a fail-open timeout, want 0:\n%s", n, logs)
	}
	if n := strings.Count(logs, "level=WARN"); n != 1 {
		t.Errorf("WARN lines = %d, want exactly 1:\n%s", n, logs)
	}
	if !strings.Contains(logs, "event.name=proxy.filter.degraded") || !strings.Contains(logs, "self_deg=1") {
		t.Errorf("the single WARN must be proxy.filter.degraded with self_deg=1, got:\n%s", logs)
	}

	// --- THEN: the grading-aware request verdict ran and concluded nothing -----
	snap := p.escalationSnapshot()
	if snap.evaluated != 1 || snap.triggered != 0 {
		t.Errorf("escalation evaluated=%d triggered=%d, want 1/0 — with rules installed the request-level "+
			"verdict must run and must not escalate a request whose detection never completed", snap.evaluated, snap.triggered)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R-compliance-grading-8.S1 — route_policy: an L4 hit may only go to an allowed
// provider (T/AMAC §11.2 b: high-sensitivity data is inferred in an isolated
// environment only).
// ─────────────────────────────────────────────────────────────────────────────

// TestRoutePolicy_L4ToExternalProviderDenied is the fence for
// R-compliance-grading-8.S1 (task 11.2).
//
// GIVEN route_policy=[{min_level:4, allowed_providers:["intranet-*"], otherwise:"block"}]
// WHEN  a request carrying a CONFIRMED L4 hit targets `anthropic`
// THEN  403 COMPLIANCE_ROUTE_POLICY_DENIED and the upstream receives NOTHING;
//
//	the same request targeting `intranet-qwen` is forwarded, and the upstream
//	receives ZERO X-Aikey-* headers (red line: stripAikeyRequestHeaders, no
//	exception for intranet providers);
//	an empty route_policy leaves the forwarded bytes identical.
//
// It drives serveRoute — the single funnel every real route passes through — so
// the header assertion reads what the upstream actually RECEIVED, not what a
// helper returned. The L3 / unconfirmed / MAX_ACTION=warn cases are the controls
// that make the refusal mean something: without them a policy that blocked every
// flagged request would pass the first case.
//
// The audit-row half of the scenario (「事件 action_taken='block' 且 metadata 记
// route_policy」) is fenced separately since TODO-171 (DEC-compliance-grading-27
// declared the field on master first): TestRoutePolicy_DeniedRequestEmitsVerdictRow
// and its siblings in route_policy_verdict_test.go. What THIS test asserts is the
// in-process evidence: the INFO line carrying min_level + target_provider, and
// the per-generation counter.
func TestRoutePolicy_L4ToExternalProviderDenied(t *testing.T) {
	const (
		idCard   = "110101199003074578"
		prompt   = "customer id " + idCard + " please summarize the file"
		l4Policy = `{"route_policy":[{"min_level":4,"allowed_providers":["intranet-*"],"otherwise":"block"}]}`
	)
	type outcome struct {
		status          int
		body            string
		upstreamHits    int
		upstreamHeaders http.Header
		upstreamBody    string
		logs            string
		proxy           *Proxy
	}
	run := func(t *testing.T, grading, providerCode string, hit gradedHit, maxAction string) outcome {
		t.Helper()
		var (
			hits    atomic.Int32
			gotHdr  http.Header
			gotBody string
		)
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			gotHdr = r.Header.Clone()
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			w.Header().Set("Content-Type", "application/json")
			if strings.HasSuffix(r.URL.Path, "/messages") {
				_, _ = w.Write([]byte(`{"id":"msg_rp","type":"message","content":[{"type":"text","text":"ok"}],` +
					`"usage":{"input_tokens":1,"output_tokens":1}}`))
				return
			}
			_, _ = w.Write([]byte(`{"id":"chatcmpl_rp","choices":[{"message":{"content":"ok"}}],` +
				`"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
		}))
		defer upstream.Close()

		p := setupTestProxy(t, upstream.URL)
		if grading != "" {
			if _, _, err := p.SetComplianceGrading([]byte(grading)); err != nil {
				t.Fatalf("SetComplianceGrading(%s): %v", grading, err)
			}
		}
		if maxAction != "" {
			if err := p.SetComplianceMaxAction(maxAction); err != nil {
				t.Fatalf("SetComplianceMaxAction(%q): %v", maxAction, err)
			}
		}
		p.SetFilterHook(&contentScriptedHook{answer: func(payload string) *apphook.Response {
			if !strings.Contains(payload, idCard) {
				return &apphook.Response{Action: apphook.ActionAllow}
			}
			// warn = the ladder's own per-piece action lets it through; only the
			// route policy can stop this request.
			return &apphook.Response{Action: apphook.ActionWarn,
				Event: eventJSON(t, "ev-route-policy", "warn", payload, []gradedHit{hit})}
		}})

		protocol, path, body := "openai_compatible", "/v1/chat/completions",
			`{"model":"qwen-72b","messages":[{"role":"user","content":"`+prompt+`"}]}`
		if providerCode == "anthropic" {
			protocol, path, body = "anthropic", "/v1/messages",
				`{"model":"claude-3-5-sonnet-20241022","max_tokens":64,"messages":[{"role":"user","content":"`+prompt+`"}]}`
		}
		prov, err := p.providers.Get(protocol)
		if err != nil {
			t.Fatalf("provider %s: %v", protocol, err)
		}
		route := &vkeys.ResolvedRoute{
			VirtualKeyID: "vk-route-policy", Provider: providerCode, ProviderCode: providerCode,
			ProtocolType: protocol, PlaintextKey: "sk-fake", BaseURL: upstream.URL,
			RouteSource: "team", OrgID: "org-route-policy",
		}
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// Two inbound X-Aikey-* headers the client sent, in both spellings. The
		// proxy also stamps its own (extractModel writes x-aikey-model), so the
		// outbound assertion covers client-sent AND proxy-added headers.
		req.Header.Set("X-Aikey-Trace-Id", "client-trace")
		req.Header["x-aikey-client"] = []string{"lowercase-variant"}
		var logBuf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		w := httptest.NewRecorder()

		p.serveRoute(w, req, route, prov, "sk-fake", "", time.Now(), logger)

		return outcome{status: w.Code, body: w.Body.String(), upstreamHits: int(hits.Load()),
			upstreamHeaders: gotHdr, upstreamBody: gotBody, logs: logBuf.String(), proxy: p}
	}
	l4 := gradedHit{value: idCard, category: "pii", level: 4, confirmed: true}

	t.Run("L4 to anthropic is refused before any upstream request", func(t *testing.T) {
		o := run(t, l4Policy, "anthropic", l4, "")
		if got := len(o.proxy.ComplianceRoutePolicy()); got != 1 {
			t.Fatalf("installed route_policy rules = %d, want 1 — the grading document's route_policy "+
				"member did not reach the proxy", got)
		}
		if o.status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%s", o.status, o.body)
		}
		if !strings.Contains(o.body, observability.ErrCodeComplianceRoutePolicyDenied) {
			t.Errorf("body must carry %s, got %s", observability.ErrCodeComplianceRoutePolicyDenied, o.body)
		}
		if o.upstreamHits != 0 {
			t.Errorf("upstream received %d request(s); a route-policy refusal must forward NOTHING", o.upstreamHits)
		}
		if strings.Contains(o.body, idCard) {
			t.Errorf("refusal body echoes the matched value: %s", o.body)
		}
		for _, needle := range []string{
			`"event.name":"` + observability.EventProxyFilterRoutePolicyDenied + `"`,
			`"min_level":4`, `"target_provider":"anthropic"`,
		} {
			if !strings.Contains(o.logs, needle) {
				t.Errorf("route-policy refusal log must carry %s; logs:\n%s", needle, o.logs)
			}
		}
		if snap := o.proxy.routePolicySnapshot(); snap.evaluated != 1 || snap.denied != 1 {
			t.Errorf("route policy evaluated=%d denied=%d, want 1/1", snap.evaluated, snap.denied)
		}
	})

	t.Run("L4 to intranet-qwen is forwarded with zero X-Aikey headers", func(t *testing.T) {
		o := run(t, l4Policy, "intranet-qwen", l4, "")
		if o.status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", o.status, o.body)
		}
		if o.upstreamHits != 1 {
			t.Fatalf("upstream hits = %d, want 1", o.upstreamHits)
		}
		// Anti-vacuity: a header map that captured nothing would pass the loop.
		if o.upstreamHeaders.Get("Content-Type") == "" {
			t.Fatalf("upstream captured no headers — the X-Aikey-* assertion below would be vacuous")
		}
		var leaked []string
		for k := range o.upstreamHeaders {
			if len(k) >= 8 && strings.EqualFold(k[:8], "X-Aikey-") {
				leaked = append(leaked, k)
			}
		}
		if len(leaked) != 0 {
			t.Errorf("RED LINE: the intranet upstream received X-Aikey-* headers %v — no exception for "+
				"intranet providers (stripAikeyRequestHeaders)", leaked)
		}
		if snap := o.proxy.routePolicySnapshot(); snap.evaluated != 1 || snap.denied != 0 {
			t.Errorf("route policy evaluated=%d denied=%d, want 1/0", snap.evaluated, snap.denied)
		}
	})

	t.Run("empty route_policy leaves the forwarded request byte-identical", func(t *testing.T) {
		baseline := run(t, "", "anthropic", l4, "")
		if baseline.status != http.StatusOK || baseline.upstreamHits != 1 {
			t.Fatalf("baseline: status=%d hits=%d, want 200/1", baseline.status, baseline.upstreamHits)
		}
		for _, doc := range []string{`{}`, `{"route_policy":[]}`, `{"escalation":[]}`} {
			o := run(t, doc, "anthropic", l4, "")
			if o.status != http.StatusOK || o.upstreamHits != 1 {
				t.Errorf("grading %s: status=%d hits=%d, want 200/1", doc, o.status, o.upstreamHits)
				continue
			}
			if o.upstreamBody != baseline.upstreamBody {
				t.Errorf("grading %s changed the forwarded body:\n got %s\nwant %s", doc, o.upstreamBody, baseline.upstreamBody)
			}
			if strings.Contains(o.logs, observability.EventProxyFilterRoutePolicyDenied) {
				t.Errorf("grading %s: a route-policy refusal was logged with no route_policy configured", doc)
			}
		}
	})

	// Controls — each one is a way the refusal above could be passing for the
	// wrong reason.
	t.Run("L3 hit to anthropic is forwarded (level floor is read)", func(t *testing.T) {
		o := run(t, l4Policy, "anthropic", gradedHit{value: idCard, category: "pii", level: 3, confirmed: true}, "")
		if o.status != http.StatusOK || o.upstreamHits != 1 {
			t.Errorf("status=%d hits=%d, want 200/1 — an L3 hit is below min_level 4", o.status, o.upstreamHits)
		}
	})
	t.Run("unconfirmed L4 hit to anthropic is forwarded (weak hits never strengthen)", func(t *testing.T) {
		o := run(t, l4Policy, "anthropic", gradedHit{value: idCard, category: "pii", level: 4, confirmed: false}, "")
		if o.status != http.StatusOK || o.upstreamHits != 1 {
			t.Errorf("status=%d hits=%d, want 200/1 — an unconfirmed hit must not raise the action "+
				"(R-compliance-grading-16)", o.status, o.upstreamHits)
		}
	})
	t.Run("MAX_ACTION=warn caps the refusal", func(t *testing.T) {
		o := run(t, l4Policy, "anthropic", l4, "warn")
		if o.status != http.StatusOK || o.upstreamHits != 1 {
			t.Errorf("status=%d hits=%d, want 200/1 — the operator's MAX_ACTION ceiling only presses down", o.status, o.upstreamHits)
		}
		if snap := o.proxy.routePolicySnapshot(); snap.capped != 1 {
			t.Errorf("route policy capped=%d, want 1 — a capped refusal must be counted, not silent", snap.capped)
		}
	})
}
