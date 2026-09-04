package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
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
		Event:  []byte(`{"event_id":"e-team-1","action_taken":"allow","prompt_length":10,"findings":[]}`),
	}}
	p := &Proxy{filterHook: hook, reporter: rep}
	r := newReq(`{"model":"m","messages":[{"role":"user","content":"hello team"}]}`)
	if !p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org", "vk", "seat", "", "", discardLogger()) {
		t.Fatal("expected proceed")
	}

	select {
	case b := <-teamCh:
		if !strings.Contains(string(b), "e-team-1") {
			t.Fatalf("team sink got an envelope without the event: %s", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("team sink never received the event (existing behavior regressed)")
	}
	select {
	case b := <-localCh:
		if !strings.Contains(string(b), "e-team-1") {
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

// TestApplyInboundFilter_UnknownAction_FailsLoudDegraded — regression for the
// 2026-06-22 third-party review: an exhaustive-switch refactor replaced the
// switch's `default` with an explicit `case ActionAllow`, dropping the catch-all.
// childhook converts the child's raw wire byte straight to Action, so a
// misbehaving child / protocol skew can yield a value outside {Allow,Mask,Block,
// Warn}. Such an unknown action MUST fail-OPEN (content proceeds, per §6 #11)
// but LOUDLY: a WARN is logged and it counts as degraded — never a silent clean
// Allow that slips through unscanned with zero signal.
func TestApplyInboundFilter_UnknownAction_FailsLoudDegraded(t *testing.T) {
	const unknownAction = apphook.Action(99) // outside the defined action set
	hook := &stubHook{resp: &apphook.Response{Action: unknownAction}}
	p := &Proxy{filterHook: hook}
	r := newReq(`{"model":"m","messages":[{"role":"user","content":"hello world"}]}`)
	w := httptest.NewRecorder()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", logger)

	// 1. fail-OPEN: the request proceeds and content is forwarded unchanged.
	if !proceed {
		t.Fatal("unknown action must fail-OPEN (proceed=true), got proceed=false")
	}
	if got := readReqBody(t, r); !strings.Contains(got, "hello world") {
		t.Errorf("content must pass through unchanged on unknown action, got %q", got)
	}
	// 2. fail-LOUD: a WARN names the unknown action (not a silent clean Allow).
	if logs := logBuf.String(); !strings.Contains(logs, "proxy.filter.unknown_action") {
		t.Errorf("expected a WARN (proxy.filter.unknown_action) for the unknown action, got logs:\n%s", logs)
	}
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
