package proxy

// escalation_zero_rules_refused_pieces_test.go — the EVENT half of
// R-compliance-grading-15.S2 that no fence held before TODO-99.
//
// rules (PROPOSAL + stable layer of 需求包 roadmap20260320/技术实现/阶段9-商业化版本/
// 博时基金合规能力融合, openspec/specs/compliance-grading/spec.md — referenced by id,
// same convention as escalation_wiring_test.go):
//
//	R-compliance-grading-15.S2  [回归] 未配升级规则时：响应逐字节一致；被拒的多片段
//	                            请求，拒绝点之后被扫描的片段也各自记内容行
//	                            (2026-09-15 用户拍板追认, TODO-99 选项 A)
//
// WHY A SEPARATE FILE: the three neighboring fences each miss this exact case,
// and that is how the pre-2026-09-15 S2 wording ("事件字段逐字节一致") stayed
// literally false without anything going red:
//
//   - TestEscalation_EmptyRulesKeepsOutcome runs on the PERSONAL route (the
//     proxy never sees an event there) and only substring-checks responses;
//   - TestCannedAnswer_UnconfiguredPathsByteIdentical byte-compares the upload,
//     but its request has ONE piece, so "what happens after the refusal point"
//     never exists in it;
//   - TestEscalation_BlockedRequestStillScansRemainingPieces proves the later
//     pieces are SCANNED, never that they are RECORDED.
//
// 能红 (verified in an isolated copy, see task-execution/runs/task-todo-99-report.md):
//
//	mutation 1 — reintroduce the pre-3.11 early return on the first block in
//	             applyInboundFilter → pipe frames 1 ≠ 3 and content rows 1 ≠ 3;
//	mutation 2 — keep scanning but stop appending team events once a refusal is
//	             recorded → content rows 1 ≠ 3 (frames stay 3).
//
// Both mutations leave the two controls green, which is what shows the fence is
// about "pieces AFTER the refusal point" and not about refusals in general.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
)

// zeroRulePiece is one content piece plus the verdict the fake detector gives it.
type zeroRulePiece struct {
	text   string
	action apphook.Action
}

// zeroRuleOutcome is everything observable about one filtered request.
type zeroRuleOutcome struct {
	proceed  bool
	status   int
	respBody string
	frames   []string
	batch    []byte // nil = nothing was uploaded within the wait
	// escalation counters after the request: evaluated / triggered.
	evaluated, triggered int
}

// runZeroRuleRequest drives ONE request through applyInboundFilter on the TEAM
// route with NO escalation rules configured (SetComplianceGrading is never
// called — the default state of an org that never configured grading), and
// returns what the client saw, what the detector was handed and what was
// uploaded to master.
//
// Each piece's fake verdict carries a detector event whose action_taken is the
// piece's own verdict and whose prompt_length is the piece's length, so an
// uploaded row can be tied back to exactly one piece.
func runZeroRuleRequest(t *testing.T, pieces []zeroRulePiece) zeroRuleOutcome {
	t.Helper()
	byText := make(map[string]zeroRulePiece, len(pieces))
	seenLen := map[int]bool{}
	msgs := make([]string, 0, len(pieces))
	for _, pc := range pieces {
		if seenLen[len(pc.text)] {
			t.Fatalf("fixture is wrong: two pieces share length %d; rows are matched by prompt_length", len(pc.text))
		}
		seenLen[len(pc.text)] = true
		byText[pc.text] = pc
		msgs = append(msgs, `{"role":"user","content":`+mustJSON(t, pc.text)+`}`)
	}

	teamCh := make(chan []byte, 8)
	teamSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		teamCh <- b
		_, _ = w.Write([]byte(`{"accepted_ids":[]}`))
	}))
	defer teamSink.Close()
	rep, err := events.NewReporter(&events.ReporterConfig{
		CollectorRoutes: map[string]string{"team": teamSink.URL},
		CollectorRouteCredentials: map[string]events.Credential{
			"team": &events.StaticTokenCredential{Token: "fixture-member-token"},
		},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	hook := &contentScriptedHook{answer: func(payload string) *apphook.Response {
		pc, ok := byText[payload]
		if !ok {
			t.Errorf("detector was handed a payload that is not a fixture piece: %q", payload)
			return &apphook.Response{Action: apphook.ActionAllow}
		}
		action := pc.action.String()
		resp := &apphook.Response{
			Action: pc.action,
			Reason: "fixture " + action + " reason",
			Event:  eventJSON(t, "det-"+action, action, payload, nil),
		}
		if pc.action == apphook.ActionMask {
			resp.MutatedPayload = []byte(strings.Replace(payload, "fixture", "{{MASKED}}", 1))
		}
		return resp
	}}
	p := &Proxy{filterHook: hook, reporter: rep}

	w := httptest.NewRecorder()
	r := newReq(`{"messages":[` + strings.Join(msgs, ",") + `]}`)
	proceed := p.applyInboundFilter(w, r, "m", "team", "org-fixture", "vk-fixture", "seat-fixture",
		"sess-fixture", "trace-todo99", discardLogger())

	out := zeroRuleOutcome{
		proceed:  proceed,
		status:   w.Code,
		respBody: w.Body.String(),
		frames:   hook.seen(),
	}
	snap := p.escalationSnapshot()
	out.evaluated, out.triggered = snap.evaluated, snap.triggered
	select {
	case out.batch = <-teamCh:
	case <-time.After(3 * time.Second):
	}
	// The whole request's events leave in ONE deferred POST; a second one would
	// mean the rows this fence counts were split and the count is not the batch.
	select {
	case extra := <-teamCh:
		t.Fatalf("a second upload arrived for one request — the per-request batch was split: %s", extra)
	case <-time.After(200 * time.Millisecond):
	}
	return out
}

// TestEscalation_ZeroRulesRefusedMultiPieceRecordsEveryScannedPiece is the fence
// for the event half of R-compliance-grading-15.S2.
//
// GIVEN team route, ZERO escalation rules, and a three-piece request whose
//
//	detector verdicts are block → mask → warn, each with its own event
//
// WHEN  the request is filtered
// THEN  the client receives exactly the bytes a single blocked piece produces
//
//	(403, COMPLIANCE_BLOCKED) — the response half is unchanged;
//
// AND   the uploaded batch holds exactly one content row per scanned piece, in
//
//	piece order, each carrying the action the detector gave that piece —
//	the refused request records the pieces AFTER the refusal point
//	(2026-09-15 用户拍板追认);
//
// AND   there is NO request_verdict row: no rule is configured, so none fired.
//
// Controls: a single block piece → 1 row; block last (mask, block) → 2 rows.
// Under the pre-3.11 code both controls are identical to today, so they pin that
// the difference this fence detects lives only after the refusal point.
func TestEscalation_ZeroRulesRefusedMultiPieceRecordsEveryScannedPiece(t *testing.T) {
	const (
		blockText = "fixture piece one, the detector refuses this"
		maskText  = "fixture piece two is masked"
		warnText  = "fixture piece three: warned only"
	)

	// Reference response: what a request whose ONLY piece is blocked receives.
	single := runZeroRuleRequest(t, []zeroRulePiece{{blockText, apphook.ActionBlock}})

	multiPieces := []zeroRulePiece{
		{blockText, apphook.ActionBlock},
		{maskText, apphook.ActionMask},
		{warnText, apphook.ActionWarn},
	}
	multi := runZeroRuleRequest(t, multiPieces)

	// ── (1) the response half: byte-identical to the single-block-piece one ──
	if multi.proceed {
		t.Fatal("proceed = true — a request with a blocked piece must be refused")
	}
	if multi.status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", multi.status, http.StatusForbidden)
	}
	if !strings.Contains(multi.respBody, "COMPLIANCE_BLOCKED") {
		t.Errorf("response body = %q, want the COMPLIANCE_BLOCKED refusal", multi.respBody)
	}
	if multi.status != single.status || multi.respBody != single.respBody {
		t.Errorf("the refused multi-piece response is NOT byte-identical to the single-block-piece response "+
			"(R-compliance-grading-15.S2: 最终响应逐字节一致).\n multi: %d %q\nsingle: %d %q",
			multi.status, multi.respBody, single.status, single.respBody)
	}

	// ── (3) anti-vacuity: every piece really reached the detector ────────────
	// Without this, "3 rows" could not distinguish "recorded every scanned piece"
	// from a fixture whose later pieces were never scanned at all.
	if len(multi.frames) != len(multiPieces) {
		t.Errorf("pipe frames = %d, want %d — the pieces after the refusal point were not scanned, so "+
			"nothing about recording them is being tested (DEC-compliance-grading-11 决定 5)",
			len(multi.frames), len(multiPieces))
	}
	for i, f := range multi.frames {
		if i < len(multiPieces) && f != multiPieces[i].text {
			t.Errorf("pipe frame %d = %q, want %q", i, f, multiPieces[i].text)
		}
	}

	// "no rule fired" is a conclusion the verdict path must have REACHED, not a
	// path it skipped (「不接受『没配就走不到』作为等价性论据」).
	if multi.evaluated != 1 || multi.triggered != 0 {
		t.Errorf("escalation evaluated/triggered = %d/%d, want 1/0", multi.evaluated, multi.triggered)
	}

	// ── (2) the event half ───────────────────────────────────────────────────
	assertRowsFollowPieces(t, "block→mask→warn", multi.batch, multiPieces)

	// ── (4) controls ─────────────────────────────────────────────────────────
	t.Run("control: single block piece records one row", func(t *testing.T) {
		assertRowsFollowPieces(t, "block only", single.batch, []zeroRulePiece{{blockText, apphook.ActionBlock}})
	})
	t.Run("control: block last records both rows", func(t *testing.T) {
		pieces := []zeroRulePiece{{maskText, apphook.ActionMask}, {blockText, apphook.ActionBlock}}
		got := runZeroRuleRequest(t, pieces)
		if got.proceed || got.status != single.status || got.respBody != single.respBody {
			t.Errorf("block-last response = proceed %v, %d %q; want refused with the single-block bytes %d %q",
				got.proceed, got.status, got.respBody, single.status, single.respBody)
		}
		assertRowsFollowPieces(t, "mask→block", got.batch, pieces)
	})
}

// assertRowsFollowPieces asserts the uploaded batch is exactly one content row
// per piece, in piece order, with each row's action_taken as the detector gave
// it, and no request_verdict row.
func assertRowsFollowPieces(t *testing.T, label string, batch []byte, pieces []zeroRulePiece) {
	t.Helper()
	if batch == nil {
		t.Errorf("[%s] master sink received nothing — the refused request uploaded no audit rows", label)
		return
	}
	var env struct {
		Events []struct {
			EventID      string `json:"event_id"`
			Scenario     string `json:"scenario"`
			ActionTaken  string `json:"action_taken"`
			PromptLength int    `json:"prompt_length"`
		} `json:"events"`
	}
	if err := json.Unmarshal(batch, &env); err != nil {
		t.Errorf("[%s] upload batch is not a compliance envelope: %v\nbody: %s", label, err, batch)
		return
	}
	for _, ev := range env.Events {
		if ev.Scenario == scenarioRequestVerdict {
			t.Errorf("[%s] batch carries a %q row (%s) — no escalation rule is configured, so none may fire"+
				"\nbody: %s", label, scenarioRequestVerdict, ev.EventID, batch)
		}
	}
	if len(env.Events) != len(pieces) {
		t.Errorf("[%s] uploaded rows = %d, want exactly %d (one content row per scanned piece). "+
			"R-compliance-grading-15.S2 (2026-09-15 用户拍板追认): 被拒的多片段请求，拒绝点之后被扫描的片段"+
			"也各自记内容行.\nbody: %s", label, len(env.Events), len(pieces), batch)
		return
	}
	for i, ev := range env.Events {
		want := pieces[i]
		if ev.PromptLength != len(want.text) || ev.ActionTaken != want.action.String() {
			t.Errorf("[%s] row %d = {prompt_length %d, action_taken %q}, want piece %d {prompt_length %d, "+
				"action_taken %q} — rows must follow piece order and keep the detector's own verdict\nbody: %s",
				label, i, ev.PromptLength, ev.ActionTaken, i, len(want.text), want.action.String(), batch)
		}
	}
}
