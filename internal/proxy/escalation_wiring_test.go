package proxy

// escalation_wiring_test.go — fences for step 4 of DEC-compliance-grading-11:
// the request-level verdict actually being REACHED from applyInboundFilter.
//
// WHY A SECOND FILE NEXT TO escalation_test.go: that file fences the counting
// PRIMITIVE (a pure function, no request path on purpose — see its header). The
// three fences here are the opposite half: they only prove anything by going
// through the dispatcher, because what they guard is the WIRING — the decode,
// the timing change, and what leaves the process. Steps 1–3 of DEC-11 were all
// green while being unreachable; that is the specific failure this file exists
// to make impossible to repeat.
//
// rules (still PROPOSAL-layer — 需求包 roadmap20260320/技术实现/阶段9-商业化版本/
// 博时基金合规能力融合/openspec/changes/add-compliance-grading-fusion/specs/
// compliance-grading/spec.md, hence `rules:` and not `spec:` anchors):
//
//	R-compliance-grading-15.S1  跨三个片段各命中一次触发升级
//	R-compliance-grading-15.S2  [回归] 未配升级规则时处置时序对外结果不变
//	R-compliance-grading-16.S3  [回归] 内容派生值不出现在任何 wire 或落库字段
//
// task: 3.11

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

// gradedHit is one detector finding as it appears INSIDE a compliance event —
// i.e. the shape the proxy has to decode, not the shape it stores.
//
// 🔴 The JSON keys are written out by hand rather than reusing proxy.Finding on
// purpose. proxy.Finding is the DECODER under test; encoding the fixture with it
// would make the test agree with the decoder by construction, and a field the
// decoder forgets (the `category` this whole family filter reads) would stay
// green. These keys are copied from the detector's intake.Finding tags
// (ai-compliance-detector internal/intake/event.go).
type gradedHit struct {
	value     string
	category  string
	level     int
	confirmed bool
}

// eventJSON renders one detector compliance event containing these hits, with
// the offsets resolved against the piece text they were found in.
//
// It carries NO snippet fields (`redacted_snippet` / `context_snippet`): those
// are the detector's own privacy-tier decision and have their own rules. Leaving
// them out keeps TestEscalation_NoContentDerivedValueLeavesProcess asserting
// what THIS change adds, instead of re-litigating the snippet policy.
func eventJSON(t *testing.T, eventID, action, text string, hits []gradedHit) []byte {
	t.Helper()
	findings := make([]map[string]any, 0, len(hits))
	for i, h := range hits {
		start := strings.Index(text, h.value)
		if start < 0 {
			t.Fatalf("fixture is wrong: piece %q does not contain %q", text, h.value)
		}
		f := map[string]any{
			// 🔴 NOT derived from the value: the fence below hunts for content
			// derivations in the uploaded bytes, and a fixture that stitched the
			// ID card number into its own finding_id would fail its own
			// assertion. (It did, on the first run — which is the fence working.)
			"finding_id":   fmt.Sprintf("f-%d-%d", len(text), i),
			"rule_id":      "fixture-rule",
			"category":     h.category,
			"entity_type":  "FIXTURE",
			"severity":     "high",
			"confidence":   90,
			"start_offset": start,
			"end_offset":   start + len(h.value),
		}
		if h.level > 0 {
			f["level"] = h.level
		}
		if h.confirmed {
			f["confirmed"] = true
		}
		findings = append(findings, f)
	}
	raw, err := json.Marshal(map[string]any{
		"event_id":      eventID,
		"created_at":    time.Now().UTC(),
		"tenant_id":     "",
		"prompt_length": len(text),
		"action_taken":  action,
		"findings":      findings,
	})
	if err != nil {
		t.Fatalf("marshal fixture event: %v", err)
	}
	return raw
}

// contentScriptedHook answers per PIECE CONTENT, which is what a request with
// three different customers in three different messages needs: stubHook returns
// one canned response for every piece.
//
// It also records every payload it was handed, so a fence can assert on the PIPE
// FRAME — the first of the four surfaces R-compliance-grading-16.S3 names.
type contentScriptedHook struct {
	answer   func(payload string) *apphook.Response
	mu       sync.Mutex
	payloads []string
}

func (h *contentScriptedHook) Name() string { return "content-scripted" }

func (h *contentScriptedHook) Detect(_ context.Context, req *apphook.Request) *apphook.Response {
	h.mu.Lock()
	h.payloads = append(h.payloads, string(req.Payload))
	h.mu.Unlock()
	return h.answer(string(req.Payload))
}

func (h *contentScriptedHook) Status() *apphook.Status { return &apphook.Status{Healthy: true} }

func (h *contentScriptedHook) seen() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.payloads...)
}

func (h *contentScriptedHook) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.payloads)
}

// ─────────────────────────────────────────────────────────────────────────────
// R-compliance-grading-15.S1 — three pieces, one hit each, one blocked request
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalation_CountsAcrossPieces is the fence for R-compliance-grading-15.S1.
//
// GIVEN 阶梯 L4=脱敏, 升级规则「≥L4 命中 ≥3 条 → 拦截」
// WHEN  one request carries three content pieces, each with one CONFIRMED L4 hit
//
//	on a DIFFERENT value
//
// THEN  the whole request is refused — not masked three times and forwarded.
//
// The three sub-cases are one fence because each is the other's control:
//
//	① three different values  → blocked        (the rule fires across pieces)
//	② three secret-family hits → NOT blocked   (the family filter is REACHED)
//	③ the same value 3×       → NOT blocked    (dedup is REACHED)
//
// 🔴 ② and ③ are what make ① mean something. A wiring that decodes the findings
// but drops `category` passes ① and fails ②, silently, in production — the
// failure 3.10 handed forward in writing ("永远读到 \"\" → 永不排除 → 不报错").
func TestEscalation_CountsAcrossPieces(t *testing.T) {
	const (
		idA = "110101199003071234"
		idB = "310101198807153695"
		idC = "440305197502289517"
	)
	rules := []EscalationRule{{MinLevel: escalationMinLevel, MinCount: escalationMinCount, Action: "block"}}

	type piece struct {
		text string
		hit  gradedHit
	}
	cases := []struct {
		name       string
		pieces     []piece
		wantBlock  bool
		wantCount  int
		wantReason string
	}{
		{
			name: "three different L4 values across three pieces escalate to block",
			pieces: []piece{
				{"请核对客户 " + idA + " 的资料", gradedHit{idA, "pii", 4, true}},
				{"另外 " + idB + " 也要一起处理", gradedHit{idB, "pii", 4, true}},
				{idC + " 是第三位客户", gradedHit{idC, "pii", 4, true}},
			},
			wantBlock: true, wantCount: 3,
		},
		{
			name: "three credential hits do not escalate (family filter reached)",
			pieces: []piece{
				{"AWS_ACCESS_KEY=" + apiKeyA, gradedHit{apiKeyA, "secret", 4, true}},
				{"STRIPE_KEY=" + apiKeyB, gradedHit{apiKeyB, "secret", 4, true}},
				{"OPENAI_KEY=" + apiKeyC, gradedHit{apiKeyC, "secret", 4, true}},
			},
			wantBlock: false, wantCount: 0,
			wantReason: "category=secret must be excluded from the cumulative count " +
				"(R-compliance-grading-17.S1) — if this blocked, `category` never reached the counter",
		},
		{
			name: "the same value in three pieces does not escalate (dedup reached)",
			pieces: []piece{
				{"请核对客户 " + idA + " 的资料", gradedHit{idA, "pii", 4, true}},
				{"提醒:" + idA + " 是账户持有人", gradedHit{idA, "pii", 4, true}},
				{idA + " 再次出现", gradedHit{idA, "pii", 4, true}},
			},
			wantBlock: false, wantCount: 1,
			wantReason: "one distinct value counts once (R-compliance-grading-16.S1)",
		},
		{
			name: "an unconfirmed hit does not help reach the threshold",
			pieces: []piece{
				{"请核对客户 " + idA + " 的资料", gradedHit{idA, "pii", 4, true}},
				{"另外 " + idB + " 也要一起处理", gradedHit{idB, "pii", 4, true}},
				{idC + " 是第三位客户", gradedHit{idC, "pii", 4, false}},
			},
			wantBlock: false, wantCount: 2,
			wantReason: "the evidence gate said no (R-compliance-grading-16.S4)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			byText := map[string]gradedHit{}
			msgs := make([]string, 0, len(tc.pieces))
			for _, p := range tc.pieces {
				byText[p.text] = p.hit
				msgs = append(msgs, `{"role":"user","content":`+mustJSON(t, p.text)+`}`)
			}
			hook := &contentScriptedHook{answer: func(payload string) *apphook.Response {
				h, ok := byText[payload]
				if !ok {
					return &apphook.Response{Action: apphook.ActionAllow}
				}
				// L4 = 脱敏: every piece's OWN verdict is mask. The request-level
				// conclusion has to come from the cumulative rule, not from any
				// single piece already saying block.
				return &apphook.Response{
					Action:         apphook.ActionMask,
					MutatedPayload: []byte(strings.ReplaceAll(payload, h.value, "{{IDCARD}}")),
					Event:          eventJSON(t, "ev-"+h.category+"-"+itoaInt64(int64(len(payload))), "mask", payload, []gradedHit{h}),
				}
			}}

			p := &Proxy{filterHook: hook}
			mustSetGrading(t, p, rules)
			w := httptest.NewRecorder()
			r := newReq(`{"messages":[` + strings.Join(msgs, ",") + `]}`)
			proceed := p.applyInboundFilter(w, r, "m", "team", "org-1", "vk-1", "seat-1", "sess-1", "trace-1", discardLogger())

			esc := p.escalationSnapshot()
			if esc.evaluated != 1 {
				t.Fatalf("the request-level verdict did not run: evaluated = %d, want 1", esc.evaluated)
			}
			if got := esc.counted; got != tc.wantCount {
				t.Errorf("counted = %d, want %d — %s", got, tc.wantCount, tc.wantReason)
			}
			if tc.wantBlock {
				if proceed {
					t.Fatalf("three distinct confirmed L4 hits across three pieces were forwarded; "+
						"the request must be refused (R-compliance-grading-15.S1). counted=%d", esc.counted)
				}
				if w.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403", w.Code)
				}
				if !strings.Contains(w.Body.String(), "COMPLIANCE_BLOCKED") {
					t.Fatalf("body does not carry COMPLIANCE_BLOCKED: %s", w.Body.String())
				}
				if esc.triggered != 1 {
					t.Fatalf("triggered = %d, want 1", esc.triggered)
				}
				return
			}
			if !proceed {
				t.Fatalf("the request was refused but must not be — %s (counted=%d)", tc.wantReason, esc.counted)
			}
			if esc.triggered != 0 {
				t.Fatalf("triggered = %d, want 0 — %s", esc.triggered, tc.wantReason)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R-compliance-grading-15.S2 — the timing change is invisible with no rules
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalation_EmptyRulesKeepsOutcome is the fence for
// R-compliance-grading-15.S2, and it asserts TWO things that must both hold:
//
//  1. with `escalation` empty, block / mask / warn / allow produce byte-identical
//     responses, bodies and forwarding decisions — the move of `block` from
//     "return on sight" to "return after the loop" changes nothing an outside
//     observer can see;
//  2. the request-level verdict path RAN and concluded "no escalation".
//
// 🔴 (2) is not decoration. Without it this fence passes with the entire
// evaluation commented out — the strongest possible way to keep outcomes
// unchanged, and the exact reading the spec rules out: 「不接受"没配就走不到"
// 作为等价性论据」.
func TestEscalation_EmptyRulesKeepsOutcome(t *testing.T) {
	const secret = "110101199003071234"
	body := `{"messages":[{"role":"user","content":"客户 ` + secret + ` 的资料"},` +
		`{"role":"user","content":"第二段内容,没有敏感信息"}]}`

	cases := []struct {
		name         string
		resp         func(payload string) *apphook.Response
		wantProceed  bool
		wantStatus   int
		wantBodyHas  string
		wantForward  string // substring the forwarded body must contain ("" = not checked)
		wantMaskedTo string
	}{
		{
			name: "block",
			resp: func(payload string) *apphook.Response {
				if strings.Contains(payload, secret) {
					return &apphook.Response{Action: apphook.ActionBlock}
				}
				return &apphook.Response{Action: apphook.ActionAllow}
			},
			wantProceed: false, wantStatus: http.StatusForbidden,
			wantBodyHas: "COMPLIANCE_BLOCKED",
		},
		{
			name: "mask",
			resp: func(payload string) *apphook.Response {
				if strings.Contains(payload, secret) {
					return &apphook.Response{Action: apphook.ActionMask,
						MutatedPayload: []byte(strings.ReplaceAll(payload, secret, "{{IDCARD}}"))}
				}
				return &apphook.Response{Action: apphook.ActionAllow}
			},
			wantProceed: true, wantMaskedTo: "{{IDCARD}}",
		},
		{
			name: "warn",
			resp: func(string) *apphook.Response {
				return &apphook.Response{Action: apphook.ActionWarn, Reason: "warned"}
			},
			wantProceed: true, wantForward: secret,
		},
		{
			name: "allow",
			resp: func(string) *apphook.Response {
				return &apphook.Response{Action: apphook.ActionAllow}
			},
			wantProceed: true, wantForward: secret,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hook := &contentScriptedHook{answer: tc.resp}
			p := &Proxy{filterHook: hook}
			// No SetComplianceGrading call at all: an org that never configured
			// grading is the default state, and it is the state this fence is
			// about.
			w := httptest.NewRecorder()
			r := newReq(body)
			proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "trace-2", discardLogger())

			if proceed != tc.wantProceed {
				t.Fatalf("proceed = %v, want %v", proceed, tc.wantProceed)
			}
			if tc.wantStatus != 0 && w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			if tc.wantBodyHas != "" && !strings.Contains(w.Body.String(), tc.wantBodyHas) {
				t.Fatalf("response body = %q, want it to contain %q", w.Body.String(), tc.wantBodyHas)
			}
			if tc.wantMaskedTo != "" {
				out := readReqBody(t, r)
				if !strings.Contains(out, tc.wantMaskedTo) || strings.Contains(out, secret) {
					t.Fatalf("mask path changed: forwarded body = %s", out)
				}
			}
			if tc.wantForward != "" {
				if out := readReqBody(t, r); !strings.Contains(out, tc.wantForward) {
					t.Fatalf("pass-through path changed: forwarded body = %s", out)
				}
			}

			// (2) — "新逻辑已生效": the verdict path ran, and concluded nothing.
			esc := p.escalationSnapshot()
			if esc.evaluated != 1 {
				t.Fatalf("the request-level verdict path did not execute (evaluated = %d, want 1). "+
					"An unchanged outcome proves nothing on its own — 「不接受『没配就走不到』作为等价性论据」.",
					esc.evaluated)
			}
			if esc.triggered != 0 {
				t.Fatalf("triggered = %d, want 0 — no escalation rule is configured", esc.triggered)
			}
			if esc.counted != 0 {
				t.Fatalf("counted = %d, want 0 — with no rule there is no level floor to count against", esc.counted)
			}
		})
	}
}

// TestEscalation_BlockedRequestStillScansRemainingPieces pins the one visible
// consequence of the timing change, so that it is a DECISION on the record
// rather than a surprise: a refused request now finishes the loop.
//
// It is the companion of the fence above — that one says "nothing an outside
// observer sees changed", this one says "and here is exactly what did".
// DEC-compliance-grading-11 决定 5 accepted this cost in writing ("被拒请求会多
// 扫完剩余片段"), because the cumulative rule cannot count hits in pieces that
// were never scanned.
func TestEscalation_BlockedRequestStillScansRemainingPieces(t *testing.T) {
	const secret = "110101199003071234"
	hook := &contentScriptedHook{answer: func(payload string) *apphook.Response {
		if strings.Contains(payload, secret) {
			return &apphook.Response{Action: apphook.ActionBlock}
		}
		return &apphook.Response{Action: apphook.ActionAllow}
	}}
	p := &Proxy{filterHook: hook}
	r := newReq(`{"messages":[{"role":"user","content":"客户 ` + secret + ` 的资料"},` +
		`{"role":"user","content":"第二段"},{"role":"user","content":"第三段"}]}`)
	if p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", "trace-3", discardLogger()) {
		t.Fatal("expected the request to be refused")
	}
	if got := hook.count(); got != 3 {
		t.Fatalf("detector calls on a refused request = %d, want 3 — the loop must complete so the "+
			"cumulative rule sees every piece (DEC-compliance-grading-11 决定 5)", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// DEC-compliance-grading-11 决定 5, the BOOKKEEPING half — a refused request
// still records every piece it scanned
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalation_RefusedRequestStillRecordsUncountedPieces fences the
// constraint the user approved on 2026-09-14 (「都记，完整留痕」), recorded in
// design.md under DEC-compliance-grading-11:
//
//	被累计升级拒绝的多片段请求，扫到的每个片段——无论是否计入累计——SHALL 各自
//	产生内容审计行。
//
// GIVEN team route, rule 「≥L4 命中 ≥3 条 → block」, and a five-piece request
//
//	whose first three pieces each carry a distinct CONFIRMED L4 hit (so the
//	cumulative rule refuses the request) and whose last two each carry a hit
//	the counter must NOT count — one below min_level, one unconfirmed
//
// WHEN  the request is filtered
// THEN  it is refused, AND every one of the five pieces has its own content row
//
//	in the batch uploaded to master — the two uncounted pieces included
//
// AND   the three counted pieces' rows are exactly the ones the verdict row lists
//
//	(R-compliance-grading-18)
//
// 🔴 WHY THIS IS NOT AN ASSERTION ADDED TO
// TestEscalation_BlockedRequestStillScansRemainingPieces: that fence runs on the
// PERSONAL route, where the detector uploads its own events and the proxy
// forwards none — so it can prove "every piece was scanned" and can never prove
// "every piece was recorded". Recording is a team-route property of the upload
// batch, so this fence reads the batch.
//
// 🔴 WHY THE ANTI-VACUITY HALF: "the trailing piece has a row" is worthless if
// that piece was in fact counted — its row is then mandatory under
// R-compliance-grading-18 and no approval was needed for it. So the fence also
// proves each uncounted piece was scanned (its pipe frame), carries its hit (the
// finding's level/confirmed on the uploaded row), and was NOT counted (counted
// stays 3 and its row id is absent from escalation.unit_ids).
//
// rule: DEC-compliance-grading-11 (决定 5, 2026-09-14 记账面约束) · R-compliance-grading-18
func TestEscalation_RefusedRequestStillRecordsUncountedPieces(t *testing.T) {
	const (
		idA       = "110101199003071234"
		idB       = "310101198807153695"
		idC       = "440305197502289517"
		idLow     = "320102198001011237"
		idUnconfd = "510104199512127890"
	)
	type piece struct {
		text    string
		hit     gradedHit
		counted bool
	}
	pieces := []piece{
		{"请核对客户 " + idA + " 的资料", gradedHit{idA, "pii", escalationMinLevel, true}, true},
		{"另外 " + idB + " 也要一起处理一下", gradedHit{idB, "pii", escalationMinLevel, true}, true},
		{idC + " 是第三位客户", gradedHit{idC, "pii", escalationMinLevel, true}, true},
		// Uncounted by level: confirmed, but below the rule's min_level.
		{"备注里顺带提到 " + idLow + " 这个号码,仅供参考", gradedHit{idLow, "pii", escalationMinLevel - 2, true}, false},
		// Uncounted by evidence: at the rule's level, but not confirmed.
		{"未核实的号码 " + idUnconfd + " 请忽略", gradedHit{idUnconfd, "pii", escalationMinLevel, false}, false},
	}

	// Uploaded rows are matched back to their piece by prompt_length (a detector
	// field the proxy forwards untouched), so the fixture must keep it unique.
	byLen := map[int]int{}
	byText := map[string]gradedHit{}
	msgs := make([]string, 0, len(pieces))
	for i, pc := range pieces {
		if j, dup := byLen[len(pc.text)]; dup {
			t.Fatalf("fixture is wrong: pieces %d and %d have the same length %d", j, i, len(pc.text))
		}
		byLen[len(pc.text)] = i
		byText[pc.text] = pc.hit
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
			"team": &events.StaticTokenCredential{Token: "member-jwt"},
		},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	hook := &contentScriptedHook{answer: func(payload string) *apphook.Response {
		h, ok := byText[payload]
		if !ok {
			return &apphook.Response{Action: apphook.ActionAllow}
		}
		return &apphook.Response{
			Action:         apphook.ActionMask,
			MutatedPayload: []byte(strings.ReplaceAll(payload, h.value, "{{IDCARD}}")),
			Event:          eventJSON(t, "ev-"+itoaInt64(int64(len(payload))), "mask", payload, []gradedHit{h}),
		}
	}}
	p := &Proxy{filterHook: hook, reporter: rep}
	mustSetGrading(t, p, []EscalationRule{
		{MinLevel: escalationMinLevel, MinCount: escalationMinCount, Action: "block"},
	})

	r := newReq(`{"messages":[` + strings.Join(msgs, ",") + `]}`)
	if p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org-1", "vk-1", "seat-1", "sess-1",
		"trace-todo88", discardLogger()) {
		t.Fatal("the request must be refused — three distinct confirmed L4 hits reach the threshold")
	}

	// ── anti-vacuity 1: the uncounted hits really were not counted ───────────
	esc := p.escalationSnapshot()
	if esc.evaluated != 1 || esc.triggered != 1 || esc.counted != escalationMinCount {
		t.Fatalf("evaluated/triggered/counted = %d/%d/%d, want 1/1/%d — if counted is higher, the "+
			"\"uncounted\" pieces were counted and their rows prove nothing about this constraint",
			esc.evaluated, esc.triggered, esc.counted, escalationMinCount)
	}

	// ── anti-vacuity 2: every piece, trailing ones included, was scanned ─────
	frames := hook.seen()
	if len(frames) != len(pieces) {
		t.Fatalf("pipe frames = %d, want %d — a piece that was never scanned cannot be recorded, and "+
			"this fence would be checking nothing for it", len(frames), len(pieces))
	}
	for i, f := range frames {
		if f != pieces[i].text {
			t.Fatalf("pipe frame %d = %q, want %q", i, f, pieces[i].text)
		}
	}

	// ── the uploaded batch ───────────────────────────────────────────────────
	var body []byte
	select {
	case body = <-teamCh:
	case <-time.After(3 * time.Second):
		t.Fatal("master sink received nothing — the refused request uploaded no audit rows at all")
	}

	verdict := findRequestVerdict(t, body)
	if verdict.ActionTaken != "block" {
		t.Errorf("request verdict action_taken = %q, want \"block\"", verdict.ActionTaken)
	}
	listed := map[string]bool{}
	for _, id := range verdict.Escalation.UnitIDs {
		listed[id] = true
	}

	var env struct {
		Events []struct {
			EventID      string `json:"event_id"`
			Scenario     string `json:"scenario"`
			PromptLength int    `json:"prompt_length"`
			Findings     []struct {
				Level     int  `json:"level"`
				Confirmed bool `json:"confirmed"`
			} `json:"findings"`
		} `json:"events"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("upload batch is not a compliance envelope: %v\nbody: %s", err, body)
	}
	rowOf := make([]int, len(pieces)) // piece index → index into env.Events, -1 = no row
	for i := range rowOf {
		rowOf[i] = -1
	}
	contentRowCount := 0
	for k, ev := range env.Events {
		if ev.Scenario == scenarioRequestVerdict {
			continue
		}
		contentRowCount++
		i, ok := byLen[ev.PromptLength]
		if !ok {
			t.Errorf("content row %s has prompt_length %d, which matches no piece", ev.EventID, ev.PromptLength)
			continue
		}
		if rowOf[i] >= 0 {
			t.Errorf("piece %d has two content rows (%s, %s)", i, env.Events[rowOf[i]].EventID, ev.EventID)
			continue
		}
		rowOf[i] = k
	}

	for i, pc := range pieces {
		kind := "counted"
		if !pc.counted {
			kind = "UNCOUNTED"
		}
		k := rowOf[i]
		if k < 0 {
			if pc.counted {
				t.Errorf("piece %d (%s) has no content row, so the verdict row's unit_ids points at "+
					"nothing (R-compliance-grading-18).\nbody: %s", i, kind, body)
			} else {
				t.Errorf("piece %d (%s: level=%d confirmed=%v) was scanned and hit, but produced NO "+
					"content audit row on a refused request.\n\nDEC-compliance-grading-11 (2026-09-14 用户"+
					"拍板「都记，完整留痕」): 被累计升级拒绝的多片段请求，扫到的每个片段——无论是否计入"+
					"累计——SHALL 各自产生内容审计行. Do not gate a piece's event on whether it was "+
					"counted.\nbody: %s", i, kind, pc.hit.level, pc.hit.confirmed, body)
			}
			continue
		}
		row := env.Events[k]
		// anti-vacuity 3: the row carries THIS piece's hit, as the counter saw it.
		if len(row.Findings) != 1 || row.Findings[0].Level != pc.hit.level ||
			row.Findings[0].Confirmed != pc.hit.confirmed {
			t.Errorf("piece %d (%s) row %s findings = %+v, want exactly one with level=%d confirmed=%v",
				i, kind, row.EventID, row.Findings, pc.hit.level, pc.hit.confirmed)
		}
		// anti-vacuity 4: counted ⇔ listed on the verdict row.
		if listed[row.EventID] != pc.counted {
			t.Errorf("piece %d (%s) row %s listed in escalation.unit_ids = %v, want %v — the verdict "+
				"lists exactly the counted rows (R-compliance-grading-18); an uncounted piece that is "+
				"listed means the fixture no longer exercises an uncounted piece",
				i, kind, row.EventID, listed[row.EventID], pc.counted)
		}
	}
	if contentRowCount != len(pieces) {
		t.Errorf("content rows = %d, want %d (one per scanned piece)", contentRowCount, len(pieces))
	}
	if got := len(verdict.Escalation.UnitIDs); got != escalationMinCount {
		t.Errorf("escalation.unit_ids has %d entries, want %d", got, escalationMinCount)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R-compliance-grading-16.S3 — nothing content-derived leaves the process
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalation_NoContentDerivedValueLeavesProcess is the fence for
// R-compliance-grading-16.S3.
//
// It drives ONE escalating request and then inspects all four surfaces the rule
// names, asserting that none of them carries a matched value, its hash, or any
// equivalent fingerprint:
//
//	pipe 帧      — every payload handed to the detector child
//	上报 wire    — the batch POSTed to master's compliance intake
//	master 落库行 — what that POST would store: the batch is what master parses,
//	              so the bytes on the wire ARE the row's source. Asserting on
//	              the received body is the strongest statement this repository
//	              can make about master's row without running master.
//	本机镜像行    — the batch POSTed to the local self-view store
//
// 🔴 WHAT "不含命中子串或其哈希" MEANS HERE, precisely, because a careless reading
// makes this fence either vacuous or impossible:
//
//   - the PIPE FRAME necessarily carries the content itself — that is what the
//     detector is for. What it must NOT carry is anything the ESCALATION added:
//     the frame must be exactly the piece text, nothing appended.
//   - the three upload/storage surfaces must not carry the matched VALUE, nor
//     sha256(value) in any spelling. They DO legitimately carry `event_id` and
//     `escalation.unit_ids`, which are ids of audit rows (audit unit ids derive
//     from the whole piece, not the matched value, and they were already on this
//     wire before this feature — see injectEventID). The fence therefore hunts
//     the VALUE and its derivations, which is the equal-join surface the rule
//     exists to prevent ("拿已知身份证号算哈希反查谁提过这个人").
//
// AND, per the scenario's second half, it asserts the dedup really ran and
// counted correctly — otherwise "no content-derived value left the process" is
// satisfied by an escalation that never happened.
func TestEscalation_NoContentDerivedValueLeavesProcess(t *testing.T) {
	const (
		idA = "110101199003071234"
		idB = "310101198807153695"
		idC = "440305197502289517"
	)
	pieces := []struct{ text, value string }{
		{"请核对客户 " + idA + " 的资料", idA},
		{"另外 " + idB + " 也要一起处理", idB},
		{idC + " 是第三位客户,谢谢", idC},
	}

	teamCh, localCh := make(chan []byte, 8), make(chan []byte, 8)
	sink := func(ch chan<- []byte) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			ch <- b
			_, _ = w.Write([]byte(`{"accepted_ids":[]}`))
		}))
	}
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

	byText := map[string]string{}
	msgs := make([]string, 0, len(pieces))
	for _, p := range pieces {
		byText[p.text] = p.value
		msgs = append(msgs, `{"role":"user","content":`+mustJSON(t, p.text)+`}`)
	}
	hook := &contentScriptedHook{answer: func(payload string) *apphook.Response {
		v, ok := byText[payload]
		if !ok {
			return &apphook.Response{Action: apphook.ActionAllow}
		}
		return &apphook.Response{
			Action:         apphook.ActionMask,
			MutatedPayload: []byte(strings.ReplaceAll(payload, v, "{{IDCARD}}")),
			Event: eventJSON(t, "ev-"+itoaInt64(int64(len(payload))), "mask", payload,
				[]gradedHit{{value: v, category: "pii", level: escalationMinLevel, confirmed: true}}),
		}
	}}

	p := &Proxy{filterHook: hook, reporter: rep}
	mustSetGrading(t, p, []EscalationRule{
		{MinLevel: escalationMinLevel, MinCount: escalationMinCount, Action: "block"},
	})
	w := httptest.NewRecorder()
	r := newReq(`{"messages":[` + strings.Join(msgs, ",") + `]}`)
	if p.applyInboundFilter(w, r, "m", "team", "org-1", "vk-1", "seat-1", "sess-1", "trace-16s3", discardLogger()) {
		t.Fatal("the request must be refused — three distinct confirmed L4 hits reach the threshold")
	}

	// ── "新逻辑已生效": the dedup ran and counted correctly ────────────────────
	esc := p.escalationSnapshot()
	if esc.evaluated != 1 || esc.triggered != 1 || esc.counted != escalationMinCount {
		t.Fatalf("evaluated/triggered/counted = %d/%d/%d, want 1/1/%d — without a real count the "+
			"content-free assertions below are vacuous", esc.evaluated, esc.triggered, esc.counted, escalationMinCount)
	}

	// ── surface 1: the pipe frames ───────────────────────────────────────────
	frames := hook.seen()
	if len(frames) != len(pieces) {
		t.Fatalf("pipe frames = %d, want %d", len(frames), len(pieces))
	}
	for i, f := range frames {
		if f != pieces[i].text {
			t.Errorf("pipe frame %d is not the piece text verbatim; the escalation must add NOTHING "+
				"to the frame.\n got: %q\nwant: %q", i, f, pieces[i].text)
		}
	}

	// ── surfaces 2/3/4: the two upload batches ───────────────────────────────
	collect := func(name string, ch <-chan []byte) []byte {
		t.Helper()
		var all []byte
		deadline := time.After(3 * time.Second)
		for {
			select {
			case b := <-ch:
				all = append(all, b...)
				// One batch is enough: the dispatcher uploads all events of a
				// request in a single call.
				if len(all) > 0 {
					return all
				}
			case <-deadline:
				if len(all) == 0 {
					t.Fatalf("%s sink received nothing — this surface was never inspected", name)
				}
				return all
			}
		}
	}
	uploaded := collect("team (master)", teamCh)
	mirrored := collect("local mirror", localCh)

	for _, surface := range []struct {
		name string
		body []byte
	}{
		{"上报 wire / master 落库行", uploaded},
		{"本机镜像行", mirrored},
	} {
		s := string(surface.body)
		for _, pc := range pieces {
			for _, probe := range derivations(pc.value) {
				if strings.Contains(s, probe.text) {
					t.Errorf("%s carries %s of the matched value %q.\n\n"+
						"R-compliance-grading-16 red line: NOTHING content-derived may cross the wire or "+
						"land in a row. A comparable derivation creates a 「拿已知身份证号算哈希就能反查谁提过"+
						"这个人」 lookup surface over the audit store.\n\nbody: %s",
						surface.name, probe.what, pc.value, s)
				}
			}
		}
		// Anti-vacuity: an empty batch trivially contains no value.
		if !strings.Contains(s, `"escalation"`) {
			t.Errorf("%s carries no request-verdict event (`escalation` key absent), so the "+
				"content-free assertions above inspected nothing that this change produced. body: %s",
				surface.name, s)
		}
	}

	// ── and the verdict row says what it should ──────────────────────────────
	verdict := findRequestVerdict(t, uploaded)
	if got := verdict.Escalation.Counted; got != escalationMinCount {
		t.Errorf("request verdict escalation.counted = %d, want %d", got, escalationMinCount)
	}
	if got := len(verdict.Escalation.UnitIDs); got != len(pieces) {
		t.Errorf("request verdict escalation.unit_ids has %d entries, want %d — the verdict row must "+
			"name the content rows that were counted (R-compliance-grading-18)", got, len(pieces))
	}
	for _, id := range verdict.Escalation.UnitIDs {
		if !strings.HasPrefix(id, "au_") {
			t.Errorf("escalation.unit_ids carries %q, which is not an audit unit id. The list SHALL "+
				"hold event ids and nothing else (R-compliance-grading-18).", id)
		}
	}
	if verdict.Escalation.Rule == "" {
		t.Error("request verdict does not name the rule that fired (R-compliance-grading-15.S1: " +
			"「请求级事件记录触发的升级规则」)")
	}
	if verdict.ActionTaken != "block" {
		t.Errorf("request verdict action_taken = %q, want \"block\"", verdict.ActionTaken)
	}
	if verdict.TraceID != "trace-16s3" {
		t.Errorf("request verdict trace_id = %q, want the turn's trace", verdict.TraceID)
	}
	// The content rows keep their own verdict (R-compliance-grading-18: 内容行
	// 保持各自处置). A wiring that rewrote them to `block` would be a false
	// statement in an audit log AND would break master's ON CONFLICT idempotence.
	for _, row := range contentRows(t, uploaded) {
		if row.ActionTaken != "mask" {
			t.Errorf("content row %s action_taken = %q, want \"mask\" — the request was blocked, "+
				"that piece was not (R-compliance-grading-18)", row.EventID, row.ActionTaken)
		}
	}
}

// derivations enumerates the spellings a content-derived value could plausibly
// arrive in. Hand-listing them is the point: the fence has to name what it hunts
// for, or it degenerates into "the raw string is absent", which any hashing
// implementation passes.
func derivations(value string) []struct{ what, text string } {
	sum := sha256.Sum256([]byte(value))
	return []struct{ what, text string }{
		{"the value itself", value},
		{"sha256 hex", hex.EncodeToString(sum[:])},
		{"sha256 hex, truncated to 16 bytes (the auditUnitID/gradingComponent spelling)",
			hex.EncodeToString(sum[:16])},
		{"sha256 hex, truncated to 8 bytes", hex.EncodeToString(sum[:8])},
		{"sha256 base64 (std)", base64.StdEncoding.EncodeToString(sum[:])},
		{"sha256 base64 (url)", base64.RawURLEncoding.EncodeToString(sum[:])},
	}
}

// uploadedEvent is the subset of an intake event these fences read back.
type uploadedEvent struct {
	EventID     string `json:"event_id"`
	Scenario    string `json:"scenario"`
	ActionTaken string `json:"action_taken"`
	TraceID     string `json:"trace_id"`
	Escalation  struct {
		Rule    string   `json:"rule"`
		Counted int      `json:"counted"`
		UnitIDs []string `json:"unit_ids"`
	} `json:"escalation"`
}

func decodeBatch(t *testing.T, body []byte) []uploadedEvent {
	t.Helper()
	var env struct {
		Events []uploadedEvent `json:"events"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("upload batch is not a compliance envelope: %v\nbody: %s", err, body)
	}
	return env.Events
}

func findRequestVerdict(t *testing.T, body []byte) uploadedEvent {
	t.Helper()
	for _, e := range decodeBatch(t, body) {
		if e.Scenario == scenarioRequestVerdict {
			return e
		}
	}
	t.Fatalf("no scenario=%q event in the uploaded batch — the escalation conclusion was never "+
		"recorded (R-compliance-grading-18)\nbody: %s", scenarioRequestVerdict, body)
	return uploadedEvent{}
}

func contentRows(t *testing.T, body []byte) []uploadedEvent {
	t.Helper()
	var out []uploadedEvent
	for _, e := range decodeBatch(t, body) {
		if e.Scenario != scenarioRequestVerdict {
			out = append(out, e)
		}
	}
	return out
}

// mustSetGrading installs escalation rules through the PRODUCTION entry point
// (the one the supervisor calls), so a fence can never be green against a rule
// set that no real deployment could load.
func mustSetGrading(t *testing.T, p *Proxy, rules []EscalationRule) {
	t.Helper()
	entries := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		entries = append(entries, map[string]any{
			"min_level": r.MinLevel, "min_count": r.MinCount, "action": r.Action,
		})
	}
	doc, err := json.Marshal(map[string]any{"escalation": entries})
	if err != nil {
		t.Fatalf("marshal grading doc: %v", err)
	}
	applied, rejected, err := p.SetComplianceGrading(doc)
	if err != nil {
		t.Fatalf("SetComplianceGrading(%s): %v", doc, err)
	}
	if len(rejected) > 0 {
		t.Fatalf("SetComplianceGrading rejected %v from %s", rejected, doc)
	}
	if applied != len(rules) {
		t.Fatalf("SetComplianceGrading applied %d rules, want %d", applied, len(rules))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The rule reader
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalation_RulesAreReadFromTheGradingDocument covers the reader end to
// end: the bytes master hands down become the rules this proxy enforces, and
// every rule it will NOT enforce is REPORTED rather than dropped.
//
// 🔴 The refusal half is the important one. A rule this proxy silently ignores
// still shows up on the administrator's console as a configured control, so the
// failure mode is not "the feature is off" — it is "the operator believes a
// control is running that is not".
func TestEscalation_RulesAreReadFromTheGradingDocument(t *testing.T) {
	cases := []struct {
		name        string
		doc         string
		wantRules   int
		wantRefused int
		wantErr     bool
	}{
		{name: "no document at all", doc: "", wantRules: 0},
		{name: "empty document", doc: `{}`, wantRules: 0},
		{name: "grading configured but no escalation member",
			doc: `{"labels":{"4":"商密"},"ladder":{"4":{"action":"mask"}}}`, wantRules: 0},
		{name: "the shape design §4b.1 documents",
			doc: `{"escalation":[{"min_level":4,"min_count":3,"action":"block"}]}`, wantRules: 1},
		{name: "several rules keep document order",
			doc: `{"escalation":[{"min_level":5,"min_count":1,"action":"block"},` +
				`{"min_level":4,"min_count":3,"action":"block"}]}`, wantRules: 2},
		{name: "a zero threshold is refused, not silently enforced",
			doc: `{"escalation":[{"min_level":4,"action":"block"}]}`, wantRules: 0, wantRefused: 1},
		{name: "an action this proxy cannot enact at request level is refused",
			doc:       `{"escalation":[{"min_level":4,"min_count":3,"action":"mask"}]}`,
			wantRules: 0, wantRefused: 1},
		{name: "代答 is refused rather than degraded in silence",
			doc:       `{"escalation":[{"min_level":4,"min_count":3,"action":"answer"}]}`,
			wantRules: 0, wantRefused: 1},
		{name: "a usable rule beside a refused one still installs",
			doc: `{"escalation":[{"min_level":4,"min_count":3,"action":"warn"},` +
				`{"min_level":5,"min_count":2,"action":"block"}]}`, wantRules: 1, wantRefused: 1},
		{name: "a document that is not JSON is an error, not an empty policy",
			doc: `{"escalation":`, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{}
			applied, refused, err := p.SetComplianceGrading([]byte(tc.doc))
			if tc.wantErr {
				if err == nil {
					t.Fatal("want an error for an unparseable document — an empty policy would " +
						"silently switch every cumulative control off")
				}
				return
			}
			if err != nil {
				t.Fatalf("SetComplianceGrading: %v", err)
			}
			if applied != tc.wantRules {
				t.Errorf("applied = %d, want %d (rules = %v)", applied, tc.wantRules, p.ComplianceEscalationRules())
			}
			if len(refused) != tc.wantRefused {
				t.Errorf("refused %d rules, want %d: %v", len(refused), tc.wantRefused, refused)
			}
			for _, r := range refused {
				if !strings.Contains(r, "level>=") || !strings.Contains(r, "action=") {
					t.Errorf("a refusal line must name the rule it is about so the operator can find "+
						"it on the console; got %q", r)
				}
			}
		})
	}
}

// TestEscalation_EnactableActionSetIsSingular is a TRIPWIRE, not a behaviour
// test: evaluateEscalation picks the FIRST rule that fires, which is only
// correct while every enactable action concludes the same thing.
//
// If you are here because this went red, you have added a second enactable
// request-level action. That is fine — but evaluateEscalation now needs a
// strength ordering (「SHALL NOT 弱于逐片段动作的最强项」, R-compliance-grading-15),
// and this test is the note that says so.
func TestEscalation_EnactableActionSetIsSingular(t *testing.T) {
	var enactable []string
	for _, name := range []string{"allow", "warn", "audit", "mask", "block", "answer", "", "BLOCK", "off"} {
		if _, ok := escalationEnactableAction(name); ok {
			enactable = append(enactable, name)
		}
	}
	if len(enactable) != 1 || enactable[0] != "block" {
		t.Fatalf("escalationEnactableAction admits %v; this fence assumed exactly [block]. "+
			"evaluateEscalation takes the FIRST firing rule, which is only correct while all "+
			"enactable actions are equally strong — give it a strength ordering in the same "+
			"change that widened the set.", enactable)
	}
}

// TestEscalation_CeilingClampsTheEscalatedAction proves the clamp is WIRED, not
// merely available: R-compliance-grading-15 requires the escalated action to
// pass through the request-level ceiling.
//
// It calls evaluateEscalation directly with each rung. ceilingWarn is the one
// the dispatcher passes when MAX_ACTION=warn (task 3.13); ceilingAudit is not
// reachable at request level and stays here to prove the clamp itself works —
// and, next to the warn case, to pin that the two rungs are NOT interchangeable.
func TestEscalation_CeilingClampsTheEscalatedAction(t *testing.T) {
	const idA, idB, idC = "110101199003071234", "310101198807153695", "440305197502289517"
	pieces := []contentPiece{{text: idA}, {text: idB}, {text: idC}}
	findings := [][]Finding{
		{{StartOffset: 0, EndOffset: len(idA), Level: 4, Confirmed: true, Category: "pii"}},
		{{StartOffset: 0, EndOffset: len(idB), Level: 4, Confirmed: true, Category: "pii"}},
		{{StartOffset: 0, EndOffset: len(idC), Level: 4, Confirmed: true, Category: "pii"}},
	}
	rules := []EscalationRule{{MinLevel: escalationMinLevel, MinCount: escalationMinCount, Action: "block"}}

	full := evaluateEscalation(pieces, findings, rules, ceilingFull)
	if full.Action != apphook.ActionBlock || full.Capped {
		t.Fatalf("at ceilingFull the escalation must block: action=%v capped=%v", full.Action, full.Capped)
	}
	if len(full.Units) != 3 {
		t.Fatalf("Units = %v, want all three pieces — the verdict row must name every counted row", full.Units)
	}
	capped := evaluateEscalation(pieces, findings, rules, ceilingAudit)
	if capped.Action != apphook.ActionAllow || !capped.Capped {
		t.Fatalf("at ceilingAudit the escalated block must be clamped away: action=%v capped=%v "+
			"(R-compliance-grading-15: 升级后的动作受请求级天花板钳制)", capped.Action, capped.Capped)
	}
	if capped.Rule == nil || capped.Counted != 3 {
		t.Fatalf("a clamped escalation still concluded: rule=%v counted=%d — the audit row must "+
			"record what the rule decided, not what the ceiling allowed", capped.Rule, capped.Counted)
	}
	// MAX_ACTION=warn (task 3.13): the SAME escalation, capped to a WARNING. Not
	// allow — that would be the ceilingAudit trap (see
	// TestEscalation_MaxActionWarnCapsEscalatedBlock).
	warned := evaluateEscalation(pieces, findings, rules, ceilingWarn)
	if warned.Action != apphook.ActionWarn || !warned.Capped {
		t.Fatalf("at ceilingWarn the escalated block must become warn: action=%v capped=%v "+
			"(actionpolicy.capRuntimeAction: MaxActionWarn maps block → warn)", warned.Action, warned.Capped)
	}
	if warned.Rule == nil || warned.Counted != 3 || len(warned.Units) != 3 {
		t.Fatalf("a warn-capped escalation still concluded: rule=%v counted=%d units=%v", warned.Rule, warned.Counted, warned.Units)
	}
	// And the accessor the dispatcher calls resolves each MAX_ACTION to its rung.
	for maxAction, want := range map[string]actionCeiling{"": ceilingFull, "full": ceilingFull, "warn": ceilingWarn} {
		p := &Proxy{}
		if err := p.SetComplianceMaxAction(maxAction); err != nil {
			t.Fatalf("SetComplianceMaxAction(%q): %v", maxAction, err)
		}
		if got := p.requestEscalationCeiling(); got != want {
			t.Errorf("MAX_ACTION %q → request ceiling %v, want %v", maxAction, got, want)
		}
	}
	p := &Proxy{}
	if err := p.SetComplianceMaxAction("block"); err == nil {
		t.Error("SetComplianceMaxAction accepted \"block\"; the domain is exactly full / warn (actionpolicy.ParseMaxAction)")
	}
	if got := p.requestEscalationCeiling(); got != ceilingFull {
		t.Errorf("a refused MAX_ACTION changed the ceiling to %v; the previous value (full) must stand", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Cost
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalationPerf_RequestLevelVerdictCost prices what step 4 adds to the
// SYNCHRONOUS filter path, which is bounded by 「≤15ms（16KB 输入）且 fail-open」.
//
// Two things were added per request, and neither depends on the detector:
//
//	① one JSON decode of each piece's event `findings` array;
//	② one evaluateEscalation pass (one substring slice + one map insert per
//	   counted hit, per rule).
//
// The THIRD change — a refused request now finishes the loop instead of
// returning on the offending piece — costs extra Detect calls, and its upper
// bound is already known without measuring it: a refused request now does what
// an ALLOWED request of the same shape has always done. It cannot exceed the
// allowed-path cost for that shape, which is the number the budget was set
// against in the first place.
//
// Reports with `-v`; asserts only the SHAPE (bounded, and small next to the
// budget), never a wall-clock threshold — this package has no perf-isolated
// environment, and a timing gate here would be a flake generator rather than a
// fence (same posture as filter_toolblock_perf_test.go).
func TestEscalationPerf_RequestLevelVerdictCost(t *testing.T) {
	const (
		pieceCount = 20 // a long agent turn: system + a dozen messages + tool blocks
		iterations = 2000
	)
	rules := []EscalationRule{
		{MinLevel: 4, MinCount: 3, Action: "block"},
		{MinLevel: 5, MinCount: 1, Action: "block"},
	}

	pieces := make([]contentPiece, pieceCount)
	events := make([][]byte, pieceCount)
	for i := range pieces {
		// Each piece is a realistic ~200-byte message carrying one graded hit.
		v := fmt.Sprintf("1101011990030%05d", i)
		text := "请核对客户 " + v + " 的资料," + strings.Repeat("补充说明与背景信息。", 8)
		pieces[i] = contentPiece{text: text}
		events[i] = eventJSON(t, fmt.Sprintf("ev-%d", i), "mask", text,
			[]gradedHit{{value: v, category: "pii", level: 4, confirmed: true}})
	}

	lat := make([]time.Duration, 0, iterations)
	var lastCount int
	for n := 0; n < iterations; n++ {
		start := time.Now()
		findings := make([][]Finding, pieceCount)
		for i := range events {
			findings[i] = decodeEventFindings(events[i])
		}
		out := evaluateEscalation(pieces, findings, rules, (&Proxy{}).requestEscalationCeiling())
		lat = append(lat, time.Since(start))
		lastCount = out.Counted
	}
	if lastCount != pieceCount {
		t.Fatalf("the measured pass counted %d distinct values, want %d — a measurement of a "+
			"code path that did nothing is not a measurement", lastCount, pieceCount)
	}

	p50, p95 := pctlDuration(lat, 50), pctlDuration(lat, 95)
	t.Logf("request-level verdict cost, %d pieces × 1 confirmed L4 hit, %d rules, %d iterations:",
		pieceCount, len(rules), iterations)
	t.Logf("  decode(%d events) + evaluateEscalation: p50 %v · p95 %v", pieceCount, p50, p95)
	t.Logf("  synchronous filter budget: 15ms → this is %.2f%% of it at p95",
		100*float64(p95)/float64(15*time.Millisecond))

	// SHAPE assertion: the added work must stay a rounding error against the
	// budget. One tenth of it is two orders of magnitude of headroom over the
	// measured value, so this fires on an algorithmic regression (a quadratic
	// dedup, a re-decode per rule) and not on a loaded CI box.
	if p95 > 15*time.Millisecond/10 {
		t.Errorf("the request-level verdict cost %v at p95 for %d pieces — more than a tenth of the "+
			"15ms synchronous budget. Something turned super-linear; the pass is meant to be one "+
			"slice + one map insert per hit per rule.", p95, pieceCount)
	}
}

func pctlDuration(d []time.Duration, p int) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := (len(s)*p + 99) / 100
	if i >= len(s) {
		i = len(s) - 1
	}
	return s[i]
}

// ─────────────────────────────────────────────────────────────────────────────
// The desync WARN task 3.9 handed over
// ─────────────────────────────────────────────────────────────────────────────

// The WARN fence below reuses logCapture / correlatedLogger from
// filter_scan_coverage_test.go: that harness already keeps the attributes a
// caller pre-binds with slog.With, which is the half this fence is about.

// TestEscalation_UnresolvedHitsRaiseAWarn is the fence for the logging
// obligation task 3.9 HANDED OVER rather than discharged: countDistinctHits is a
// pure function with no request context, so it returns `skipped` as a number and
// 「WARN 必须由调用方打，带 request_id/trace_id」.
//
// 🔴 WITHOUT THIS FENCE THE OBLIGATION IS UNENFORCED, which is exactly the state
// it was in when this task started ("已移交、未执行"). Deleting the WARN would
// otherwise change no test: the count is unaffected, the request still succeeds,
// and a cross-process desync between the detector's offsets and the proxy's text
// goes back to being invisible.
//
// The negative half is as load bearing as the positive one: a hit the RULES
// exclude must NOT raise it. A WARN that fires on every ordinary agent turn
// stops being read, and then the real desync is invisible again — by a different
// route.
func TestEscalation_UnresolvedHitsRaiseAWarn(t *testing.T) {
	const value = "110101199003071234"
	text := "请核对客户 " + value + " 的资料"

	run := func(t *testing.T, hits []map[string]any) (capturedRecord, bool, int) {
		t.Helper()
		ev, err := json.Marshal(map[string]any{
			"event_id": "ev-desync", "created_at": time.Now().UTC(), "tenant_id": "",
			"prompt_length": len(text), "action_taken": "mask", "findings": hits,
		})
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		hook := &contentScriptedHook{answer: func(payload string) *apphook.Response {
			if payload != text {
				return &apphook.Response{Action: apphook.ActionAllow}
			}
			return &apphook.Response{Action: apphook.ActionWarn, Event: ev}
		}}
		p := &Proxy{filterHook: hook}
		mustSetGrading(t, p, []EscalationRule{
			{MinLevel: escalationMinLevel, MinCount: escalationMinCount, Action: "block"},
		})
		h := newLogCapture()
		r := newReq(`{"messages":[{"role":"user","content":` + mustJSON(t, text) + `}]}`)
		if !p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org-1", "vk-1", "seat-1", "s", "trace-abc123", correlatedLogger(h)) {
			t.Fatal("a single warn verdict must not refuse the request")
		}
		recs := h.withEvent(observability.EventProxyFilterEscalationUnresolved)
		if len(recs) > 1 {
			t.Fatalf("%d desync WARNs for one request, want at most 1 — one aggregated line per "+
				"request, never one per hit or per rule", len(recs))
		}
		if len(recs) == 0 {
			return capturedRecord{}, false, p.escalationSnapshot().unresolved
		}
		return recs[0], true, p.escalationSnapshot().unresolved
	}

	t.Run("a confirmed hit whose span does not fit the piece raises the WARN", func(t *testing.T) {
		rec, ok, unresolved := run(t, []map[string]any{{
			"finding_id": "f-1", "category": "pii", "entity_type": "IDCARD", "severity": "high",
			"confidence": 95, "level": escalationMinLevel, "confirmed": true,
			// Past the end of this piece: the detector's offsets and the proxy's
			// text disagree — the desync this WARN exists to surface.
			"start_offset": 0, "end_offset": len(text) + 64,
		}})
		if !ok {
			t.Fatalf("no %q WARN was emitted. Task 3.9 returned `skipped` instead of logging it "+
				"BECAUSE the caller has the request context — an obligation that is only discharged "+
				"if this line actually exists.", observability.EventProxyFilterEscalationUnresolved)
		}
		if rec.level != slog.LevelWarn {
			t.Errorf("level = %v, want WARN — a cross-process desync is not a debug detail", rec.level)
		}
		for _, key := range []string{"trace_id", "span_id", "request_id"} {
			if rec.str(key) == "" {
				t.Errorf("the WARN carries no %s. 日志规范: every WARN must carry request_id / "+
					"trace_id / span_id, and in this package they arrive on the logger the caller "+
					"passes in — so this line must be emitted on `logger`, never on the package "+
					"default. attrs: %v", key, rec.attrs)
			}
		}
		if got := rec.num("unresolved_hits"); got != 1 {
			t.Errorf("unresolved_hits = %d, want 1", got)
		}
		if unresolved != 1 {
			t.Errorf("the counter reads %d unresolved hits, want 1", unresolved)
		}
	})

	t.Run("hits the rules exclude do NOT raise it", func(t *testing.T) {
		// Both of these are unresolvable AND excluded. The family filter and the
		// confirmed gate run BEFORE the slice attempt, so neither may be reported
		// as a desync — a WARN that fires on every agent turn that reads a config
		// file is a WARN nobody reads (R-compliance-grading-17.S1).
		_, ok, unresolved := run(t, []map[string]any{
			{"finding_id": "f-1", "category": "secret", "entity_type": "API_KEY", "severity": "high",
				"confidence": 95, "level": escalationMinLevel, "confirmed": true,
				"start_offset": 0, "end_offset": len(text) + 64},
			{"finding_id": "f-2", "category": "pii", "entity_type": "IDCARD", "severity": "high",
				"confidence": 95, "level": escalationMinLevel, "confirmed": false,
				"start_offset": 0, "end_offset": len(text) + 64},
		})
		if ok {
			t.Error("an excluded hit raised the desync WARN. Folding by-design exclusions into " +
				"`skipped` makes the WARN fire on ordinary traffic, and a WARN nobody reads hides " +
				"the desync it exists to surface (see countDistinctHits' contract).")
		}
		if unresolved != 0 {
			t.Errorf("the counter reads %d unresolved hits, want 0", unresolved)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Task 3.13 — the request-level escalation obeys MAX_ACTION
// ─────────────────────────────────────────────────────────────────────────────

// TestEscalation_MaxActionWarnCapsEscalatedBlock is the fence for the
// `MAX_ACTION` half of R-compliance-grading-15: 「升级后的动作 SHALL 受请求级天花板
// （MAX_ACTION / audit_only 包 / 许可）钳制」.
//
// WHY IT MATTERS: an operator sets AIKEY_COMPLIANCE_FILTER_MAX_ACTION=warn during
// a rollout observation window — "block nothing yet, show me what would
// happen". The detector honours it per piece (mask/block → warn inside
// actionpolicy.capRuntimeAction). Before this task the CUMULATIVE rule ignored
// it and refused the whole request anyway: the safety valve failed exactly when
// an operator is most likely to be using it (a new escalation rule and a lowered
// MAX_ACTION arrive together), and it failed in the "blocked what it should not"
// direction — a business outage on a private deployment.
//
// Sub-cases, each the other's control:
//
//	unset → refused, verdict row `block`   (3.11 behaviour, byte-for-byte)
//	full  → refused, verdict row `block`   (same)
//	warn  → FORWARDED, verdict row `warn`  (the fix)
//
// 🔴 THE ceilingAudit TRAP. The proxy's pre-existing ceilings are audit / full /
// off, and "cap it with ceilingAudit" also makes the request go through — so a
// fence that only checked "not refused" would be green against that wrong
// implementation. It is wrong because ceilingAudit turns block into ALLOW: the
// warning the operator asked for silently becomes "nothing happened", the
// opposite of the detector's own reading of warn. The action_taken assertion
// below is what tells the two apart, and it names the trap when it fires.
func TestEscalation_MaxActionWarnCapsEscalatedBlock(t *testing.T) {
	const (
		idA = "110101199003071234"
		idB = "310101198807153695"
		idC = "440305197502289517"
	)
	pieces := []struct{ text, value string }{
		{"请核对客户 " + idA + " 的资料", idA},
		{"另外 " + idB + " 也要一起处理", idB},
		{idC + " 是第三位客户", idC},
	}

	cases := []struct {
		name        string
		maxAction   string
		setIt       bool
		wantRefused bool
		wantVerdict string
	}{
		{name: "MAX_ACTION unset keeps the 3.11 block", setIt: false, wantRefused: true, wantVerdict: "block"},
		{name: "MAX_ACTION=full keeps the 3.11 block", maxAction: "full", setIt: true, wantRefused: true, wantVerdict: "block"},
		{name: "MAX_ACTION=warn caps the escalated block to warn", maxAction: "warn", setIt: true, wantRefused: false, wantVerdict: "warn"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			teamCh := make(chan []byte, 8)
			teamSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				teamCh <- b
				_, _ = w.Write([]byte(`{"accepted_ids":[]}`))
			}))
			defer teamSink.Close()
			localSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = w.Write([]byte(`{"accepted_ids":[]}`))
			}))
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

			// Per-piece verdicts as the REAL detector returns them under this
			// MAX_ACTION: L4=脱敏 is mask at full, and capRuntimeAction turns it
			// into warn at warn. The request-level conclusion therefore has to come
			// from the cumulative rule in every sub-case.
			pieceAction, pieceWord := apphook.ActionMask, "mask"
			if tc.maxAction == "warn" {
				pieceAction, pieceWord = apphook.ActionWarn, "warn"
			}
			byText := map[string]string{}
			msgs := make([]string, 0, len(pieces))
			for _, pc := range pieces {
				byText[pc.text] = pc.value
				msgs = append(msgs, `{"role":"user","content":`+mustJSON(t, pc.text)+`}`)
			}
			hook := &contentScriptedHook{answer: func(payload string) *apphook.Response {
				v, ok := byText[payload]
				if !ok {
					return &apphook.Response{Action: apphook.ActionAllow}
				}
				resp := &apphook.Response{
					Action: pieceAction,
					Event: eventJSON(t, "ev-"+itoaInt64(int64(len(payload))), pieceWord, payload,
						[]gradedHit{{value: v, category: "pii", level: escalationMinLevel, confirmed: true}}),
				}
				if pieceAction == apphook.ActionMask {
					resp.MutatedPayload = []byte(strings.ReplaceAll(payload, v, "{{IDCARD}}"))
				}
				return resp
			}}

			p := &Proxy{filterHook: hook, reporter: rep}
			mustSetGrading(t, p, []EscalationRule{
				{MinLevel: escalationMinLevel, MinCount: escalationMinCount, Action: "block"},
			})
			if tc.setIt {
				if err := p.SetComplianceMaxAction(tc.maxAction); err != nil {
					t.Fatalf("SetComplianceMaxAction(%q): %v", tc.maxAction, err)
				}
			}

			w := httptest.NewRecorder()
			r := newReq(`{"messages":[` + strings.Join(msgs, ",") + `]}`)
			proceed := p.applyInboundFilter(w, r, "m", "team", "org-1", "vk-1", "seat-1", "sess-1", "trace-313", discardLogger())

			// The rule still CONCLUDED in every sub-case — the ceiling limits what
			// is done about it, never whether it is recorded.
			esc := p.escalationSnapshot()
			if esc.evaluated != 1 || esc.triggered != 1 || esc.counted != escalationMinCount {
				t.Fatalf("evaluated/triggered/counted = %d/%d/%d, want 1/1/%d — the cumulative rule must fire "+
					"regardless of MAX_ACTION; only its enactment is capped", esc.evaluated, esc.triggered, esc.counted, escalationMinCount)
			}

			var uploaded []byte
			select {
			case uploaded = <-teamCh:
			case <-time.After(3 * time.Second):
				t.Fatal("team sink received nothing — the verdict row was never uploaded, so the audit trail " +
					"for this escalation is gone (R-compliance-grading-18)")
			}
			verdict := findRequestVerdict(t, uploaded)
			if verdict.Escalation.Rule == "" || verdict.Escalation.Counted != escalationMinCount ||
				len(verdict.Escalation.UnitIDs) != len(pieces) {
				t.Errorf("verdict row escalation = %+v, want the rule, counted=%d and %d unit ids",
					verdict.Escalation, escalationMinCount, len(pieces))
			}
			for _, row := range contentRows(t, uploaded) {
				if row.ActionTaken != pieceWord {
					t.Errorf("content row %s action_taken = %q, want %q — content rows keep their own verdict "+
						"(R-compliance-grading-18)", row.EventID, row.ActionTaken, pieceWord)
				}
			}

			if tc.wantRefused {
				if proceed || w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "COMPLIANCE_BLOCKED") {
					t.Fatalf("proceed=%v status=%d body=%q — with MAX_ACTION %q the escalation must refuse the "+
						"request exactly as 3.11 did", proceed, w.Code, w.Body.String(), tc.maxAction)
				}
				if verdict.ActionTaken != tc.wantVerdict {
					t.Fatalf("verdict row action_taken = %q, want %q", verdict.ActionTaken, tc.wantVerdict)
				}
				return
			}

			if !proceed || w.Code == http.StatusForbidden {
				t.Fatalf("proceed=%v status=%d body=%q — MAX_ACTION=warn means \"block nothing\", but the "+
					"cumulative rule refused the request anyway. The per-piece verdicts were capped inside the "+
					"detector; the request-level one was not (R-compliance-grading-15: 升级后的动作 SHALL 受请求级"+
					"天花板 MAX_ACTION 钳制).", proceed, w.Code, w.Body.String())
			}
			if out := readReqBody(t, r); !strings.Contains(out, idA) {
				t.Fatalf("warn must forward the content untouched; forwarded body = %s", out)
			}
			if verdict.ActionTaken == "allow" {
				t.Fatalf("🔴 ceilingAudit TRAP: verdict row action_taken = \"allow\". The escalated block was " +
					"capped with the audit rung, which turns block into ALLOW — the warning the operator asked " +
					"for became \"nothing happened\". The detector's capRuntimeAction maps block → WARN under " +
					"MAX_ACTION=warn; the request-level verdict must say the same word.")
			}
			if verdict.ActionTaken != tc.wantVerdict {
				t.Fatalf("verdict row action_taken = %q, want %q (actionpolicy.capRuntimeAction: block → warn)",
					verdict.ActionTaken, tc.wantVerdict)
			}
		})
	}
}
