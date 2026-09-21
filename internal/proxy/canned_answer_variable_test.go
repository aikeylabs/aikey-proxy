package proxy

// === Fences for TODO-178 — the ONE whitelisted variable in a canned answer ===
//
// 需求包: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// spec:   R-compliance-canned-answer-10 (代答文案支持唯一白名单变量 {{机密内容}}，
//         展开为「命中类别 + 打码片段」) — 取代 R-compliance-canned-answer-3 的
//         「一律不插值」那一句，其余部分不变。
// 用户拍板: 2026-09-20.
//
// ---------------------------------------------------------------------------
// 🔴 WHY THIS FILE CARRIES DIGITS WHEN ITS SIBLING FORBIDS THEM
//
// canned_answer_test.go's header says every synthetic value in it has "no run of
// 7+ digits". That convention cannot hold here and the deviation is deliberate:
// the reveal rule this file fences is GATED ON DIGIT COUNT (a fragment only ever
// shows characters when the value carries at least
// cannedAnswerMinDigitsToReveal digits), so a fence for it that used no digits
// would be testing the other branch and reporting green about the branch that
// matters. The values below are one-glance-fake ramps ("123400009876"), fail
// every checksum the detector applies, and never reach a real detector — they
// are stub input, and the only thing that ever slices them is the proxy's own
// hitValue.
//
// 🔴 THE ASSERTION THAT MATTERS MOST is the negative one: every case that
// constructs a hit also asserts the raw value is NOT a substring of the response
// body. A reveal rule that grew a bug would show up there first.
//
// ---------------------------------------------------------------------------
// 能红 (recorded in task-execution/runs/task-todo-178-report.md): with
// renderCannedAnswerText returning its input unchanged, every case below except
// the byte-identical one fails, naming the unexpanded `{{机密内容}}`.

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
)

// ---------------------------------------------------------------------------
// Test inputs. Every "sensitive" value is a one-glance-fake ramp.
// ---------------------------------------------------------------------------

const (
	// A 12-digit ramp standing in for a structured identifier. Enough digits to
	// cross cannedAnswerMinDigitsToReveal, so it exercises the reveal branch.
	fakeStructuredValue = "123400009876"
	// Free text in CJK — the branch that must NEVER reveal a character.
	fakeFreeTextValue = "张小明同学"
	// The admin sentence the user asked for on 2026-09-20, verbatim shape.
	answerWithVar = "该消息涉及机密，请修改后重新发出：{{机密内容}}"
)

// answerHitEvent builds the compliance event JSON a detector hands back for one
// piece, with one finding per (value, leafPath) pair. Offsets are computed from
// the piece text rather than hand-counted: they are BYTE offsets and the values
// sit behind multi-byte CJK, so a hand-written number would be wrong in a way
// that silently slices a different substring.
func answerHitEvent(t *testing.T, piece string, hits ...[2]string) []byte {
	t.Helper()
	findings := make([]map[string]any, 0, len(hits))
	for i, h := range hits {
		value, leafPath := h[0], h[1]
		start := strings.Index(piece, value)
		if start < 0 {
			t.Fatalf("answerHitEvent: %q is not in the piece text — the fixture is wrong", value)
		}
		level := 4
		findings = append(findings, map[string]any{
			"finding_id":   fmt.Sprintf("f-%d", i+1),
			"category":     "pii",
			"entity_type":  "SYNTHETIC_TEST_ENTITY",
			"severity":     "high",
			"confidence":   90,
			"start_offset": start,
			"end_offset":   start + len(value),
			"confirmed":    true,
			"level":        level,
			"leaf_path":    leafPath,
		})
	}
	ev := map[string]any{
		"event_id":      "det-answer-1",
		"scenario":      "todo-178",
		"action_taken":  "answer",
		"prompt_length": len(piece),
		"findings":      findings,
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("answerHitEvent: %v", err)
	}
	return b
}

// serveAnswer drives the real guardrail (applyInboundFilter) with an Answer
// verdict and returns the Anthropic non-streaming body the client would read.
func serveAnswer(t *testing.T, piece, answerText string, event []byte) string {
	t.Helper()
	hook := &stubHook{resp: &apphook.Response{
		Action:       apphook.ActionAnswer,
		AnswerText:   answerText,
		AnswerSource: "level",
		Event:        event,
	}}
	p := &Proxy{filterHook: hook}
	body, err := json.Marshal(map[string]any{
		"model":    "m",
		"messages": []any{map[string]any{"role": "user", "content": piece}},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	w := httptest.NewRecorder()
	if proceed := p.applyInboundFilter(w, newReq(string(body)), "m", "personal",
		"", "", "", "", "", discardLogger()); proceed {
		t.Fatal("an Answer verdict must short-circuit (proceed=false)")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

// answerTextOf pulls the single text field out of an Anthropic non-streaming
// canned answer.
func answerTextOf(t *testing.T, body string) string {
	t.Helper()
	var frame map[string]any
	if err := json.Unmarshal([]byte(body), &frame); err != nil {
		t.Fatalf("response is not JSON: %v\n%s", err, body)
	}
	v, ok := lookupJSONString(frame, "content.0.text")
	if !ok {
		t.Fatalf("no content.0.text in the response — this assertion is looking at nothing:\n%s", body)
	}
	return v
}

// ---------------------------------------------------------------------------
// R-compliance-canned-answer-10.S1 — the variable expands to 类别 + 打码片段.
// ---------------------------------------------------------------------------

func TestCannedAnswerVariable_ExpandsToCategoryAndMaskedFragment(t *testing.T) {
	piece := "客户 " + fakeFreeTextValue + " 的证件号 " + fakeStructuredValue + " 请核对"
	body := serveAnswer(t, piece, answerWithVar, answerHitEvent(t, piece,
		[2]string{fakeStructuredValue, "个人金融信息/C2 身份标识信息/身份证号"},
		[2]string{fakeFreeTextValue, "个人金融信息/C1 基本信息/客户姓名"},
	))
	text := answerTextOf(t, body)

	// 🔴 The red line first: no raw hit value may appear anywhere in the body.
	for _, raw := range []string{fakeStructuredValue, fakeFreeTextValue} {
		if strings.Contains(body, raw) {
			t.Fatalf("the response body carries the RAW hit value %q — 代答变成了原文回显通道:\n%s", raw, body)
		}
	}
	if strings.Contains(text, cannedAnswerConfidentialVar) {
		t.Errorf("the variable was not expanded; the user sees the raw token:\n%s", text)
	}
	// The administrator's own sentence is still there, unchanged around it.
	if !strings.HasPrefix(text, "该消息涉及机密，请修改后重新发出：") {
		t.Errorf("the administrator's sentence was altered:\n%s", text)
	}
	// 类别名 = the tenant's own leaf name; 片段 = 4 revealed digits each side.
	for _, want := range []string{"身份证号 1234****9876", "客户姓名"} {
		if !strings.Contains(text, want) {
			t.Errorf("expanded text is missing %q:\n%s", want, text)
		}
	}
	// Free text reveals NOTHING — not one character of the name.
	for _, r := range []string{"张", "小", "明", "同", "学"} {
		if strings.Contains(text, r) {
			t.Errorf("a character of the free-text hit (%q) leaked into the answer:\n%s", r, text)
		}
	}
}

// ---------------------------------------------------------------------------
// R-compliance-canned-answer-10.S2 — every OTHER {{...}} stays verbatim.
// ---------------------------------------------------------------------------

func TestCannedAnswerVariable_OtherPlaceholdersStayVerbatim(t *testing.T) {
	piece := "证件号 " + fakeStructuredValue
	ev := answerHitEvent(t, piece, [2]string{fakeStructuredValue, "个人金融信息/C2 身份标识信息/身份证号"})

	t.Run("mixed with the whitelisted one", func(t *testing.T) {
		admin := "请去掉 {{IDCARD_1}} 后重试。{{机密内容}}。其他变量 {{FOO}} {{机密内容 }} 也照原样。"
		text := answerTextOf(t, serveAnswer(t, piece, admin, ev))
		for _, keep := range []string{"{{IDCARD_1}}", "{{FOO}}", "{{机密内容 }}"} {
			if !strings.Contains(text, keep) {
				t.Errorf("%q must survive verbatim — only the exact token %q is whitelisted:\n%s",
					keep, cannedAnswerConfidentialVar, text)
			}
		}
		if strings.Contains(text, "："+cannedAnswerConfidentialVar) {
			t.Errorf("the whitelisted token was not expanded:\n%s", text)
		}
	})

	t.Run("no whitelisted variable at all — byte-identical", func(t *testing.T) {
		admin := "请去掉 {{IDCARD_1}} 后重试。"
		if got := answerTextOf(t, serveAnswer(t, piece, admin, ev)); got != admin {
			t.Errorf("a text WITHOUT the variable must reach the client byte for byte "+
				"(R-compliance-canned-answer-3.S1 unchanged)\n got %q\nwant %q", got, admin)
		}
	})
}

// ---------------------------------------------------------------------------
// R-compliance-canned-answer-10.S3 — caps: at most N hits, then 「等 N 处」.
// ---------------------------------------------------------------------------

func TestCannedAnswerVariable_TruncatesAtCap(t *testing.T) {
	var sb strings.Builder
	var hits [][2]string
	const total = 9
	for i := 0; i < total; i++ {
		v := fmt.Sprintf("12340000%04d", i) // 12 digits, distinct, obviously fake
		sb.WriteString("证件 " + v + " ")
		hits = append(hits, [2]string{v, "个人金融信息/C2 身份标识信息/身份证号"})
	}
	piece := sb.String()
	text := answerTextOf(t, serveAnswer(t, piece, answerWithVar, answerHitEvent(t, piece, hits...)))

	if got := strings.Count(text, "身份证号"); got != cannedAnswerMaxHits {
		t.Errorf("rendered %d hits, want the cap %d — 命中很多时不得把整段内容拼回去:\n%s",
			got, cannedAnswerMaxHits, text)
	}
	if want := fmt.Sprintf("等 %d 处", total); !strings.Contains(text, want) {
		t.Errorf("a truncated list must say how many there were in total (%q):\n%s", want, text)
	}
	for i := 0; i < total; i++ {
		if raw := fmt.Sprintf("12340000%04d", i); strings.Contains(text, raw) {
			t.Fatalf("raw value %q leaked:\n%s", raw, text)
		}
	}
}

// ---------------------------------------------------------------------------
// R-compliance-canned-answer-10.S4 — the audit row is untouched.
// ---------------------------------------------------------------------------

func TestCannedAnswerVariable_AuditRowUnchanged(t *testing.T) {
	piece := "证件号 " + fakeStructuredValue
	ev := answerHitEvent(t, piece, [2]string{fakeStructuredValue, "个人金融信息/C2 身份标识信息/身份证号"})

	upload := func(answerText string) string {
		evCh := make(chan string, 4)
		sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			evCh <- string(b)
			_, _ = w.Write([]byte(`{"accepted_ids":[]}`))
		}))
		defer sink.Close()
		rep, err := events.NewReporter(&events.ReporterConfig{
			CollectorRoutes:           map[string]string{"team": sink.URL},
			CollectorRouteCredentials: map[string]events.Credential{"team": &events.StaticTokenCredential{Token: "tk"}},
		})
		if err != nil {
			t.Fatalf("NewReporter: %v", err)
		}
		hook := &stubHook{resp: &apphook.Response{
			Action: apphook.ActionAnswer, AnswerText: answerText, AnswerSource: "level", Event: ev,
		}}
		p := &Proxy{filterHook: hook, reporter: rep}
		body, _ := json.Marshal(map[string]any{
			"model":    "m",
			"messages": []any{map[string]any{"role": "user", "content": piece}},
		})
		w := httptest.NewRecorder()
		p.applyInboundFilter(w, newReq(string(body)), "m", "team", "org-9", "vk-7", "seat-3", "sess-r", "trace-r",
			discardLogger())
		// The upload is async (observability.GoSafe); the shared helper turns a
		// missing envelope into a loud "<none>" instead of a hang.
		return waitForEnvelope(t, evCh)
	}

	withVar := upload(answerWithVar)
	withoutVar := upload("该消息涉及机密，请修改后重新发出。")
	if withVar != withoutVar {
		t.Errorf("the uploaded audit row changed when the variable was used — 审计行不得因此多出任何内容"+
			"或内容派生值\n with: %s\nwithout: %s", withVar, withoutVar)
	}
	if !strings.Contains(withVar, `"action_taken":"answer"`) {
		t.Errorf("the action must still be `answer`:\n%s", withVar)
	}
	// 🔴 The leaf path legitimately carries 「身份证号」 — it is the detector's own
	// field and predates this change. What must NOT appear is the raw value or the
	// rendered fragment: those are the content-derived things this feature makes.
	for _, leak := range []string{fakeStructuredValue, "1234****9876"} {
		if strings.Contains(withVar, leak) {
			t.Errorf("the rendered fragment (%q) reached the audit upload:\n%s", leak, withVar)
		}
	}
}

// ---------------------------------------------------------------------------
// The masking primitive itself.
// ---------------------------------------------------------------------------

func TestMaskHitFragment_NeverRevealsANonDigit(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"18-digit identifier reveals 4+4", "330100199001011234", "3301**********1234"},
		{"12-digit ramp", fakeStructuredValue, "1234****9876"},
		{"fewer than the digit floor stays fully masked", "13800138", "********"},
		{"cjk free text stays fully masked", "张小明同学", "*****"},
		{"ascii words stay fully masked", "project-orion", "*************"},
		{"email stays fully masked", "a.b@example.com", "***************"},
		{"separators inside a long number are never revealed", "6222 0000 0000 8888", "6222***********8888"},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := maskHitFragment(tc.in); got != tc.want {
				t.Errorf("maskHitFragment(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	t.Run("a very long value is capped", func(t *testing.T) {
		long := strings.Repeat("9", 400)
		got := maskHitFragment(long)
		if n := len([]rune(got)); n > cannedAnswerFragmentMaxRunes {
			t.Errorf("fragment is %d runes, cap is %d: %q", n, cannedAnswerFragmentMaxRunes, got)
		}
		if strings.Contains(long, got) {
			t.Errorf("the capped fragment %q is a substring of the original — that is not masking", got)
		}
	})
}

// ---------------------------------------------------------------------------
// English answers render English.
// ---------------------------------------------------------------------------

func TestCannedAnswerVariable_FollowsTheLanguageOfTheAdminSentence(t *testing.T) {
	piece := "id " + fakeStructuredValue
	ev := answerHitEvent(t, piece, [2]string{fakeStructuredValue, "Personal data/Identifiers/ID number"})
	text := answerTextOf(t, serveAnswer(t,
		piece, "This message contains confidential data. Please edit and resend: {{机密内容}}", ev))
	if !strings.Contains(text, "ID number 1234****9876") {
		t.Errorf("an English sentence must render an English list:\n%s", text)
	}
	if strings.ContainsAny(text, "、。") {
		t.Errorf("CJK punctuation leaked into an English answer:\n%s", text)
	}
}

// ---------------------------------------------------------------------------
// Fence — the token has exactly one spelling in the source.
// ---------------------------------------------------------------------------

// TestFence_ConfidentialVariableHasOneSpelling keeps the whitelist a whitelist.
// A second hand-written copy of the token is how "only one variable" becomes
// "two variables, one of which nobody fenced" — the concept must have ONE outlet
// (principles/documented-contract-needs-enforcement.md).
func TestFence_ConfidentialVariableHasOneSpelling(t *testing.T) {
	files := parseGuardrailPackage(t) // non-test sources only
	hits := 0
	for name, f := range files {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatalf("read %s: %v", f.path, err)
		}
		src := string(raw)
		if name != "canned_answer_variable.go" && strings.Contains(src, "机密内容") {
			t.Errorf("%s spells the whitelisted variable itself; it must reference "+
				"cannedAnswerConfidentialVar instead", name)
		}
		hits += strings.Count(src, `"{{机密内容}}"`)
	}
	if hits != 1 {
		t.Errorf("the token literal appears %d time(s) in non-test sources, want exactly 1 "+
			"(the cannedAnswerConfidentialVar declaration)", hits)
	}
}

// TestFence_CannedAnswerFragmentHasOneProducer derives, from the source, that
// every value ever stored in cannedAnswerHit.fragment comes out of
// maskHitFragment.
//
// WHY A SOURCE SCAN AND NOT A BEHAVIORAL CASE: the property is negative ("no
// fragment is ever built any other way"), and the next way to build one has not
// been written yet. A behavioral case can only speak about the paths that exist
// today; this one reddens the moment a second producer appears — which is the
// shape the 「写下来的合约必须驱动机器动作」 principle asks for, and the reason the
// red-line exemption in compliance_guardrail_response_fence_test.go is allowed to
// say "the fragments can only ever be masked output".
//
// Anti-vacuity: it fails if it finds zero assignments, because a scan that
// matches nothing passes forever.
func TestFence_CannedAnswerFragmentHasOneProducer(t *testing.T) {
	files := parseGuardrailPackage(t) // non-test sources only
	found := 0
	for name, f := range files {
		ast.Inspect(f.syntax, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.CompositeLit:
				id, ok := v.Type.(*ast.Ident)
				if !ok || id.Name != "cannedAnswerHit" {
					return true
				}
				for _, elt := range v.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, _ := kv.Key.(*ast.Ident)
					if key == nil || key.Name != "fragment" {
						continue
					}
					found++
					if !isCallTo(kv.Value, "maskHitFragment") {
						t.Errorf("%s:%s builds a cannedAnswerHit.fragment from %q — every fragment "+
							"must come out of maskHitFragment, the one masking outlet. A second "+
							"producer is how an unmasked value reaches the user.",
							name, f.fset.Position(kv.Value.Pos()), exprString(kv.Value))
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range v.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "fragment" || i >= len(v.Rhs) {
						continue
					}
					found++
					if !isCallTo(v.Rhs[i], "maskHitFragment") {
						t.Errorf("%s:%s assigns .fragment from %q — see above.",
							name, f.fset.Position(v.Rhs[i].Pos()), exprString(v.Rhs[i]))
					}
				}
			}
			return true
		})
	}
	if found == 0 {
		t.Fatal("no cannedAnswerHit.fragment assignment found — this fence is looking at nothing. " +
			"Fix the derivation in the same change that moved the code; do not delete the assertion.")
	}
}

func isCallTo(e ast.Expr, name string) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == name
}
