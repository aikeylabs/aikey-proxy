package apphook

// === Fence for task 3.12 — the 代答 text carrier, detector → proxy ===
//
// 需求包: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// spec (PROPOSAL layer, openspec/changes/add-compliance-grading-fusion/specs/
// compliance-canned-answer/spec.md):
//
//	R-compliance-canned-answer-1.S1  代答不产生任何上游请求 (端到端的 detector 半边)
//	R-compliance-canned-answer-2.S2  三级皆空 → 退回阻断而非放行
//
// ⚠️ Deliberately NOT written as `spec:` anchors — the rules still live in
// openspec/changes/…, not openspec/specs/. Same convention as
// internal/proxy/canned_answer_test.go.
//
// # What this fence is for
//
// Task 3.6 built the whole proxy-side answer (six protocol shapes, the dispatch
// branch, the degrade-to-block guard) and could not reach any of it: nothing
// carried the administrator's TEXT across the pipe. This fence is the carrier's
// only proof, and it drives a REAL ChildHook against a REAL child process over a
// REAL pipe — not decodeChildResponsePayload in isolation — because the hop that
// has gone missing eleven times in this codebase is not the decoder, it is the
// hand-written projection from the decoded frame onto the caller-facing
// Response (「手工搬运的中转层会静默吞字段」). A decoder test would stay green
// with that projection deleted.
//
// 🔴 NO REAL HIT SAMPLES. The "sensitive" tokens below are obviously synthetic.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/pipewire"
)

// carrierChildEnv switches the test binary into "be a detector" mode. The value
// is the exact byte string the child puts in the response Findings slot, so one
// spawned child serves every sub-case.
const carrierChildEnv = "AIKEY_APPHOOK_CARRIER_CHILD"

// carrierChildEvent is what the child returns in the EVENT slot — the team-routed
// audit record. It exists so the fence can prove the carrier did not steal or
// disturb the slot that actually travels to master (`Response.Findings` and the
// `findings` array INSIDE this event are 同名异物, and confusing them is what
// task 3.12 exists to prevent).
const carrierChildEvent = `{"event_id":"e-carrier-1","action_taken":"answer","findings":[]}`

// cannedAnswerGolden is the administrator's text in the shape a real one takes:
// non-ASCII, multi-line, and carrying a literal placeholder token that nothing
// in the pipeline may treat as a template.
const cannedAnswerGolden = "抱歉，这条内容命中了公司合规策略，无法发送给模型。\n" +
	"如需帮助请联系合规部门。占位语法示例：{{IDCARD_1}} 原样保留。"

// cannedAnswerWire renders the Findings-slot payload the detector writes for an
// ActionAnswer verdict, using the shared pipewire type both sides compile
// against.
//
// It is deliberately NOT a byte literal (TODO-85). The literal used to be pinned
// here and in ai-compliance-detector as a stand-in for a shared type; the type
// now exists, its bytes are pinned once in pkg/pipewire
// TestCannedAnswerWireBytes, and TestCannedAnswerContractIsPipewireAlias below
// keeps this package decoding with that type.
func cannedAnswerWire(t *testing.T, text, source string) string {
	t.Helper()
	wire, err := json.Marshal(pipewire.CannedAnswer{Text: text, Source: source})
	if err != nil {
		t.Fatalf("marshal canned answer: %v", err)
	}
	return string(wire)
}

// TestCannedAnswerContractIsPipewireAlias — the 代答 action byte and payload type
// are pkg/pipewire's; this package references them and must not re-spell them.
//
// Why a structural check for the constant: a local `ActionAnswer Action = 4` has
// the right value, so any value comparison stays green with the copy back in
// place. The re-spelling itself is what must go red.
func TestCannedAnswerContractIsPipewireAlias(t *testing.T) {
	if reflect.TypeOf(wireCannedAnswer{}) != reflect.TypeOf(pipewire.CannedAnswer{}) {
		t.Errorf("wireCannedAnswer is %v, not an alias of pipewire.CannedAnswer — a local "+
			"struct copy is exactly the hand-copied mirror whose JSON tags drift unseen",
			reflect.TypeOf(wireCannedAnswer{}))
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var decls []string
	for _, entry := range entries {
		file := entry.Name()
		if !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, decl := range parsed.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, ident := range vs.Names {
					if ident.Name != "ActionAnswer" {
						continue
					}
					pos := fset.Position(ident.Pos()).String()
					decls = append(decls, pos)
					if i >= len(vs.Values) || !selectsPipewireActionAnswer(vs.Values[i]) {
						t.Errorf("ActionAnswer at %s does not reference pipewire.ActionAnswer — the "+
							"value must be referenced, never re-spelled as a literal", pos)
					}
				}
			}
		}
	}
	if len(decls) != 1 {
		t.Errorf("ActionAnswer declared %d times (%v), want exactly 1 referencing pipewire.ActionAnswer",
			len(decls), decls)
	}
}

func selectsPipewireActionAnswer(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "pipewire" && sel.Sel.Name == "ActionAnswer" {
			found = true
		}
		return !found
	})
	return found
}

// TestHelperCannedAnswerChild is not a test: it is the child process for
// TestCannedAnswerTextReachesProxy, re-executed from this same binary (the
// os/exec TestHelperProcess pattern, already used by detector_gate_test.go).
//
// It speaks the real protocol with the real codec, so the fence exercises the
// parent's reader goroutine, its request-id demux and its frame projection
// exactly as a detector would drive them.
//
// 🔴 STDOUT IS THE PIPE. It must never carry test-framework output, which is why
// the loop ends in os.Exit rather than returning into the framework's summary.
func TestHelperCannedAnswerChild(t *testing.T) {
	findings := os.Getenv(carrierChildEnv)
	if findings == "" {
		t.Skip("helper process; not a test")
	}
	// Ready sentinel goes to stderr — the parent scans for "ready" there.
	fmt.Fprintln(os.Stderr, "ready canned-answer-carrier-child")

	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	for {
		version, payload, err := pipewire.ReadFrame(in)
		if err != nil {
			os.Exit(0) // stdin closed: the parent shut us down
		}
		if version != pipewire.ProtocolVersion {
			os.Exit(1)
		}
		req, err := pipewire.DecodeRequest(payload)
		if err != nil || req.Op != pipewire.OpDetect {
			continue
		}
		// The prompt IS the payload to hand back, so one child serves every
		// sub-case. `unset` means "answer verdict with an empty Findings slot".
		body := []byte(req.Prompt)
		if req.Prompt == "unset" {
			body = nil
		}
		res := &pipewire.Response{
			ReqID:    req.ReqID,
			Action:   pipewire.ActionAnswer,
			Findings: body,
			Event:    []byte(carrierChildEvent),
		}
		if err := pipewire.WriteFrame(out, pipewire.EncodeResponse(res)); err != nil {
			os.Exit(1)
		}
	}
}

// TestCannedAnswerTextReachesProxy — the detector hands down an ActionAnswer
// verdict with the administrator's text in the Findings slot, and the proxy must
// end up holding that text and its source in the fields writeCannedAnswer reads.
//
// GIVEN 探测器判定为代答且已解析出文案 WHEN 经 pipe 送达 proxy
// THEN proxy 拿得到 answer_text 与 answer_source (验收 3.A14 前半)
func TestCannedAnswerTextReachesProxy(t *testing.T) {
	if uint8(ActionAnswer) != pipewire.ActionAnswer {
		t.Fatalf("ActionAnswer = %d, want pipewire.ActionAnswer (%d) — the child writes the raw "+
			"pipewire byte and the enum value travels the pipe unvalidated",
			uint8(ActionAnswer), pipewire.ActionAnswer)
	}
	goldenWire := cannedAnswerWire(t, cannedAnswerGolden, "level")

	h := NewChildHook(&ChildHookConfig{
		Name:         "canned-answer-carrier",
		BinaryPath:   os.Args[0],
		BinaryArgs:   []string{"-test.run", "^TestHelperCannedAnswerChild$"},
		ExtraEnv:     []string{carrierChildEnv + "=" + goldenWire},
		Timeout:      5 * time.Second,
		ReadyTimeout: 15 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("start carrier child: %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()

	// --- the case the feature exists for -------------------------------------
	t.Run("text_and_source_arrive", func(t *testing.T) {
		res := h.Detect(ctx, &Request{Payload: []byte(goldenWire)})
		if res.Degraded {
			t.Fatalf("child degraded: %s", res.Reason)
		}
		if res.Action != ActionAnswer {
			t.Fatalf("Action = %s, want answer", res.Action)
		}
		if res.AnswerText != cannedAnswerGolden {
			t.Errorf("AnswerText did not survive the pipe.\n got: %q\nwant: %q\n"+
				"An empty value here is the whole defect task 3.12 exists to fix: the proxy "+
				"degrades a configured 代答 to a hard 403 and the administrator sees no reason why.",
				res.AnswerText, cannedAnswerGolden)
		}
		if res.AnswerSource != "level" {
			t.Errorf("AnswerSource = %q, want \"level\" — the tier label is what tells an "+
				"administrator whether the sentence came from the rule they just edited or "+
				"from the org default they forgot about", res.AnswerSource)
		}
		// The carrier must not disturb the slot that actually goes to master.
		if string(res.Event) != carrierChildEvent {
			t.Errorf("Event slot changed: got %q, want %q — Response.Findings and the `findings` "+
				"array inside the event are 同名异物; the carrier must touch only the former",
				res.Event, carrierChildEvent)
		}
		if res.MutatedPayload != nil {
			t.Errorf("MutatedPayload = %q, want nil — the masked-payload meaning of the Findings "+
				"slot belongs to ActionMask only", res.MutatedPayload)
		}
	})

	// --- boundaries: every one of these must land on "no text", never on a
	// half-answer, because an empty 200 reads to the user as 「模型什么也没说」.
	for _, tc := range []struct {
		name, wire, wantText, wantSource string
	}{
		{"empty_findings_slot", "unset", "", ""},
		{"malformed_json", `{"answer_text":`, "", ""},
		{"not_an_object", `["answer_text"]`, "", ""},
		{"source_none_carries_no_text", cannedAnswerWire(t, "", "none"), "", "none"},
		{"non_ascii_and_emoji", cannedAnswerWire(t, "合规策略拒绝了这条请求 🚫 — “引号” и кириллица", "org"),
			"合规策略拒绝了这条请求 🚫 — “引号” и кириллица", "org"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := h.Detect(ctx, &Request{Payload: []byte(tc.wire)})
			if res.Degraded {
				t.Fatalf("child degraded: %s", res.Reason)
			}
			if res.Action != ActionAnswer {
				t.Fatalf("Action = %s, want answer", res.Action)
			}
			if res.AnswerText != tc.wantText {
				t.Errorf("AnswerText = %q, want %q", res.AnswerText, tc.wantText)
			}
			if res.AnswerSource != tc.wantSource {
				t.Errorf("AnswerSource = %q, want %q", res.AnswerSource, tc.wantSource)
			}
		})
	}

	// An administrator can paste a long refusal. The only hard bound is the
	// protocol's own payload cap, and the text must arrive byte-identical up to it.
	t.Run("oversized_text_survives", func(t *testing.T) {
		long := strings.Repeat("合规提示。Compliance notice. ", 900) // ~30 KB of UTF-8
		wire := cannedAnswerWire(t, long, "org")
		if len(wire) >= pipewire.MaxPayloadBytes {
			t.Fatalf("fixture %d bytes exceeds the protocol cap; shrink it", len(wire))
		}
		res := h.Detect(ctx, &Request{Payload: []byte(wire)})
		if res.AnswerText != long {
			t.Errorf("oversized text truncated: got %d bytes, want %d", len(res.AnswerText), len(long))
		}
	})
}
