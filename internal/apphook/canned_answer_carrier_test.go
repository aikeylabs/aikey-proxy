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
	"os"
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

// cannedAnswerGoldenWire is the EXACT byte string the detector writes into the
// Findings slot for an ActionAnswer verdict.
//
// 🔴 IT IS A LITERAL ON PURPOSE, AND IT IS PAIRED. ai-compliance-detector's
// cmd/detector/canned_answer_carrier_test.go pins the same bytes from the
// producing side. The two repositories cannot share a Go type (the shared wire
// package pkg/pipewire is a sibling repo and adding to it was ruled out of scope
// — see the report for task 3.12), so a byte-for-byte literal on each side is
// what stands in for the shared type: rename a JSON tag on either side and that
// side's own suite goes red.
const cannedAnswerGoldenWire = `{"answer_text":"抱歉，这条内容命中了公司合规策略，无法发送给模型。\n如需帮助请联系合规部门。占位语法示例：{{IDCARD_1}} 原样保留。","answer_source":"level"}`

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
			ReqID: req.ReqID,
			// 4 = ActionAnswer. Spelled as a literal because pkg/pipewire does
			// not name it (see cannedAnswerGoldenWire); apphook.ActionAnswer is
			// the authority and is asserted against it below.
			Action:   4,
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
	if uint8(ActionAnswer) != 4 {
		t.Fatalf("ActionAnswer = %d, want 4 — the child writes the raw byte 4 and "+
			"the enum value travels the pipe unvalidated; renumbering it reinterprets "+
			"every verdict in flight", uint8(ActionAnswer))
	}

	h := NewChildHook(&ChildHookConfig{
		Name:         "canned-answer-carrier",
		BinaryPath:   os.Args[0],
		BinaryArgs:   []string{"-test.run", "^TestHelperCannedAnswerChild$"},
		ExtraEnv:     []string{carrierChildEnv + "=" + cannedAnswerGoldenWire},
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
		res := h.Detect(ctx, &Request{Payload: []byte(cannedAnswerGoldenWire)})
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
		{"source_none_carries_no_text", `{"answer_text":"","answer_source":"none"}`, "", "none"},
		{"non_ascii_and_emoji", `{"answer_text":"合规策略拒绝了这条请求 🚫 — “引号” и кириллица","answer_source":"org"}`,
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
		wire, err := json.Marshal(map[string]string{"answer_text": long, "answer_source": "org"})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if len(wire) >= pipewire.MaxPayloadBytes {
			t.Fatalf("fixture %d bytes exceeds the protocol cap; shrink it", len(wire))
		}
		res := h.Detect(ctx, &Request{Payload: wire})
		if res.AnswerText != long {
			t.Errorf("oversized text truncated: got %d bytes, want %d", len(res.AnswerText), len(long))
		}
	})
}
