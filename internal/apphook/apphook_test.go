package apphook

import "testing"

// TestUnknownAction_TreatedAsBlock pins the FAIL-CLOSED direction for an action
// value this proxy build does not recognize.
//
// spec (PROPOSAL layer, 需求包 roadmap20260320/技术实现/阶段9-商业化版本/
// 博时基金合规能力融合/openspec/changes/add-compliance-grading-fusion/specs/
// compliance-canned-answer/spec.md):
//
//	R-compliance-canned-answer-6   proxy 收到无法识别的动作值时 SHALL 按 ActionBlock
//	                               处理（fail-safe），SHALL NOT 按放行处理
//	R-compliance-canned-answer-6.S1 老 proxy 遇到代答动作按阻断处理
//
// ⚠️ WHY THIS REVERSES THE PREVIOUS POSTURE — read before "simplifying" it back.
// Until 2026-09-13 an unrecognized action fell into applyInboundFilter's
// `default:` and was forwarded as a degraded fail-open (see the 2026-06-22
// regression note that used to live on TestApplyInboundFilter_UnknownAction_
// FailsLoudDegraded). That is the right posture for a detector that could not
// ANSWER (§6 #11: a child that times out or crashes must not block traffic —
// those paths return an explicit ActionAllow + Degraded, and are untouched by
// this test). It is the wrong posture for a detector that answered with a
// verdict we cannot read: the action value is a policy the master handed down,
// so "I do not recognize it" means either this proxy is older than the policy or
// the policy was tampered with. Neither is a reason to forward the content.
//
// This is the apphook half of the assertion — the enum-level contract every
// consumer derives from. The observable half (403 COMPLIANCE_BLOCKED, zero
// upstream requests) is asserted in
// internal/proxy: TestApplyInboundFilter_UnknownAction_FailsClosedBlocked.
func TestUnknownAction_TreatedAsBlock(t *testing.T) {
	// Every value outside the defined set, not just one sample: the failure this
	// guards is "a policy from a NEWER master carries an action this build never
	// heard of", and which byte that is depends on how the enum grows next.
	known := map[Action]bool{
		ActionAllow: true, ActionMask: true, ActionBlock: true,
		ActionWarn: true, ActionAnswer: true,
	}
	for v := 0; v <= 255; v++ {
		a := Action(v)
		if known[a] {
			if !a.Recognized() {
				t.Errorf("Action(%d) is a defined value but Recognized() = false", v)
			}
			if got := NormalizeAction(a); got != a {
				t.Errorf("NormalizeAction(Action(%d)) = %v, want it unchanged", v, got)
			}
			continue
		}
		if a.Recognized() {
			t.Errorf("Action(%d) is outside the defined set but Recognized() = true", v)
		}
		if got := NormalizeAction(a); got != ActionBlock {
			t.Errorf("NormalizeAction(Action(%d)) = %v, want ActionBlock (fail-CLOSED). "+
				"Allow here means a version skew silently switches the compliance policy off.", v, got)
		}
		if got := NormalizeAction(a); got == ActionAllow {
			t.Errorf("Action(%d) normalized to Allow — R-compliance-canned-answer-6 forbids it", v)
		}
	}
}

// TestActionAnswer_EnumAndString pins the new rung of the action enum: the value
// itself and its wire/log spelling, which the audit record's `action_taken`
// column and the DB CHECK constraint (task 5.1) both use verbatim.
func TestActionAnswer_EnumAndString(t *testing.T) {
	if ActionAnswer != 4 {
		t.Errorf("ActionAnswer = %d, want 4 (appended after ActionWarn=3; renumbering "+
			"an existing rung would reinterpret every action byte already on the pipe)", ActionAnswer)
	}
	want := map[Action]string{
		ActionAllow: "allow", ActionMask: "mask", ActionBlock: "block",
		ActionWarn: "warn", ActionAnswer: "answer", Action(200): "unknown",
	}
	for a, s := range want {
		if got := a.String(); got != s {
			t.Errorf("Action(%d).String() = %q, want %q", a, got, s)
		}
	}
}

// TestSupportsCannedAnswer_TrueOnceWriterLanded pins the honesty of the
// capability declaration: this build both KNOWS the answer action (it is in the
// enum, above) and can SYNTHESIZE the response.
//
// The declaration is what the detector reads to decide whether to hand down
// `answer` at all ("探测器仅在为真时下发代答；为假时下发 ActionBlock",
// design.md §4b). Declaring a capability we cannot serve is the exact failure
// R-compliance-canned-answer-6 exists to prevent, from the other side — and so
// is the mirror image, refusing to declare one we CAN serve, which leaves an
// administrator's configured canned answer coming out as a hard block forever.
//
// 🔴 THIS TEST IS AN INVERSION, NOT A NEW TEST. Until 2026-09-13 it stood here
// as TestSupportsCannedAnswer_FalseUntilWriterLands and asserted the opposite.
// Task 3.5 added the enum rung and left the writer for 3.6, so `false` was the
// truthful value then; task 3.6 landed internal/proxy/canned_answer.go
// (writeCannedAnswer — three protocol families × streaming/non-streaming) and
// the `case ActionAnswer` dispatch branch, so `true` is the truthful value now.
// 3.5 handed the inversion over explicitly and the controller signed it off in
// the 3.6 dispatch. The test is kept rather than deleted because what it really
// guards is "the declaration matches the build", in whichever direction that
// currently points.
//
// ⚠️ WHAT IT DOES NOT ASSERT: that the end-to-end feature works. The detector
// still has no way to READ this bit (TODO-68) and nothing carries the resolved
// text back to the proxy (Response.AnswerText's NO PRODUCER YET note). Both are
// cross-boundary contracts outside 3.6's scope. A green here means this binary
// can serve a canned answer, not that one has ever been served.
func TestSupportsCannedAnswer_TrueOnceWriterLanded(t *testing.T) {
	if !SupportsCannedAnswer() {
		t.Fatal("SupportsCannedAnswer() = false, but this build DOES have writeCannedAnswer " +
			"(internal/proxy/canned_answer.go, task 3.6). A build that can serve a canned " +
			"answer and says it cannot leaves every configured 代答 coming out as a hard " +
			"block. If the writer was removed, invert this assertion in the SAME change — " +
			"do not delete it.")
	}
}
