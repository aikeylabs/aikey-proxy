// filter_restore_toolblock_test.go — the RESPONSE half of the 2026-08-10 方案②
// decision.
//
// # The rule, and why it had to change wording
//
// Spec 2026-06-04 关键不变量 says: "新增任何还原通道前，必须先确认该通道在请求侧可扫."
// That test — "is it SCANNED?" — was sufficient while scanning and masking were
// the same act. Since 方案② they are not: agent tool blocks ARE scanned, but at
// ceilingAudit, so a finding inside one is recorded and the bytes go out
// untouched.
//
// So if restore wrote an original into a `tool_use` argument the model echoed
// back, the chain would be:
//
//	turn N   : user prose masked  → {{ADDR_1}} forwarded
//	turn N   : model echoes {{ADDR_1}} inside tool_use.input.command
//	turn N   : restore swaps it to the ORIGINAL → client stores plaintext
//	turn N+1 : client replays that tool_use → scanned, audit event, NOT masked
//	           → the original reaches the upstream LLM in plaintext
//
// which is the S3 thinking-block leak with one extra log line. The operative
// test is therefore "是否可 MASK", and restoreSkipBlockTypes derives itself from
// blockScanPolicy so the two legs cannot drift apart.
package proxy

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/tidwall/gjson"
)

// TestRestoreSkip_DerivedFromBlockScanPolicy is the anti-drift fence: it feeds
// the derivation a SYNTHETIC policy so it proves the RULE, not today's table.
func TestRestoreSkip_DerivedFromBlockScanPolicy(t *testing.T) {
	reasoning := map[string]bool{"thinking": true}
	policy := map[string]blockScanRule{
		"text":       {ceiling: ceilingFull},
		"audit_only": {ceiling: ceilingAudit},
	}
	skip := buildRestoreSkipBlockTypes(reasoning, policy)

	if !skip["thinking"] {
		t.Error("reasoning blocks must stay skipped — they can never be scanned at all (signature)")
	}
	if !skip["audit_only"] {
		t.Error("a block type scanned at a ceiling BELOW full must be skipped by restore: it can be " +
			"recorded but never masked, so writing an original into it opens an un-maskable回流 channel")
	}
	if skip["text"] {
		t.Error("a ceilingFull block type must remain restorable — restore is the whole point of the " +
			"placeholder chain on the answer channel")
	}
	if skip["message"] {
		t.Error("the derivation must not skip types absent from the policy by default: this walker also " +
			"visits the response ROOT, whose type is \"message\". Skipping unknown types would silently " +
			"disable restore for the entire body.")
	}
}

// TestRestoreSkip_LiveSetCoversToolBlocks pins today's table against the rule.
func TestRestoreSkip_LiveSetCoversToolBlocks(t *testing.T) {
	skip := restoreSkipBlockTypes()
	for _, bt := range append([]string{"thinking", "redacted_thinking", "reasoning"}, toolBlockTypes...) {
		if !skip[bt] {
			t.Errorf("restore does not skip %q — every block type the request leg cannot MASK must be "+
				"skipped whole, or restore becomes a plaintext回流 channel (spec 2026-06-04 关键不变量)", bt)
		}
	}
	for _, bt := range []string{"text", "output_text", "message"} {
		if skip[bt] {
			t.Errorf("restore must NOT skip %q", bt)
		}
	}
}

// TestRestoreBody_ToolUseArgumentKeepsPlaceholder is the behavioral half: an
// end-to-end non-streaming response where the model echoed the placeholder into
// BOTH its answer text and a tool_use argument.
func TestRestoreBody_ToolUseArgumentKeepsPlaceholder(t *testing.T) {
	st := newMaskRestore()
	st.add("{{ADDR_1}}", "北京市朝阳区望京街1号")

	body := []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[
		{"type":"text","text":"I will use {{ADDR_1}} for the lookup."},
		{"type":"thinking","thinking":"the address is {{ADDR_1}}","signature":"sig"},
		{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"geocode {{ADDR_1}}"}}]}`)

	out := restoreMaskedResponseBody(context.WithValue(context.Background(), ctxKeyMaskRestore, st), body, discardLogger())

	answer := gjson.GetBytes(out, `content.0.text`).String()
	if !strings.Contains(answer, "北京市朝阳区望京街1号") {
		t.Fatalf("the ANSWER channel must still be restored (that is the sanctioned exception); got %q", answer)
	}
	thinking := gjson.GetBytes(out, `content.1.thinking`).String()
	if !strings.Contains(thinking, "{{ADDR_1}}") {
		t.Fatalf("S3 regression: the thinking block was restored; got %q", thinking)
	}
	cmd := gjson.GetBytes(out, `content.2.input.command`).String()
	if !strings.Contains(cmd, "{{ADDR_1}}") {
		t.Fatalf("🔴 restore wrote the ORIGINAL into a tool_use argument. The client stores that in its "+
			"history and replays it next turn, where the request leg scans it at ceilingAudit — recorded, "+
			"NOT masked — so the plaintext reaches the upstream LLM. This is the S3 chain with an extra log "+
			"line. Restore must skip every block type the request leg cannot MASK.\ngot: %q", cmd)
	}
}

// A tool_result the CLIENT is replaying must be left alone for the same reason.
func TestRestoreBody_ToolResultKeepsPlaceholder(t *testing.T) {
	st := newMaskRestore()
	st.add("{{ADDR_1}}", "北京市朝阳区望京街1号")
	body := []byte(`{"type":"message","content":[
		{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"found {{ADDR_1}}"}]}]}`)
	out := restoreMaskedResponseBody(context.WithValue(context.Background(), ctxKeyMaskRestore, st), body, discardLogger())
	if got := gjson.GetBytes(out, `content.0.content.0.text`).String(); !strings.Contains(got, "{{ADDR_1}}") {
		t.Fatalf("tool_result must keep the placeholder (un-maskable回流 channel); got %q", got)
	}
}

// TestSSERestore_ToolInputDeltaIsNotARestoreChannel: the streaming leg reaches
// the same conclusion structurally — it recognizes ONLY text_delta, so a
// tool_use argument streamed as input_json_delta passes through verbatim. Fenced
// so a future "let's also restore partial_json" cannot land quietly.
func TestSSERestore_ToolInputDeltaIsNotARestoreChannel(t *testing.T) {
	cases := map[string]string{
		"tool_use argument":      `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"{{ADDR_1}}\"}"}}`,
		"thinking (S3)":          `{"type":"content_block_delta","index":1,"delta":{"type":"thinking_delta","thinking":"{{ADDR_1}}"}}`,
		"signature":              `{"type":"content_block_delta","index":1,"delta":{"type":"signature_delta","signature":"abc"}}`,
		"answer text (restored)": `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"{{ADDR_1}}"}}`,
	}
	for name, payload := range cases {
		path := sseTextFieldPath([]byte(payload))
		want := ""
		if name == "answer text (restored)" {
			want = "delta.text"
		}
		if path != want {
			t.Errorf("%s: sseTextFieldPath=%q, want %q — only the ANSWER channel may be restored; a tool "+
				"argument or reasoning channel restored on the streaming leg reopens the same plaintext "+
				"回流 chain the non-streaming leg blocks", name, path, want)
		}
	}
}

// TestRestoreLegs_AgreeOnToolBlocks: the streaming and non-streaming legs must
// not disagree about a given block, or the same response differs between
// stream:true and stream:false (the parity bug reasoningTextFields documents).
func TestRestoreLegs_AgreeOnToolBlocks(t *testing.T) {
	for bt := range restoreSkipBlockTypes() {
		if bt == "text" || bt == "output_text" {
			t.Fatalf("%q must never be in the skip set — it is the answer channel both legs restore", bt)
		}
	}
	// The streaming leg's allow-list is `text_delta` only, i.e. the complement of
	// every skip entry by construction. Assert the one shape that could drift.
	if sseTextFieldPath([]byte(`{"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":"x"}}`)) != "" {
		t.Fatal("streaming leg accepted a tool-argument channel the non-streaming leg skips")
	}
}

// TestRestore_NoPlaceholderIssuedFromToolBlocks: end-to-end, an audit-capped
// piece must never contribute a placeholder in the first place — no mask, no
// restorable, nothing on the response leg to swap back.
func TestRestore_NoPlaceholderIssuedFromToolBlocks(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte("{{ADDR}}"),
		Restorables: []apphook.RestorableMask{{
			Token: "{{ADDR}}", NumberedPrefix: "{{ADDR_", NumberedSuffix: "}}",
			Spans: [][2]int{{0, 6}},
		}},
	}}
	p := &Proxy{filterHook: hook}
	r := newReq(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1",
		"content":[{"type":"text","text":"abcdef ghi"}]}]}]}`)
	if !p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", "", discardLogger()) {
		t.Fatal("audit-capped verdict must not fail the request")
	}
	if st := maskRestoreFromContext(r.Context()); st != nil {
		t.Fatalf("a tool block produced %d restorable placeholder(s). Capped pieces are never masked, so "+
			"they must never issue a placeholder either — an issued-but-never-substituted label would "+
			"corrupt the L3 fidelity ratio and could restore into unrelated text.", len(st.keys))
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(readReqBody(t, r)), &parsed); err != nil {
		t.Fatalf("forwarded body is not JSON: %v", err)
	}
}
