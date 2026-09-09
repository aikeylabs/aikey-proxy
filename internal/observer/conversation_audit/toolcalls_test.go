package conversation_audit

// toolcalls_test.go — P13 leg A fences.
//
// 🔴 These drive the REAL extractor over frame fixtures written from each
// published wire format. What they cannot prove is that a real client emits
// exactly these bytes — that is the live-stack acceptance (13.A1–13.A4), and it
// has not been run. Both facts are stated in toolcalls.go's header so the next
// reader learns it from the code rather than from a report.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// feed runs a sequence of frames through the accumulator the way OnSSEEvent
// does — 🔴 through extractFrame, so the test exercises the SAME single
// traversal production uses rather than calling the per-protocol readers
// directly.
func feed(family string, frames ...string) *toolCallAcc {
	acc := newToolCallAcc()
	for _, f := range frames {
		_, tools := extractFrame(family, "", []byte(f), len(acc.order))
		for _, tf := range tools {
			acc.observe(tf)
		}
	}
	return acc
}

// ---------------------------------------------------------------------------
// 13.F1 / R-conversation-tool-visibility-1 — the calls must appear
// ---------------------------------------------------------------------------

// TestFence_13F1_ATurnRequestingTwoToolsRecordsTwo is the spec's headline
// scenario, with the number written out.
//
// 🔴 The count is 2, not "non-empty". A turn where the model asked for two
// tools and the audit shows one is the failure this feature exists to prevent,
// and only an exact number catches it.
func TestFence_13F1_ATurnRequestingTwoToolsRecordsTwo(t *testing.T) {
	acc := feed(protoAnthropic,
		`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me look."}}`,
		`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_a","name":"query_readonly"}}`,
		`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"sql\":\"SELECT 1\"}"}}`,
		`{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_b","name":"create_issue"}}`,
		`{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"title\":\"x\"}"}}`,
		`{"type":"message_stop"}`,
	)
	got := acc.result()
	if len(got) != 2 {
		t.Fatalf("a turn that requested 2 tools recorded %d — an audit that undercounts tool "+
			"calls is worse than one that has none, because it reads as complete: %+v", len(got), got)
	}
	if got[0].ToolName != "query_readonly" || got[1].ToolName != "create_issue" {
		t.Errorf("names or ORDER wrong: %q then %q. The order is a fact an auditor reads.",
			got[0].ToolName, got[1].ToolName)
	}
	if got[0].ToolCallID != "toolu_a" {
		t.Errorf("tool_call_id = %q; it is the only thing that links this request to its "+
			"result in a later turn", got[0].ToolCallID)
	}
}

// TestArgumentsAreSummarisedAndTheRawFormIsNeverCaptured is R-4 and its
// fail-safe scenario in one.
//
// 🔴 The gate that would permit raw arguments does not exist yet. This asserts
// the fail-safe DIRECTION, not merely today's value: "cannot read the gate"
// resolves to closed.
func TestArgumentsAreSummarisedAndTheRawFormIsNeverCaptured(t *testing.T) {
	acc := feed(protoAnthropic,
		`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"run_sql"}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"sql\":\"SELECT * FROM salaries\","}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\"limit\":10}"}}`,
	)
	got := acc.result()
	if len(got) != 1 {
		t.Fatalf("want 1 call, got %d", len(got))
	}
	if got[0].ArgsRaw != nil {
		t.Fatalf("🔴 raw arguments were captured (%s). They are SQL, file contents and "+
			"sometimes credentials; the switch that permits them follows the MCP raw-arguments "+
			"gate (R16) and does not exist yet. Cannot read the gate ⇒ the gate is shut.",
			string(got[0].ArgsRaw))
	}
	digest := got[0].ArgsDigest
	if len(digest) != 2 {
		t.Fatalf("want 2 digest entries (sql, limit), got %d: %+v", len(digest), digest)
	}
	// Sorted by key, so `limit` precedes `sql`.
	if digest[0].Key != "limit" || digest[1].Key != "sql" {
		t.Errorf("digest keys/order = %+v; sorting by key is what makes two identical calls "+
			"produce identical digests", digest)
	}
	if digest[1].Type != "string" {
		t.Errorf("sql should be summarised as a string, got %q", digest[1].Type)
	}
	// 🔴 The VALUE must not survive anywhere in the digest.
	blob, _ := json.Marshal(got[0])
	if strings.Contains(string(blob), "salaries") {
		t.Errorf("🔴 an argument VALUE leaked into the serialised tool call: %s", blob)
	}
}

// TestAnUnnamedToolUseBlockIsCountedNotSwallowed — task 13.6.
func TestAnUnnamedToolUseBlockIsCountedNotSwallowed(t *testing.T) {
	acc := feed(protoAnthropic,
		`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1"}}`,
	)
	if acc.unnamed != 1 {
		t.Fatalf("🔴 a tool_use block with no readable name was silently dropped. "+
			"'We could not parse it' and 'this turn made no tool calls' are opposite facts, "+
			"and only the second one is safe to render. unnamed=%d", acc.unnamed)
	}
}

// TestEveryCallStartsPendingNotLinked — leg A captures the model's REQUEST; it
// has performed no join, so claiming `linked` would assert something nobody
// checked.
func TestEveryCallStartsPendingNotLinked(t *testing.T) {
	acc := feed(protoAnthropic,
		`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"x"}}`)
	got := acc.result()
	if got[0].LinkState != mcpwire.LinkStatePending {
		t.Errorf("link_state = %q, want %q — leg A performs no join, so any other value "+
			"claims a verdict nobody reached", got[0].LinkState, mcpwire.LinkStatePending)
	}
}

// ---------------------------------------------------------------------------
// the other wire formats
// ---------------------------------------------------------------------------

func TestOpenAIChatCompletionsToolCallsAreExtracted(t *testing.T) {
	acc := feed(protoOpenAI,
		`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"get_weather","arguments":"{\"city\":"}}]}}]}`,
		`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Berlin\"}"}}]}}]}`,
	)
	got := acc.result()
	if len(got) != 1 || got[0].ToolName != "get_weather" || got[0].ToolCallID != "call_1" {
		t.Fatalf("chat-completions tool call not extracted: %+v", got)
	}
	if len(got[0].ArgsDigest) != 1 || got[0].ArgsDigest[0].Key != "city" {
		t.Errorf("arguments did not accumulate across chunks: %+v", got[0].ArgsDigest)
	}
}

// 🔴 Two calls in ONE delta frame. The format permits it, and reading only the
// first entry is the silent-undercount bug in its most likely form.
func TestOpenAIChatCompletionsCarriesEveryToolCallInAFrame(t *testing.T) {
	acc := feed(protoOpenAI,
		`{"choices":[{"delta":{"tool_calls":[`+
			`{"index":0,"id":"call_1","function":{"name":"a","arguments":"{}"}},`+
			`{"index":1,"id":"call_2","function":{"name":"b","arguments":"{}"}}]}}]}`,
	)
	if got := acc.result(); len(got) != 2 {
		t.Fatalf("🔴 a frame carrying two tool calls recorded %d. Reading only the first entry "+
			"is exactly the undercount this feature exists to prevent: %+v", len(got), got)
	}
}

func TestOpenAIResponsesAPIToolCallsAreExtracted(t *testing.T) {
	acc := feed(protoOpenAI,
		`{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"call_9","name":"shell"}}`,
		`{"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"cmd\":\"ls\"}"}`,
	)
	got := acc.result()
	if len(got) != 1 || got[0].ToolName != "shell" || got[0].ToolCallID != "call_9" {
		t.Fatalf("🔴 the Responses API tool call was missed: %+v.\n"+
			"Missing this wire format silently dropped every Codex turn from the audit once "+
			"already (2026-07-07); the same omission here would drop every Codex tool call.", got)
	}
}

func TestGeminiFunctionCallsAreExtracted(t *testing.T) {
	acc := feed(protoGemini,
		`{"candidates":[{"content":{"parts":[{"functionCall":{"name":"lookup","args":{"q":"x"}}}]}}]}`,
		`{"candidates":[{"content":{"parts":[{"functionCall":{"name":"second","args":{}}}]}}]}`,
	)
	got := acc.result()
	if len(got) != 2 {
		t.Fatalf("gemini function calls: want 2, got %d (%+v)", len(got), got)
	}
	if got[0].ToolName != "lookup" || got[1].ToolName != "second" {
		t.Errorf("names/order wrong: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// 13.F6 — the existing text behaviour is untouched
// ---------------------------------------------------------------------------

// TestFence_13F6_TextExtractionIsUnchangedByToolCapture.
//
// 🔴 The whole leg-A change runs inside the traversal that already produced
// `assistant_text`, which is a shipped, load-bearing behaviour. This asserts
// the two do not interfere: a frame carrying text still yields exactly that
// text, and a frame carrying a tool call yields NO text (rather than, say, the
// argument bytes leaking into the transcript).
func TestFence_13F6_TextExtractionIsUnchangedByToolCapture(t *testing.T) {
	for _, tc := range []struct {
		name, family, frame, wantText string
	}{
		{"anthropic text", protoAnthropic,
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}`, "hello"},
		{"anthropic tool args carry no text", protoAnthropic,
			`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"a\":1}"}}`, ""},
		{"anthropic tool start carries no text", protoAnthropic,
			`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t","name":"n"}}`, ""},
		{"openai text", protoOpenAI,
			`{"choices":[{"delta":{"content":"hi"}}]}`, "hi"},
		{"openai tool call carries no text", protoOpenAI,
			`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c","function":{"name":"n","arguments":"{}"}}]}}]}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractAssistantDelta(tc.family, "", []byte(tc.frame)); got != tc.wantText {
				t.Errorf("assistant text = %q, want %q — 🔴 tool capture must not change what "+
					"lands in the transcript", got, tc.wantText)
			}
		})
	}
}

// TestAFrameCarryingBothTextAndAToolCallYieldsBoth.
//
// 🔴 Written because a drill exposed a hole in the fence, not the product. The
// "does the tool branch swallow the text" mutations could not go red: every
// fixture here had frames that were EITHER text OR a tool call, so a mutation
// that skipped the text probe whenever a tool signal was present changed
// nothing observable.
//
// The Chat Completions schema permits one delta to carry `content` AND
// `tool_calls`. Models usually split them, which is exactly why nobody would
// notice the day one does not — and the turn would lose its text.
func TestAFrameCarryingBothTextAndAToolCallYieldsBoth(t *testing.T) {
	frame := `{"choices":[{"delta":{"content":"thinking…","tool_calls":[` +
		`{"index":0,"id":"call_1","function":{"name":"peek","arguments":"{}"}}]}}]}`
	text, tools := extractFrame(protoOpenAI, "", []byte(frame), 0)
	if text != "thinking…" {
		t.Errorf("🔴 the text was lost from a frame that also carried a tool call: %q. "+
			"The two are independent fields and one must not consume the other.", text)
	}
	if len(tools) != 1 {
		t.Errorf("the tool call was lost from a frame that also carried text: %+v", tools)
	}
}

// TestAFrameWithNoToolSignalProducesNoCall keeps the common path honest: the
// overwhelming majority of frames carry nothing, and a reader that invents an
// entry for them would fill every audit with phantom calls.
func TestAFrameWithNoToolSignalProducesNoCall(t *testing.T) {
	acc := feed(protoAnthropic,
		`{"type":"message_start","message":{"id":"m"}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`,
		`{"type":"message_delta","usage":{"output_tokens":3}}`,
		`{"type":"message_stop"}`,
	)
	got := acc.result()
	if len(got) != 0 {
		t.Errorf("a text-only turn produced %d tool calls: %+v", len(got), got)
	}
	// 🔴 EMPTY, not nil. On the wire `[]` means "a proxy that collects tool
	// calls looked and found none"; absent means "this node does not collect
	// them". Returning nil here would collapse the two and let the console
	// report "no tool calls" for a turn nobody examined (task 13.8).
	if got == nil {
		t.Error("result() returned nil for a captured turn; that is indistinguishable " +
			"downstream from a proxy that does not support tool-call capture at all")
	}
}
