package responses_openai

import (
	"context"
	"testing"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

func mustConvert(t *testing.T, body, model string, stream bool) gjson.Result {
	t.Helper()
	out, tErr := ConvertRequest(context.Background(), model, []byte(body), stream)
	if tErr != nil {
		t.Fatalf("ConvertRequest returned %v", tErr)
	}
	if !gjson.ValidBytes(out) {
		t.Fatalf("produced invalid JSON: %s", out)
	}
	return gjson.ParseBytes(out)
}

// TestRequest_PreviousResponseIdIsRefused is the most important fence in this
// package.
//
// Responses keeps the conversation server-side; previous_response_id says
// "continue from the turn you still hold". A Chat Completions upstream holds
// nothing and cannot be told to fetch anything, so forwarding the request
// without that field produces a VALID request, a 200, and a fluent answer —
// written with only the current turn as context. Nothing anywhere surfaces that
// the rest of the conversation was dropped.
//
// If someone later "simplifies" this into a drop, this test is what says no.
func TestRequest_PreviousResponseIdIsRefused(t *testing.T) {
	_, tErr := ConvertRequest(context.Background(), "m",
		[]byte(`{"model":"m","previous_response_id":"resp_earlier","input":"and then?"}`), false)
	if tErr == nil {
		t.Fatal("previous_response_id was accepted; the upstream would answer without the conversation " +
			"it refers to, and the caller would never know")
	}
	if tErr.Param != "previous_response_id" {
		t.Errorf("refusal names %q, want previous_response_id", tErr.Param)
	}
	if tErr.HTTPStatus != 400 {
		t.Errorf("status = %d, want 400", tErr.HTTPStatus)
	}
}

func TestRequest_OtherStatefulParamsRefused(t *testing.T) {
	base := `{"model":"m","input":"hi"`
	for _, tc := range []struct{ name, extra, wantParam string }{
		{"include", `,"include":["reasoning.encrypted_content"]`, "include"},
		{"truncation auto", `,"truncation":"auto"`, "truncation"},
		{"structured output", `,"text":{"format":{"type":"json_schema","name":"x"}}`, "text.format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, tErr := ConvertRequest(context.Background(), "m", []byte(base+tc.extra+"}"), false)
			if tErr == nil {
				t.Fatalf("%s was accepted", tc.wantParam)
			}
			if tErr.Param != tc.wantParam {
				t.Errorf("refusal names %q, want %q", tErr.Param, tc.wantParam)
			}
		})
	}
}

// TestRequest_HarmlessStatefulFieldsPass — truncation:"disabled" and store are
// not behaviour changes for this turn, so refusing them would block callers who
// asked for nothing.
func TestRequest_HarmlessStatefulFieldsPass(t *testing.T) {
	if _, tErr := ConvertRequest(context.Background(), "m",
		[]byte(`{"model":"m","input":"hi","truncation":"disabled","store":false}`), false); tErr != nil {
		t.Fatalf("a request with only inert stateful fields was refused: %v", tErr)
	}
}

// TestRequest_InstructionsBecomeLeadingSystemMessage
func TestRequest_InstructionsBecomeLeadingSystemMessage(t *testing.T) {
	got := mustConvert(t, `{"model":"m","instructions":"be terse","input":"hi"}`, "m", false)
	msgs := got.Get("messages").Array()
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].Get("role").String() != "system" || msgs[0].Get("content").String() != "be terse" {
		t.Errorf("messages[0] = %s, want the system prompt first", msgs[0].Raw)
	}
	if msgs[1].Get("role").String() != "user" || msgs[1].Get("content").String() != "hi" {
		t.Errorf("messages[1] = %s", msgs[1].Raw)
	}
}

// TestRequest_ParallelToolCallsMergeIntoOneAssistantMessage pins the fold that
// the shape mismatch forces.
//
// Responses lists each call as its own sibling item. Chat Completions puts
// parallel calls in ONE assistant message's tool_calls array. Emitting one
// assistant message per call would present a single parallel call to the model
// as a multi-turn exchange it never had — and models condition on turn
// structure, so the next completion is drawn from a conversation that did not
// happen.
func TestRequest_ParallelToolCallsMergeIntoOneAssistantMessage(t *testing.T) {
	got := mustConvert(t, `{"model":"m","input":[
		{"role":"user","content":[{"type":"input_text","text":"weather in both"}]},
		{"type":"function_call","call_id":"c1","name":"w","arguments":"{\"city\":\"SF\"}"},
		{"type":"function_call","call_id":"c2","name":"w","arguments":"{\"city\":\"NY\"}"},
		{"type":"function_call_output","call_id":"c1","output":"18C"},
		{"type":"function_call_output","call_id":"c2","output":"9C"}
	]}`, "m", false)

	msgs := got.Get("messages").Array()
	if len(msgs) != 4 {
		t.Fatalf("got %d messages, want 4 (user, ONE assistant with both calls, two tool results):\n%s",
			len(msgs), got.Get("messages").Raw)
	}
	assistant := msgs[1]
	if assistant.Get("role").String() != "assistant" {
		t.Fatalf("messages[1].role = %q", assistant.Get("role").String())
	}
	calls := assistant.Get("tool_calls").Array()
	if len(calls) != 2 {
		t.Fatalf("assistant carries %d tool_calls, want both parallel calls on ONE message", len(calls))
	}
	if calls[0].Get("id").String() != "c1" || calls[1].Get("id").String() != "c2" {
		t.Errorf("tool call ids/order wrong: %s", assistant.Get("tool_calls").Raw)
	}
	if calls[0].Get("function.name").String() != "w" {
		t.Errorf("tool call not nested under `function`: %s", calls[0].Raw)
	}
	// content must be present-but-null on a tool-call-only turn.
	if !assistant.Get("content").Exists() {
		t.Error("assistant message omits `content`; SDKs and upstreams expect it present and null here")
	}
	if assistant.Get("content").Type != gjson.Null {
		t.Errorf("assistant content = %s, want null", assistant.Get("content").Raw)
	}

	for i, want := range []struct{ id, out string }{{"c1", "18C"}, {"c2", "9C"}} {
		m := msgs[2+i]
		if m.Get("role").String() != "tool" {
			t.Errorf("messages[%d].role = %q, want tool", 2+i, m.Get("role").String())
		}
		if m.Get("tool_call_id").String() != want.id {
			t.Errorf("messages[%d].tool_call_id = %q, want %q", 2+i, m.Get("tool_call_id").String(), want.id)
		}
		if m.Get("content").String() != want.out {
			t.Errorf("messages[%d].content = %q, want %q", 2+i, m.Get("content").String(), want.out)
		}
	}
}

// TestRequest_NarrationThenToolCallShareOneMessage — the model may narrate
// before calling; both belong to the same assistant turn.
func TestRequest_NarrationThenToolCallShareOneMessage(t *testing.T) {
	got := mustConvert(t, `{"model":"m","input":[
		{"role":"user","content":"go"},
		{"role":"assistant","content":[{"type":"output_text","text":"checking"}]},
		{"type":"function_call","call_id":"c1","name":"f","arguments":"{}"}
	]}`, "m", false)
	msgs := got.Get("messages").Array()
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2 (user + one assistant carrying text AND the call):\n%s",
			len(msgs), got.Get("messages").Raw)
	}
	if msgs[1].Get("content").String() != "checking" {
		t.Errorf("narration lost: %s", msgs[1].Raw)
	}
	if len(msgs[1].Get("tool_calls").Array()) != 1 {
		t.Errorf("the call did not attach to the narrating turn: %s", msgs[1].Raw)
	}
}

// TestRequest_TextOnlyContentIsAPlainString pins a compatibility decision, not
// a cosmetic one: a parts array is rejected by some of the older
// OpenAI-compatible relays this direction exists to reach.
func TestRequest_TextOnlyContentIsAPlainString(t *testing.T) {
	got := mustConvert(t, `{"model":"m","input":[
		{"role":"user","content":[{"type":"input_text","text":"a"},{"type":"input_text","text":"b"}]}
	]}`, "m", false)
	c := got.Get("messages.0.content")
	if c.Type != gjson.String {
		t.Fatalf("text-only content emitted as %s, want a plain string: %s", c.Type, c.Raw)
	}
	if c.String() != "a\nb" {
		t.Errorf("content = %q, want the parts joined", c.String())
	}
}

// TestRequest_ImageForcesPartsArray — the one case where the array is required.
func TestRequest_ImageForcesPartsArray(t *testing.T) {
	got := mustConvert(t, `{"model":"m","input":[
		{"role":"user","content":[
			{"type":"input_text","text":"what is this"},
			{"type":"input_image","image_url":"https://example.test/a.png"}]}
	]}`, "m", false)
	parts := got.Get("messages.0.content")
	if !parts.IsArray() {
		t.Fatalf("multimodal content collapsed to a string, losing the image: %s", parts.Raw)
	}
	if parts.Array()[1].Get("image_url.url").String() != "https://example.test/a.png" {
		t.Errorf("image url not re-nested under image_url.url: %s", parts.Raw)
	}
}

// TestRequest_ToolsAreReNested — the mirror of the forward pair's flattening.
func TestRequest_ToolsAreReNested(t *testing.T) {
	got := mustConvert(t, `{"model":"m","input":"x","tools":[
		{"type":"function","name":"f","description":"d","parameters":{"type":"object"}}],
		"tool_choice":{"type":"function","name":"f"}}`, "m", false)
	tool := got.Get("tools.0")
	if tool.Get("function.name").String() != "f" {
		t.Errorf("tool name not nested under `function`: %s", tool.Raw)
	}
	if tool.Get("name").Exists() {
		t.Errorf("tool still carries a flat `name`: %s", tool.Raw)
	}
	if tool.Get("function.parameters.type").String() != "object" {
		t.Errorf("schema lost: %s", tool.Raw)
	}
	if got.Get("tool_choice.function.name").String() != "f" {
		t.Errorf("tool_choice not re-nested: %s", got.Get("tool_choice").Raw)
	}
}

// TestRequest_ServerSideToolsAreRefused — web_search and friends run INSIDE the
// Responses API. A Chat Completions upstream cannot run them, and answering
// without the search the caller asked for is the silent-wrong-answer failure.
func TestRequest_ServerSideToolsAreRefused(t *testing.T) {
	_, tErr := ConvertRequest(context.Background(), "m",
		[]byte(`{"model":"m","input":"x","tools":[{"type":"web_search_preview"}]}`), false)
	if tErr == nil {
		t.Fatal("a server-side Responses tool was silently dropped")
	}
	if tErr.Param != "tools" {
		t.Errorf("refusal names %q, want tools", tErr.Param)
	}
}

func TestRequest_SamplingParamsAndReasoningEffort(t *testing.T) {
	got := mustConvert(t, `{"model":"m","input":"x","max_output_tokens":64,
		"temperature":0.3,"top_p":0.8,"parallel_tool_calls":true,"reasoning":{"effort":"high"}}`, "m", true)
	if got.Get("max_tokens").Int() != 64 {
		t.Errorf("max_output_tokens did not become max_tokens: %s", got.Raw)
	}
	if got.Get("max_output_tokens").Exists() {
		t.Error("the Responses spelling survived into the Chat Completions body")
	}
	if got.Get("temperature").Float() != 0.3 || got.Get("top_p").Float() != 0.8 {
		t.Errorf("sampling params lost: %s", got.Raw)
	}
	if !got.Get("parallel_tool_calls").Bool() {
		t.Error("parallel_tool_calls lost")
	}
	if got.Get("reasoning_effort").String() != "high" {
		t.Errorf("reasoning.effort did not map to reasoning_effort: %s", got.Raw)
	}
	if !got.Get("stream").Bool() {
		t.Error("stream flag lost")
	}
}

func TestRequest_EmptyRequestIsRefused(t *testing.T) {
	if _, tErr := ConvertRequest(context.Background(), "m", []byte(`{"model":"m"}`), false); tErr == nil {
		t.Fatal("a request with neither instructions nor input was accepted")
	}
	if _, tErr := ConvertRequest(context.Background(), "m", []byte(`{"model":`), false); tErr == nil {
		t.Fatal("malformed JSON was accepted")
	}
}

func TestRequest_PairIsRegistered(t *testing.T) {
	reg := translator.DefaultRegistry()
	if !reg.HasPair(translator.FormatOpenAIResponses, translator.FormatOpenAI) {
		t.Fatal("openai-responses → openai request pair is not registered")
	}
	if !reg.HasStreamPair(translator.FormatOpenAIResponses, translator.FormatOpenAI) {
		t.Fatal("stream transform is not registered")
	}
	// The response side of THIS pair emits Responses frames, which are named.
	name := reg.StreamEventName(translator.FormatOpenAIResponses, translator.FormatOpenAI,
		[]byte(`{"type":"response.created"}`))
	if name != "response.created" {
		t.Fatalf("StreamEventName = %q, want response.created — a client using per-event "+
			"listeners receives nothing without the name", name)
	}
	// The forward pair emits Chat Completions frames, which are unnamed.
	if n := reg.StreamEventName(translator.FormatOpenAI, translator.FormatOpenAIResponses,
		[]byte(`{"object":"chat.completion.chunk"}`)); n != "" {
		t.Errorf("forward pair reported an event name %q; Chat Completions streams unnamed frames", n)
	}
}
