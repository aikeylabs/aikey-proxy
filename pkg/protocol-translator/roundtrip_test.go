package translator_test

import (
	"context"
	"testing"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	_ "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator/pairs/openai_responses"
	_ "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator/pairs/responses_openai"
	"github.com/tidwall/gjson"
)

// roundtrip_test.go — the two OpenAI-family pairs checked against EACH OTHER.
//
// Every other test in these packages asserts a mapping against a fixture, which
// proves the translator agrees with what its author believed. A round trip
// proves something the fixtures cannot: that the two directions agree about
// what each field MEANS. A field one side drops and the other never had is
// invisible to both fixture suites and shows up here as content that did not
// come back.
//
// The assertion is semantic equivalence, not byte equality. A round trip is
// lossy by construction in ways that do not matter — the Responses hop has no
// slot for a field's original spelling, ids get re-prefixed, `store:false` is
// injected on the way out — so this checks the things a caller would notice:
// the conversation, the tool calls and their correlation, the tools, and the
// sampling parameters.

const (
	fmtCC = translator.FormatOpenAI
	fmtR  = translator.FormatOpenAIResponses
)

// TestRoundTrip_ChatCompletionsRequestSurvivesBothHops sends a request through
// CC → Responses → CC and checks the conversation came back intact.
func TestRoundTrip_ChatCompletionsRequestSurvivesBothHops(t *testing.T) {
	original := `{
		"model":"gpt-4o",
		"messages":[
			{"role":"system","content":"be terse"},
			{"role":"user","content":"weather in SF?"},
			{"role":"assistant","content":"checking","tool_calls":[
				{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"SF\"}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"18C"},
			{"role":"user","content":"and tomorrow?"}
		],
		"tools":[{"type":"function","function":{
			"name":"get_weather","description":"look it up",
			"parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}}],
		"tool_choice":"auto",
		"max_tokens":256,
		"temperature":0.4,
		"top_p":0.9,
		"parallel_tool_calls":true
	}`

	reg := translator.DefaultRegistry()
	ctx := context.Background()

	viaResponses, tErr := reg.TranslateRequest(ctx, fmtCC, fmtR, "gpt-4o", []byte(original), false)
	if tErr != nil {
		t.Fatalf("CC → Responses: %v", tErr)
	}
	back, tErr := reg.TranslateRequest(ctx, fmtR, fmtCC, "gpt-4o", viaResponses, false)
	if tErr != nil {
		t.Fatalf("Responses → CC: %v", tErr)
	}
	got := gjson.ParseBytes(back)

	// ── the conversation ────────────────────────────────────────────────────
	msgs := got.Get("messages").Array()
	if len(msgs) != 5 {
		t.Fatalf("round trip produced %d messages, want the original 5:\n%s", len(msgs), got.Get("messages").Raw)
	}
	want := []struct{ role, content string }{
		{"system", "be terse"},
		{"user", "weather in SF?"},
		{"assistant", "checking"},
		{"tool", "18C"},
		{"user", "and tomorrow?"},
	}
	for i, w := range want {
		if msgs[i].Get("role").String() != w.role {
			t.Errorf("messages[%d].role = %q, want %q", i, msgs[i].Get("role").String(), w.role)
		}
		if msgs[i].Get("content").String() != w.content {
			t.Errorf("messages[%d].content = %q, want %q", i, msgs[i].Get("content").String(), w.content)
		}
	}

	// ── the tool call and its correlation ───────────────────────────────────
	call := msgs[2].Get("tool_calls.0")
	if call.Get("id").String() != "call_1" {
		t.Errorf("tool call id = %q, want call_1", call.Get("id").String())
	}
	if call.Get("function.name").String() != "get_weather" {
		t.Errorf("tool call name = %q", call.Get("function.name").String())
	}
	if call.Get("function.arguments").String() != `{"city":"SF"}` {
		t.Errorf("tool call arguments = %q", call.Get("function.arguments").String())
	}
	if msgs[3].Get("tool_call_id").String() != "call_1" {
		t.Errorf("tool result correlation lost: %q", msgs[3].Get("tool_call_id").String())
	}

	// ── the tool declaration ────────────────────────────────────────────────
	tool := got.Get("tools.0")
	if tool.Get("function.name").String() != "get_weather" {
		t.Errorf("tool declaration name lost: %s", tool.Raw)
	}
	if tool.Get("function.description").String() != "look it up" {
		t.Errorf("tool description lost: %s", tool.Raw)
	}
	if tool.Get("function.parameters.properties.city.type").String() != "string" {
		t.Errorf("tool schema lost: %s", tool.Raw)
	}
	if tool.Get("function.parameters.required.0").String() != "city" {
		t.Errorf("tool schema `required` lost: %s", tool.Raw)
	}
	if got.Get("tool_choice").String() != "auto" {
		t.Errorf("tool_choice = %q, want auto", got.Get("tool_choice").String())
	}

	// ── sampling parameters ─────────────────────────────────────────────────
	if got.Get("max_tokens").Int() != 256 {
		t.Errorf("max_tokens = %d, want 256 (it becomes max_output_tokens mid-trip)", got.Get("max_tokens").Int())
	}
	if got.Get("temperature").Float() != 0.4 || got.Get("top_p").Float() != 0.9 {
		t.Errorf("sampling params lost: %s", back)
	}
	if !got.Get("parallel_tool_calls").Bool() {
		t.Error("parallel_tool_calls lost")
	}
}

// TestRoundTrip_ParallelToolCallsKeepTheirGrouping is the round trip's sharpest
// case: the Responses hop SPLITS a parallel call into sibling items, and the
// return hop has to put them back on one assistant turn. Two turns coming back
// out of one going in is a conversation the caller never had.
func TestRoundTrip_ParallelToolCallsKeepTheirGrouping(t *testing.T) {
	original := `{"model":"m","messages":[
		{"role":"user","content":"both cities"},
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"a","type":"function","function":{"name":"w","arguments":"{\"c\":\"SF\"}"}},
			{"id":"b","type":"function","function":{"name":"w","arguments":"{\"c\":\"NY\"}"}}]},
		{"role":"tool","tool_call_id":"a","content":"18C"},
		{"role":"tool","tool_call_id":"b","content":"9C"}
	]}`

	reg := translator.DefaultRegistry()
	ctx := context.Background()
	mid, tErr := reg.TranslateRequest(ctx, fmtCC, fmtR, "m", []byte(original), false)
	if tErr != nil {
		t.Fatal(tErr)
	}
	back, tErr := reg.TranslateRequest(ctx, fmtR, fmtCC, "m", mid, false)
	if tErr != nil {
		t.Fatal(tErr)
	}

	msgs := gjson.ParseBytes(back).Get("messages").Array()
	if len(msgs) != 4 {
		t.Fatalf("round trip produced %d messages, want 4 — the two parallel calls must come back "+
			"on ONE assistant turn:\n%s", len(msgs), gjson.ParseBytes(back).Get("messages").Raw)
	}
	calls := msgs[1].Get("tool_calls").Array()
	if len(calls) != 2 {
		t.Fatalf("assistant turn carries %d calls, want 2", len(calls))
	}
	if calls[0].Get("id").String() != "a" || calls[1].Get("id").String() != "b" {
		t.Errorf("call order/ids changed: %s", msgs[1].Get("tool_calls").Raw)
	}
}

// TestRoundTrip_ResponsesResponseSurvivesBothHops is the response-side mirror:
// a Responses body translated to Chat Completions and back.
func TestRoundTrip_ResponsesResponseSurvivesBothHops(t *testing.T) {
	original := `{
		"id":"resp_abc","object":"response","created_at":1700000000,"model":"gpt-5-codex","status":"completed",
		"output":[
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"here you go"}]},
			{"type":"function_call","call_id":"call_9","name":"run","arguments":"{\"cmd\":\"ls\"}"}
		],
		"usage":{"input_tokens":12,"output_tokens":5,"total_tokens":17}}`

	reg := translator.DefaultRegistry()
	ctx := context.Background()

	// forward pair's response leg: Responses → Chat Completions
	asCC, tErr := reg.TranslateNonStream(ctx, fmtCC, fmtR, []byte(original))
	if tErr != nil {
		t.Fatalf("Responses → CC: %v", tErr)
	}
	// reverse pair's response leg: Chat Completions → Responses
	back, tErr := reg.TranslateNonStream(ctx, fmtR, fmtCC, asCC)
	if tErr != nil {
		t.Fatalf("CC → Responses: %v", tErr)
	}
	got := gjson.ParseBytes(back)

	if got.Get("status").String() != "completed" {
		t.Errorf("status = %q", got.Get("status").String())
	}
	if got.Get("output.0.content.0.text").String() != "here you go" {
		t.Errorf("assistant text lost: %s", got.Get("output").Raw)
	}
	if got.Get("output.1.type").String() != "function_call" {
		t.Fatalf("the function call did not survive: %s", got.Get("output").Raw)
	}
	if got.Get("output.1.call_id").String() != "call_9" {
		t.Errorf("call_id lost: %s", got.Get("output.1").Raw)
	}
	if got.Get("output.1.name").String() != "run" {
		t.Errorf("tool name lost: %s", got.Get("output.1").Raw)
	}
	if got.Get("output.1.arguments").String() != `{"cmd":"ls"}` {
		t.Errorf("tool arguments lost: %s", got.Get("output.1").Raw)
	}
	if got.Get("usage.input_tokens").Int() != 12 || got.Get("usage.output_tokens").Int() != 5 {
		t.Errorf("usage did not survive two renames: %s", got.Get("usage").Raw)
	}
	// The id is re-derived on each hop; it must still trace back to the original
	// suffix rather than becoming a fresh random one.
	if got.Get("id").String() != "resp_abc" {
		t.Errorf("id = %q, want resp_abc — traceability across both hops is lost", got.Get("id").String())
	}
}

// TestRoundTrip_TruncationSurvives — a cut-off answer must still read as cut
// off after two hops. This is the one status value a caller acts on.
func TestRoundTrip_TruncationSurvives(t *testing.T) {
	original := `{"id":"resp_t","model":"m","created_at":1,"status":"incomplete",
		"incomplete_details":{"reason":"max_output_tokens"},
		"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"half"}]}]}`

	reg := translator.DefaultRegistry()
	ctx := context.Background()
	asCC, tErr := reg.TranslateNonStream(ctx, fmtCC, fmtR, []byte(original))
	if tErr != nil {
		t.Fatal(tErr)
	}
	if fr := gjson.GetBytes(asCC, "choices.0.finish_reason").String(); fr != "length" {
		t.Fatalf("mid-trip finish_reason = %q, want length", fr)
	}
	back, tErr := reg.TranslateNonStream(ctx, fmtR, fmtCC, asCC)
	if tErr != nil {
		t.Fatal(tErr)
	}
	if s := gjson.GetBytes(back, "status").String(); s != "incomplete" {
		t.Errorf("status = %q, want incomplete — a truncated answer came back looking finished", s)
	}
	if r := gjson.GetBytes(back, "incomplete_details.reason").String(); r != "max_output_tokens" {
		t.Errorf("incomplete reason = %q", r)
	}
}
