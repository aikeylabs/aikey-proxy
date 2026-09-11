package openai_responses

import (
	"context"
	"testing"

	"github.com/tidwall/gjson"
)

// The fixtures below are byte-shaped after aikey-mock-provider's
// openAIResponses / writeOpenAIStream handlers
// (aikey-mock-provider/internal/server/server.go), which is the resident stand-in
// for chatgpt.com/backend-api/codex in the OAuth pool E2Es. Keeping the two in
// the same shape is what makes a green unit test predictive of the live path;
// an invented fixture would only prove the translator agrees with itself.

func mustConvertResponse(t *testing.T, body string) gjson.Result {
	t.Helper()
	out, tErr := ConvertNonStreamResponse(context.Background(), []byte(body))
	if tErr != nil {
		t.Fatalf("ConvertNonStreamResponse returned %v", tErr)
	}
	if !gjson.ValidBytes(out) {
		t.Fatalf("produced invalid JSON: %s", out)
	}
	return gjson.ParseBytes(out)
}

// TestResponse_MockProviderShape is the happy path against the exact body the
// resident mock emits.
func TestResponse_MockProviderShape(t *testing.T) {
	got := mustConvertResponse(t, `{
		"id":"resp_abc","object":"response","status":"completed","model":"gpt-5.4",
		"output":[{"type":"message","role":"assistant","content":[
			{"type":"output_text","text":"hello from mock"}]}],
		"usage":{"input_tokens":11,"output_tokens":7,"total_tokens":18}}`)

	if got.Get("object").String() != "chat.completion" {
		t.Errorf("object = %q, want chat.completion", got.Get("object").String())
	}
	if c := got.Get("choices.0.message.content").String(); c != "hello from mock" {
		t.Errorf("content = %q", c)
	}
	if r := got.Get("choices.0.message.role").String(); r != "assistant" {
		t.Errorf("role = %q, want assistant", r)
	}
	if fr := got.Get("choices.0.finish_reason").String(); fr != "stop" {
		t.Errorf("finish_reason = %q, want stop", fr)
	}
	if got.Get("usage.prompt_tokens").Int() != 11 || got.Get("usage.completion_tokens").Int() != 7 {
		t.Errorf("usage was not renamed: %s", got.Get("usage").Raw)
	}
	if got.Get("usage.total_tokens").Int() != 18 {
		t.Errorf("total_tokens = %d, want 18", got.Get("usage.total_tokens").Int())
	}
	if id := got.Get("id").String(); id != "chatcmpl-abc" {
		t.Errorf("id = %q, want chatcmpl-abc (traceable back to the upstream resp_ id)", id)
	}
	if got.Get("created").Int() <= 0 {
		t.Error("created must be a positive unix timestamp; some SDKs fail to deserialize zero")
	}
}

// TestResponse_ToolCallFinishReason is the fence for the defect that would be
// invisible in a chat UI and fatal in an agent: a turn ending in a tool call is
// reported by the upstream as status=completed, but a Chat Completions client
// keys its loop on finish_reason=="tool_calls". Reporting "stop" ends the loop
// with the tool never run — the request looks entirely successful.
func TestResponse_ToolCallFinishReason(t *testing.T) {
	got := mustConvertResponse(t, `{
		"id":"resp_t","status":"completed","model":"m",
		"output":[
			{"type":"function_call","call_id":"call_9","name":"get_weather","arguments":"{\"city\":\"SF\"}"}
		]}`)

	if fr := got.Get("choices.0.finish_reason").String(); fr != "tool_calls" {
		t.Fatalf("finish_reason = %q, want tool_calls — an agent client stops looping on anything else", fr)
	}
	tc := got.Get("choices.0.message.tool_calls.0")
	if tc.Get("id").String() != "call_9" {
		t.Errorf("tool_calls[0].id = %q, want call_9", tc.Get("id").String())
	}
	if tc.Get("type").String() != "function" {
		t.Errorf("tool_calls[0].type = %q, want function", tc.Get("type").String())
	}
	if tc.Get("function.name").String() != "get_weather" {
		t.Errorf("tool_calls[0].function.name = %q", tc.Get("function.name").String())
	}
	if tc.Get("function.arguments").String() != `{"city":"SF"}` {
		t.Errorf("arguments = %q", tc.Get("function.arguments").String())
	}
	// content must be present-but-null on a tool-call turn: that is what the
	// OpenAI SDKs check before reading tool_calls.
	if !got.Get("choices.0.message.content").Exists() {
		t.Error("message.content key is absent; SDKs expect it present and null on a tool-call turn")
	}
}

// TestResponse_MixedTextAndToolCall — the model may narrate before calling.
func TestResponse_MixedTextAndToolCall(t *testing.T) {
	got := mustConvertResponse(t, `{
		"id":"resp_m","status":"completed","model":"m",
		"output":[
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"let me check"}]},
			{"type":"function_call","call_id":"c1","name":"f","arguments":"{}"}
		]}`)
	if got.Get("choices.0.message.content").String() != "let me check" {
		t.Errorf("narration lost: %q", got.Get("choices.0.message.content").String())
	}
	if got.Get("choices.0.finish_reason").String() != "tool_calls" {
		t.Error("finish_reason must still be tool_calls when the turn both narrates and calls")
	}
}

// TestResponse_TruncationBecomesLength — a caller that hit max_output_tokens
// must be able to tell, or it will treat a cut-off answer as a complete one.
func TestResponse_TruncationBecomesLength(t *testing.T) {
	got := mustConvertResponse(t, `{
		"id":"resp_i","status":"incomplete","model":"m",
		"incomplete_details":{"reason":"max_output_tokens"},
		"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"half an ans"}]}]}`)
	if fr := got.Get("choices.0.finish_reason").String(); fr != "length" {
		t.Errorf("finish_reason = %q, want length", fr)
	}
}

// TestResponse_ReasoningItemsAreNotLeaked — reasoning items carry the model's
// private chain of thought. There is no Chat Completions field for them and
// the caller did not ask for them.
func TestResponse_ReasoningItemsAreNotLeaked(t *testing.T) {
	got := mustConvertResponse(t, `{
		"id":"resp_r","status":"completed","model":"m",
		"output":[
			{"type":"reasoning","summary":[{"type":"summary_text","text":"SECRET-THOUGHT"}]},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]}
		]}`)
	if c := got.Get("choices.0.message.content").String(); c != "answer" {
		t.Errorf("content = %q, want just the answer", c)
	}
	if gjson.ParseBytes([]byte(got.Raw)).Get("choices.0.message.content").String() == "SECRET-THOUGHTanswer" {
		t.Fatal("reasoning text was folded into the visible answer")
	}
}

// TestResponse_ErrorBodyIsPassedThrough — folding an upstream error into an
// empty completion would render a failure as a successful blank answer.
func TestResponse_ErrorBodyIsPassedThrough(t *testing.T) {
	in := `{"error":{"message":"rate limited","type":"rate_limit_error"}}`
	out, tErr := ConvertNonStreamResponse(context.Background(), []byte(in))
	if tErr != nil {
		t.Fatal(tErr)
	}
	if string(out) != in {
		t.Errorf("error body was rewritten: %s", out)
	}
}

// TestResponse_MissingUsageStaysAbsent — reporting a confident zero where the
// upstream reported nothing is worse than reporting nothing.
func TestResponse_MissingUsageStaysAbsent(t *testing.T) {
	got := mustConvertResponse(t, `{"id":"resp_n","status":"completed","model":"m","output":[]}`)
	if got.Get("usage").Exists() {
		t.Errorf("usage was synthesized from nothing: %s", got.Get("usage").Raw)
	}
}

// TestResponse_MalformedUpstreamIsLoud
func TestResponse_MalformedUpstreamIsLoud(t *testing.T) {
	if _, tErr := ConvertNonStreamResponse(context.Background(), []byte(`{"id":`)); tErr == nil {
		t.Fatal("a malformed upstream body was accepted")
	}
}

// Every real Responses object carries `"error": null`, alongside other null keys.
// gjson's Exists() is true for an explicit null, so the error-envelope passthrough
// used to swallow every successful response untranslated (master2 staging
// 2026-09-11). The fixture keeps the real null keys on purpose.
func TestConvertNonStreamResponse_ExplicitNullErrorIsASuccessNotAnErrorEnvelope(t *testing.T) {
	in := `{"id":"resp_1","object":"response","created_at":1789104799,"status":"completed",` +
		`"error":null,"incomplete_details":null,"previous_response_id":null,"user":null,"moderation":null,` +
		`"model":"gpt-5.5","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],` +
		`"usage":{"input_tokens":18,"output_tokens":21,"total_tokens":39}}`
	out, tErr := ConvertNonStreamResponse(context.Background(), []byte(in))
	if tErr != nil {
		t.Fatalf("unexpected translate error: %+v", tErr)
	}
	if got := gjson.GetBytes(out, "object").String(); got != "chat.completion" {
		t.Fatalf("an explicit \"error\": null was treated as an error envelope; the body passed through untranslated:\n%s", out)
	}
	if got := gjson.GetBytes(out, "choices.0.message.content").String(); got != "ok" {
		t.Errorf("content = %q, want ok\n%s", got, out)
	}
	if got := gjson.GetBytes(out, "usage.prompt_tokens").Int(); got != 18 {
		t.Errorf("usage.prompt_tokens = %d, want 18", got)
	}
}
