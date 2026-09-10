package responses_openai

import (
	"context"
	"testing"

	"github.com/tidwall/gjson"
)

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

func TestResponse_TextAnswer(t *testing.T) {
	got := mustConvertResponse(t, `{
		"id":"chatcmpl-abc","object":"chat.completion","created":1700000000,"model":"m",
		"choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],
		"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`)

	if got.Get("object").String() != "response" {
		t.Errorf("object = %q, want response", got.Get("object").String())
	}
	if got.Get("status").String() != "completed" {
		t.Errorf("status = %q, want completed", got.Get("status").String())
	}
	if got.Get("id").String() != "resp_abc" {
		t.Errorf("id = %q, want resp_abc (traceable to the upstream chatcmpl- id)", got.Get("id").String())
	}
	if got.Get("created_at").Int() != 1700000000 {
		t.Errorf("created_at = %d", got.Get("created_at").Int())
	}
	item := got.Get("output.0")
	if item.Get("type").String() != "message" || item.Get("role").String() != "assistant" {
		t.Errorf("output[0] = %s", item.Raw)
	}
	if item.Get("content.0.type").String() != "output_text" || item.Get("content.0.text").String() != "hello" {
		t.Errorf("content part = %s", item.Get("content").Raw)
	}
	if !item.Get("content.0.annotations").IsArray() {
		t.Error("annotations must be an array, not absent/null — SDKs range over it")
	}
	// The flattened convenience field the SDKs expose as response.output_text.
	if got.Get("output_text").String() != "hello" {
		t.Errorf("output_text = %q; a client reading only that field would see nothing",
			got.Get("output_text").String())
	}
	if got.Get("usage.input_tokens").Int() != 5 || got.Get("usage.output_tokens").Int() != 2 {
		t.Errorf("usage not renamed: %s", got.Get("usage").Raw)
	}
}

// TestResponse_ToolCallsBecomeSiblingItems pins the unfold: one Chat
// Completions message carrying content + tool_calls becomes SEVERAL Responses
// output items, in order.
func TestResponse_ToolCallsBecomeSiblingItems(t *testing.T) {
	got := mustConvertResponse(t, `{
		"id":"chatcmpl-t","object":"chat.completion","created":1,"model":"m",
		"choices":[{"index":0,"message":{"role":"assistant","content":"checking",
			"tool_calls":[
				{"id":"c1","type":"function","function":{"name":"a","arguments":"{\"x\":1}"}},
				{"id":"c2","type":"function","function":{"name":"b","arguments":"{}"}}]},
			"finish_reason":"tool_calls"}]}`)

	items := got.Get("output").Array()
	if len(items) != 3 {
		t.Fatalf("output has %d items, want 3 (message + two function_calls):\n%s", len(items), got.Get("output").Raw)
	}
	if items[0].Get("type").String() != "message" {
		t.Errorf("items[0].type = %q", items[0].Get("type").String())
	}
	for i, want := range []struct{ callID, name string }{{"c1", "a"}, {"c2", "b"}} {
		it := items[1+i]
		if it.Get("type").String() != "function_call" {
			t.Errorf("items[%d].type = %q, want function_call", 1+i, it.Get("type").String())
		}
		if it.Get("call_id").String() != want.callID || it.Get("name").String() != want.name {
			t.Errorf("items[%d] = %s", 1+i, it.Raw)
		}
		// item id and call_id are DIFFERENT correlations: streamed argument
		// deltas address the item, the eventual tool result addresses the call.
		if it.Get("id").String() == it.Get("call_id").String() {
			t.Errorf("items[%d] conflates item id with call_id: %s", 1+i, it.Raw)
		}
	}
	// A tool-call turn is `completed` in Responses; the caller detects the call
	// by finding a function_call item, not by reading the status.
	if got.Get("status").String() != "completed" {
		t.Errorf("status = %q, want completed", got.Get("status").String())
	}
}

// TestResponse_LengthBecomesIncomplete — a client reading only `status` would
// otherwise treat a cut-off answer as a finished one.
func TestResponse_LengthBecomesIncomplete(t *testing.T) {
	got := mustConvertResponse(t, `{"id":"chatcmpl-l","model":"m","created":1,
		"choices":[{"index":0,"message":{"role":"assistant","content":"half"},"finish_reason":"length"}]}`)
	if got.Get("status").String() != "incomplete" {
		t.Fatalf("status = %q, want incomplete", got.Get("status").String())
	}
	if got.Get("incomplete_details.reason").String() != "max_output_tokens" {
		t.Errorf("incomplete_details.reason = %q", got.Get("incomplete_details.reason").String())
	}
}

func TestResponse_ErrorBodyIsPassedThrough(t *testing.T) {
	in := `{"error":{"message":"boom","type":"server_error"}}`
	out, tErr := ConvertNonStreamResponse(context.Background(), []byte(in))
	if tErr != nil {
		t.Fatal(tErr)
	}
	if string(out) != in {
		t.Errorf("error body was rewritten: %s", out)
	}
}

func TestResponse_MissingUsageStaysAbsent(t *testing.T) {
	got := mustConvertResponse(t, `{"id":"chatcmpl-n","model":"m","created":1,
		"choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}]}`)
	if got.Get("usage").Exists() {
		t.Errorf("usage synthesized from nothing: %s", got.Get("usage").Raw)
	}
	if !got.Get("output").IsArray() {
		t.Error("output must always be an array")
	}
}

func TestResponse_MalformedUpstreamIsLoud(t *testing.T) {
	if _, tErr := ConvertNonStreamResponse(context.Background(), []byte(`{"id":`)); tErr == nil {
		t.Fatal("a malformed upstream body was accepted")
	}
}
