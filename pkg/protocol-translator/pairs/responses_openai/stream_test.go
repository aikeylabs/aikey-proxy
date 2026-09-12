package responses_openai

import (
	"context"
	"strings"
	"testing"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// feed runs a whole upstream Chat Completions stream through ONE StreamState,
// the way a real response arrives. Testing chunks in isolation would miss the
// ordering contract, which is the entire difficulty of this direction.
func feed(t *testing.T, chunks ...string) []string {
	t.Helper()
	st := &translator.StreamState{}
	var out []string
	for _, c := range chunks {
		got, tErr := ConvertStreamChunk(context.Background(), st, []byte(c))
		if tErr != nil {
			t.Fatalf("ConvertStreamChunk(%s) returned %v", c, tErr)
		}
		for _, p := range got {
			out = append(out, string(p))
		}
	}
	return out
}

func types(payloads []string) []string {
	out := make([]string, 0, len(payloads))
	for _, p := range payloads {
		out = append(out, gjson.Get(p, "type").String())
	}
	return out
}

const (
	ccRole = `{"id":"chatcmpl-s","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`
	ccHel  = `{"id":"chatcmpl-s","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Hel"},"finish_reason":null}]}`
	ccLo   = `{"id":"chatcmpl-s","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":null}]}`
	ccStop = `{"id":"chatcmpl-s","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`
)

// TestStream_TextLifecycleOrder pins the lifecycle this direction has to
// SYNTHESIZE. Responses deltas are addressed to an item and a content part that
// must have been announced first; a client that receives a delta for an item it
// was never told about treats the stream as malformed.
func TestStream_TextLifecycleOrder(t *testing.T) {
	got := feed(t, ccRole, ccHel, ccLo, ccStop, "[DONE]")
	want := []string{
		"response.created",
		"response.in_progress",
		"response.output_item.added",
		"response.content_part.added",
		"response.output_text.delta",
		"response.output_text.delta",
		"response.output_text.done",
		"response.content_part.done",
		"response.output_item.done",
		"response.completed",
	}
	if strings.Join(types(got), ",") != strings.Join(want, ",") {
		t.Fatalf("lifecycle order wrong.\n got: %v\nwant: %v", types(got), want)
	}

	// Identity is repeated by Chat Completions on every chunk and stated ONCE
	// by Responses — it must survive into the opening frame.
	created := got[0]
	if gjson.Get(created, "response.id").String() != "resp_s" {
		t.Errorf("response.id = %q, want resp_s", gjson.Get(created, "response.id").String())
	}
	if gjson.Get(created, "response.model").String() != "gpt-4o" {
		t.Errorf("model lost: %s", created)
	}
	if gjson.Get(created, "response.created_at").Int() != 1700000000 {
		t.Errorf("created_at lost: %s", created)
	}
	if gjson.Get(created, "response.status").String() != "in_progress" {
		t.Errorf("opening status = %q, want in_progress", gjson.Get(created, "response.status").String())
	}

	// Deltas must address the item that was announced.
	itemID := gjson.Get(got[2], "item.id").String()
	if itemID == "" {
		t.Fatal("output_item.added carries no item id")
	}
	for _, i := range []int{4, 5} {
		if gjson.Get(got[i], "item_id").String() != itemID {
			t.Errorf("delta[%d] addresses %q, want the announced item %q",
				i, gjson.Get(got[i], "item_id").String(), itemID)
		}
	}
	if gjson.Get(got[6], "text").String() != "Hello" {
		t.Errorf("output_text.done text = %q, want the accumulated Hello", gjson.Get(got[6], "text").String())
	}
}

// TestStream_CompletedCarriesAssembledOutput — Chat Completions never sends a
// terminal snapshot, so this has to be built from the deltas. A client that
// ignored every delta must still be able to read the whole answer from the
// final frame, which is exactly what the non-streaming shape guarantees.
func TestStream_CompletedCarriesAssembledOutput(t *testing.T) {
	got := feed(t, ccRole, ccHel, ccLo, ccStop)
	final := got[len(got)-1]
	if gjson.Get(final, "type").String() != "response.completed" {
		t.Fatalf("last frame = %s", final)
	}
	if gjson.Get(final, "response.status").String() != "completed" {
		t.Errorf("final status = %q", gjson.Get(final, "response.status").String())
	}
	if gjson.Get(final, "response.output.0.content.0.text").String() != "Hello" {
		t.Fatalf("response.completed does not carry the assembled text:\n%s", final)
	}
	if gjson.Get(final, "response.output_text").String() != "Hello" {
		t.Errorf("response.completed lacks the flattened output_text: %s", final)
	}
	if gjson.Get(final, "response.usage.input_tokens").Int() != 5 ||
		gjson.Get(final, "response.usage.output_tokens").Int() != 2 {
		t.Errorf("usage did not survive onto the terminal frame: %s", final)
	}
}

// TestStream_DoneSentinelIsSwallowed — `[DONE]` is the Chat Completions
// terminator and is not part of the Responses wire format. Forwarding it hands
// a non-JSON line to a client that parses every data frame as JSON.
func TestStream_DoneSentinelIsSwallowed(t *testing.T) {
	got := feed(t, ccRole, ccHel, ccStop, "[DONE]")
	for _, p := range got {
		if strings.Contains(p, "[DONE]") {
			t.Fatalf("the Chat Completions terminator leaked into a Responses stream: %q", p)
		}
	}
	if gjson.Get(got[len(got)-1], "type").String() != "response.completed" {
		t.Errorf("stream does not end at response.completed: %s", got[len(got)-1])
	}
}

// TestStream_ToolCallLifecycle pins the second addressing scheme. Chat
// Completions correlates argument deltas by a dense tool index; Responses
// addresses them to an output item that counts ALL items, message included.
// Conflating the two sends the second tool's arguments to the first tool's item.
func TestStream_ToolCallLifecycle(t *testing.T) {
	got := feed(t,
		ccRole,
		ccHel, // a message item exists first, so output_index 0 is taken
		`{"id":"chatcmpl-s","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"alpha","arguments":""}}]},"finish_reason":null}]}`,
		`{"id":"chatcmpl-s","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"x\":"}}]},"finish_reason":null}]}`,
		`{"id":"chatcmpl-s","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"c2","type":"function","function":{"name":"beta","arguments":""}}]},"finish_reason":null}]}`,
		`{"id":"chatcmpl-s","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]},"finish_reason":null}]}`,
		`{"id":"chatcmpl-s","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
	)

	// The message took output_index 0; the two tools must take 1 and 2.
	var alphaItem, betaItem string
	var alphaIdx, betaIdx int64 = -1, -1
	for _, p := range got {
		if gjson.Get(p, "type").String() != "response.output_item.added" {
			continue
		}
		switch gjson.Get(p, "item.name").String() {
		case "alpha":
			alphaItem, alphaIdx = gjson.Get(p, "item.id").String(), gjson.Get(p, "output_index").Int()
		case "beta":
			betaItem, betaIdx = gjson.Get(p, "item.id").String(), gjson.Get(p, "output_index").Int()
		}
	}
	if alphaIdx != 1 || betaIdx != 2 {
		t.Fatalf("tool output_index = alpha:%d beta:%d, want 1 and 2 (index 0 is the message item)", alphaIdx, betaIdx)
	}
	if alphaItem == betaItem || alphaItem == "" {
		t.Fatalf("tool item ids not distinct: %q / %q", alphaItem, betaItem)
	}

	// Interleaved argument deltas must reassemble per item.
	args := map[string]string{}
	for _, p := range got {
		if gjson.Get(p, "type").String() == "response.function_call_arguments.delta" {
			args[gjson.Get(p, "item_id").String()] += gjson.Get(p, "delta").String()
		}
	}
	if args[alphaItem] != `{"x":1}` {
		t.Errorf("alpha arguments reassembled to %q, want {\"x\":1} — interleaved deltas mis-routed", args[alphaItem])
	}

	// Each tool closes, and the terminal frame carries both calls.
	final := got[len(got)-1]
	out := gjson.Get(final, "response.output").Array()
	if len(out) != 3 {
		t.Fatalf("response.completed carries %d output items, want 3:\n%s", len(out), final)
	}
	if gjson.Get(final, "response.output.1.arguments").String() != `{"x":1}` {
		t.Errorf("terminal frame lost the assembled arguments: %s", final)
	}
	if gjson.Get(final, "response.output.1.call_id").String() != "c1" {
		t.Errorf("call_id lost on the terminal frame: %s", final)
	}
}

// TestStream_LengthBecomesResponseIncomplete
func TestStream_LengthBecomesResponseIncomplete(t *testing.T) {
	got := feed(t, ccRole, ccHel,
		`{"id":"chatcmpl-s","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}`)
	final := got[len(got)-1]
	if gjson.Get(final, "type").String() != "response.incomplete" {
		t.Errorf("terminal event = %q, want response.incomplete", gjson.Get(final, "type").String())
	}
	if gjson.Get(final, "response.incomplete_details.reason").String() != "max_output_tokens" {
		t.Errorf("incomplete reason missing: %s", final)
	}
}

// TestStream_TrailingUsageOnlyChunkIsAbsorbed — with
// stream_options.include_usage some upstreams send usage on a chunk whose
// choices array is empty, AFTER the finish chunk.
func TestStream_TrailingUsageOnlyChunkIsAbsorbed(t *testing.T) {
	got := feed(t, ccRole, ccHel, ccStop,
		`{"id":"chatcmpl-s","created":1,"model":"m","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":9,"total_tokens":18}}`)
	// The stream already terminated; a late chunk must not emit a second
	// terminal frame.
	n := 0
	for _, p := range got {
		if strings.HasPrefix(gjson.Get(p, "type").String(), "response.completed") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("emitted %d terminal frames, want 1", n)
	}
}

func TestStream_MalformedFrameIsReported(t *testing.T) {
	st := &translator.StreamState{}
	if _, tErr := ConvertStreamChunk(context.Background(), st, []byte(`{bad`)); tErr == nil {
		t.Fatal("a malformed frame was accepted silently")
	}
}

// TestStream_StateIsPerResponse — reusing a StreamState would carry one
// response's id and item indices into the next.
func TestStream_StateIsPerResponse(t *testing.T) {
	a := feed(t, ccRole, ccHel, ccStop)
	b := feed(t, `{"id":"chatcmpl-OTHER","created":2,"model":"other","choices":[{"index":0,"delta":{"content":"x"},"finish_reason":null}]}`)
	if gjson.Get(a[0], "response.id").String() == gjson.Get(b[0], "response.id").String() {
		t.Fatal("two responses produced the same id")
	}
	if gjson.Get(b[0], "response.model").String() != "other" {
		t.Errorf("second stream reported model %q", gjson.Get(b[0], "response.model").String())
	}
}
