package openai_responses

import (
	"context"
	"strings"
	"testing"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// feed runs a whole upstream event sequence through one StreamState — the way
// a real response arrives — and returns every emitted payload as a string.
// Testing chunk-at-a-time in isolation would miss the ordering contract, which
// is the part a Chat Completions consumer actually depends on.
func feed(t *testing.T, events ...string) []string {
	t.Helper()
	st := &translator.StreamState{}
	var out []string
	for _, e := range events {
		chunks, tErr := ConvertStreamChunk(context.Background(), st, []byte(e))
		if tErr != nil {
			t.Fatalf("ConvertStreamChunk(%s) returned %v", e, tErr)
		}
		for _, c := range chunks {
			out = append(out, string(c))
		}
	}
	return out
}

// The event bodies mirror aikey-mock-provider's writeOpenAIStream exactly.
const (
	evCreated   = `{"type":"response.created","response":{"id":"resp_s1","object":"response","status":"in_progress","model":"gpt-5.4"}}`
	evDeltaA    = `{"type":"response.output_text.delta","response_id":"resp_s1","delta":"Hel"}`
	evDeltaB    = `{"type":"response.output_text.delta","response_id":"resp_s1","delta":"lo"}`
	evCompleted = `{"type":"response.completed","response":{"id":"resp_s1","object":"response","status":"completed","model":"gpt-5.4","usage":{"input_tokens":5,"output_tokens":2,"total_tokens":7}}}`
)

// TestStream_TextSequenceOrdering pins the contract a Chat Completions
// consumer relies on: exactly one role delta first, content in order, exactly
// one chunk carrying a non-null finish_reason, exactly one [DONE].
func TestStream_TextSequenceOrdering(t *testing.T) {
	got := feed(t, evCreated, evDeltaA, evDeltaB, evCompleted, "[DONE]")

	if len(got) != 5 {
		t.Fatalf("emitted %d payloads, want 5 (role, 2 content, finish, DONE):\n%s",
			len(got), strings.Join(got, "\n"))
	}
	if r := gjson.Get(got[0], "choices.0.delta.role").String(); r != "assistant" {
		t.Errorf("payload[0] must be the role delta, got %s", got[0])
	}
	if c := gjson.Get(got[1], "choices.0.delta.content").String(); c != "Hel" {
		t.Errorf("payload[1] content = %q", c)
	}
	if c := gjson.Get(got[2], "choices.0.delta.content").String(); c != "lo" {
		t.Errorf("payload[2] content = %q", c)
	}

	fin := got[3]
	if fr := gjson.Get(fin, "choices.0.finish_reason").String(); fr != "stop" {
		t.Errorf("finish chunk finish_reason = %q, want stop", fr)
	}
	if gjson.Get(fin, "usage.prompt_tokens").Int() != 5 || gjson.Get(fin, "usage.completion_tokens").Int() != 2 {
		t.Errorf("usage missing from the closing chunk: %s", fin)
	}
	if got[4] != "[DONE]" {
		t.Errorf("last payload = %q, want [DONE]", got[4])
	}

	// Identity is stated once upstream and repeated on every chunk downstream.
	for i, c := range got[:4] {
		if gjson.Get(c, "object").String() != "chat.completion.chunk" {
			t.Errorf("payload[%d] object = %q", i, gjson.Get(c, "object").String())
		}
		if gjson.Get(c, "id").String() != "chatcmpl-s1" {
			t.Errorf("payload[%d] id = %q, want chatcmpl-s1", i, gjson.Get(c, "id").String())
		}
		if gjson.Get(c, "model").String() != "gpt-5.4" {
			t.Errorf("payload[%d] model = %q", i, gjson.Get(c, "model").String())
		}
		if gjson.Get(c, "created").Int() <= 0 {
			t.Errorf("payload[%d] created is not positive", i)
		}
	}
}

// TestStream_DuplicateDoneIsCollapsed — the upstream ends the stream with
// response.completed AND its own [DONE] (the mock does exactly this). Emitting
// two terminators makes SDKs that keep reading after the first one either hang
// or error.
func TestStream_DuplicateDoneIsCollapsed(t *testing.T) {
	got := feed(t, evCreated, evDeltaA, evCompleted, "[DONE]")
	n := 0
	for _, c := range got {
		if c == "[DONE]" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("emitted %d [DONE] terminators, want exactly 1:\n%s", n, strings.Join(got, "\n"))
	}
}

// TestStream_RoleDeltaSentEvenWithoutCreated — response.created is not
// guaranteed. Content deltas arriving before any role announcement read as a
// malformed stream to an SDK.
func TestStream_RoleDeltaSentEvenWithoutCreated(t *testing.T) {
	got := feed(t, evDeltaA)
	if len(got) < 2 {
		t.Fatalf("want a synthesized role delta before content, got %v", got)
	}
	if gjson.Get(got[0], "choices.0.delta.role").String() != "assistant" {
		t.Errorf("first payload is not the role delta: %s", got[0])
	}
}

// TestStream_ToolCallDeltas pins the indexing translation. Responses correlates
// tool arguments by opaque item id; Chat Completions correlates by a dense
// zero-based index over tool calls only. Getting this wrong concatenates two
// tools' arguments into one unparseable blob.
func TestStream_ToolCallDeltas(t *testing.T) {
	got := feed(t,
		evCreated,
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"it_A","type":"function_call","call_id":"call_A","name":"alpha"}}`,
		`{"type":"response.function_call_arguments.delta","item_id":"it_A","delta":"{\"x\":"}`,
		`{"type":"response.output_item.added","output_index":1,"item":{"id":"it_B","type":"function_call","call_id":"call_B","name":"beta"}}`,
		`{"type":"response.function_call_arguments.delta","item_id":"it_B","delta":"{\"y\":"}`,
		`{"type":"response.function_call_arguments.delta","item_id":"it_A","delta":"1}"}`,
		evCompleted,
	)

	var idxA, idxB int64 = -1, -1
	argsByIdx := map[int64]string{}
	for _, c := range got {
		tc := gjson.Get(c, "choices.0.delta.tool_calls.0")
		if !tc.Exists() {
			continue
		}
		i := tc.Get("index").Int()
		switch tc.Get("function.name").String() {
		case "alpha":
			idxA = i
		case "beta":
			idxB = i
		}
		argsByIdx[i] += tc.Get("function.arguments").String()
	}
	if idxA != 0 || idxB != 1 {
		t.Fatalf("tool indices = alpha:%d beta:%d, want 0 and 1 in first-seen order", idxA, idxB)
	}
	if argsByIdx[0] != `{"x":1}` {
		t.Errorf("index 0 arguments reassembled to %q, want {\"x\":1} — interleaved deltas were mis-routed", argsByIdx[0])
	}
	if argsByIdx[1] != `{"y":` {
		t.Errorf("index 1 arguments reassembled to %q", argsByIdx[1])
	}

	// A streamed tool call must close with finish_reason=tool_calls for the
	// same reason the non-stream leg must — the agent loop keys on it.
	last := got[len(got)-2]
	if fr := gjson.Get(last, "choices.0.finish_reason").String(); fr != "tool_calls" {
		t.Errorf("closing finish_reason = %q, want tool_calls", fr)
	}
}

// TestStream_UnknownEventsAreDropped — forwarding a Responses-shaped payload to
// a client parsing every data line as a chat.completion.chunk either throws or
// silently deserializes into an empty chunk counted as real content.
func TestStream_UnknownEventsAreDropped(t *testing.T) {
	got := feed(t,
		evCreated,
		`{"type":"response.content_part.added","part":{"type":"output_text","text":""}}`,
		`{"type":"response.output_text.done","text":"Hello"}`,
		`{"type":"response.reasoning_summary_text.delta","delta":"thinking"}`,
	)
	if len(got) != 1 {
		t.Fatalf("emitted %d payloads, want only the role delta:\n%s", len(got), strings.Join(got, "\n"))
	}
	for _, c := range got {
		if strings.Contains(c, "thinking") {
			t.Error("reasoning text leaked into the client stream")
		}
	}
}

// TestStream_TruncatedStreamReportsLength
func TestStream_TruncatedStreamReportsLength(t *testing.T) {
	got := feed(t, evCreated, evDeltaA,
		`{"type":"response.incomplete","response":{"id":"resp_s1","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}}`)
	fin := got[len(got)-2]
	if fr := gjson.Get(fin, "choices.0.finish_reason").String(); fr != "length" {
		t.Errorf("finish_reason = %q, want length", fr)
	}
	if got[len(got)-1] != "[DONE]" {
		t.Error("a truncated stream must still be terminated")
	}
}

// TestStream_MalformedFrameIsReported — the caller decides policy (drop + WARN),
// but the transform must not pretend the frame was fine.
func TestStream_MalformedFrameIsReported(t *testing.T) {
	st := &translator.StreamState{}
	if _, tErr := ConvertStreamChunk(context.Background(), st, []byte(`{malformed`)); tErr == nil {
		t.Fatal("a malformed SSE frame was accepted silently")
	}
}

// TestStream_StateIsPerResponse guards the one mistake that would cross-talk
// between concurrent users: reusing a StreamState would carry one response's id
// and tool indices into the next.
func TestStream_StateIsPerResponse(t *testing.T) {
	first := feed(t, evCreated, evDeltaA, evCompleted)
	second := feed(t,
		`{"type":"response.created","response":{"id":"resp_OTHER","model":"other-model"}}`,
		evDeltaB,
	)
	if gjson.Get(first[0], "id").String() == gjson.Get(second[0], "id").String() {
		t.Fatal("two responses produced the same chat completion id")
	}
	if gjson.Get(second[0], "model").String() != "other-model" {
		t.Errorf("second stream reported model %q", gjson.Get(second[0], "model").String())
	}
}
