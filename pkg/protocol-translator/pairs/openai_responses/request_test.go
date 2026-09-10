package openai_responses

import (
	"context"
	"encoding/json"
	"testing"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

func mustConvert(t *testing.T, body string, model string, stream bool) gjson.Result {
	t.Helper()
	out, tErr := ConvertRequest(context.Background(), model, []byte(body), stream)
	if tErr != nil {
		t.Fatalf("ConvertRequest returned %v", tErr)
	}
	if !gjson.ValidBytes(out) {
		t.Fatalf("ConvertRequest produced invalid JSON: %s", out)
	}
	return gjson.ParseBytes(out)
}

// TestRequest_SystemBecomesInstructions pins the mapping that has no field
// rename equivalent: the Responses API rejects a system role inside input[].
func TestRequest_SystemBecomesInstructions(t *testing.T) {
	got := mustConvert(t, `{
		"model":"gpt-5.4",
		"messages":[
			{"role":"system","content":"be terse"},
			{"role":"user","content":"hi"}
		]}`, "gpt-5.4", false)

	if got.Get("instructions").String() != "be terse" {
		t.Errorf("instructions = %q, want %q", got.Get("instructions").String(), "be terse")
	}
	if n := len(got.Get("input").Array()); n != 1 {
		t.Fatalf("input has %d items, want 1 (the system turn must not appear there)", n)
	}
	item := got.Get("input.0")
	if item.Get("role").String() != "user" {
		t.Errorf("input[0].role = %q, want user", item.Get("role").String())
	}
	if pt := item.Get("content.0.type").String(); pt != "input_text" {
		t.Errorf("user content part type = %q, want input_text", pt)
	}
}

// TestRequest_MultipleSystemMessagesAreAllKept guards the "last one wins"
// shortcut: agent harnesses emit a base prompt plus per-turn addenda, and
// dropping the earlier ones silently removes instructions the caller relies on.
func TestRequest_MultipleSystemMessagesAreAllKept(t *testing.T) {
	got := mustConvert(t, `{"model":"m","messages":[
		{"role":"system","content":"rule one"},
		{"role":"developer","content":"rule two"},
		{"role":"user","content":"go"}
	]}`, "m", false)

	want := "rule one\n\nrule two"
	if got.Get("instructions").String() != want {
		t.Errorf("instructions = %q, want %q", got.Get("instructions").String(), want)
	}
}

// TestRequest_AssistantTurnUsesOutputText pins the role-dependent content tag.
// Sending input_text for an assistant turn is rejected upstream, so a single
// shared tag would break every multi-turn conversation.
func TestRequest_AssistantTurnUsesOutputText(t *testing.T) {
	got := mustConvert(t, `{"model":"m","messages":[
		{"role":"user","content":"a"},
		{"role":"assistant","content":"b"},
		{"role":"user","content":"c"}
	]}`, "m", false)

	if pt := got.Get("input.1.content.0.type").String(); pt != "output_text" {
		t.Errorf("assistant content part type = %q, want output_text", pt)
	}
	if pt := got.Get("input.0.content.0.type").String(); pt != "input_text" {
		t.Errorf("user content part type = %q, want input_text", pt)
	}
}

// TestRequest_ToolCallRoundTrip covers the half that makes agent loops work:
// the assistant's tool call and the tool's result become sibling input items,
// correlated by call_id. Without it the model sees its own call with no result
// and calls the tool again.
func TestRequest_ToolCallRoundTrip(t *testing.T) {
	got := mustConvert(t, `{"model":"m","messages":[
		{"role":"user","content":"weather?"},
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"SF\"}"}}
		]},
		{"role":"tool","tool_call_id":"call_1","content":"18C"}
	]}`, "m", false)

	items := got.Get("input").Array()
	if len(items) != 3 {
		t.Fatalf("input has %d items, want 3", len(items))
	}
	if items[1].Get("type").String() != "function_call" {
		t.Errorf("items[1].type = %q, want function_call", items[1].Get("type").String())
	}
	if items[1].Get("call_id").String() != "call_1" {
		t.Errorf("items[1].call_id = %q, want call_1", items[1].Get("call_id").String())
	}
	if items[1].Get("name").String() != "get_weather" {
		t.Errorf("items[1].name = %q, want get_weather", items[1].Get("name").String())
	}
	if items[2].Get("type").String() != "function_call_output" {
		t.Errorf("items[2].type = %q, want function_call_output", items[2].Get("type").String())
	}
	if items[2].Get("call_id").String() != "call_1" {
		t.Errorf("items[2].call_id = %q, want call_1 (the correlation the model needs)", items[2].Get("call_id").String())
	}
	if items[2].Get("output").String() != "18C" {
		t.Errorf("items[2].output = %q, want 18C", items[2].Get("output").String())
	}
}

// TestRequest_ToolsAreFlattened pins the schema un-nesting. Chat Completions
// wraps the declaration in `function`; Responses hoists it.
func TestRequest_ToolsAreFlattened(t *testing.T) {
	got := mustConvert(t, `{"model":"m","messages":[{"role":"user","content":"x"}],
		"tools":[{"type":"function","function":{
			"name":"f","description":"d","parameters":{"type":"object","properties":{"a":{"type":"string"}}}
		}}],
		"tool_choice":{"type":"function","function":{"name":"f"}}}`, "m", false)

	tool := got.Get("tools.0")
	if tool.Get("name").String() != "f" {
		t.Errorf("tools[0].name = %q, want f (must be hoisted out of `function`)", tool.Get("name").String())
	}
	if tool.Get("function").Exists() {
		t.Error("tools[0] still nests a `function` object; Responses expects it flattened")
	}
	if tool.Get("parameters.properties.a.type").String() != "string" {
		t.Error("tool parameters schema was not carried through intact")
	}
	if got.Get("tool_choice.name").String() != "f" {
		t.Errorf("tool_choice.name = %q, want f", got.Get("tool_choice.name").String())
	}
}

// TestRequest_MaxTokensSpellings pins both Chat Completions spellings onto the
// one Responses field, newer winning.
func TestRequest_MaxTokensSpellings(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       int64
	}{
		{"legacy", `{"model":"m","messages":[{"role":"user","content":"x"}],"max_tokens":64}`, 64},
		{"current", `{"model":"m","messages":[{"role":"user","content":"x"}],"max_completion_tokens":128}`, 128},
		{"both, newer wins", `{"model":"m","messages":[{"role":"user","content":"x"}],"max_tokens":64,"max_completion_tokens":128}`, 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mustConvert(t, tc.body, "m", false)
			if v := got.Get("max_output_tokens").Int(); v != tc.want {
				t.Errorf("max_output_tokens = %d, want %d", v, tc.want)
			}
		})
	}
}

// TestRequest_StoreIsAlwaysFalse pins the privacy decision: AiKey passes
// through someone else's subscription, so it must not silently persist the
// caller's prompts into that ChatGPT account's server-side history.
func TestRequest_StoreIsAlwaysFalse(t *testing.T) {
	for _, body := range []string{
		`{"model":"m","messages":[{"role":"user","content":"x"}]}`,
		`{"model":"m","messages":[{"role":"user","content":"x"}],"store":true}`,
	} {
		got := mustConvert(t, body, "m", false)
		if !got.Get("store").Exists() {
			t.Fatal("store must always be emitted, never left to the upstream default")
		}
		if got.Get("store").Bool() {
			t.Error("store = true; a client must not be able to opt the caller's prompts into ChatGPT history")
		}
	}
}

// TestRequest_ResolvedModelWinsOverBody pins the pair contract: the caller has
// already applied route-level aliasing and re-reading the body would undo it.
func TestRequest_ResolvedModelWinsOverBody(t *testing.T) {
	got := mustConvert(t, `{"model":"from-body","messages":[{"role":"user","content":"x"}]}`, "from-caller", false)
	if got.Get("model").String() != "from-caller" {
		t.Errorf("model = %q, want from-caller", got.Get("model").String())
	}
}

// TestRequest_UnsupportedParamsAreRejectedNotDropped is the fence for the
// decision that matters most for correctness: every parameter here CHANGES the
// answer, so dropping it returns a plausible response to a question the caller
// did not ask. If this test goes green after someone "simplifies" the
// rejections into drops, the bridge has started lying.
func TestRequest_UnsupportedParamsAreRejectedNotDropped(t *testing.T) {
	base := `{"model":"m","messages":[{"role":"user","content":"x"}]`
	for _, tc := range []struct{ name, extra, wantParam string }{
		{"n>1", `,"n":3`, "n"},
		{"stop string", `,"stop":"END"`, "stop"},
		{"stop array", `,"stop":["END"]`, "stop"},
		{"logprobs", `,"logprobs":true`, "logprobs"},
		{"frequency_penalty", `,"frequency_penalty":0.5`, "frequency_penalty"},
		{"presence_penalty", `,"presence_penalty":-0.2`, "presence_penalty"},
		{"json_object", `,"response_format":{"type":"json_object"}`, "response_format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, tErr := ConvertRequest(context.Background(), "m", []byte(base+tc.extra+"}"), false)
			if tErr == nil {
				t.Fatalf("%s was accepted; it must be refused because forwarding without it "+
					"silently changes the model's output", tc.wantParam)
			}
			if tErr.Param != tc.wantParam {
				t.Errorf("refusal names param %q, want %q — the caller cannot fix what we do not name",
					tErr.Param, tc.wantParam)
			}
			if tErr.HTTPStatus != 400 {
				t.Errorf("status = %d, want 400", tErr.HTTPStatus)
			}
		})
	}
}

// TestRequest_ZeroValuedPenaltiesAreAccepted pins the other half of that
// decision: several SDKs serialize their zero defaults, and refusing those
// would block callers who never asked for the behaviour.
func TestRequest_ZeroValuedPenaltiesAreAccepted(t *testing.T) {
	_, tErr := ConvertRequest(context.Background(), "m",
		[]byte(`{"model":"m","messages":[{"role":"user","content":"x"}],
			"frequency_penalty":0,"presence_penalty":0,"stop":null,"n":1}`), false)
	if tErr != nil {
		t.Fatalf("SDK-default zero values were refused: %v", tErr)
	}
}

// TestRequest_MultimodalTextAndImage pins that a vision request survives.
func TestRequest_MultimodalTextAndImage(t *testing.T) {
	got := mustConvert(t, `{"model":"m","messages":[{"role":"user","content":[
		{"type":"text","text":"what is this"},
		{"type":"image_url","image_url":{"url":"https://example.test/a.png"}}
	]}]}`, "m", false)

	parts := got.Get("input.0.content").Array()
	if len(parts) != 2 {
		t.Fatalf("content has %d parts, want 2", len(parts))
	}
	if parts[0].Get("type").String() != "input_text" {
		t.Errorf("parts[0].type = %q, want input_text", parts[0].Get("type").String())
	}
	if parts[1].Get("type").String() != "input_image" {
		t.Errorf("parts[1].type = %q, want input_image", parts[1].Get("type").String())
	}
	if parts[1].Get("image_url").String() != "https://example.test/a.png" {
		t.Errorf("image url not carried through: %q", parts[1].Get("image_url").String())
	}
}

// TestRequest_UnknownContentPartIsRefused — an audio or file part that we
// cannot forward must not be dropped into silence.
func TestRequest_UnknownContentPartIsRefused(t *testing.T) {
	_, tErr := ConvertRequest(context.Background(), "m",
		[]byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{}}]}]}`), false)
	if tErr == nil {
		t.Fatal("an unforwardable content part was silently dropped")
	}
}

// TestRequest_MalformedBodyIsRefused keeps a parse failure from becoming an
// empty-but-valid upstream request.
func TestRequest_MalformedBodyIsRefused(t *testing.T) {
	if _, tErr := ConvertRequest(context.Background(), "m", []byte(`{"model":`), false); tErr == nil {
		t.Fatal("malformed JSON was accepted")
	}
	if _, tErr := ConvertRequest(context.Background(), "m", []byte(`{"model":"m"}`), false); tErr == nil {
		t.Fatal("a body with no messages[] was accepted")
	}
}

// TestRequest_PairIsRegistered proves init() wired all three transforms — a
// pair that registers only the request half fails at the first response.
func TestRequest_PairIsRegistered(t *testing.T) {
	reg := translator.DefaultRegistry()
	if !reg.HasPair(translator.FormatOpenAI, translator.FormatOpenAIResponses) {
		t.Fatal("openai → openai-responses request pair is not registered")
	}
	if !reg.HasStreamPair(translator.FormatOpenAI, translator.FormatOpenAIResponses) {
		t.Fatal("openai → openai-responses stream transform is not registered")
	}
	if _, tErr := reg.TranslateNonStream(context.Background(),
		translator.FormatOpenAI, translator.FormatOpenAIResponses,
		[]byte(`{"id":"resp_1","output":[]}`)); tErr != nil {
		t.Fatalf("non-stream transform is not registered: %v", tErr)
	}
}

// TestRequest_EmittedShapeIsStable is a coarse guard that the emitted body has
// no Chat Completions leftovers — those are what an upstream 400s on.
func TestRequest_EmittedShapeIsStable(t *testing.T) {
	out, tErr := ConvertRequest(context.Background(), "m",
		[]byte(`{"model":"m","messages":[{"role":"user","content":"x"}],"max_tokens":8}`), true)
	if tErr != nil {
		t.Fatal(tErr)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"messages", "max_tokens", "max_completion_tokens", "n", "stop"} {
		if _, present := decoded[forbidden]; present {
			t.Errorf("translated body still carries the Chat Completions field %q", forbidden)
		}
	}
	if decoded["stream"] != true {
		t.Error("stream flag was not carried onto the Responses request")
	}
}
