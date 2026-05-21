package openai_anthropic

import (
	"context"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// Helper: run ConvertRequest with an explicit messages JSON literal as
// the entire input body. Returns the output bytes.
func convertWithMessages(t *testing.T, messagesJSON string) []byte {
	t.Helper()
	body := `{"messages":` + messagesJSON + `}`
	out, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err != nil {
		t.Fatalf("ConvertRequest failed: %+v", err)
	}
	return out
}

// Helper: run ConvertRequest and expect a TranslateError; returns it.
func expectMessagesError(t *testing.T, messagesJSON string) *struct {
	Code, Message, Param string
} {
	t.Helper()
	body := `{"messages":` + messagesJSON + `}`
	_, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err == nil {
		t.Fatalf("expected TranslateError, got success")
	}
	return &struct {
		Code, Message, Param string
	}{err.Code, err.Message, err.Param}
}

// ── system extraction ───────────────────────────────────────────────

func TestNormalize_ExtractsSingleSystemMessage(t *testing.T) {
	out := convertWithMessages(t, `[
		{"role":"system","content":"You are helpful"},
		{"role":"user","content":"hi"}
	]`)

	// system → top-level system[]
	sys := gjson.GetBytes(out, "system")
	if !sys.IsArray() {
		t.Fatalf("system is not an array: %v", sys)
	}
	arr := sys.Array()
	if len(arr) != 1 {
		t.Fatalf("system array len=%d, want 1", len(arr))
	}
	if arr[0].Get("type").String() != "text" {
		t.Errorf("system[0].type = %q, want text", arr[0].Get("type").String())
	}
	if arr[0].Get("text").String() != "You are helpful" {
		t.Errorf("system[0].text = %q", arr[0].Get("text").String())
	}

	// messages: only the user message remains, and content is block array
	msgs := gjson.GetBytes(out, "messages").Array()
	if len(msgs) != 1 {
		t.Fatalf("messages len=%d, want 1 (system removed)", len(msgs))
	}
	if msgs[0].Get("role").String() != "user" {
		t.Errorf("messages[0].role = %q, want user", msgs[0].Get("role").String())
	}
	// content is block array: [{type:text, text:hi}]
	if !msgs[0].Get("content").IsArray() {
		t.Fatalf("messages[0].content is not array: %s", msgs[0].Get("content").Raw)
	}
}

func TestNormalize_ExtractsMultipleSystemMessages_PreservesOrder(t *testing.T) {
	out := convertWithMessages(t, `[
		{"role":"system","content":"Be helpful"},
		{"role":"system","content":"Be concise"},
		{"role":"user","content":"hi"}
	]`)

	sys := gjson.GetBytes(out, "system").Array()
	if len(sys) != 2 {
		t.Fatalf("system len=%d, want 2 (preserves multi-system)", len(sys))
	}
	if sys[0].Get("text").String() != "Be helpful" {
		t.Errorf("system[0] order wrong: %q", sys[0].Get("text").String())
	}
	if sys[1].Get("text").String() != "Be concise" {
		t.Errorf("system[1] order wrong: %q", sys[1].Get("text").String())
	}
}

func TestNormalize_TreatsDeveloperRoleAsSystem(t *testing.T) {
	// OpenAI's 2024-08 "developer" role is an alias for "system" with
	// higher priority. For Anthropic compat we treat both identically.
	out := convertWithMessages(t, `[
		{"role":"developer","content":"Dev instructions"},
		{"role":"user","content":"hi"}
	]`)
	sys := gjson.GetBytes(out, "system").Array()
	if len(sys) != 1 || sys[0].Get("text").String() != "Dev instructions" {
		t.Errorf("developer role should map to system, got: %v", sys)
	}
}

func TestNormalize_EmptySystemMessageSkipped(t *testing.T) {
	// Empty system content shouldn't produce an empty text block (would
	// Anthropic-400). Silent skip.
	out := convertWithMessages(t, `[
		{"role":"system","content":""},
		{"role":"system","content":"real"},
		{"role":"user","content":"hi"}
	]`)
	sys := gjson.GetBytes(out, "system").Array()
	if len(sys) != 1 || sys[0].Get("text").String() != "real" {
		t.Errorf("empty system not skipped: %v", sys)
	}
}

func TestNormalize_NoSystemMessageOmitsField(t *testing.T) {
	// When there are no system messages, the output should NOT have
	// a top-level system field (empty array would be valid but cluttered).
	out := convertWithMessages(t, `[{"role":"user","content":"hi"}]`)
	if gjson.GetBytes(out, "system").Exists() {
		t.Errorf("system field should be absent when no system messages, got: %s",
			gjson.GetBytes(out, "system").Raw)
	}
}

// ── user-first repair ───────────────────────────────────────────────

func TestNormalize_AssistantFirstPrependedWithPlaceholderUser(t *testing.T) {
	// LiteLLM behavior: when messages[0] is assistant (no user yet),
	// prepend a placeholder " " user message. Silent repair vs reject
	// matches industry standard.
	out := convertWithMessages(t, `[
		{"role":"assistant","content":"I'll help"},
		{"role":"user","content":"Thanks"}
	]`)
	msgs := gjson.GetBytes(out, "messages").Array()
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages (placeholder + assistant + user), got %d: %s",
			len(msgs), gjson.GetBytes(out, "messages").Raw)
	}
	if msgs[0].Get("role").String() != "user" {
		t.Errorf("messages[0].role = %q, want user (placeholder)", msgs[0].Get("role").String())
	}
}

// ── role merging ────────────────────────────────────────────────────

func TestNormalize_MergesConsecutiveSameRole(t *testing.T) {
	// Three user messages in a row (after system extraction would be
	// realistic) get merged into one with concatenated blocks.
	out := convertWithMessages(t, `[
		{"role":"user","content":"part 1"},
		{"role":"user","content":"part 2"},
		{"role":"user","content":"part 3"}
	]`)
	msgs := gjson.GetBytes(out, "messages").Array()
	if len(msgs) != 1 {
		t.Fatalf("3 consecutive users should merge to 1, got %d: %s",
			len(msgs), gjson.GetBytes(out, "messages").Raw)
	}
	blocks := msgs[0].Get("content").Array()
	if len(blocks) != 3 {
		t.Errorf("merged content should have 3 blocks, got %d: %v", len(blocks), blocks)
	}
	for i, want := range []string{"part 1", "part 2", "part 3"} {
		if blocks[i].Get("text").String() != want {
			t.Errorf("block[%d].text = %q, want %q", i, blocks[i].Get("text").String(), want)
		}
	}
}

func TestNormalize_PreservesProperAlternation(t *testing.T) {
	// Already-alternating input passes through unchanged (modulo
	// content-to-blocks conversion).
	out := convertWithMessages(t, `[
		{"role":"user","content":"u1"},
		{"role":"assistant","content":"a1"},
		{"role":"user","content":"u2"},
		{"role":"assistant","content":"a2"}
	]`)
	msgs := gjson.GetBytes(out, "messages").Array()
	if len(msgs) != 4 {
		t.Fatalf("alternating 4 should stay 4, got %d", len(msgs))
	}
	for i, wantRole := range []string{"user", "assistant", "user", "assistant"} {
		if msgs[i].Get("role").String() != wantRole {
			t.Errorf("messages[%d].role = %q, want %q",
				i, msgs[i].Get("role").String(), wantRole)
		}
	}
}

// ── tool message → user with tool_result ────────────────────────────

func TestNormalize_ToolMessageRewrappedAsUserToolResult(t *testing.T) {
	out := convertWithMessages(t, `[
		{"role":"user","content":"what's the weather?"},
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"call_abc","type":"function","function":{"name":"get_weather","arguments":"{\"loc\":\"NYC\"}"}}
		]},
		{"role":"tool","tool_call_id":"call_abc","content":"72F sunny"},
		{"role":"assistant","content":"It's 72F and sunny in NYC."}
	]`)

	// Expected after normalization:
	//   user: [text"what's the weather?"]
	//   assistant: [tool_use call_abc(get_weather)(loc=NYC)]
	//   user: [tool_result call_abc -> "72F sunny"]
	//   assistant: [text "It's 72F and sunny in NYC."]
	msgs := gjson.GetBytes(out, "messages").Array()
	if len(msgs) != 4 {
		t.Fatalf("expected 4 alternating messages, got %d: %s",
			len(msgs), gjson.GetBytes(out, "messages").Raw)
	}

	// msg[0]: user / text
	if msgs[0].Get("role").String() != "user" {
		t.Errorf("messages[0].role = %q", msgs[0].Get("role").String())
	}
	if msgs[0].Get("content.0.type").String() != "text" {
		t.Errorf("messages[0] should have text block")
	}

	// msg[1]: assistant / tool_use
	if msgs[1].Get("role").String() != "assistant" {
		t.Errorf("messages[1].role = %q", msgs[1].Get("role").String())
	}
	tu := msgs[1].Get("content.0")
	if tu.Get("type").String() != "tool_use" {
		t.Errorf("messages[1].content[0].type = %q, want tool_use", tu.Get("type").String())
	}
	if tu.Get("id").String() != "call_abc" {
		t.Errorf("tool_use.id = %q, want call_abc", tu.Get("id").String())
	}
	if tu.Get("name").String() != "get_weather" {
		t.Errorf("tool_use.name = %q, want get_weather", tu.Get("name").String())
	}
	if tu.Get("input.loc").String() != "NYC" {
		t.Errorf("tool_use.input.loc = %q, want NYC; full input=%s",
			tu.Get("input.loc").String(), tu.Get("input").Raw)
	}

	// msg[2]: user / tool_result (this is the role swap that's the
	// whole point of tool-message normalization)
	if msgs[2].Get("role").String() != "user" {
		t.Errorf("messages[2].role = %q, want user (tool→user rewrap)", msgs[2].Get("role").String())
	}
	tr := msgs[2].Get("content.0")
	if tr.Get("type").String() != "tool_result" {
		t.Errorf("messages[2].content[0].type = %q, want tool_result", tr.Get("type").String())
	}
	if tr.Get("tool_use_id").String() != "call_abc" {
		t.Errorf("tool_result.tool_use_id = %q, want call_abc", tr.Get("tool_use_id").String())
	}
	if tr.Get("content").String() != "72F sunny" {
		t.Errorf("tool_result.content = %q, want '72F sunny'", tr.Get("content").String())
	}
}

func TestNormalize_ToolMessageMissingToolCallIdRejected(t *testing.T) {
	got := expectMessagesError(t, `[
		{"role":"user","content":"hi"},
		{"role":"tool","content":"x"}
	]`)
	if got.Code != "AIKEY_BAD_REQUEST" {
		t.Errorf("Code = %q, want AIKEY_BAD_REQUEST", got.Code)
	}
	if !strings.Contains(got.Message, "tool_call_id") {
		t.Errorf("error message should name tool_call_id, got: %s", got.Message)
	}
}

func TestNormalize_AssistantToolCallsEmptyArgsBecomeEmptyObject(t *testing.T) {
	// arg-less tool calls (empty string in OpenAI) must serialize as
	// {} in Anthropic — null or empty string would 400.
	out := convertWithMessages(t, `[
		{"role":"user","content":"call it"},
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"call_1","type":"function","function":{"name":"noop","arguments":""}}
		]}
	]`)
	msgs := gjson.GetBytes(out, "messages").Array()
	input := msgs[1].Get("content.0.input").Raw
	if input != "{}" {
		t.Errorf("empty args should serialize as {}, got: %s", input)
	}
}

func TestNormalize_AssistantToolCallsMalformedJSONRejected(t *testing.T) {
	got := expectMessagesError(t, `[
		{"role":"user","content":"x"},
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"c1","type":"function","function":{"name":"f","arguments":"{ not json"}}
		]}
	]`)
	if got.Code != "AIKEY_BAD_REQUEST" {
		t.Errorf("Code = %q, want AIKEY_BAD_REQUEST", got.Code)
	}
	if !strings.Contains(got.Message, "valid JSON") {
		t.Errorf("error message should mention valid JSON: %s", got.Message)
	}
}

// ── content blocks ──────────────────────────────────────────────────

func TestNormalize_ImageUrlDataUriConvertedToBase64Source(t *testing.T) {
	out := convertWithMessages(t, `[{"role":"user","content":[
		{"type":"text","text":"describe this"},
		{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}
	]}]`)
	msgs := gjson.GetBytes(out, "messages").Array()
	blocks := msgs[0].Get("content").Array()
	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks (text + image), got %d", len(blocks))
	}
	if blocks[1].Get("type").String() != "image" {
		t.Errorf("image block type = %q, want image", blocks[1].Get("type").String())
	}
	src := blocks[1].Get("source")
	if src.Get("type").String() != "base64" {
		t.Errorf("source.type = %q, want base64", src.Get("type").String())
	}
	if src.Get("media_type").String() != "image/png" {
		t.Errorf("source.media_type = %q, want image/png", src.Get("media_type").String())
	}
	if src.Get("data").String() != "iVBORw0KGgo=" {
		t.Errorf("source.data wrong: %q", src.Get("data").String())
	}
}

func TestNormalize_ImageUrlHttpConvertedToUrlSource(t *testing.T) {
	out := convertWithMessages(t, `[{"role":"user","content":[
		{"type":"image_url","image_url":{"url":"https://example.com/cat.png"}}
	]}]`)
	msgs := gjson.GetBytes(out, "messages").Array()
	src := msgs[0].Get("content.0.source")
	if src.Get("type").String() != "url" {
		t.Errorf("source.type = %q, want url", src.Get("type").String())
	}
	if src.Get("url").String() != "https://example.com/cat.png" {
		t.Errorf("source.url = %q", src.Get("url").String())
	}
}

func TestNormalize_ImageUrlMissingUrlRejected(t *testing.T) {
	got := expectMessagesError(t, `[{"role":"user","content":[
		{"type":"image_url","image_url":{}}
	]}]`)
	if got.Code != "AIKEY_BAD_REQUEST" {
		t.Errorf("Code = %q, want AIKEY_BAD_REQUEST", got.Code)
	}
	if !strings.Contains(got.Message, "image_url.url") {
		t.Errorf("error should mention image_url.url: %s", got.Message)
	}
}

func TestNormalize_UnsupportedBlockTypeRejected(t *testing.T) {
	got := expectMessagesError(t, `[{"role":"user","content":[
		{"type":"input_audio","input_audio":{}}
	]}]`)
	if got.Code != "AIKEY_UNSUPPORTED_PARAMETER" {
		t.Errorf("Code = %q, want AIKEY_UNSUPPORTED_PARAMETER", got.Code)
	}
}

func TestNormalize_EmptyTextBlocksFiltered(t *testing.T) {
	// Per design rule 5 "空字符串", filter ONLY literal "". Whitespace-only
	// text blocks pass through — Anthropic accepts them (and the
	// user-first " " placeholder relies on this).
	out := convertWithMessages(t, `[{"role":"user","content":[
		{"type":"text","text":"keep me"},
		{"type":"text","text":""},
		{"type":"text","text":"   "},
		{"type":"text","text":"also keep"}
	]}]`)
	blocks := gjson.GetBytes(out, "messages.0.content").Array()
	if len(blocks) != 3 {
		t.Errorf("expected 3 blocks (empty filtered, whitespace kept), got %d: %v",
			len(blocks), blocks)
	}
	// Order preserved: keep / whitespace / keep.
	if blocks[0].Get("text").String() != "keep me" {
		t.Errorf("blocks[0] = %q", blocks[0].Get("text").String())
	}
	if blocks[2].Get("text").String() != "also keep" {
		t.Errorf("blocks[2] = %q", blocks[2].Get("text").String())
	}
}

// ── empty / malformed input ─────────────────────────────────────────

func TestNormalize_EmptyMessagesArrayRejected(t *testing.T) {
	got := expectMessagesError(t, `[]`)
	if got.Code != "AIKEY_BAD_REQUEST" {
		t.Errorf("Code = %q", got.Code)
	}
}

func TestNormalize_OnlySystemMessagesRejected(t *testing.T) {
	// If the user-facing messages array has ONLY system entries, after
	// extraction the messages[] is empty → reject.
	got := expectMessagesError(t, `[{"role":"system","content":"foo"}]`)
	if got.Code != "AIKEY_BAD_REQUEST" {
		t.Errorf("Code = %q", got.Code)
	}
}

func TestNormalize_MissingRoleRejected(t *testing.T) {
	got := expectMessagesError(t, `[{"content":"hi"}]`)
	if got.Code != "AIKEY_BAD_REQUEST" {
		t.Errorf("Code = %q", got.Code)
	}
	if !strings.Contains(got.Message, "no role field") {
		t.Errorf("error should mention missing role: %s", got.Message)
	}
}

func TestNormalize_UnknownRoleRejected(t *testing.T) {
	got := expectMessagesError(t, `[{"role":"sysadmin","content":"x"}]`)
	if got.Code != "AIKEY_BAD_REQUEST" {
		t.Errorf("Code = %q", got.Code)
	}
	if !strings.Contains(got.Message, "unsupported role") {
		t.Errorf("error should mention unsupported role: %s", got.Message)
	}
}
