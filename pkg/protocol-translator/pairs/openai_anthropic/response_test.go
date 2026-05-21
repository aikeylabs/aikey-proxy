package openai_anthropic

import (
	"context"
	"strings"
	"testing"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// Helper: invoke ConvertNonStreamResponse and require success. The
// timeNowUnix override is set once per test process to keep `created`
// deterministic (1234567890 ≈ 2009-02-13, well in the past so no test
// flakes from real clock progression).
func init() {
	timeNowUnix = func() int64 { return 1234567890 }
}

func convertResponse(t *testing.T, anthropicBody string) []byte {
	t.Helper()
	out, err := ConvertNonStreamResponse(context.Background(), []byte(anthropicBody))
	if err != nil {
		t.Fatalf("ConvertNonStreamResponse failed: %+v", err)
	}
	return out
}

// ── envelope shape ────────────────────────────────────────────────────

func TestResponse_TopLevelEnvelopeShape(t *testing.T) {
	out := convertResponse(t, `{
		"id":"msg_01ABC",
		"type":"message",
		"role":"assistant",
		"model":"claude-3-5-sonnet-20241022",
		"content":[{"type":"text","text":"Hello!"}],
		"stop_reason":"end_turn",
		"usage":{"input_tokens":5,"output_tokens":3}
	}`)

	if got := gjson.GetBytes(out, "id").String(); got != "msg_01ABC" {
		t.Errorf("id = %q, want passthrough msg_01ABC", got)
	}
	if got := gjson.GetBytes(out, "object").String(); got != "chat.completion" {
		t.Errorf("object = %q, want chat.completion", got)
	}
	if got := gjson.GetBytes(out, "created").Int(); got != 1234567890 {
		t.Errorf("created = %d, want stubbed 1234567890", got)
	}
	if got := gjson.GetBytes(out, "model").String(); got != "claude-3-5-sonnet-20241022" {
		t.Errorf("model = %q, want passthrough", got)
	}
	if !gjson.GetBytes(out, "choices.0").IsObject() {
		t.Errorf("choices[0] missing or not object: %s", string(out))
	}
}

// ── text content path ────────────────────────────────────────────────

func TestResponse_SingleTextBlock(t *testing.T) {
	out := convertResponse(t, `{
		"id":"msg_x","type":"message","model":"claude",
		"content":[{"type":"text","text":"Hi there"}],
		"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":2}
	}`)
	msg := gjson.GetBytes(out, "choices.0.message")
	if got := msg.Get("role").String(); got != "assistant" {
		t.Errorf("role = %q, want assistant", got)
	}
	if got := msg.Get("content").String(); got != "Hi there" {
		t.Errorf("content = %q, want Hi there", got)
	}
	if msg.Get("tool_calls").Exists() {
		t.Errorf("tool_calls should be absent for text-only response: %s", msg.Raw)
	}
}

func TestResponse_MultipleTextBlocksConcatenated(t *testing.T) {
	// Anthropic occasionally emits multiple text blocks (e.g. after a
	// reasoning step). They concatenate into one OpenAI content string.
	out := convertResponse(t, `{
		"id":"x","type":"message","model":"m",
		"content":[
			{"type":"text","text":"part1 "},
			{"type":"text","text":"part2"}
		],
		"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":2}
	}`)
	if got := gjson.GetBytes(out, "choices.0.message.content").String(); got != "part1 part2" {
		t.Errorf("content = %q, want concat 'part1 part2'", got)
	}
}

// ── tool_calls path ──────────────────────────────────────────────────

func TestResponse_SingleToolUse(t *testing.T) {
	out := convertResponse(t, `{
		"id":"x","type":"message","model":"m",
		"content":[{
			"type":"tool_use",
			"id":"toolu_01",
			"name":"get_weather",
			"input":{"location":"SF","unit":"celsius"}
		}],
		"stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":15}
	}`)
	msg := gjson.GetBytes(out, "choices.0.message")
	// Pure tool-call response: content should be JSON null.
	if msg.Get("content").Type != gjson.Null {
		t.Errorf("content should be null for pure tool_use, got %s (raw: %s)",
			msg.Get("content").Type, msg.Get("content").Raw)
	}
	tc := msg.Get("tool_calls.0")
	if got := tc.Get("id").String(); got != "toolu_01" {
		t.Errorf("tool_calls[0].id = %q", got)
	}
	if got := tc.Get("type").String(); got != "function" {
		t.Errorf("tool_calls[0].type = %q, want function", got)
	}
	if got := tc.Get("function.name").String(); got != "get_weather" {
		t.Errorf("tool_calls[0].function.name = %q", got)
	}
	// arguments must be a STRING (OpenAI shape) containing JSON.
	argsStr := tc.Get("function.arguments").String()
	if !strings.Contains(argsStr, `"location":"SF"`) || !strings.Contains(argsStr, `"unit":"celsius"`) {
		t.Errorf("function.arguments should JSON-encode the input map; got: %q", argsStr)
	}
	// finish_reason mapped from tool_use → tool_calls.
	if got := gjson.GetBytes(out, "choices.0.finish_reason").String(); got != "tool_calls" {
		t.Errorf("finish_reason = %q, want tool_calls", got)
	}
}

func TestResponse_MultipleToolUseBlocks(t *testing.T) {
	out := convertResponse(t, `{
		"id":"x","type":"message","model":"m",
		"content":[
			{"type":"tool_use","id":"t1","name":"a","input":{}},
			{"type":"tool_use","id":"t2","name":"b","input":{"k":"v"}}
		],
		"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":2}
	}`)
	tcs := gjson.GetBytes(out, "choices.0.message.tool_calls").Array()
	if len(tcs) != 2 {
		t.Fatalf("expected 2 tool_calls, got %d", len(tcs))
	}
	if tcs[0].Get("function.name").String() != "a" || tcs[1].Get("function.name").String() != "b" {
		t.Errorf("tool_calls order or names off: %s", gjson.GetBytes(out, "choices.0.message.tool_calls").Raw)
	}
}

func TestResponse_TextAndToolUseInterleaved(t *testing.T) {
	// Both text and tool_use blocks present (typical for "let me check
	// the weather" + tool_use). content + tool_calls both emit.
	out := convertResponse(t, `{
		"id":"x","type":"message","model":"m",
		"content":[
			{"type":"text","text":"Let me check."},
			{"type":"tool_use","id":"t1","name":"get_weather","input":{"city":"NYC"}}
		],
		"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":2}
	}`)
	msg := gjson.GetBytes(out, "choices.0.message")
	if got := msg.Get("content").String(); got != "Let me check." {
		t.Errorf("content = %q, want 'Let me check.'", got)
	}
	if !msg.Get("tool_calls.0").Exists() {
		t.Errorf("tool_calls missing in mixed response: %s", msg.Raw)
	}
}

// ── synthetic respond_in_json reverse ──────────────────────────────────

func TestResponse_SyntheticToolUnwrappedToContent(t *testing.T) {
	// response_format=json_object made the request force a tool call
	// to respond_in_json. The response's tool_use{name:respond_in_json}
	// must be unwrapped into message.content as a JSON STRING — NOT
	// emitted as tool_calls.
	out := convertResponse(t, `{
		"id":"x","type":"message","model":"m",
		"content":[{
			"type":"tool_use",
			"id":"toolu_synth",
			"name":"respond_in_json",
			"input":{"answer":42,"unit":"meters"}
		}],
		"stop_reason":"tool_use","usage":{"input_tokens":5,"output_tokens":10}
	}`)
	msg := gjson.GetBytes(out, "choices.0.message")

	// tool_calls must NOT be present.
	if msg.Get("tool_calls").Exists() {
		t.Errorf("synthetic tool_use must unwrap, NOT emit tool_calls: %s", msg.Raw)
	}

	// content is the JSON-encoded input.
	contentStr := msg.Get("content").String()
	// The content is a JSON STRING containing the inner JSON literal.
	// Parsing it again should recover the original map.
	inner := gjson.Parse(contentStr)
	if inner.Get("answer").Int() != 42 {
		t.Errorf("content should contain answer:42; raw content=%q", contentStr)
	}
	if inner.Get("unit").String() != "meters" {
		t.Errorf("content should contain unit:meters; raw content=%q", contentStr)
	}

	// finish_reason normalized to "stop" (caller didn't ask for tool).
	if got := gjson.GetBytes(out, "choices.0.finish_reason").String(); got != "stop" {
		t.Errorf("finish_reason = %q, want stop (synthetic-tool reverse)", got)
	}
}

// ── stop_reason mapping ──────────────────────────────────────────────

func TestResponse_StopReasonMapping(t *testing.T) {
	cases := []struct {
		anthropic string
		wantOAI   string
	}{
		{"end_turn", "stop"},
		{"stop_sequence", "stop"},
		{"max_tokens", "length"},
		{"tool_use", "tool_calls"}, // real tool present
		{"future_value", "stop"},   // unknown → safe fallback
	}
	for _, c := range cases {
		body := `{
			"id":"x","type":"message","model":"m",
			"content":[`
		if c.anthropic == "tool_use" {
			body += `{"type":"tool_use","id":"t","name":"get_x","input":{}}`
		} else {
			body += `{"type":"text","text":"hi"}`
		}
		body += `],"stop_reason":"` + c.anthropic + `","usage":{"input_tokens":1,"output_tokens":1}}`
		out := convertResponse(t, body)
		if got := gjson.GetBytes(out, "choices.0.finish_reason").String(); got != c.wantOAI {
			t.Errorf("stop_reason=%q → finish_reason=%q, want %q", c.anthropic, got, c.wantOAI)
		}
	}
}

// ── usage mapping ────────────────────────────────────────────────────

func TestResponse_UsageMapping(t *testing.T) {
	out := convertResponse(t, `{
		"id":"x","type":"message","model":"m",
		"content":[{"type":"text","text":"hi"}],
		"stop_reason":"end_turn",
		"usage":{"input_tokens":25,"output_tokens":50,"cache_read_input_tokens":10,"cache_creation_input_tokens":5}
	}`)
	u := gjson.GetBytes(out, "usage")
	if got := u.Get("prompt_tokens").Int(); got != 25 {
		t.Errorf("prompt_tokens = %d, want 25", got)
	}
	if got := u.Get("completion_tokens").Int(); got != 50 {
		t.Errorf("completion_tokens = %d, want 50", got)
	}
	if got := u.Get("total_tokens").Int(); got != 75 {
		t.Errorf("total_tokens = %d, want 25+50=75", got)
	}
	// cache_* tokens intentionally NOT surfaced at MVP.
	if u.Get("prompt_tokens_details").Exists() {
		t.Errorf("prompt_tokens_details should not be emitted at MVP: %s", u.Raw)
	}
}

// ── error envelope passthrough ───────────────────────────────────────

func TestResponse_AuthenticationErrorMapped(t *testing.T) {
	_, err := ConvertNonStreamResponse(context.Background(), []byte(`{
		"type":"error",
		"error":{"type":"authentication_error","message":"invalid api key"}
	}`))
	if err == nil {
		t.Fatalf("expected TranslateError on auth error envelope")
	}
	if err.HTTPStatus != 401 {
		t.Errorf("HTTPStatus = %d, want 401", err.HTTPStatus)
	}
	if err.Code != translator.CodeUpstreamAuth {
		t.Errorf("Code = %q, want %q", err.Code, translator.CodeUpstreamAuth)
	}
	if !strings.Contains(err.Message, "authentication_error") {
		t.Errorf("error message should mention upstream type: %q", err.Message)
	}
}

func TestResponse_RateLimitErrorMapped(t *testing.T) {
	_, err := ConvertNonStreamResponse(context.Background(), []byte(`{
		"type":"error",
		"error":{"type":"rate_limit_error","message":"too many"}
	}`))
	if err == nil || err.HTTPStatus != 429 || err.Code != translator.CodeUpstreamRateLimit {
		t.Errorf("expected 429 + CodeUpstreamRateLimit, got %+v", err)
	}
}

func TestResponse_OverloadedErrorMapped(t *testing.T) {
	_, err := ConvertNonStreamResponse(context.Background(), []byte(`{
		"type":"error",
		"error":{"type":"overloaded_error","message":"capacity"}
	}`))
	// Anthropic documents 529 for overloaded.
	if err == nil || err.HTTPStatus != 529 {
		t.Errorf("expected 529 on overloaded_error, got %+v", err)
	}
}

// ── malformed input ──────────────────────────────────────────────────

func TestResponse_InvalidJSONReturns502(t *testing.T) {
	_, err := ConvertNonStreamResponse(context.Background(), []byte(`{not json}`))
	if err == nil {
		t.Fatalf("expected error on invalid JSON")
	}
	if err.HTTPStatus != 502 {
		t.Errorf("HTTPStatus = %d, want 502 (upstream contract violation)", err.HTTPStatus)
	}
	if err.Code != translator.CodeTranslationFailed {
		t.Errorf("Code = %q, want %q", err.Code, translator.CodeTranslationFailed)
	}
}

func TestResponse_EmptyContentArrayPasses(t *testing.T) {
	// Anthropic CAN return an empty content[] (rare but observed under
	// rate limiting / safety filtering). Don't crash; emit minimal envelope.
	out := convertResponse(t, `{
		"id":"x","type":"message","model":"m",
		"content":[],"stop_reason":"end_turn",
		"usage":{"input_tokens":0,"output_tokens":0}
	}`)
	if got := gjson.GetBytes(out, "choices.0.message.content").String(); got != "" {
		t.Errorf("empty content should produce empty string, got %q", got)
	}
	if gjson.GetBytes(out, "choices.0.message.tool_calls").Exists() {
		t.Errorf("tool_calls should be absent for empty content")
	}
}

// ── Registry wire ────────────────────────────────────────────────────

func TestResponse_RegisteredOnDefaultRegistry(t *testing.T) {
	// Smoke test: the init() side-effect must register NonStream so the
	// registry can dispatch openai→anthropic response translation.
	if !translator.DefaultRegistry().HasPair(translator.FormatOpenAI, translator.FormatAnthropic) {
		t.Fatal("openai→anthropic pair not registered on DefaultRegistry")
	}
	// Drive it through the registry to confirm the wire (not just direct call).
	out, err := translator.DefaultRegistry().TranslateNonStream(
		context.Background(),
		translator.FormatOpenAI, translator.FormatAnthropic,
		[]byte(`{"id":"x","type":"message","model":"m","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`),
	)
	if err != nil {
		t.Fatalf("registry TranslateNonStream failed: %+v", err)
	}
	if got := gjson.GetBytes(out, "choices.0.message.content").String(); got != "ok" {
		t.Errorf("registry route produced wrong content: %q", got)
	}
}
