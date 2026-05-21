package openai_anthropic

import (
	"context"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// Helper: convert with a tools array embedded into a minimal otherwise-valid body.
func convertWithTools(t *testing.T, toolsJSON string) []byte {
	t.Helper()
	body := `{"messages":[{"role":"user","content":"hi"}],"tools":` + toolsJSON + `}`
	out, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err != nil {
		t.Fatalf("ConvertRequest failed: %+v", err)
	}
	return out
}

// Helper: convert with a tool_choice value embedded into a minimal body.
// Accepts either string ("auto") or object ({...}) — caller embeds the
// raw JSON value.
func convertWithToolChoice(t *testing.T, toolChoiceRaw string) []byte {
	t.Helper()
	body := `{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"x","parameters":{"type":"object"}}}],"tool_choice":` + toolChoiceRaw + `}`
	out, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err != nil {
		t.Fatalf("ConvertRequest failed: %+v", err)
	}
	return out
}

func expectToolsError(t *testing.T, toolsJSON string) *struct {
	Code, Message, Param string
} {
	t.Helper()
	body := `{"messages":[{"role":"user","content":"hi"}],"tools":` + toolsJSON + `}`
	_, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err == nil {
		t.Fatalf("expected error, got success")
	}
	return &struct{ Code, Message, Param string }{err.Code, err.Message, err.Param}
}

func expectToolChoiceError(t *testing.T, toolChoiceRaw string) *struct {
	Code, Message, Param string
} {
	t.Helper()
	body := `{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"x","parameters":{"type":"object"}}}],"tool_choice":` + toolChoiceRaw + `}`
	_, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err == nil {
		t.Fatalf("expected error, got success")
	}
	return &struct{ Code, Message, Param string }{err.Code, err.Message, err.Param}
}

// ── tools[] field mapping ───────────────────────────────────────────

func TestConvertTools_FunctionShapeRewrappedToAnthropic(t *testing.T) {
	out := convertWithTools(t, `[{
		"type":"function",
		"function":{
			"name":"get_weather",
			"description":"Get weather by location",
			"parameters":{"type":"object","properties":{"loc":{"type":"string"}}}
		}
	}]`)
	tools := gjson.GetBytes(out, "tools")
	if !tools.IsArray() {
		t.Fatalf("tools is not array: %s", tools.Raw)
	}
	arr := tools.Array()
	if len(arr) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(arr))
	}
	// Anthropic shape: top-level name/description/input_schema (no
	// "type":"function" wrapper, no "function" subkey).
	if arr[0].Get("name").String() != "get_weather" {
		t.Errorf("tools[0].name = %q", arr[0].Get("name").String())
	}
	if arr[0].Get("description").String() != "Get weather by location" {
		t.Errorf("tools[0].description = %q", arr[0].Get("description").String())
	}
	if arr[0].Get("input_schema.type").String() != "object" {
		t.Errorf("input_schema.type = %q, want object", arr[0].Get("input_schema.type").String())
	}
	if arr[0].Get("input_schema.properties.loc.type").String() != "string" {
		t.Errorf("input_schema nested properties not preserved: %s",
			arr[0].Get("input_schema").Raw)
	}
	// Old OpenAI keys MUST NOT leak through.
	if arr[0].Get("type").Exists() {
		t.Errorf(`tools[0] should not have "type" (Anthropic style): %s`, arr[0].Raw)
	}
	if arr[0].Get("function").Exists() {
		t.Errorf(`tools[0] should not have "function" wrapper: %s`, arr[0].Raw)
	}
	if arr[0].Get("parameters").Exists() {
		t.Errorf(`tools[0] should rename parameters → input_schema: %s`, arr[0].Raw)
	}
}

func TestConvertTools_InputSchemaAutoTypeObject(t *testing.T) {
	// Schema without "type" key — must auto-inject "type":"object" (Anthropic 400 otherwise).
	out := convertWithTools(t, `[{
		"type":"function",
		"function":{
			"name":"calc",
			"parameters":{"properties":{"a":{"type":"number"}}}
		}
	}]`)
	got := gjson.GetBytes(out, "tools.0.input_schema.type").String()
	if got != "object" {
		t.Errorf("input_schema.type = %q, want auto-injected object", got)
	}
}

func TestConvertTools_NoParametersDefaultsToObjectSchema(t *testing.T) {
	// Parameter-less tool — Anthropic accepts {"type":"object"}.
	out := convertWithTools(t, `[{
		"type":"function",
		"function":{"name":"noop"}
	}]`)
	schema := gjson.GetBytes(out, "tools.0.input_schema")
	if schema.Get("type").String() != "object" {
		t.Errorf("input_schema = %s, want {\"type\":\"object\"}", schema.Raw)
	}
}

func TestConvertTools_MissingNameRejected(t *testing.T) {
	got := expectToolsError(t, `[{"type":"function","function":{"description":"no name"}}]`)
	if got.Code != "AIKEY_BAD_REQUEST" {
		t.Errorf("Code = %q, want AIKEY_BAD_REQUEST", got.Code)
	}
	if !strings.Contains(got.Message, "name is required") {
		t.Errorf("error: %s", got.Message)
	}
}

func TestConvertTools_NonFunctionTypeRejected(t *testing.T) {
	// OpenAI server-side tools (code_interpreter, file_search) can't
	// be mapped to Anthropic — reject loud.
	got := expectToolsError(t, `[{"type":"code_interpreter"}]`)
	if got.Code != "AIKEY_UNSUPPORTED_PARAMETER" {
		t.Errorf("Code = %q, want AIKEY_UNSUPPORTED_PARAMETER", got.Code)
	}
}

func TestConvertTools_EmptyArrayOmittedFromOutput(t *testing.T) {
	// tools:[] is OpenAI-legal but a no-op. Anthropic accepts no
	// tools field; emitting tools:[] would be cluttered/harmless,
	// but we omit it for cleanliness.
	out := convertWithTools(t, `[]`)
	if gjson.GetBytes(out, "tools").Exists() {
		t.Errorf("empty tools[] should be omitted, got: %s", gjson.GetBytes(out, "tools").Raw)
	}
}

func TestConvertTools_AbsentNoOp(t *testing.T) {
	// No tools field at all → no tools field in output.
	body := `{"messages":[{"role":"user","content":"hi"}]}`
	out, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err != nil {
		t.Fatalf("convert failed: %+v", err)
	}
	if gjson.GetBytes(out, "tools").Exists() {
		t.Errorf("tools should be absent when input has none: %s",
			gjson.GetBytes(out, "tools").Raw)
	}
}

// ── tool_choice ────────────────────────────────────────────────────

func TestConvertToolChoice_StringAuto(t *testing.T) {
	out := convertWithToolChoice(t, `"auto"`)
	tc := gjson.GetBytes(out, "tool_choice")
	if tc.Get("type").String() != "auto" {
		t.Errorf("tool_choice = %s, want {type:auto}", tc.Raw)
	}
}

func TestConvertToolChoice_StringRequired(t *testing.T) {
	out := convertWithToolChoice(t, `"required"`)
	tc := gjson.GetBytes(out, "tool_choice")
	if tc.Get("type").String() != "any" {
		t.Errorf("tool_choice = %s, want {type:any} (Anthropic 'any' is OpenAI 'required')", tc.Raw)
	}
}

func TestConvertToolChoice_StringNone(t *testing.T) {
	out := convertWithToolChoice(t, `"none"`)
	tc := gjson.GetBytes(out, "tool_choice")
	if tc.Get("type").String() != "none" {
		t.Errorf("tool_choice = %s, want {type:none}", tc.Raw)
	}
}

func TestConvertToolChoice_StringUnknownRejected(t *testing.T) {
	got := expectToolChoiceError(t, `"random"`)
	if got.Code != "AIKEY_BAD_REQUEST" {
		t.Errorf("Code = %q", got.Code)
	}
}

func TestConvertToolChoice_ObjectFunctionSpecific(t *testing.T) {
	out := convertWithToolChoice(t, `{"type":"function","function":{"name":"get_weather"}}`)
	tc := gjson.GetBytes(out, "tool_choice")
	if tc.Get("type").String() != "tool" {
		t.Errorf("tool_choice.type = %q, want tool", tc.Get("type").String())
	}
	if tc.Get("name").String() != "get_weather" {
		t.Errorf("tool_choice.name = %q, want get_weather", tc.Get("name").String())
	}
}

func TestConvertToolChoice_ObjectFunctionMissingNameRejected(t *testing.T) {
	got := expectToolChoiceError(t, `{"type":"function","function":{}}`)
	if got.Code != "AIKEY_BAD_REQUEST" {
		t.Errorf("Code = %q", got.Code)
	}
	if !strings.Contains(got.Message, "function.name") {
		t.Errorf("error message should name function.name: %s", got.Message)
	}
}

func TestConvertToolChoice_ObjectTypeAutoRequiredNone(t *testing.T) {
	// Object-form values for the simple types (some SDKs prefer the object form).
	cases := []struct {
		in   string
		want string
	}{
		{`{"type":"auto"}`, "auto"},
		{`{"type":"required"}`, "any"},
		{`{"type":"none"}`, "none"},
	}
	for _, c := range cases {
		out := convertWithToolChoice(t, c.in)
		if got := gjson.GetBytes(out, "tool_choice.type").String(); got != c.want {
			t.Errorf("in=%s → tool_choice.type=%q, want %q", c.in, got, c.want)
		}
	}
}

func TestConvertToolChoice_ObjectUnknownTypeRejected(t *testing.T) {
	got := expectToolChoiceError(t, `{"type":"future_format"}`)
	if got.Code != "AIKEY_BAD_REQUEST" {
		t.Errorf("Code = %q", got.Code)
	}
}

func TestConvertToolChoice_AbsentNoOp(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"x","parameters":{"type":"object"}}}]}`
	out, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err != nil {
		t.Fatalf("convert failed: %+v", err)
	}
	if gjson.GetBytes(out, "tool_choice").Exists() {
		t.Errorf("tool_choice should be absent when input has none: %s",
			gjson.GetBytes(out, "tool_choice").Raw)
	}
}

// ── parallel_tool_calls reverse mapping ────────────────────────────

// Helper: convert with parallel_tool_calls + an optional tool_choice
// (default "auto" if empty string), with a real tool already declared
// so the parallel-reverse path sees a valid tool_choice to mutate.
func convertWithParallel(t *testing.T, parallel string, toolChoiceRaw string) []byte {
	t.Helper()
	if toolChoiceRaw == "" {
		toolChoiceRaw = `"auto"`
	}
	body := `{
		"messages":[{"role":"user","content":"hi"}],
		"tools":[{"type":"function","function":{"name":"x","parameters":{"type":"object"}}}],
		"tool_choice":` + toolChoiceRaw + `,
		"parallel_tool_calls":` + parallel + `
	}`
	out, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err != nil {
		t.Fatalf("ConvertRequest failed: %+v", err)
	}
	return out
}

func TestParallelToolCalls_FalseSetsDisableFlag(t *testing.T) {
	// parallel_tool_calls=false (OpenAI) → tool_choice.disable_parallel_tool_use=true (Anthropic).
	out := convertWithParallel(t, "false", `"auto"`)
	if got := gjson.GetBytes(out, "tool_choice.disable_parallel_tool_use").Bool(); !got {
		t.Errorf("disable_parallel_tool_use = %v, want true; tool_choice=%s",
			got, gjson.GetBytes(out, "tool_choice").Raw)
	}
	// type should remain "auto" (we only added the disable flag).
	if got := gjson.GetBytes(out, "tool_choice.type").String(); got != "auto" {
		t.Errorf("tool_choice.type = %q, want auto (unchanged)", got)
	}
}

func TestParallelToolCalls_TrueIsDefault_NoField(t *testing.T) {
	// parallel_tool_calls=true is the OpenAI default and matches the
	// Anthropic default — we should NOT emit disable_parallel_tool_use.
	out := convertWithParallel(t, "true", `"auto"`)
	if gjson.GetBytes(out, "tool_choice.disable_parallel_tool_use").Exists() {
		t.Errorf("parallel_tool_calls=true must NOT emit disable_parallel_tool_use, got: %s",
			gjson.GetBytes(out, "tool_choice").Raw)
	}
}

func TestParallelToolCalls_AbsentNoOp(t *testing.T) {
	// No parallel_tool_calls in inbound → no disable flag in outbound.
	body := `{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"x","parameters":{"type":"object"}}}],"tool_choice":"auto"}`
	out, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err != nil {
		t.Fatalf("convert failed: %+v", err)
	}
	if gjson.GetBytes(out, "tool_choice.disable_parallel_tool_use").Exists() {
		t.Errorf("absent parallel_tool_calls must NOT emit disable flag")
	}
}

func TestParallelToolCalls_NoneSkipsDisableFlag(t *testing.T) {
	// tool_choice="none" + parallel_tool_calls=false: Anthropic 400s on
	// this combo (new-api踩坑 reference). Translator must NOT add the
	// disable flag. "Force no tools" already implies no parallel calls.
	out := convertWithParallel(t, "false", `"none"`)
	tc := gjson.GetBytes(out, "tool_choice")
	if tc.Get("type").String() != "none" {
		t.Fatalf("tool_choice.type = %q, want none", tc.Get("type").String())
	}
	if tc.Get("disable_parallel_tool_use").Exists() {
		t.Errorf("disable_parallel_tool_use MUST be absent when tool_choice=none (Anthropic 400 on combo); got tool_choice=%s",
			tc.Raw)
	}
}

func TestParallelToolCalls_NoToolChoiceNoOp(t *testing.T) {
	// No tool_choice (and no tools either, in practice) → don't emit
	// disable_parallel_tool_use; it'd be orphaned without a tool_choice
	// object to attach to.
	body := `{"messages":[{"role":"user","content":"hi"}],"parallel_tool_calls":false}`
	out, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err != nil {
		t.Fatalf("convert failed: %+v", err)
	}
	if gjson.GetBytes(out, "tool_choice").Exists() {
		t.Errorf("no tool_choice expected; got: %s",
			gjson.GetBytes(out, "tool_choice").Raw)
	}
}

func TestParallelToolCalls_InteractsWithResponseFormat(t *testing.T) {
	// response_format forces tool_choice={type:tool,name:respond_in_json}.
	// parallel_tool_calls=false should THEN add disable_parallel_tool_use=true
	// on top of that — they don't conflict (it's NOT "none"). Confirms
	// applyParallelToolCalls runs AFTER applyResponseFormat.
	body := `{
		"messages":[{"role":"user","content":"hi"}],
		"response_format":{"type":"json_object"},
		"parallel_tool_calls":false
	}`
	out, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err != nil {
		t.Fatalf("convert failed: %+v", err)
	}
	tc := gjson.GetBytes(out, "tool_choice")
	if tc.Get("type").String() != "tool" {
		t.Errorf("tool_choice.type = %q, want tool (forced by response_format)",
			tc.Get("type").String())
	}
	if !tc.Get("disable_parallel_tool_use").Bool() {
		t.Errorf("disable_parallel_tool_use should be true on forced-tool path; tool_choice=%s",
			tc.Raw)
	}
}
