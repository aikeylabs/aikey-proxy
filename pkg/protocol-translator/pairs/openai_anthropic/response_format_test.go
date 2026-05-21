package openai_anthropic

import (
	"context"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// Helper: convert a body with an inline response_format value embedded.
// Minimal otherwise-valid body (messages + the response_format under test).
func convertWithResponseFormat(t *testing.T, rfRaw string) []byte {
	t.Helper()
	body := `{"messages":[{"role":"user","content":"hi"}],"response_format":` + rfRaw + `}`
	out, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err != nil {
		t.Fatalf("ConvertRequest failed: %+v", err)
	}
	return out
}

func expectResponseFormatError(t *testing.T, rfRaw string) *struct {
	Code, Message, Param string
} {
	t.Helper()
	body := `{"messages":[{"role":"user","content":"hi"}],"response_format":` + rfRaw + `}`
	_, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err == nil {
		t.Fatalf("expected error, got success")
	}
	return &struct{ Code, Message, Param string }{err.Code, err.Message, err.Param}
}

// ── response_format=text / absent (no-op) ─────────────────────────────

func TestResponseFormat_AbsentNoOp(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"hi"}]}`
	out, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err != nil {
		t.Fatalf("convert failed: %+v", err)
	}
	// No tools synthesized, no tool_choice set.
	if gjson.GetBytes(out, "tools").Exists() {
		t.Errorf("no response_format → no synthetic tools, got: %s",
			gjson.GetBytes(out, "tools").Raw)
	}
	if gjson.GetBytes(out, "tool_choice").Exists() {
		t.Errorf("no response_format → no tool_choice, got: %s",
			gjson.GetBytes(out, "tool_choice").Raw)
	}
}

func TestResponseFormat_TextNoOp(t *testing.T) {
	out := convertWithResponseFormat(t, `{"type":"text"}`)
	if gjson.GetBytes(out, "tools").Exists() {
		t.Errorf("response_format=text → no synthetic tools, got: %s",
			gjson.GetBytes(out, "tools").Raw)
	}
}

// ── response_format=json_object (empty schema) ────────────────────────

func TestResponseFormat_JSONObject_SynthesisesTool(t *testing.T) {
	out := convertWithResponseFormat(t, `{"type":"json_object"}`)

	// Synthetic tool should be in tools[0] (caller had no tools[]).
	tools := gjson.GetBytes(out, "tools")
	if !tools.IsArray() {
		t.Fatalf("tools not array: %s", tools.Raw)
	}
	arr := tools.Array()
	if len(arr) != 1 {
		t.Fatalf("expected 1 synthetic tool, got %d: %s", len(arr), tools.Raw)
	}
	if arr[0].Get("name").String() != JSONResponseToolName {
		t.Errorf("synthetic tool name = %q, want %q",
			arr[0].Get("name").String(), JSONResponseToolName)
	}
	// Empty-object schema for json_object (any valid JSON object).
	if arr[0].Get("input_schema.type").String() != "object" {
		t.Errorf("synthetic input_schema = %s, want {\"type\":\"object\"}",
			arr[0].Get("input_schema").Raw)
	}

	// tool_choice forced to the synthetic tool.
	tc := gjson.GetBytes(out, "tool_choice")
	if tc.Get("type").String() != "tool" {
		t.Errorf("tool_choice.type = %q, want tool", tc.Get("type").String())
	}
	if tc.Get("name").String() != JSONResponseToolName {
		t.Errorf("tool_choice.name = %q, want %q",
			tc.Get("name").String(), JSONResponseToolName)
	}
}

// ── response_format=json_schema ───────────────────────────────────────

func TestResponseFormat_JSONSchema_UsesProvidedSchema(t *testing.T) {
	out := convertWithResponseFormat(t, `{
		"type":"json_schema",
		"json_schema":{
			"name":"weather_report",
			"schema":{
				"type":"object",
				"properties":{
					"temp":{"type":"number"},
					"location":{"type":"string"}
				},
				"required":["temp"]
			}
		}
	}`)
	tools := gjson.GetBytes(out, "tools").Array()
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	// Schema content preserved verbatim (modulo possible type-injection).
	if tools[0].Get("input_schema.properties.temp.type").String() != "number" {
		t.Errorf("schema properties not preserved: %s",
			tools[0].Get("input_schema").Raw)
	}
	if tools[0].Get("input_schema.required.0").String() != "temp" {
		t.Errorf("schema required array not preserved: %s",
			tools[0].Get("input_schema").Raw)
	}
	// Description should mention the schema name.
	if !strings.Contains(tools[0].Get("description").String(), "weather_report") {
		t.Errorf("description should reference schema name: %q",
			tools[0].Get("description").String())
	}
}

func TestResponseFormat_JSONSchema_AutoInjectsTypeObject(t *testing.T) {
	// Schema without top-level "type" — translator must auto-inject
	// "type":"object" so Anthropic doesn't 400.
	out := convertWithResponseFormat(t, `{
		"type":"json_schema",
		"json_schema":{
			"schema":{"properties":{"x":{"type":"number"}}}
		}
	}`)
	got := gjson.GetBytes(out, "tools.0.input_schema.type").String()
	if got != "object" {
		t.Errorf("input_schema.type = %q, want auto-injected object", got)
	}
}

func TestResponseFormat_JSONSchema_MissingSchemaRejected(t *testing.T) {
	got := expectResponseFormatError(t, `{"type":"json_schema","json_schema":{"name":"x"}}`)
	if got.Code != "AIKEY_BAD_REQUEST" {
		t.Errorf("Code = %q, want AIKEY_BAD_REQUEST", got.Code)
	}
	if !strings.Contains(got.Message, "json_schema.schema") {
		t.Errorf("error should name json_schema.schema: %s", got.Message)
	}
}

// ── unknown response_format.type ──────────────────────────────────────

func TestResponseFormat_UnknownTypeRejected(t *testing.T) {
	got := expectResponseFormatError(t, `{"type":"yaml_output"}`)
	if got.Code != "AIKEY_UNSUPPORTED_PARAMETER" {
		t.Errorf("Code = %q, want AIKEY_UNSUPPORTED_PARAMETER", got.Code)
	}
}

// ── interaction with caller-declared tools[] ──────────────────────────

func TestResponseFormat_AppendedAfterCallerTools(t *testing.T) {
	// Caller declares a real tool; translator must KEEP it and APPEND
	// the synthetic respond_in_json tool. tool_choice still gets forced
	// to the synthetic one — JSON output guarantee wins over caller's
	// freedom-to-pick-tools.
	body := `{
		"messages":[{"role":"user","content":"hi"}],
		"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}],
		"tool_choice":"auto",
		"response_format":{"type":"json_object"}
	}`
	out, err := ConvertRequest(context.Background(), "m", []byte(body), false)
	if err != nil {
		t.Fatalf("convert failed: %+v", err)
	}
	tools := gjson.GetBytes(out, "tools").Array()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools (caller + synthetic), got %d: %s",
			len(tools), gjson.GetBytes(out, "tools").Raw)
	}
	// Caller tool first, synthetic appended (sjson tools.-1 append semantics).
	if tools[0].Get("name").String() != "get_weather" {
		t.Errorf("tools[0].name = %q, want get_weather (caller tool preserved)",
			tools[0].Get("name").String())
	}
	if tools[1].Get("name").String() != JSONResponseToolName {
		t.Errorf("tools[1].name = %q, want %s (synthetic appended)",
			tools[1].Get("name").String(), JSONResponseToolName)
	}
	// tool_choice OVERWRITTEN from "auto" to the synthetic tool.
	tc := gjson.GetBytes(out, "tool_choice")
	if tc.Get("type").String() != "tool" || tc.Get("name").String() != JSONResponseToolName {
		t.Errorf("tool_choice = %s, want forced-tool synthetic", tc.Raw)
	}
}
