package openai_anthropic

import (
	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// response_format.go — translate OpenAI `response_format` into a synthetic
// forced tool-call, the industry-standard workaround for getting
// guaranteed-JSON output out of Anthropic.
//
// Anthropic has NO `response_format` parameter. The community-aligned
// way to get JSON output is to:
//
//  1. Inject a synthetic tool (e.g. "respond_in_json") with the desired
//     JSON schema (or {"type":"object"} for json_object).
//  2. Force tool_choice to that tool's name, so Anthropic MUST call it
//     instead of returning natural-language text.
//  3. On the response side (Day 6), detect the tool_use output for
//     this synthetic tool and re-emit it as message.content (stringified
//     JSON) instead of OpenAI tool_calls.
//
// References:
//   - LiteLLM litellm/llms/anthropic/chat/transformation.py L1086-1115
//   - design doc §9.1 response_format = json_object / json_schema
//   - 主方案 §4.4 降级策略表
//
// Why this lives here vs sanitizer (Phase 1's egress.go): sanitizer is
// a protocol-agnostic security layer (strip aikey/metadata fields, drop
// logprobs/seed). response_format is Anthropic-specific compatibility —
// it's translation, not sanitization. Day 5 also removes sanitizer's
// previous response_format hard-reject; translator now handles it.

// JSONResponseToolName is the synthetic tool name used for the
// response_format → forced tool-call workaround. Exported because the
// Day 6 response-side handler needs to detect tool_use blocks with this
// name to reverse-map them into message.content.
const JSONResponseToolName = "respond_in_json"

// applyResponseFormat checks the inbound request for a `response_format`
// field and, if present and asking for JSON output, modifies the
// translated body to inject the synthetic tool + force tool_choice.
//
// Semantics by response_format.type:
//
//   - "text" or absent  — no-op, return body unchanged.
//   - "json_object"     — append synthetic tool with empty-object schema,
//                         override tool_choice to force its use.
//   - "json_schema"     — same, but the schema comes from
//                         response_format.json_schema.schema; auto-inject
//                         `"type":"object"` at top of schema if missing.
//   - anything else     — TranslateError (AIKEY_UNSUPPORTED_PARAMETER).
//
// Interaction with existing tools[] and tool_choice:
//
// The synthetic tool is APPENDED to whatever tools[] the caller already
// declared (so user-defined tools remain available, but Claude is
// forced to use the synthetic one for THIS turn). tool_choice is
// OVERWRITTEN — there's no way to "force JSON output AND let Claude
// freely pick tools" because the two are contradictory (force-tool
// can only point at one tool). This matches LiteLLM behavior; OpenAI
// itself has the same restriction (response_format=json_object disables
// tool_calls in practice).
func applyResponseFormat(body []byte, in gjson.Result) ([]byte, *translator.TranslateError) {
	rf := in.Get("response_format")
	if !rf.Exists() || !rf.IsObject() {
		return body, nil
	}
	rfType := rf.Get("type").String()
	switch rfType {
	case "", "text":
		// type=text is the OpenAI default — no JSON enforcement needed.
		return body, nil

	case "json_object":
		// Empty-object schema = "any valid JSON object".
		return appendSyntheticJSONTool(body, []byte(`{"type":"object"}`),
			"Use this tool to return your response as a valid JSON object.")

	case "json_schema":
		schemaNode := rf.Get("json_schema.schema")
		if !schemaNode.Exists() {
			return nil, &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "response_format",
				Message: `response_format={"type":"json_schema",...} requires response_format.json_schema.schema`,
			}
		}
		// Patch schema to ensure top-level type=object (Anthropic
		// requires it; OpenAI accepts schemas without explicit top type).
		schemaRaw := []byte(schemaNode.Raw)
		if gjson.Get(string(schemaRaw), "type").String() == "" {
			patched, perr := sjson.SetRawBytes(schemaRaw, "type", []byte(`"object"`))
			if perr == nil {
				schemaRaw = patched
			}
		}
		// Include the schema name in the description if provided —
		// helps Claude orient the tool's purpose.
		description := "Use this tool to return your response as JSON matching the schema."
		if name := rf.Get("json_schema.name").String(); name != "" {
			description = "Use this tool to return your response as JSON matching the " + name + " schema."
		}
		return appendSyntheticJSONTool(body, schemaRaw, description)

	default:
		return nil, &translator.TranslateError{
			Code:       translator.CodeUnsupportedParam,
			HTTPStatus: 400,
			Param:      "response_format",
			Message: `response_format.type=` + jsonQuote(rfType) +
				` not supported (expected: "text" / "json_object" / "json_schema")`,
		}
	}
}

// appendSyntheticJSONTool mutates the translated body to:
//   1. Append a synthetic tool entry to tools[] (creating tools if absent).
//   2. Set tool_choice to {"type":"tool","name":"respond_in_json"}.
//
// Why sjson "tools.-1" append rather than rebuilding the whole array:
// preserves user-declared tools verbatim (with their schemas, descriptions,
// names) so Claude knows about them even though we force the synthetic
// one for this turn. The synthetic tool's name is namespaced enough
// (respond_in_json) that collision with a user tool is unlikely; we
// don't dedupe (if user happened to declare a tool with the same name,
// they'd have a name collision; LiteLLM doesn't handle this either).
func appendSyntheticJSONTool(body []byte, inputSchema []byte, description string) ([]byte, *translator.TranslateError) {
	// Build the synthetic tool object.
	tool := []byte(`{"name":` + jsonQuote(JSONResponseToolName) +
		`,"description":` + jsonQuote(description) +
		`,"input_schema":` + string(inputSchema) + `}`)

	// Append to tools[]. sjson's "tools.-1" path is the documented
	// append-to-end syntax. When tools[] doesn't exist, sjson creates it
	// as a new array containing only this entry.
	out, err := sjson.SetRawBytes(body, "tools.-1", tool)
	if err != nil {
		return nil, &translator.TranslateError{
			Code:       translator.CodeTranslationFailed,
			HTTPStatus: 500,
			Param:      "response_format",
			Message:    "failed to append synthetic tool: " + err.Error(),
		}
	}

	// Force tool_choice to the synthetic tool. Overwrites any prior
	// tool_choice the caller had set — the JSON-output guarantee
	// conflicts with "let Claude pick a tool", so we pick the
	// hard-constraint side.
	out, err = sjson.SetRawBytes(out, "tool_choice",
		[]byte(`{"type":"tool","name":`+jsonQuote(JSONResponseToolName)+`}`))
	if err != nil {
		return nil, &translator.TranslateError{
			Code:       translator.CodeTranslationFailed,
			HTTPStatus: 500,
			Param:      "response_format",
			Message:    "failed to set tool_choice: " + err.Error(),
		}
	}

	return out, nil
}
