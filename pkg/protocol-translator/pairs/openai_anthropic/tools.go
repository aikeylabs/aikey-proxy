package openai_anthropic

import (
	"strings"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// tools.go — OpenAI tools[] + tool_choice → Anthropic tools[] + tool_choice.
//
// OpenAI shape:
//
//	{
//	  "tools": [{
//	    "type": "function",
//	    "function": {
//	      "name": "get_weather",
//	      "description": "...",
//	      "parameters": { "type": "object", ... }
//	    }
//	  }],
//	  "tool_choice": "auto" | "required" | "none" | {"type": "function", "function": {"name": "..."}}
//	}
//
// Anthropic shape:
//
//	{
//	  "tools": [{
//	    "name": "get_weather",
//	    "description": "...",
//	    "input_schema": { "type": "object", ... }
//	  }],
//	  "tool_choice": {"type": "auto"} | {"type": "any"} | {"type": "none"} | {"type": "tool", "name": "..."}
//	}
//
// Key differences pinned by this file:
//   - Strip OpenAI's wrapping `{type:function, function:{...}}` — Anthropic
//     puts name + description + input_schema directly on each tool entry.
//   - Rename `parameters` → `input_schema`. Auto-add `"type":"object"`
//     if missing — Anthropic 400 otherwise.
//   - tool_choice value forms map per the table above.
//
// Day 5 will add parallel_tool_calls reverse (`parallel_tool_calls=false`
// → `tool_choice.disable_parallel_tool_use=true`) + the
// "tool_choice=none + disable_parallel_tool_use" special case (new-api
//踩坑: Anthropic 400s if disable_parallel_tool_use is present when
// tool_choice.type==none).

// convertTools transforms OpenAI tools[] into Anthropic tools[].
// Returns the JSON array literal (e.g. `[{...},{...}]`), or nil if
// the inbound request had no tools.
//
// Errors:
//   - Unknown tool type (currently only "function" is supported by
//     either side; OpenAI's "code_interpreter" / "file_search" /
//     "web_search" are server-side tools not exposed to bring-your-own
//     models on Anthropic).
//   - Missing function.name (Anthropic requires name).
func convertTools(inTools gjson.Result) ([]byte, *translator.TranslateError) {
	if !inTools.Exists() || !inTools.IsArray() {
		return nil, nil
	}
	arr := inTools.Array()
	if len(arr) == 0 {
		return nil, nil
	}
	var entries []string
	for i, t := range arr {
		typ := t.Get("type").String()
		if typ != "function" && typ != "" {
			// Empty string treated as default-function for liberal
			// clients that omit type (OpenAI accepts that).
			return nil, &translator.TranslateError{
				Code:       translator.CodeUnsupportedParam,
				HTTPStatus: 400,
				Param:      "tools",
				Message: "tools[" + strconvIToA(i) + "].type=" + jsonQuote(typ) +
					` not supported; only "function" is portable to Anthropic`,
			}
		}
		name := t.Get("function.name").String()
		if name == "" {
			return nil, &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "tools",
				Message:    "tools[" + strconvIToA(i) + "].function.name is required",
			}
		}
		desc := t.Get("function.description").String() // optional
		// parameters → input_schema. Anthropic requires the schema to
		// have type=object at the top level; auto-add when missing
		// since OpenAI accepts no-type schemas (treated as object).
		params := t.Get("function.parameters")
		var inputSchemaRaw string
		if params.Exists() {
			inputSchemaRaw = params.Raw
			if gjson.Get(inputSchemaRaw, "type").String() == "" {
				// Inject "type":"object" at the top of the schema.
				// sjson.SetRawBytes preserves the rest of the object.
				patched, err := setRawAtKey([]byte(inputSchemaRaw), "type", []byte(`"object"`))
				if err == nil {
					inputSchemaRaw = string(patched)
				}
			}
		} else {
			// No schema at all → empty object schema. Anthropic accepts
			// {"type":"object"} with no properties for parameter-less tools.
			inputSchemaRaw = `{"type":"object"}`
		}
		// Compose entry.
		var b strings.Builder
		b.WriteByte('{')
		b.WriteString(`"name":`)
		b.WriteString(jsonQuote(name))
		if desc != "" {
			b.WriteString(`,"description":`)
			b.WriteString(jsonQuote(desc))
		}
		b.WriteString(`,"input_schema":`)
		b.WriteString(inputSchemaRaw)
		b.WriteByte('}')
		entries = append(entries, b.String())
	}
	return []byte("[" + strings.Join(entries, ",") + "]"), nil
}

// convertToolChoice transforms OpenAI tool_choice (string OR object)
// into Anthropic tool_choice (object). Returns the JSON object literal
// (e.g. `{"type":"auto"}`), or nil if the inbound request had no
// tool_choice field.
//
// Mapping table (OpenAI → Anthropic):
//
//	"auto"                                  → {"type":"auto"}
//	"required"                              → {"type":"any"}
//	"none"                                  → {"type":"none"}
//	{"type":"function","function":{name}}   → {"type":"tool","name":"..."}
//
// Anthropic doesn't have a "required" type — they use "any" which means
// "must call any tool" (same semantics as OpenAI's "required"). Tested
// against actual upstream behavior 2026-05; LiteLLM uses the same mapping.
//
// Day 5 will add the parallel_tool_calls integration (disable_parallel_tool_use
// added when parallel_tool_calls=false EXCEPT when tool_choice is "none").
func convertToolChoice(inToolChoice gjson.Result) ([]byte, *translator.TranslateError) {
	if !inToolChoice.Exists() {
		return nil, nil
	}
	if inToolChoice.Type == gjson.String {
		switch inToolChoice.String() {
		case "auto":
			return []byte(`{"type":"auto"}`), nil
		case "required":
			return []byte(`{"type":"any"}`), nil
		case "none":
			return []byte(`{"type":"none"}`), nil
		default:
			return nil, &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "tool_choice",
				Message: "tool_choice string value " + jsonQuote(inToolChoice.String()) +
					` not recognized (expected: "auto" / "required" / "none")`,
			}
		}
	}
	if inToolChoice.IsObject() {
		typ := inToolChoice.Get("type").String()
		switch typ {
		case "function":
			name := inToolChoice.Get("function.name").String()
			if name == "" {
				return nil, &translator.TranslateError{
					Code:       translator.CodeBadRequest,
					HTTPStatus: 400,
					Param:      "tool_choice",
					Message:    "tool_choice.function.name is required when tool_choice.type is function",
				}
			}
			return []byte(`{"type":"tool","name":` + jsonQuote(name) + `}`), nil
		case "auto":
			return []byte(`{"type":"auto"}`), nil
		case "required":
			return []byte(`{"type":"any"}`), nil
		case "none":
			return []byte(`{"type":"none"}`), nil
		default:
			return nil, &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "tool_choice",
				Message: "tool_choice.type=" + jsonQuote(typ) +
					` not recognized (expected: "auto" / "required" / "none" / "function")`,
			}
		}
	}
	return nil, &translator.TranslateError{
		Code:       translator.CodeBadRequest,
		HTTPStatus: 400,
		Param:      "tool_choice",
		Message:    "tool_choice must be a string or object",
	}
}

// setRawAtKey injects (or replaces) the value at `key` in a JSON object
// with the given raw-JSON bytes. Used by convertTools to add
// `"type":"object"` to parameter schemas missing the type field. Unlike
// sjsonSetRawMust in request.go this returns errors so the caller can
// distinguish "patch failed" from "patched OK" — important when the
// input is user-provided (tool schemas) rather than our own skeleton.
func setRawAtKey(body []byte, key string, valueRaw []byte) ([]byte, error) {
	return sjson.SetRawBytes(body, key, valueRaw)
}

// applyParallelToolCalls handles OpenAI's `parallel_tool_calls=false` →
// Anthropic's `tool_choice.disable_parallel_tool_use=true`.
//
// Default behavior (OpenAI default true / Anthropic default no field
// = parallel allowed): no-op.
//
// When the inbound has `parallel_tool_calls=false`, we set
// `tool_choice.disable_parallel_tool_use=true` to make Anthropic
// behave the same way — BUT with one critical exception:
//
//   - If `tool_choice.type=="none"`, we MUST NOT add disable_parallel_tool_use.
//     Anthropic 400s on this combination (new-api踩坑 reference:
//     relay-claude.go L962-1011). The reasoning is that "force no tools
//     + restrict parallel tool use" is contradictory — Anthropic
//     rejects the inconsistent semantic.
//
// Also no-op when no tool_choice exists yet (means caller didn't set
// tools either — disable_parallel_tool_use without tools is meaningless
// and may be rejected by future Anthropic API versions).
//
// Called AFTER convertToolChoice has populated tool_choice — the
// "tool_choice=none" case here detects whichever path produced the
// none type (explicit string "none" or object form, or potentially
// future special-cases).
func applyParallelToolCalls(body []byte, in gjson.Result) []byte {
	ptc := in.Get("parallel_tool_calls")
	if !ptc.Exists() {
		return body
	}
	if ptc.Bool() {
		// parallel_tool_calls=true is OpenAI's default and matches
		// Anthropic's default. Don't emit a field.
		return body
	}
	// parallel_tool_calls=false → disable_parallel_tool_use=true.
	// Defensive guards:
	tc := gjson.GetBytes(body, "tool_choice")
	if !tc.Exists() {
		// No tool_choice means no tools either; nothing to disable.
		return body
	}
	if tc.Get("type").String() == "none" {
		// Anthropic 400 on (tool_choice.type=none + disable_parallel_tool_use).
		// Skip the disable; the "force no tools" already prevents
		// parallel tool calls trivially.
		return body
	}
	out, err := sjson.SetBytes(body, "tool_choice.disable_parallel_tool_use", true)
	if err != nil {
		// Shouldn't happen — tool_choice is a structurally valid object
		// at this point. Defensive: return unchanged.
		return body
	}
	return out
}
