package mcp

// schema.go — P6 task 6.7. Validating a tool call's arguments against the
// tool's own `inputSchema` BEFORE the backend is contacted.
//
// # What this is for
//
// Two things, and the second is the one that pays for it:
//
//  1. The model gets a precise field path back, so it can fix the call itself
//     instead of retrying the same broken arguments.
//  2. 🔴 Malformed arguments never reach the customer's production database.
//     That is the requirement (R6, fence 6.F5: "upstream zero calls"), and it
//     is why validation happens here rather than being left to the backend.
//
// # 🔴 Why this is a SUBSET validator, and why that is the safe direction
//
// There is no JSON Schema library in this module, and adding one to a
// product that ships into air-gapped customer networks is a supply-chain
// decision, not an implementation detail. So this validates a deliberate
// subset — and the design rule that makes a subset acceptable is:
//
//	🔴 IT MAY ONLY EVER PRODUCE **TRUE** REJECTIONS.
//
// Anything it does not fully understand, it passes. A validator that wrongly
// REJECTS a valid call is strictly worse than no validator at all: it breaks
// working tools, and the developer cannot route around it. A validator that
// wrongly ACCEPTS one merely leaves us where we were — the backend still
// rejects it, exactly as it does today.
//
// Concretely, that means every combinator whose semantics depend on evaluating
// alternatives — `$ref`, `oneOf`, `anyOf`, `allOf`, `not`, `if`/`then`/`else` —
// causes the whole subtree to be SKIPPED rather than partially evaluated.
// Half-evaluating `anyOf` is precisely how a correct call gets refused.
//
// Fence: TestSchema_NeverRejectsWhatItDoesNotFullyUnderstand.
//
// # What it does check
//
//	type              object / array / string / number / integer / boolean / null
//	required          named properties present on an object
//	properties        recursively, by name
//	additionalProperties: false   → unknown keys are a violation
//	enum              value is one of the listed constants
//	minimum/maximum   numeric bounds (inclusive)
//	minLength/maxLength, minItems/maxItems
//	items             recursively, for arrays
//
// That set is what MCP tool schemas overwhelmingly consist of, and each rule
// above can be decided from the value alone — no alternatives to weigh.

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

// SchemaViolation is one problem with the arguments.
//
// 🔴 Path is the whole point of the type. "arguments are invalid" tells a model
// nothing it can act on; `$.filters[0].since` tells it exactly what to fix,
// which is the difference between one retry and an infinite loop.
type SchemaViolation struct {
	// Path is a JSONPath-ish pointer into the arguments, always starting at `$`.
	Path string `json:"path"`
	// Message says what is wrong, in the terms the schema used.
	Message string `json:"message"`
}

func (v SchemaViolation) String() string { return v.Path + ": " + v.Message }

// maxSchemaViolations caps how many problems are reported.
//
// 🔴 A cap, because the consumer is a model with a context window: handing back
// two hundred violations for one wrong type is how a useful error becomes an
// unusable wall of text. The first few are the actionable ones.
const maxSchemaViolations = 10

// ValidateArguments checks args against schema.
//
// Returns nil when the arguments are acceptable OR when the schema is one this
// validator will not judge (see the file header). An empty/absent schema means
// "no constraints" — 🔴 NOT "reject everything": a tool whose schema we could
// not read must keep working exactly as it did before this file existed.
func ValidateArguments(schema string, args json.RawMessage) []SchemaViolation {
	schema = strings.TrimSpace(schema)
	if schema == "" || schema == "{}" || schema == "null" {
		return nil
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(schema), &root); err != nil {
		// 🔴 An unparseable schema is OUR problem or the backend's, never the
		// caller's. Refusing the call here would take a working tool offline
		// because of a manifest we failed to read.
		return nil
	}
	if containsUnsupportedCombinator(root) {
		return nil
	}

	var value any
	if len(args) > 0 {
		if err := json.Unmarshal(args, &value); err != nil {
			return []SchemaViolation{{Path: "$", Message: "arguments are not valid JSON"}}
		}
	}
	v := &schemaValidator{}
	v.check("$", root, value, len(args) > 0)
	sort.SliceStable(v.out, func(i, j int) bool { return v.out[i].Path < v.out[j].Path })
	if len(v.out) > maxSchemaViolations {
		v.out = v.out[:maxSchemaViolations]
	}
	return v.out
}

// containsUnsupportedCombinator reports whether the schema uses anything whose
// meaning depends on weighing alternatives.
//
// 🔴 Searched RECURSIVELY and applied to the WHOLE schema, not just the branch
// containing it. A `oneOf` nested three levels down still means this validator
// cannot reason about the document as a whole — and "validate the parts I
// recognise" is exactly the partial evaluation that produces false rejections.
func containsUnsupportedCombinator(node any) bool {
	switch n := node.(type) {
	case map[string]any:
		for _, kw := range []string{"$ref", "oneOf", "anyOf", "allOf", "not", "if", "then", "else", "dependentSchemas", "patternProperties"} {
			if _, present := n[kw]; present {
				return true
			}
		}
		for _, v := range n {
			if containsUnsupportedCombinator(v) {
				return true
			}
		}
	case []any:
		for _, v := range n {
			if containsUnsupportedCombinator(v) {
				return true
			}
		}
	}
	return false
}

type schemaValidator struct{ out []SchemaViolation }

func (v *schemaValidator) add(path, msg string) {
	if len(v.out) >= maxSchemaViolations*4 { // hard stop; the caller trims
		return
	}
	v.out = append(v.out, SchemaViolation{Path: path, Message: msg})
}

// check validates one value against one schema node.
//
// present=false means the caller sent no arguments at all, which is different
// from sending `{}`: a tool with no required properties accepts both, and a
// tool WITH required properties must reject both the same way.
func (v *schemaValidator) check(path string, schema map[string]any, value any, present bool) {
	if !present {
		value = map[string]any{} // an absent argument object is an empty one
	}
	if want, ok := schema["type"].(string); ok && !typeMatches(want, value) {
		v.add(path, fmt.Sprintf("expected %s, got %s", want, jsonTypeName(value)))
		// 🔴 Stop descending on a type mismatch. Reporting "expected object" AND
		// "missing required field x" for the same string is two messages about
		// one mistake, and the second is nonsense.
		return
	}
	if enum, ok := schema["enum"].([]any); ok && len(enum) > 0 && !enumContains(enum, value) {
		v.add(path, "value is not one of the permitted values: "+describeEnum(enum))
		return
	}

	switch typed := value.(type) {
	case map[string]any:
		v.checkObject(path, schema, typed)
	case []any:
		v.checkArray(path, schema, typed)
	case string:
		v.checkString(path, schema, typed)
	case float64:
		v.checkNumber(path, schema, typed)
	}
}

func (v *schemaValidator) checkObject(path string, schema map[string]any, obj map[string]any) {
	props, _ := schema["properties"].(map[string]any)

	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			name, isStr := r.(string)
			if !isStr {
				continue
			}
			if _, found := obj[name]; !found {
				v.add(childPath(path, name), "required property is missing")
			}
		}
	}
	// additionalProperties:false — an unknown key is a violation. 🔴 Only when
	// EXPLICITLY false: absent means "allowed" in JSON Schema, and treating
	// absent as false would reject valid calls on most real schemas.
	if extra, ok := schema["additionalProperties"].(bool); ok && !extra && props != nil {
		for name := range obj {
			if _, known := props[name]; !known {
				v.add(childPath(path, name), "unknown property (this tool's schema does not allow extra properties)")
			}
		}
	}
	for name, raw := range obj {
		sub, ok := props[name].(map[string]any)
		if !ok {
			continue
		}
		v.check(childPath(path, name), sub, raw, true)
	}
}

func (v *schemaValidator) checkArray(path string, schema map[string]any, arr []any) {
	if n, ok := numberOf(schema["minItems"]); ok && float64(len(arr)) < n {
		v.add(path, fmt.Sprintf("expected at least %s items, got %d", trimNum(n), len(arr)))
	}
	if n, ok := numberOf(schema["maxItems"]); ok && float64(len(arr)) > n {
		v.add(path, fmt.Sprintf("expected at most %s items, got %d", trimNum(n), len(arr)))
	}
	// `items` as a single schema (2020-12 style). An ARRAY-valued `items`
	// (draft-07 tuple form) is skipped: positional semantics are a different
	// rule, and guessing between the two is how a valid tuple gets rejected.
	sub, ok := schema["items"].(map[string]any)
	if !ok {
		return
	}
	for i, item := range arr {
		v.check(fmt.Sprintf("%s[%d]", path, i), sub, item, true)
	}
}

func (v *schemaValidator) checkString(path string, schema map[string]any, s string) {
	// 🔴 Counted in RUNES, not bytes. A schema saying maxLength:10 means ten
	// characters; rejecting a ten-character Chinese string as "too long" is a
	// false rejection, and this product's customers are largely Chinese-speaking.
	n := float64(len([]rune(s)))
	if m, ok := numberOf(schema["minLength"]); ok && n < m {
		v.add(path, fmt.Sprintf("expected at least %s characters, got %d", trimNum(m), int(n)))
	}
	if m, ok := numberOf(schema["maxLength"]); ok && n > m {
		v.add(path, fmt.Sprintf("expected at most %s characters, got %d", trimNum(m), int(n)))
	}
	// `pattern` is deliberately NOT enforced: JSON Schema specifies ECMA-262
	// regexes and Go's RE2 rejects constructs ECMA-262 allows (backreferences,
	// lookaround). A pattern we cannot compile would become a false rejection.
}

func (v *schemaValidator) checkNumber(path string, schema map[string]any, f float64) {
	if m, ok := numberOf(schema["minimum"]); ok && f < m {
		v.add(path, fmt.Sprintf("expected a value >= %s, got %s", trimNum(m), trimNum(f)))
	}
	if m, ok := numberOf(schema["maximum"]); ok && f > m {
		v.add(path, fmt.Sprintf("expected a value <= %s, got %s", trimNum(m), trimNum(f)))
	}
}

// typeMatches implements JSON Schema's type names against Go's decoded values.
func typeMatches(want string, value any) bool {
	switch want {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	case "number":
		_, ok := value.(float64)
		return ok
	case "integer":
		// 🔴 JSON has one number type, so `1.0` IS an integer per the spec's
		// own wording ("a number with a zero fractional part"). Rejecting it
		// would refuse arguments many clients legitimately produce.
		f, ok := value.(float64)
		return ok && f == math.Trunc(f) && !math.IsInf(f, 0)
	}
	// An unrecognised type keyword (or a type ARRAY, e.g. ["string","null"]) is
	// not judged — the safe direction.
	return true
}

func jsonTypeName(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case nil:
		return "null"
	}
	return "unknown"
}

func enumContains(enum []any, value any) bool {
	want, err := json.Marshal(value)
	if err != nil {
		return true // cannot compare → do not reject
	}
	for _, e := range enum {
		got, err := json.Marshal(e)
		if err == nil && string(got) == string(want) {
			return true
		}
	}
	return false
}

func describeEnum(enum []any) string {
	parts := make([]string, 0, len(enum))
	for i, e := range enum {
		if i == 5 {
			parts = append(parts, "…")
			break
		}
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		parts = append(parts, string(b))
	}
	return strings.Join(parts, ", ")
}

func numberOf(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func trimNum(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}

// childPath renders a property access, quoting names that are not plain
// identifiers so the path stays unambiguous.
func childPath(parent, name string) string {
	if isPlainIdentifier(name) {
		return parent + "." + name
	}
	b, err := json.Marshal(name)
	if err != nil {
		return parent + "[?]"
	}
	return parent + "[" + string(b) + "]"
}

func isPlainIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
