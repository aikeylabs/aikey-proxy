package mcp

// P6 task 6.7 / fence 6.F5 — argument validation.
//
// Two properties, and they pull in opposite directions:
//
//	6.F5   malformed arguments are refused WITH A FIELD PATH, and the upstream
//	       sees ZERO calls
//	safety the validator may only ever produce TRUE rejections — anything it
//	       does not fully understand it must pass
//
// The second is the one that needs guarding hardest. A validator that wrongly
// refuses a valid call breaks a working tool and the developer cannot route
// around it; a validator that wrongly accepts one merely leaves the backend to
// reject it, exactly as today.

import (
	"encoding/json"
	"strings"
	"testing"
)

func paths(vs []SchemaViolation) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Path)
	}
	return out
}

// ---------------------------------------------------------------------------
// true rejections
// ---------------------------------------------------------------------------

func TestSchema_RejectsWithAFieldPath(t *testing.T) {
	const schema = `{
	  "type": "object",
	  "required": ["query", "limit"],
	  "properties": {
	    "query":  {"type": "string", "minLength": 1},
	    "limit":  {"type": "integer", "minimum": 1, "maximum": 100},
	    "mode":   {"type": "string", "enum": ["fast", "thorough"]},
	    "filters": {
	      "type": "array",
	      "items": {"type": "object", "required": ["field"],
	                "properties": {"field": {"type": "string"}}}
	    }
	  }
	}`
	for _, tc := range []struct {
		name, args, wantPath, wantMsg string
	}{
		{"missing required", `{"query":"x"}`, "$.limit", "required"},
		{"wrong type", `{"query":123,"limit":5}`, "$.query", "expected string"},
		{"below minimum", `{"query":"x","limit":0}`, "$.limit", ">= 1"},
		{"above maximum", `{"query":"x","limit":1000}`, "$.limit", "<= 100"},
		{"not in enum", `{"query":"x","limit":5,"mode":"turbo"}`, "$.mode", "permitted values"},
		{"too short", `{"query":"","limit":5}`, "$.query", "at least 1 characters"},
		{"nested array element", `{"query":"x","limit":5,"filters":[{"other":1}]}`, "$.filters[0].field", "required"},
		{"nested wrong type", `{"query":"x","limit":5,"filters":[{"field":9}]}`, "$.filters[0].field", "expected string"},
		{"no arguments at all", ``, "$.limit", "required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateArguments(schema, json.RawMessage(tc.args))
			if len(got) == 0 {
				t.Fatalf("expected a violation, got none")
			}
			var found *SchemaViolation
			for i := range got {
				if got[i].Path == tc.wantPath {
					found = &got[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("no violation at %s; got %v", tc.wantPath, paths(got))
			}
			if !strings.Contains(found.Message, tc.wantMsg) {
				t.Fatalf("message must name the constraint (%q): %q", tc.wantMsg, found.Message)
			}
		})
	}
}

// TestSchema_AdditionalPropertiesOnlyWhenExplicitlyFalse.
//
// 🔴 Absent `additionalProperties` means ALLOWED in JSON Schema. Treating
// absent as false would reject extra keys on most real-world schemas — a false
// rejection on the majority case.
func TestSchema_AdditionalPropertiesOnlyWhenExplicitlyFalse(t *testing.T) {
	strict := `{"type":"object","additionalProperties":false,"properties":{"a":{"type":"string"}}}`
	if got := ValidateArguments(strict, json.RawMessage(`{"a":"x","b":1}`)); len(got) == 0 {
		t.Fatal("additionalProperties:false must reject an unknown key")
	} else if got[0].Path != "$.b" {
		t.Fatalf("the path must name the offending key, got %s", got[0].Path)
	}
	lax := `{"type":"object","properties":{"a":{"type":"string"}}}`
	if got := ValidateArguments(lax, json.RawMessage(`{"a":"x","b":1}`)); len(got) != 0 {
		t.Fatalf("an absent additionalProperties means ALLOWED; got %v", got)
	}
}

// ---------------------------------------------------------------------------
// the safety property — no false rejections
// ---------------------------------------------------------------------------

// TestSchema_NeverRejectsWhatItDoesNotFullyUnderstand is the fence that makes a
// subset validator acceptable at all.
//
// 🔴 Every case here is a VALID call. If any of them is rejected, a working
// tool goes offline and the developer has no way around it.
func TestSchema_NeverRejectsWhatItDoesNotFullyUnderstand(t *testing.T) {
	for _, tc := range []struct{ name, schema, args string }{
		{
			// Alternatives cannot be half-evaluated: `x` satisfies the second
			// branch, and a validator checking only the first would refuse it.
			"anyOf", `{"type":"object","properties":{"x":{"anyOf":[{"type":"number"},{"type":"string"}]}}}`,
			`{"x":"a string"}`,
		},
		{"oneOf", `{"oneOf":[{"type":"object"},{"type":"array"}]}`, `{"anything":true}`},
		{"allOf", `{"allOf":[{"type":"object"}]}`, `{"a":1}`},
		{"not", `{"not":{"type":"string"}}`, `{"a":1}`},
		{"if/then", `{"type":"object","if":{"required":["a"]},"then":{"required":["b"]}}`, `{"a":1}`},
		{
			// A $ref anywhere means the document is not self-contained.
			"$ref", `{"type":"object","properties":{"a":{"$ref":"#/$defs/T"}},"$defs":{"T":{"type":"string"}}}`,
			`{"a":12345}`,
		},
		{"patternProperties", `{"type":"object","patternProperties":{"^x":{"type":"string"}}}`, `{"xa":1}`},
		{
			// A tuple-form `items` has positional semantics this validator does
			// not implement; guessing between the two forms is a false rejection.
			"tuple items", `{"type":"array","items":[{"type":"string"},{"type":"number"}]}`,
			`[1,"two"]`,
		},
		{"union type", `{"type":"object","properties":{"a":{"type":["string","null"]}}}`, `{"a":null}`},
		{"unknown keyword", `{"type":"object","properties":{"a":{"type":"string","format":"uuid"}}}`, `{"a":"not-a-uuid"}`},
		{"pattern is not enforced", `{"type":"object","properties":{"a":{"type":"string","pattern":"^\\d+$"}}}`, `{"a":"abc"}`},
		{"unparseable schema", `{not json`, `{"a":1}`},
		{"empty schema", `{}`, `{"a":1}`},
		{"absent schema", ``, `{"a":1}`},
		{
			// 1.0 IS an integer: JSON has one number type and the spec says a
			// zero fractional part qualifies. Many clients emit it.
			"integer written as 1.0", `{"type":"object","properties":{"n":{"type":"integer"}}}`, `{"n":1.0}`,
		},
		{
			// maxLength counts CHARACTERS. Counting bytes would refuse a
			// four-character Chinese string against maxLength:10.
			"multibyte length", `{"type":"object","properties":{"s":{"type":"string","maxLength":5}}}`,
			`{"s":"你好世界"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidateArguments(tc.schema, json.RawMessage(tc.args)); len(got) != 0 {
				t.Fatalf("🔴 FALSE REJECTION — this is a VALID call and the gateway refused it: %v\n"+
					"A subset validator may only ever produce TRUE rejections; anything it does not "+
					"fully understand must pass.", got)
			}
		})
	}
}

// TestSchema_ANestedCombinatorSkipsTheWholeDocument.
//
// 🔴 The skip is document-wide, not branch-local. "Validate the parts I
// recognise" is exactly the partial evaluation that produces false rejections,
// because a combinator three levels down can change what the outer constraints
// mean.
func TestSchema_ANestedCombinatorSkipsTheWholeDocument(t *testing.T) {
	schema := `{"type":"object","required":["a"],
	            "properties":{"b":{"type":"object","properties":{"c":{"oneOf":[{"type":"string"}]}}}}}`
	// `a` is missing — which the validator WOULD normally catch.
	if got := ValidateArguments(schema, json.RawMessage(`{}`)); len(got) != 0 {
		t.Fatalf("a nested combinator must disable the whole document, got %v", got)
	}
}

// TestSchema_ViolationsAreCappedAndOrdered — the consumer is a model with a
// context window; two hundred violations for one mistake is unusable.
func TestSchema_ViolationsAreCappedAndOrdered(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"type":"object","required":[`)
	for i := 0; i < 40; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"f` + string(rune('a'+i%26)) + string(rune('0'+i/26)) + `"`)
	}
	b.WriteString(`]}`)
	got := ValidateArguments(b.String(), json.RawMessage(`{}`))
	if len(got) == 0 || len(got) > maxSchemaViolations {
		t.Fatalf("want 1..%d violations, got %d", maxSchemaViolations, len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Path > got[i].Path {
			t.Fatalf("violations must be ordered for a stable message: %v", paths(got))
		}
	}
}

// TestSchema_OneMistakeProducesOneMessage.
//
// 🔴 The consumer is a model. Reporting "not one of the permitted values" AND
// "too short" for the same wrong word is two messages about one mistake, and
// fixing the second does not fix the call — which is how a model ends up
// looping on the wrong correction.
//
// 🔴 The ENUM early-return is what this guards. An earlier version of this test
// used a TYPE mismatch instead, and the drill showed that case is protected by
// the type switch anyway — the assertion passed for a reason unrelated to the
// code it claimed to fence.
func TestSchema_OneMistakeProducesOneMessage(t *testing.T) {
	schema := `{"type":"object","properties":{"mode":{"type":"string","enum":["thorough"],"minLength":5}}}`
	got := ValidateArguments(schema, json.RawMessage(`{"mode":"xy"}`))
	if len(got) != 1 {
		t.Fatalf("one wrong value must produce ONE violation, not that plus every other "+
			"constraint it also happens to miss: %v", got)
	}
	if !strings.Contains(got[0].Message, "permitted values") {
		t.Fatalf("the reported violation must be the primary one: %q", got[0].Message)
	}
}
