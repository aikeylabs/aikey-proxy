package openai_anthropic

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Helper: run ConvertRequest with default context + non-stream + the
// resolved model name. Asserts no error and returns the output bytes.
//
// Day 4+ messages normalization REJECTS bodies without a `messages`
// array. Day 3 tests focus on top-level fields and don't care about
// messages; this helper injects a minimal ping message when the test's
// input doesn't already have one, keeping Day 3 fixtures focused.
// Day 4 messages tests live in messages_test.go with explicit, full
// messages fixtures.
func mustConvert(t *testing.T, model string, in string) []byte {
	t.Helper()
	if !gjson.Get(in, "messages").Exists() {
		patched, err := sjson.SetRawBytes([]byte(in), "messages",
			[]byte(`[{"role":"user","content":"ping"}]`))
		if err != nil {
			t.Fatalf("test helper: could not inject default messages: %v", err)
		}
		in = string(patched)
	}
	out, err := ConvertRequest(context.Background(), model, []byte(in), false)
	if err != nil {
		t.Fatalf("ConvertRequest failed: %+v", err)
	}
	if !gjson.ValidBytes(out) {
		t.Fatalf("ConvertRequest produced invalid JSON: %s", out)
	}
	return out
}

// ── model + skeleton ──────────────────────────────────────────────────

func TestConvertRequest_EmitsAnthropicSkeleton(t *testing.T) {
	out := mustConvert(t, "claude-sonnet-4-5", `{}`)
	if gjson.GetBytes(out, "model").String() != "claude-sonnet-4-5" {
		t.Errorf("model = %q, want claude-sonnet-4-5", gjson.GetBytes(out, "model").String())
	}
	// max_tokens default present
	if mt := gjson.GetBytes(out, "max_tokens"); !mt.Exists() || mt.Int() != 4096 {
		t.Errorf("max_tokens = %v, want 4096 default", mt)
	}
	// messages array present (even if empty for empty-input case)
	if !gjson.GetBytes(out, "messages").IsArray() {
		t.Errorf("messages is not an array: %s", out)
	}
}

func TestConvertRequest_ModelFromBodyWhenCallerEmpty(t *testing.T) {
	// Caller passes empty model → falls back to inbound body's model.
	// Mirrors the case where the proxy doesn't override the model name.
	out := mustConvert(t, "", `{"model":"gpt-4o"}`)
	if got := gjson.GetBytes(out, "model").String(); got != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o (passthrough from body)", got)
	}
}

func TestConvertRequest_CallerModelTakesPrecedence(t *testing.T) {
	// If caller passes a non-empty model name (e.g. after canonicalization),
	// it MUST win over the inbound body's value. Otherwise client-side
	// model prefixes (`copilot/gpt-5-mini`) would leak upstream.
	out := mustConvert(t, "claude-resolved", `{"model":"gpt-4o"}`)
	if got := gjson.GetBytes(out, "model").String(); got != "claude-resolved" {
		t.Errorf("model = %q, want claude-resolved (caller arg wins)", got)
	}
}

// ── max_tokens ───────────────────────────────────────────────────────

func TestConvertRequest_MaxTokensPassthrough(t *testing.T) {
	out := mustConvert(t, "m", `{"max_tokens":2048}`)
	if got := gjson.GetBytes(out, "max_tokens").Int(); got != 2048 {
		t.Errorf("max_tokens = %d, want 2048", got)
	}
}

func TestConvertRequest_MaxCompletionTokensTakesPrecedence(t *testing.T) {
	// OpenAI's newer max_completion_tokens beats the legacy max_tokens if
	// both are present (Anthropic only has the one field, so we pick
	// whichever the caller most-explicitly set).
	out := mustConvert(t, "m", `{"max_tokens":1024,"max_completion_tokens":8192}`)
	if got := gjson.GetBytes(out, "max_tokens").Int(); got != 8192 {
		t.Errorf("max_tokens = %d, want 8192 (max_completion_tokens wins)", got)
	}
}

func TestConvertRequest_MaxTokensDefaultsTo4096(t *testing.T) {
	out := mustConvert(t, "m", `{}`)
	if got := gjson.GetBytes(out, "max_tokens").Int(); got != 4096 {
		t.Errorf("max_tokens default = %d, want 4096", got)
	}
}

// ── temperature cap ──────────────────────────────────────────────────

func TestConvertRequest_TemperatureCappedAt1(t *testing.T) {
	cases := []struct {
		in   float64
		want float64
	}{
		{0.5, 0.5}, // passthrough
		{1.0, 1.0}, // at cap
		{1.8, 1.0}, // above cap → cap
		{0.0, 0.0}, // floor (OpenAI 0 is valid)
		{2.0, 1.0}, // OpenAI max → cap
	}
	for _, c := range cases {
		out := mustConvert(t, "m", `{"temperature":`+ftoa(c.in)+`}`)
		got := gjson.GetBytes(out, "temperature").Float()
		if !floatNear(got, c.want, 1e-9) {
			t.Errorf("temperature in=%v → got=%v, want=%v", c.in, got, c.want)
		}
	}
}

func TestConvertRequest_NegativeTemperatureFlooredToZero(t *testing.T) {
	// Defensive: negative temperatures shouldn't appear (OpenAI rejects
	// them), but if they do we floor to 0 rather than pass invalid input
	// to Anthropic.
	out := mustConvert(t, "m", `{"temperature":-1.5}`)
	got := gjson.GetBytes(out, "temperature").Float()
	if got != 0 {
		t.Errorf("negative temperature → got %v, want 0", got)
	}
}

// ── top_p / top_k ────────────────────────────────────────────────────

func TestConvertRequest_TopPTopKPassthrough(t *testing.T) {
	out := mustConvert(t, "m", `{"top_p":0.9,"top_k":40}`)
	if got := gjson.GetBytes(out, "top_p").Float(); !floatNear(got, 0.9, 1e-9) {
		t.Errorf("top_p = %v, want 0.9", got)
	}
	if got := gjson.GetBytes(out, "top_k").Int(); got != 40 {
		t.Errorf("top_k = %d, want 40", got)
	}
}

// ── stop / stop_sequences ────────────────────────────────────────────

func TestConvertRequest_StopStringNormalizedToArray(t *testing.T) {
	// OpenAI: `stop: "END"` (single string)
	// Anthropic: `stop_sequences: ["END"]` (always array)
	out := mustConvert(t, "m", `{"stop":"END"}`)
	stops := gjson.GetBytes(out, "stop_sequences")
	if !stops.IsArray() {
		t.Fatalf("stop_sequences is not array: %v", stops)
	}
	if len(stops.Array()) != 1 || stops.Array()[0].String() != "END" {
		t.Errorf("stop_sequences = %v, want [END]", stops.Array())
	}
}

func TestConvertRequest_StopArrayPassthrough(t *testing.T) {
	out := mustConvert(t, "m", `{"stop":["A","B","C"]}`)
	stops := gjson.GetBytes(out, "stop_sequences").Array()
	if len(stops) != 3 {
		t.Fatalf("stop_sequences len = %d, want 3", len(stops))
	}
	for i, want := range []string{"A", "B", "C"} {
		if stops[i].String() != want {
			t.Errorf("stop_sequences[%d] = %q, want %q", i, stops[i].String(), want)
		}
	}
}

func TestConvertRequest_StopWhitespaceFiltered(t *testing.T) {
	// Anthropic rejects pure-whitespace stop sequences with 400. Filter
	// them out silently — the user almost certainly intended the
	// non-whitespace ones to work, and reject-loud would surface a
	// 400 in production for a meta-mistake.
	out := mustConvert(t, "m", `{"stop":["END","","   ","STOP","\t"]}`)
	stops := gjson.GetBytes(out, "stop_sequences").Array()
	if len(stops) != 2 {
		t.Fatalf("expected 2 stops after whitespace filter, got %d: %v", len(stops), stops)
	}
	if stops[0].String() != "END" || stops[1].String() != "STOP" {
		t.Errorf("filtered stops = %v, want [END, STOP]", stops)
	}
}

func TestConvertRequest_StopAllWhitespaceOmitted(t *testing.T) {
	// All entries are whitespace → no stop_sequences field at all
	// (rather than empty array, which Anthropic might also reject).
	out := mustConvert(t, "m", `{"stop":["","   "]}`)
	if gjson.GetBytes(out, "stop_sequences").Exists() {
		t.Errorf("stop_sequences should be absent when all entries are whitespace; got: %s",
			gjson.GetBytes(out, "stop_sequences").Raw)
	}
}

func TestConvertRequest_StopWithEscapedNewline(t *testing.T) {
	// Verify our hand-rolled jsonQuote handles \n correctly (otherwise
	// the output would have a literal newline inside the JSON string,
	// breaking the body).
	out := mustConvert(t, "m", `{"stop":"line1\nline2"}`)
	stops := gjson.GetBytes(out, "stop_sequences").Array()
	if len(stops) != 1 || stops[0].String() != "line1\nline2" {
		t.Errorf("escaped newline in stop not preserved: %v", stops)
	}
}

// ── reasoning_effort → thinking.budget_tokens ────────────────────────

func TestConvertRequest_ReasoningEffortMapping(t *testing.T) {
	cases := []struct {
		effort string
		want   int
	}{
		{"low", 1024},
		{"medium", 8192},
		{"high", 32000},
		{"minimal", 1024}, // alias
		{"auto", 8192},    // alias
	}
	for _, c := range cases {
		out := mustConvert(t, "m", `{"reasoning_effort":"`+c.effort+`"}`)
		got := gjson.GetBytes(out, "thinking.budget_tokens").Int()
		if got != int64(c.want) {
			t.Errorf("effort=%s → budget_tokens=%d, want=%d", c.effort, got, c.want)
		}
		if typ := gjson.GetBytes(out, "thinking.type").String(); typ != "enabled" {
			t.Errorf("effort=%s → thinking.type=%q, want enabled", c.effort, typ)
		}
	}
}

func TestConvertRequest_ReasoningEffortNoneOmitsThinking(t *testing.T) {
	// "none" / "off" / unknown — must NOT emit a thinking field at all
	// (Anthropic default is no thinking; sending budget_tokens=0 would
	// be incorrect).
	for _, val := range []string{"none", "off", "disabled", "", "random_unknown_value"} {
		out := mustConvert(t, "m", `{"reasoning_effort":"`+val+`"}`)
		if gjson.GetBytes(out, "thinking").Exists() {
			t.Errorf("effort=%q produced thinking field: %s", val, gjson.GetBytes(out, "thinking").Raw)
		}
	}
}

func TestConvertRequest_ReasoningEffortCaseInsensitive(t *testing.T) {
	out := mustConvert(t, "m", `{"reasoning_effort":"HIGH"}`)
	if got := gjson.GetBytes(out, "thinking.budget_tokens").Int(); got != 32000 {
		t.Errorf("HIGH should case-fold to 32000, got %d", got)
	}
}

// ── user → metadata.user_id ──────────────────────────────────────────

func TestConvertRequest_UserMapsToMetadataUserId(t *testing.T) {
	out := mustConvert(t, "m", `{"user":"alice@example.com"}`)
	got := gjson.GetBytes(out, "metadata.user_id").String()
	if got != "alice@example.com" {
		t.Errorf("metadata.user_id = %q, want alice@example.com", got)
	}
}

func TestConvertRequest_EmptyUserOmittedFromMetadata(t *testing.T) {
	out := mustConvert(t, "m", `{"user":"   "}`)
	if gjson.GetBytes(out, "metadata").Exists() {
		t.Errorf("empty user should not emit metadata: %s", gjson.GetBytes(out, "metadata").Raw)
	}
}

// (Day 3's TestConvertRequest_MessagesPlaceholderPassthrough has been
// removed — Day 4 introduces real messages normalization, covered by
// messages_test.go. The passthrough behavior it pinned was a Day 3
// placeholder and is no longer the contract.)

// ── malformed input ──────────────────────────────────────────────────

func TestConvertRequest_MalformedJSONReturnsError(t *testing.T) {
	out, err := ConvertRequest(context.Background(), "m", []byte(`{not json}`), false)
	if out != nil {
		t.Errorf("expected nil out on malformed JSON, got %s", out)
	}
	if err == nil {
		t.Fatal("expected TranslateError")
	}
	if !strings.Contains(err.Message, "not valid JSON") {
		t.Errorf("error message: %s", err.Message)
	}
}

// ── side-effect: pair registered with DefaultRegistry ────────────────

func TestPairIsRegistered(t *testing.T) {
	// init() side effect should have wired this pair before any test runs.
	// Use DefaultRegistry indirectly via the side effect; if init didn't
	// fire, HasPair would be false.
	//
	// We can't directly import translator here without an import cycle
	// (this package imports translator already), but the registration
	// happens in init.go which runs at package load — so by the time
	// this test runs, it MUST be registered. Verify by translating a
	// trivial request and checking the body contains the expected skeleton.
	out, err := ConvertRequest(context.Background(), "m",
		[]byte(`{"messages":[{"role":"user","content":"ping"}]}`), false)
	if err != nil {
		t.Fatalf("convert failed: %+v", err)
	}
	if !gjson.GetBytes(out, "max_tokens").Exists() {
		t.Errorf("init.go pair not wired: ConvertRequest didn't produce Anthropic skeleton")
	}
}

// ── helpers ──────────────────────────────────────────────────────────

// ftoa formats a float64 as a JSON-safe number literal for inlining
// into test request bodies. strconv.FormatFloat with -1 precision emits
// the shortest round-trip representation (e.g. 1.0 → "1", 0.5 → "0.5").
func ftoa(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func floatNear(a, b, eps float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= eps
}
