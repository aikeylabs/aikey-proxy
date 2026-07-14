package conversation_audit

import "testing"

// --- prompt extraction (request body) --------------------------------------

func TestExtractPrompt_Anthropic_StringAndBlocks(t *testing.T) {
	// Anthropic: system is a string, content is a string; latest user wins.
	body := []byte(`{
		"model":"claude-x",
		"system":"You are helpful.",
		"messages":[
			{"role":"user","content":"first"},
			{"role":"assistant","content":"ok"},
			{"role":"user","content":"second"}
		]
	}`)
	user, sys, model := extractPrompt(protoAnthropic, body)
	if user != "second" {
		t.Fatalf("user=%q want latest user turn %q", user, "second")
	}
	if sys != "You are helpful." {
		t.Fatalf("system=%q want %q", sys, "You are helpful.")
	}
	if model != "claude-x" {
		t.Fatalf("model=%q want claude-x (parsed once with prompt)", model)
	}

	// Block-array form for both system and content.
	body2 := []byte(`{
		"system":[{"type":"text","text":"sys-a"},{"type":"text","text":"sys-b"}],
		"messages":[{"role":"user","content":[{"type":"text","text":"hello"},{"type":"image","source":{}}]}]
	}`)
	user2, sys2, _ := extractPrompt(protoAnthropic, body2)
	if user2 != "hello" {
		t.Fatalf("user2=%q want %q (image block skipped)", user2, "hello")
	}
	if sys2 != "sys-a\nsys-b" {
		t.Fatalf("sys2=%q want joined text blocks", sys2)
	}
}

func TestExtractPrompt_OpenAI(t *testing.T) {
	body := []byte(`{
		"model":"gpt-x",
		"messages":[
			{"role":"system","content":"sys"},
			{"role":"user","content":"u1"},
			{"role":"assistant","content":"a1"},
			{"role":"user","content":"u2"}
		]
	}`)
	user, sys, model := extractPrompt(protoOpenAI, body)
	if user != "u2" || sys != "sys" {
		t.Fatalf("got user=%q sys=%q want u2/sys", user, sys)
	}
	if model != "gpt-x" {
		t.Fatalf("model=%q want gpt-x (parsed once with prompt)", model)
	}
}

func TestExtractPrompt_Gemini(t *testing.T) {
	body := []byte(`{
		"systemInstruction":{"parts":[{"text":"be brief"}]},
		"contents":[
			{"role":"user","parts":[{"text":"hi"}]},
			{"role":"model","parts":[{"text":"hello"}]},
			{"role":"user","parts":[{"text":"again"},{"text":"more"}]}
		]
	}`)
	user, sys, model := extractPrompt(protoGemini, body)
	if user != "again\nmore" {
		t.Fatalf("user=%q want joined latest user parts", user)
	}
	if sys != "be brief" {
		t.Fatalf("sys=%q want %q", sys, "be brief")
	}
	if model != "" {
		t.Fatalf("model=%q want empty (Gemini carries model in URL, not body)", model)
	}
}

func TestExtractPrompt_UnknownProtocolReturnsEmpty(t *testing.T) {
	// Unknown protocol must NOT guess — mis-parsing would store garbage.
	u, s, m := extractPrompt("", []byte(`{"model":"x","messages":[{"role":"user","content":"x"}]}`))
	if u != "" || s != "" || m != "" {
		t.Fatalf("unknown protocol got user=%q sys=%q model=%q want all empty", u, s, m)
	}
}

func TestExtractPrompt_MalformedBodyDegradesToEmpty(t *testing.T) {
	u, s, m := extractPrompt(protoAnthropic, []byte(`{not json`))
	if u != "" || s != "" || m != "" {
		t.Fatalf("malformed body got user=%q sys=%q model=%q want all empty (no error)", u, s, m)
	}
}

// --- assistant delta extraction (SSE frames) -------------------------------

func TestExtractAssistantDelta_Anthropic(t *testing.T) {
	// Only content_block_delta/text_delta contributes.
	frames := []struct {
		ev      string
		payload string
		want    string
	}{
		{"message_start", `{"type":"message_start","message":{}}`, ""},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hel"}}`, "Hel"},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"lo"}}`, "lo"},
		{"content_block_delta", `{"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":"{"}}`, ""}, // tool-call delta skipped
		{"message_stop", `{"type":"message_stop"}`, ""},
	}
	var got string
	for _, f := range frames {
		got += extractAssistantDelta(protoAnthropic, f.ev, []byte(f.payload))
		if d := extractAssistantDelta(protoAnthropic, f.ev, []byte(f.payload)); d != f.want {
			t.Fatalf("frame %q delta=%q want %q", f.payload, d, f.want)
		}
	}
	if got != "Hello" {
		t.Fatalf("accumulated=%q want %q", got, "Hello")
	}
}

func TestExtractAssistantDelta_OpenAI(t *testing.T) {
	d1 := extractAssistantDelta(protoOpenAI, "", []byte(`{"choices":[{"delta":{"content":"Hel"}}]}`))
	d2 := extractAssistantDelta(protoOpenAI, "", []byte(`{"choices":[{"delta":{"content":"lo"}}]}`))
	role := extractAssistantDelta(protoOpenAI, "", []byte(`{"choices":[{"delta":{"role":"assistant"}}]}`))
	if d1+d2 != "Hello" {
		t.Fatalf("accumulated=%q want Hello", d1+d2)
	}
	if role != "" {
		t.Fatalf("role-only delta=%q want empty", role)
	}
}

func TestExtractAssistantDelta_Gemini(t *testing.T) {
	d := extractAssistantDelta(protoGemini, "", []byte(`{"candidates":[{"content":{"parts":[{"text":"Hi"}]}}]}`))
	if d != "Hi" {
		t.Fatalf("gemini delta=%q want Hi", d)
	}
}

func TestIsCompletionMarker(t *testing.T) {
	cases := []struct {
		proto, ev, payload string
		want               bool
	}{
		{protoAnthropic, "message_stop", `{"type":"message_stop"}`, true},
		{protoAnthropic, "content_block_delta", `{"type":"content_block_delta"}`, false},
		{protoOpenAI, "", `[DONE]`, true},
		{protoOpenAI, "", `{"choices":[{"delta":{"content":"x"}}]}`, false},
		{protoGemini, "", `{"candidates":[{"finishReason":"STOP"}]}`, true},
		{protoGemini, "", `{"candidates":[{"content":{"parts":[{"text":"x"}]}}]}`, false},
	}
	for _, c := range cases {
		if got := isCompletionMarker(c.proto, c.ev, []byte(c.payload)); got != c.want {
			t.Fatalf("isCompletionMarker(%s,%q,%s)=%v want %v", c.proto, c.ev, c.payload, got, c.want)
		}
	}
}

// --- Responses API wire format (Codex, /v1/responses) -----------------------
//
// Fixtures mirror what Codex actually sends with wire_api="responses" (the
// same format provider/openai.go's usage extractor documents). Live incident
// 2026-07-07: this format extracted to empty → every Codex turn was skipped
// from the conversation audit (CONTENT_EMPTY_EXTRACT) while usage recorded
// fine. Chat Completions fixtures above must stay green untouched — the probe
// table's first entry pins the legacy behavior.

func TestExtractPrompt_OpenAI_ResponsesAPI_ItemArray(t *testing.T) {
	body := []byte(`{
		"model": "gpt-5-codex",
		"instructions": "You are Codex, a coding agent.",
		"stream": true,
		"input": [
			{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "old turn"}]},
			{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "old answer"}]},
			{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "写一个快排"}]}
		]
	}`)
	user, system, model := extractPrompt(protoOpenAI, body)
	if user != "写一个快排" {
		t.Errorf("user = %q, want latest user turn", user)
	}
	if system != "You are Codex, a coding agent." {
		t.Errorf("system = %q, want instructions", system)
	}
	if model != "gpt-5-codex" {
		t.Errorf("model = %q", model)
	}
}

func TestExtractPrompt_OpenAI_ResponsesAPI_StringInput(t *testing.T) {
	body := []byte(`{"model":"gpt-5-codex","input":"hello codex"}`)
	user, system, model := extractPrompt(protoOpenAI, body)
	if user != "hello codex" || system != "" || model != "gpt-5-codex" {
		t.Errorf("got (%q,%q,%q), want plain-string input as user text", user, system, model)
	}
}

func TestExtractPrompt_OpenAI_ChatCompletionsStillWinsWhenMessagesPresent(t *testing.T) {
	// A body carrying messages[] must keep the legacy extraction even if it
	// also carries stray Responses-ish fields — chat/completions probes first.
	body := []byte(`{
		"model": "gpt-4o",
		"instructions": "should be ignored",
		"messages": [
			{"role": "system", "content": "sys"},
			{"role": "user", "content": "hi"}
		]
	}`)
	user, system, model := extractPrompt(protoOpenAI, body)
	if user != "hi" || system != "sys" || model != "gpt-4o" {
		t.Errorf("got (%q,%q,%q), legacy chat/completions extraction regressed", user, system, model)
	}
}

func TestExtractPrompt_OpenAI_BareModelBodyKeepsLegacyModelFallback(t *testing.T) {
	// Neither format claims a bare probe body; legacy behavior surfaced the
	// model anyway (OnRequestEnd's fallback chain depends on it).
	user, system, model := extractPrompt(protoOpenAI, []byte(`{"model":"gpt-4o"}`))
	if user != "" || system != "" || model != "gpt-4o" {
		t.Errorf("got (%q,%q,%q), want empty text + model passthrough", user, system, model)
	}
}

func TestExtractAssistantDelta_OpenAI_ResponsesAPI(t *testing.T) {
	if got := extractAssistantDelta(protoOpenAI, "", []byte(`{"type":"response.output_text.delta","delta":"chunk"}`)); got != "chunk" {
		t.Errorf("delta = %q, want chunk", got)
	}
	// Non-text Responses frames carry no assistant text.
	if got := extractAssistantDelta(protoOpenAI, "", []byte(`{"type":"response.output_item.added","item":{}}`)); got != "" {
		t.Errorf("non-text frame leaked %q", got)
	}
	// Chat Completions delta unchanged (probe order).
	if got := extractAssistantDelta(protoOpenAI, "", []byte(`{"choices":[{"delta":{"content":"cc"}}]}`)); got != "cc" {
		t.Errorf("chat delta = %q, want cc", got)
	}
}

func TestIsCompletionMarker_OpenAI_BothFormats(t *testing.T) {
	if !isCompletionMarker(protoOpenAI, "", []byte(`[DONE]`)) {
		t.Error("[DONE] must stay a completion marker (chat/completions)")
	}
	if !isCompletionMarker(protoOpenAI, "", []byte(`{"type":"response.completed","response":{"usage":{"input_tokens":10}}}`)) {
		t.Error("response.completed must mark completion (Responses API)")
	}
	if isCompletionMarker(protoOpenAI, "", []byte(`{"type":"response.output_text.delta","delta":"x"}`)) {
		t.Error("delta frame must not mark completion")
	}
}
