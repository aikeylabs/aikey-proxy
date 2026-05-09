package provider

import "testing"

// ---- Anthropic ----

func TestAnthropic_ExtractTokens_NonStreaming(t *testing.T) {
	body := []byte(`{"type":"message","usage":{"input_tokens":15,"output_tokens":42}}`)
	in, out := (&Anthropic{}).ExtractTokens(body, false, nil)
	if in != 15 || out != 42 {
		t.Fatalf("got (%d,%d), want (15,42)", in, out)
	}
}

func TestAnthropic_ExtractTokens_NonStreaming_EmptyBody(t *testing.T) {
	in, out := (&Anthropic{}).ExtractTokens([]byte(`{}`), false, nil)
	if in != 0 || out != 0 {
		t.Fatalf("got (%d,%d), want (0,0)", in, out)
	}
}

func TestAnthropic_ExtractTokens_NonStreaming_InvalidJSON(t *testing.T) {
	in, out := (&Anthropic{}).ExtractTokens([]byte(`not-json`), false, nil)
	if in != 0 || out != 0 {
		t.Fatalf("got (%d,%d), want (0,0)", in, out)
	}
}

func TestAnthropic_ExtractTokens_Streaming(t *testing.T) {
	sse := "" +
		"event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":0}\n\n" +
		"event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":25}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"

	in, out := (&Anthropic{}).ExtractTokens([]byte(sse), true, nil)
	if in != 10 || out != 25 {
		t.Fatalf("got (%d,%d), want (10,25)", in, out)
	}
}

func TestAnthropic_ExtractTokens_Streaming_PartialStream(t *testing.T) {
	// Only message_start received before client disconnect.
	sse := "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":8}}}\n\n"
	in, out := (&Anthropic{}).ExtractTokens([]byte(sse), true, nil)
	if in != 8 || out != 0 {
		t.Fatalf("got (%d,%d), want (8,0)", in, out)
	}
}

func TestAnthropic_ExtractTokens_Streaming_EmptyStream(t *testing.T) {
	in, out := (&Anthropic{}).ExtractTokens([]byte(""), true, nil)
	if in != 0 || out != 0 {
		t.Fatalf("got (%d,%d), want (0,0)", in, out)
	}
}

// With prompt caching, Anthropic splits input into three fields. The total
// input we report must include all three or statusline will show a tiny
// value (e.g. ↑1) while Claude Code's own counter shows the full ~43k
// context. Regression test for 2026-04-18 diagnosis.
func TestAnthropic_ExtractTokens_Streaming_WithCacheFields(t *testing.T) {
	sse := "" +
		`data: {"type":"message_start","message":{"usage":` +
		`{"input_tokens":1,"cache_creation_input_tokens":200,` +
		`"cache_read_input_tokens":43000}}}` + "\n\n" +
		`data: {"type":"message_delta","usage":{"output_tokens":463}}` + "\n\n"

	in, out := (&Anthropic{}).ExtractTokens([]byte(sse), true, nil)
	want := 1 + 200 + 43000
	if in != want || out != 463 {
		t.Fatalf("got (%d,%d), want (%d,463)", in, out, want)
	}
}

func TestAnthropic_ExtractTokens_NonStreaming_WithCacheFields(t *testing.T) {
	body := []byte(`{"usage":{"input_tokens":5,"cache_creation_input_tokens":0,` +
		`"cache_read_input_tokens":40000,"output_tokens":150}}`)
	in, out := (&Anthropic{}).ExtractTokens(body, false, nil)
	if in != 40005 || out != 150 {
		t.Fatalf("got (%d,%d), want (40005,150)", in, out)
	}
}

// ---- OpenAI ----

func TestOpenAI_ExtractTokens_NonStreaming(t *testing.T) {
	body := []byte(`{"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":20,"completion_tokens":30,"total_tokens":50}}`)
	in, out := (&OpenAI{}).ExtractTokens(body, false, nil)
	if in != 20 || out != 30 {
		t.Fatalf("got (%d,%d), want (20,30)", in, out)
	}
}

func TestOpenAI_ExtractTokens_NonStreaming_NoUsage(t *testing.T) {
	in, out := (&OpenAI{}).ExtractTokens([]byte(`{"id":"chatcmpl-1"}`), false, nil)
	if in != 0 || out != 0 {
		t.Fatalf("got (%d,%d), want (0,0)", in, out)
	}
}

func TestOpenAI_ExtractTokens_Streaming_WithUsageChunk(t *testing.T) {
	// stream_options.include_usage=true adds usage to the last data chunk.
	sse := "" +
		"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n" +
		"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n" +
		"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":12}}\n\n" +
		"data: [DONE]\n\n"

	in, out := (&OpenAI{}).ExtractTokens([]byte(sse), true, nil)
	if in != 5 || out != 12 {
		t.Fatalf("got (%d,%d), want (5,12)", in, out)
	}
}

func TestOpenAI_ExtractTokens_Streaming_NoUsageChunk(t *testing.T) {
	// Streaming without stream_options.include_usage: no usage data.
	sse := "" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: [DONE]\n\n"
	in, out := (&OpenAI{}).ExtractTokens([]byte(sse), true, nil)
	if in != 0 || out != 0 {
		t.Fatalf("got (%d,%d), want (0,0)", in, out)
	}
}

// ---- Kimi delegates to OpenAI ----

func TestKimi_ExtractTokens_DelegatesToOpenAI(t *testing.T) {
	body := []byte(`{"usage":{"prompt_tokens":7,"completion_tokens":14}}`)
	in, out := (&Kimi{}).ExtractTokens(body, false, nil)
	if in != 7 || out != 14 {
		t.Fatalf("got (%d,%d), want (7,14)", in, out)
	}
}

func TestOpenAI_ExtractTokens_Streaming_NoSpaceAfterData(t *testing.T) {
	// KIMI/Moonshot sends "data:{...}" without space after colon.
	sse := "" +
		"data:{\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data:{\"id\":\"chatcmpl-1\",\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":5}}\n\n" +
		"data: [DONE]\n\n"

	in, out := (&OpenAI{}).ExtractTokens([]byte(sse), true, nil)
	if in != 9 || out != 5 {
		t.Fatalf("got (%d,%d), want (9,5)", in, out)
	}
}

func TestOpenAI_ExtractTokens_Streaming_ZeroPromptTokens(t *testing.T) {
	// Edge case: prompt_tokens=0 (e.g. fully cached request).
	// Must still extract completion_tokens, not return (0,0).
	sse := "" +
		"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\"cached\"}}]}\n\n" +
		"data: {\"id\":\"chatcmpl-1\",\"choices\":[],\"usage\":{\"prompt_tokens\":0,\"completion_tokens\":8}}\n\n" +
		"data: [DONE]\n\n"

	in, out := (&OpenAI{}).ExtractTokens([]byte(sse), true, nil)
	if in != 0 || out != 8 {
		t.Fatalf("got (%d,%d), want (0,8)", in, out)
	}
}

func TestOpenAI_ExtractTokens_NonStreaming_ZeroPromptTokens(t *testing.T) {
	body := []byte(`{"usage":{"prompt_tokens":0,"completion_tokens":5}}`)
	in, out := (&OpenAI{}).ExtractTokens(body, false, nil)
	if in != 0 || out != 5 {
		t.Fatalf("got (%d,%d), want (0,5)", in, out)
	}
}

// ---- Generic delegates to OpenAI ----

func TestGeneric_ExtractTokens_DelegatesToOpenAI(t *testing.T) {
	body := []byte(`{"usage":{"prompt_tokens":3,"completion_tokens":9}}`)
	in, out := (&Generic{}).ExtractTokens(body, false, nil)
	if in != 3 || out != 9 {
		t.Fatalf("got (%d,%d), want (3,9)", in, out)
	}
}

// ---------------------------------------------------------------------------
// StopReason extraction — Anthropic
// ---------------------------------------------------------------------------

func TestAnthropic_StopReason_Streaming_MessageDelta(t *testing.T) {
	sse := "" +
		"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":20}}\n\n"
	br := (&Anthropic{}).ExtractTokenBreakdown([]byte(sse), true, nil)
	if br.StopReason != "end_turn" {
		t.Fatalf("StopReason = %q, want end_turn", br.StopReason)
	}
}

func TestAnthropic_StopReason_Streaming_MaxTokens(t *testing.T) {
	sse := "" +
		"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":5}}}\n\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"},\"usage\":{\"output_tokens\":100}}\n\n"
	br := (&Anthropic{}).ExtractTokenBreakdown([]byte(sse), true, nil)
	if br.StopReason != "max_tokens" {
		t.Fatalf("StopReason = %q, want max_tokens", br.StopReason)
	}
}

func TestAnthropic_StopReason_NonStreaming(t *testing.T) {
	body := []byte(`{"usage":{"input_tokens":15,"output_tokens":42},"stop_reason":"tool_use"}`)
	br := (&Anthropic{}).ExtractTokenBreakdown(body, false, nil)
	if br.StopReason != "tool_use" {
		t.Fatalf("StopReason = %q, want tool_use", br.StopReason)
	}
}

func TestAnthropic_StopReason_Missing(t *testing.T) {
	// message_delta without stop_reason → StopReason stays empty (not "" sentinel, not a default).
	sse := "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1}}\n\n"
	br := (&Anthropic{}).ExtractTokenBreakdown([]byte(sse), true, nil)
	if br.StopReason != "" {
		t.Fatalf("StopReason should be empty, got %q", br.StopReason)
	}
}

// ---------------------------------------------------------------------------
// StopReason extraction — OpenAI / Kimi
// ---------------------------------------------------------------------------

func TestOpenAI_StopReason_NonStreaming(t *testing.T) {
	body := []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5},"choices":[{"finish_reason":"stop"}]}`)
	br := (&OpenAI{}).ExtractTokenBreakdown(body, false, nil)
	if br.StopReason != "stop" {
		t.Fatalf("StopReason = %q, want stop", br.StopReason)
	}
}

func TestOpenAI_StopReason_Streaming_ToolCalls(t *testing.T) {
	sse := "" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n" +
		"data: {\"choices\":[{\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":20,\"completion_tokens\":30}}\n\n" +
		"data: [DONE]\n\n"
	br := (&OpenAI{}).ExtractTokenBreakdown([]byte(sse), true, nil)
	if br.StopReason != "tool_calls" {
		t.Fatalf("StopReason = %q, want tool_calls", br.StopReason)
	}
}

func TestOpenAI_StopReason_Streaming_LastReasonWins(t *testing.T) {
	// If multiple chunks somehow carry finish_reason (shouldn't normally
	// happen), the last non-empty wins — consistent with "final chunk
	// defines the turn outcome".
	sse := "" +
		"data: {\"choices\":[{\"finish_reason\":\"stop\"}]}\n\n" +
		"data: {\"choices\":[{\"finish_reason\":\"length\"}]}\n\n"
	br := (&OpenAI{}).ExtractTokenBreakdown([]byte(sse), true, nil)
	if br.StopReason != "length" {
		t.Fatalf("StopReason = %q, want length (last wins)", br.StopReason)
	}
}

func TestOpenAI_StopReason_Missing(t *testing.T) {
	body := []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5},"choices":[{}]}`)
	br := (&OpenAI{}).ExtractTokenBreakdown(body, false, nil)
	if br.StopReason != "" {
		t.Fatalf("StopReason should be empty, got %q", br.StopReason)
	}
}

func TestKimi_StopReason_DelegatesToOpenAI(t *testing.T) {
	body := []byte(`{"usage":{"prompt_tokens":3,"completion_tokens":9},"choices":[{"finish_reason":"length"}]}`)
	br := (&Kimi{}).ExtractTokenBreakdown(body, false, nil)
	if br.StopReason != "length" {
		t.Fatalf("StopReason = %q, want length (kimi delegates to openai)", br.StopReason)
	}
}

// ---------------------------------------------------------------------------
// Model extraction (response-first, 2026-05-09)
// ---------------------------------------------------------------------------
//
// These tests pin the contract that `ExtractTokenBreakdown` carries the
// upstream-resolved model id in `breakdown.Model`. The proxy uses this to
// override the request-body model captured by extractModel(), so the WAL /
// receipt records the actual billed version (e.g. "claude-opus-4-7-20251015"
// instead of the alias "claude-opus-4-7").
//
// Empty Model → graceful fallback to request.model (same as today's behavior).

func TestAnthropic_Model_Streaming(t *testing.T) {
	// Real Anthropic SSE shape — the message_start frame carries the
	// upstream-resolved model on the `message.model` field.
	sse := "" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"model\":\"claude-opus-4-7-20251015\",\"usage\":{\"input_tokens\":10}}}\n\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n"
	br := (&Anthropic{}).ExtractTokenBreakdown([]byte(sse), true, nil)
	if br.Model != "claude-opus-4-7-20251015" {
		t.Fatalf("Model = %q, want claude-opus-4-7-20251015", br.Model)
	}
}

func TestAnthropic_Model_NonStreaming(t *testing.T) {
	body := []byte(`{"id":"msg_x","model":"claude-sonnet-4-20250514","usage":{"input_tokens":15,"output_tokens":42},"stop_reason":"end_turn"}`)
	br := (&Anthropic{}).ExtractTokenBreakdown(body, false, nil)
	if br.Model != "claude-sonnet-4-20250514" {
		t.Fatalf("Model = %q, want claude-sonnet-4-20250514", br.Model)
	}
}

func TestAnthropic_Model_StreamCutEarly(t *testing.T) {
	// Stream interrupted before message_start — Model stays empty so the
	// proxy falls back to the request-body model. Don't synthesize a value.
	sse := "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n"
	br := (&Anthropic{}).ExtractTokenBreakdown([]byte(sse), true, nil)
	if br.Model != "" {
		t.Fatalf("Model should be empty when message_start absent, got %q", br.Model)
	}
}

func TestOpenAI_Model_Streaming_FirstChunkWins(t *testing.T) {
	// Production OpenAI shape: every chunk carries `model`. The first
	// non-empty hit wins; subsequent chunks (which would be redundantly
	// identical anyway) don't override.
	sse := "" +
		"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1234,\"model\":\"gpt-4o-2024-08-06\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n" +
		"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-2024-08-06\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: [DONE]\n\n"
	br := (&OpenAI{}).ExtractTokenBreakdown([]byte(sse), true, nil)
	if br.Model != "gpt-4o-2024-08-06" {
		t.Fatalf("Model = %q, want gpt-4o-2024-08-06", br.Model)
	}
}

func TestOpenAI_Model_NonStreaming(t *testing.T) {
	body := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o-2024-08-06","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`)
	br := (&OpenAI{}).ExtractTokenBreakdown(body, false, nil)
	if br.Model != "gpt-4o-2024-08-06" {
		t.Fatalf("Model = %q, want gpt-4o-2024-08-06", br.Model)
	}
}

func TestOpenAI_Model_MissingFromAllChunks(t *testing.T) {
	// Stripped fixture (or non-conformant compatible provider) — no chunk
	// carries `model`. Extractor returns "" so proxy falls back to
	// request.model. Don't synthesize.
	sse := "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n"
	br := (&OpenAI{}).ExtractTokenBreakdown([]byte(sse), true, nil)
	if br.Model != "" {
		t.Fatalf("Model should be empty when chunks omit it, got %q", br.Model)
	}
}

func TestKimi_Model_DelegatesToOpenAI(t *testing.T) {
	// Kimi follows OpenAI-compatible shape — same chunk structure, same
	// extractor. Pin via delegation that the model field round-trips.
	body := []byte(`{"id":"cmpl-kimi","object":"chat.completion","model":"kimi-k2.5","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`)
	br := (&Kimi{}).ExtractTokenBreakdown(body, false, nil)
	if br.Model != "kimi-k2.5" {
		t.Fatalf("Model = %q, want kimi-k2.5 (kimi delegates to openai)", br.Model)
	}
}
