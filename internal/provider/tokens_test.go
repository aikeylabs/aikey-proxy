package provider

import "testing"

// ---- Anthropic ----

func TestAnthropic_ExtractTokens_NonStreaming(t *testing.T) {
	body := []byte(`{"type":"message","usage":{"input_tokens":15,"output_tokens":42}}`)
	in, out := (&Anthropic{}).ExtractTokens(body, false)
	if in != 15 || out != 42 {
		t.Fatalf("got (%d,%d), want (15,42)", in, out)
	}
}

func TestAnthropic_ExtractTokens_NonStreaming_EmptyBody(t *testing.T) {
	in, out := (&Anthropic{}).ExtractTokens([]byte(`{}`), false)
	if in != 0 || out != 0 {
		t.Fatalf("got (%d,%d), want (0,0)", in, out)
	}
}

func TestAnthropic_ExtractTokens_NonStreaming_InvalidJSON(t *testing.T) {
	in, out := (&Anthropic{}).ExtractTokens([]byte(`not-json`), false)
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

	in, out := (&Anthropic{}).ExtractTokens([]byte(sse), true)
	if in != 10 || out != 25 {
		t.Fatalf("got (%d,%d), want (10,25)", in, out)
	}
}

func TestAnthropic_ExtractTokens_Streaming_PartialStream(t *testing.T) {
	// Only message_start received before client disconnect.
	sse := "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":8}}}\n\n"
	in, out := (&Anthropic{}).ExtractTokens([]byte(sse), true)
	if in != 8 || out != 0 {
		t.Fatalf("got (%d,%d), want (8,0)", in, out)
	}
}

func TestAnthropic_ExtractTokens_Streaming_EmptyStream(t *testing.T) {
	in, out := (&Anthropic{}).ExtractTokens([]byte(""), true)
	if in != 0 || out != 0 {
		t.Fatalf("got (%d,%d), want (0,0)", in, out)
	}
}

// ---- OpenAI ----

func TestOpenAI_ExtractTokens_NonStreaming(t *testing.T) {
	body := []byte(`{"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":20,"completion_tokens":30,"total_tokens":50}}`)
	in, out := (&OpenAI{}).ExtractTokens(body, false)
	if in != 20 || out != 30 {
		t.Fatalf("got (%d,%d), want (20,30)", in, out)
	}
}

func TestOpenAI_ExtractTokens_NonStreaming_NoUsage(t *testing.T) {
	in, out := (&OpenAI{}).ExtractTokens([]byte(`{"id":"chatcmpl-1"}`), false)
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

	in, out := (&OpenAI{}).ExtractTokens([]byte(sse), true)
	if in != 5 || out != 12 {
		t.Fatalf("got (%d,%d), want (5,12)", in, out)
	}
}

func TestOpenAI_ExtractTokens_Streaming_NoUsageChunk(t *testing.T) {
	// Streaming without stream_options.include_usage: no usage data.
	sse := "" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: [DONE]\n\n"
	in, out := (&OpenAI{}).ExtractTokens([]byte(sse), true)
	if in != 0 || out != 0 {
		t.Fatalf("got (%d,%d), want (0,0)", in, out)
	}
}

// ---- Kimi delegates to OpenAI ----

func TestKimi_ExtractTokens_DelegatesToOpenAI(t *testing.T) {
	body := []byte(`{"usage":{"prompt_tokens":7,"completion_tokens":14}}`)
	in, out := (&Kimi{}).ExtractTokens(body, false)
	if in != 7 || out != 14 {
		t.Fatalf("got (%d,%d), want (7,14)", in, out)
	}
}

// ---- Generic delegates to OpenAI ----

func TestGeneric_ExtractTokens_DelegatesToOpenAI(t *testing.T) {
	body := []byte(`{"usage":{"prompt_tokens":3,"completion_tokens":9}}`)
	in, out := (&Generic{}).ExtractTokens(body, false)
	if in != 3 || out != 9 {
		t.Fatalf("got (%d,%d), want (3,9)", in, out)
	}
}
