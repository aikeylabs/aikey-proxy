package provider

// Shared streaming fixtures for the token-extraction fence (gap7 incremental
// refactor). Bodies use REAL provider wire formats lifted from tokens_test.go /
// openai_reasoning_test.go. The fence test (tokenstream_fence_test.go) locks the
// CURRENT ExtractTokenBreakdown output for each, so the upcoming incremental
// extractor can be proven byte-identical. Covers both families (Anthropic;
// OpenAI + Kimi/Generic delegation) and the field matrix (input/output, cache,
// reasoning, model, stop_reason, partial, empty).

type streamFenceFixture struct {
	name string
	prov Provider
	sse  string
}

var streamFenceFixtures = []streamFenceFixture{
	// ---- Anthropic family ----
	{"anthropic_basic", &Anthropic{},
		`event: message_start` + "\n" +
			`data: {"type":"message_start","message":{"usage":{"input_tokens":10}}}` + "\n\n" +
			`data: {"type":"content_block_start","index":0}` + "\n\n" +
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":25}}` + "\n\n" +
			`data: {"type":"message_stop"}` + "\n\n"},
	{"anthropic_cache", &Anthropic{},
		`data: {"type":"message_start","message":{"usage":{"input_tokens":1,"cache_creation_input_tokens":200,"cache_read_input_tokens":43000}}}` + "\n\n" +
			`data: {"type":"message_delta","usage":{"output_tokens":463}}` + "\n\n"},
	{"anthropic_model", &Anthropic{},
		`data: {"type":"message_start","message":{"id":"msg_x","model":"claude-opus-4-7-20251015","usage":{"input_tokens":10}}}` + "\n\n" +
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}` + "\n\n"},
	{"anthropic_max_tokens", &Anthropic{},
		`data: {"type":"message_start","message":{"usage":{"input_tokens":5}}}` + "\n\n" +
			`data: {"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"output_tokens":100}}` + "\n\n"},
	{"anthropic_partial_start_only", &Anthropic{},
		`data: {"type":"message_start","message":{"usage":{"input_tokens":8}}}` + "\n\n"},
	{"anthropic_partial_delta_only", &Anthropic{},
		`data: {"type":"message_delta","usage":{"output_tokens":1}}` + "\n\n"},
	{"anthropic_empty", &Anthropic{}, ""},

	// ---- OpenAI family ----
	{"openai_basic", &OpenAI{},
		`data: {"id":"chatcmpl-1","choices":[{"delta":{"content":"Hello"}}]}` + "\n\n" +
			`data: {"id":"chatcmpl-1","choices":[{"delta":{"content":" world"}}]}` + "\n\n" +
			`data: {"id":"chatcmpl-1","choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":12}}` + "\n\n" +
			`data: [DONE]` + "\n"},
	{"openai_cached", &OpenAI{},
		`data: {"id":"chatcmpl-1","choices":[{"delta":{"content":"x"}}]}` + "\n\n" +
			`data: {"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":100,"completion_tokens":50,"prompt_tokens_details":{"cached_tokens":30}}}` + "\n\n" +
			`data: [DONE]` + "\n"},
	{"openai_reasoning", &OpenAI{},
		`data: {"choices":[{"delta":{"content":"hi"}}]}` + "\n\n" +
			`data: {"usage":{"prompt_tokens":100,"completion_tokens":500,"completion_tokens_details":{"reasoning_tokens":400}}}` + "\n\n" +
			`data: [DONE]` + "\n"},
	{"openai_model", &OpenAI{},
		`data: {"id":"chatcmpl-1","model":"gpt-4o-mini","choices":[{"delta":{"content":"hi"}}]}` + "\n\n" +
			`data: {"id":"chatcmpl-1","model":"gpt-4o-mini","choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3}}` + "\n\n" +
			`data: [DONE]` + "\n"},
	{"openai_no_space", &OpenAI{},
		`data:{"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":5}}` + "\n\n"},
	{"openai_tool_calls", &OpenAI{},
		`data: {"choices":[{"delta":{"content":"partial"}}]}` + "\n\n" +
			`data: {"choices":[{"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":20,"completion_tokens":30}}` + "\n\n"},
	{"openai_partial_no_usage", &OpenAI{},
		`data: {"choices":[{"delta":{"content":"hi"}}]}` + "\n\n"},
	{"openai_empty", &OpenAI{}, ""},

	// ---- delegation lock (Kimi / Generic → OpenAI) ----
	{"kimi_basic", &Kimi{},
		`data: {"id":"chatcmpl-1","choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":4}}` + "\n\n"},
	{"generic_basic", &Generic{},
		`data: {"id":"chatcmpl-1","choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":13,"completion_tokens":6}}` + "\n\n"},
}
