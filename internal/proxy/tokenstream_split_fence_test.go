package proxy

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// gap7 chunk-split invariance fence: driving the StreamAccumulator through the
// REAL observer.SSEParser (the exact path the drainer uses) must produce the
// SAME TokenBreakdown as the whole-body ExtractTokenBreakdown, NO MATTER where
// the byte chunk boundaries fall. This proves the incremental SSE reassembly is
// correct (frames split across reads are rejoined) and that nothing is lost at
// stream end (Flush recovers an unterminated final frame).

// feedIncremental replays body through SSEParser in the given chunk slices,
// feeding each parsed frame to the accumulator, then Flush()es the tail exactly
// like newStreamDrainer does at stream end.
func feedIncremental(prov provider.Provider, body string, cuts []int) provider.TokenBreakdown {
	acc := prov.(provider.StreamAccumulatorFactory).NewStreamAccumulator()
	p := observer.NewSSEParser()
	start := 0
	bounds := append(append([]int{}, cuts...), len(body))
	for _, end := range bounds {
		if end <= start || end > len(body) {
			continue
		}
		for _, fr := range p.Parse([]byte(body[start:end])) {
			acc.Feed(fr.Data)
		}
		start = end
	}
	if fr, ok := p.Flush(); ok {
		acc.Feed(fr.Data)
	}
	return acc.Result()
}

func TestStreamSplitInvariance(t *testing.T) {
	cases := []struct {
		name string
		prov provider.Provider
		body string
	}{
		{"anthropic_cache_terminated", &provider.Anthropic{},
			`data: {"type":"message_start","message":{"usage":{"input_tokens":1,"cache_creation_input_tokens":200,"cache_read_input_tokens":43000}}}` + "\n\n" +
				`data: {"type":"message_delta","usage":{"output_tokens":463}}` + "\n\n"},
		// Ends WITHOUT a trailing blank line — exercises SSEParser.Flush so the
		// final message_delta (output tokens) is not lost.
		{"anthropic_unterminated", &provider.Anthropic{},
			`data: {"type":"message_start","message":{"usage":{"input_tokens":7}}}` + "\n\n" +
				`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":20}}`},
		{"openai_usage_model_cached", &provider.OpenAI{},
			`data: {"id":"x","model":"gpt-4o-mini","choices":[{"delta":{"content":"hi"}}]}` + "\n\n" +
				`data: {"id":"x","model":"gpt-4o-mini","choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"prompt_tokens_details":{"cached_tokens":30}}}` + "\n\n" +
				`data: [DONE]` + "\n\n"},
		{"openai_no_space", &provider.OpenAI{},
			`data:{"id":"x","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":5}}` + "\n\n"},
		{"kimi_basic", &provider.Kimi{},
			`data: {"id":"x","choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":4}}` + "\n\n"},
	}

	for _, c := range cases {
		// Whole-body extractor is the source of truth (untouched, fence-locked).
		want := c.prov.ExtractTokenBreakdown([]byte(c.body), true, nil)

		// 1) single-shot incremental (no split)
		if got := feedIncremental(c.prov, c.body, nil); got != want {
			t.Errorf("%s single-shot: got %+v want %+v", c.name, got, want)
		}
		// 2) every single split point
		for i := 1; i < len(c.body); i++ {
			if got := feedIncremental(c.prov, c.body, []int{i}); got != want {
				t.Errorf("%s split@%d: got %+v want %+v", c.name, i, got, want)
				break
			}
		}
		// 3) byte-by-byte (worst-case reassembly — every read is 1 byte)
		bytewise := make([]int, 0, len(c.body))
		for i := 1; i < len(c.body); i++ {
			bytewise = append(bytewise, i)
		}
		if got := feedIncremental(c.prov, c.body, bytewise); got != want {
			t.Errorf("%s byte-by-byte: got %+v want %+v", c.name, got, want)
		}
	}
}
