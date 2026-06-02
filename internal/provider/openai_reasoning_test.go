package provider

import "testing"

// extractOpenAIReasoning must read the o-series reasoning bucket across all wire
// formats (CLAUDE.md: extractor changes need fixture-based tests per wire shape).
func TestExtractOpenAIReasoning(t *testing.T) {
	cases := []struct {
		name      string
		data      string
		streaming bool
		want      int
	}{
		{
			name: "chat completions completion_tokens_details",
			data: `{"usage":{"prompt_tokens":100,"completion_tokens":500,"completion_tokens_details":{"reasoning_tokens":400}}}`,
			want: 400,
		},
		{
			name: "responses api output_tokens_details",
			data: `{"usage":{"input_tokens":100,"output_tokens":500,"output_tokens_details":{"reasoning_tokens":350}}}`,
			want: 350,
		},
		{
			name: "responses api nested under response",
			data: `{"response":{"usage":{"output_tokens_details":{"reasoning_tokens":120}}}}`,
			want: 120,
		},
		{
			name: "non-reasoning model has no details",
			data: `{"usage":{"prompt_tokens":100,"completion_tokens":50}}`,
			want: 0,
		},
		{
			name:      "streaming: usage on final chunk",
			data:      "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: {\"usage\":{\"completion_tokens_details\":{\"reasoning_tokens\":200}}}\n\ndata: [DONE]\n",
			streaming: true,
			want:      200,
		},
		{
			name:      "streaming: no reasoning → 0",
			data:      "data: {\"choices\":[{\"delta\":{}}]}\n\ndata: {\"usage\":{\"completion_tokens\":10}}\n\ndata: [DONE]\n",
			streaming: true,
			want:      0,
		},
		{
			name: "garbage is tolerated → 0",
			data: `{ not json`,
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractOpenAIReasoning([]byte(tc.data), tc.streaming); got != tc.want {
				t.Errorf("extractOpenAIReasoning = %d, want %d", got, tc.want)
			}
		})
	}
}
