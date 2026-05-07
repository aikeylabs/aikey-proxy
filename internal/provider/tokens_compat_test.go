package provider

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExtractTokens_CompatMatrix is a unified table-driven test that verifies
// token extraction across all providers, streaming modes, and SSE format variants.
//
// Each fixture file is a recorded provider response (real format, sanitized content).
// When adding a new provider, add fixture files to testdata/ and extend this table.
//
// This test is the CI gate referenced in the stability plan (section 5.1):
// changes to internal/provider/** or internal/proxy/streaming.go must pass this.
func TestExtractTokens_CompatMatrix(t *testing.T) {
	tests := []struct {
		name      string
		provider  Provider
		fixture   string
		streaming bool
		wantIn    int
		wantOut   int
	}{
		// ---- Anthropic ----
		{
			name:      "anthropic/non-streaming",
			provider:  &Anthropic{},
			fixture:   "anthropic_non_stream.json",
			streaming: false,
			wantIn:    150,
			wantOut:   80,
		},
		{
			name:      "anthropic/streaming",
			provider:  &Anthropic{},
			fixture:   "anthropic_stream.txt",
			streaming: true,
			wantIn:    150,
			wantOut:   80,
		},

		// ---- OpenAI ----
		{
			name:      "openai/non-streaming",
			provider:  &OpenAI{},
			fixture:   "openai_non_stream.json",
			streaming: false,
			wantIn:    120,
			wantOut:   60,
		},
		{
			name:      "openai/streaming (with include_usage)",
			provider:  &OpenAI{},
			fixture:   "openai_stream.txt",
			streaming: true,
			wantIn:    120,
			wantOut:   60,
		},
		{
			name:      "openai/streaming (no usage - missing stream_options)",
			provider:  &OpenAI{},
			fixture:   "openai_stream_no_usage.txt",
			streaming: true,
			wantIn:    0, // expected: no usage data when stream_options not set
			wantOut:   0,
		},

		// ---- KIMI / Moonshot (no space after "data:") ----
		{
			name:      "kimi/streaming (data:{} no space)",
			provider:  &OpenAI{}, // Kimi delegates to OpenAI extractor
			fixture:   "kimi_stream_no_space.txt",
			streaming: true,
			wantIn:    100,
			wantOut:   50,
		},

		// ---- Generic (delegates to OpenAI) ----
		{
			name:      "generic/non-streaming",
			provider:  &Generic{},
			fixture:   "openai_non_stream.json",
			streaming: false,
			wantIn:    120,
			wantOut:   60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := loadFixture(t, tt.fixture)
			gotIn, gotOut := tt.provider.ExtractTokens(data, tt.streaming, nil)
			if gotIn != tt.wantIn {
				t.Errorf("input_tokens = %d, want %d", gotIn, tt.wantIn)
			}
			if gotOut != tt.wantOut {
				t.Errorf("output_tokens = %d, want %d", gotOut, tt.wantOut)
			}
		})
	}
}

// TestExtractTokens_NonZero_Positive verifies that fixtures expected to have
// usage data actually produce non-zero tokens. This is the "must not regress
// to all-zeros" guard for the most common production paths.
func TestExtractTokens_NonZero_Positive(t *testing.T) {
	positives := []struct {
		name      string
		provider  Provider
		fixture   string
		streaming bool
	}{
		{"anthropic/stream", &Anthropic{}, "anthropic_stream.txt", true},
		{"anthropic/non-stream", &Anthropic{}, "anthropic_non_stream.json", false},
		{"openai/stream", &OpenAI{}, "openai_stream.txt", true},
		{"openai/non-stream", &OpenAI{}, "openai_non_stream.json", false},
		{"kimi/stream", &OpenAI{}, "kimi_stream_no_space.txt", true},
	}

	for _, tt := range positives {
		t.Run(tt.name, func(t *testing.T) {
			data := loadFixture(t, tt.fixture)
			in, out := tt.provider.ExtractTokens(data, tt.streaming, nil)
			if in == 0 && out == 0 {
				t.Errorf("both input_tokens and output_tokens are 0; expected non-zero usage")
			}
		})
	}
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", path, err)
	}
	return data
}
