package provider

import "testing"

func TestInferUpstreamFromModel(t *testing.T) {
	cases := []struct {
		model string
		want  string
	}{
		// Anthropic Claude family
		{"claude-3-5-sonnet-20241022", "anthropic"},
		{"claude-3-5-haiku-latest", "anthropic"},
		{"claude-opus-4-7", "anthropic"},
		{"Claude-3-5-Sonnet-Latest", "anthropic"}, // case-insensitive

		// OpenAI GPT / o-series
		{"gpt-4o", "openai"},
		{"gpt-4o-mini", "openai"},
		{"gpt-3.5-turbo", "openai"},
		{"o1-preview", "openai"},
		{"o3-mini", "openai"},
		{"o4-mini", "openai"},
		{"chatgpt-4o-latest", "openai"},
		{"text-davinci-003", "openai"},
		{"davinci-002", "openai"},

		// Google Gemini
		{"gemini-1.5-pro", "gemini"},
		{"gemini-2.0-flash-exp", "gemini"},

		// Moonshot / Kimi
		{"moonshot-v1-8k", "kimi"},
		{"kimi-k2-turbo-preview", "kimi"},

		// DeepSeek
		{"deepseek-chat", "deepseek"},
		{"deepseek-coder-v2", "deepseek"},

		// Qwen
		{"qwen-max", "qwen"},
		{"qwen-turbo", "qwen"},

		// LiteLLM-style explicit-provider prefix
		{"openai/gpt-4o", "openai"},
		{"anthropic/claude-3-5-sonnet", "anthropic"},
		{"gemini/gemini-1.5-pro", "gemini"},

		// Cloud-prefix forms — peel and re-infer
		{"bedrock/anthropic.claude-3-haiku-20240307", "anthropic"},
		{"azure/gpt-4o-eu", "openai"},
		{"vertex_ai/gemini-1.5-flash", "gemini"},

		// Unknown / unmapped — empty string (caller surfaces an error)
		{"", ""},
		{"llama-3-70b-instruct", ""}, // Meta — no single canonical upstream (Bedrock / Together / Groq / local)
		{"my-custom-finetune-2024", ""},
		{"random-string", ""},
	}

	for _, c := range cases {
		got := InferUpstreamFromModel(c.model)
		if got != c.want {
			t.Errorf("InferUpstreamFromModel(%q) = %q, want %q", c.model, got, c.want)
		}
	}
}

// TestNormalizeModelForUpstream pins the G1 fix matrix (2026-05-21):
// strip `<upstream>/` prefix when it matches the bound upstream; keep
// otherwise (aggregator sub-route case).
func TestNormalizeModelForUpstream(t *testing.T) {
	cases := []struct {
		raw      string
		upstream string
		want     string
		why      string
	}{
		// Direct upstreams strip the matching prefix.
		{"anthropic/claude-3-5-sonnet-20241022", "anthropic", "claude-3-5-sonnet-20241022", "direct anthropic, strip"},
		{"openai/gpt-4o", "openai", "gpt-4o", "direct openai, strip"},
		{"gemini/gemini-1.5-pro", "gemini", "gemini-1.5-pro", "direct gemini, strip"},
		{"kimi/kimi-k2-turbo", "kimi", "kimi-k2-turbo", "direct kimi, strip"},

		// Aggregator: strip only the outer segment.
		{"openrouter/openai/gpt-5.2-codex", "openrouter", "openai/gpt-5.2-codex", "openrouter aggregator, keep sub-prefix"},
		{"openrouter/anthropic/claude-3-5-sonnet", "openrouter", "anthropic/claude-3-5-sonnet", "openrouter aggregator + anthropic model"},
		{"siliconflow-cn/Pro/zai-org/GLM-4.7", "siliconflow-cn", "Pro/zai-org/GLM-4.7", "siliconflow aggregator with multi-level sub-path"},

		// Bedrock-style "<vendor>.<modelid>" — upstream is "bedrock",
		// strip "bedrock/" but preserve the "anthropic.claude" form
		// (Bedrock expects vendor.modelid).
		{"bedrock/anthropic.claude-3-haiku-20240307", "bedrock", "anthropic.claude-3-haiku-20240307", "bedrock with vendor.model preserved"},

		// No prefix in model id — unchanged.
		{"claude-3-5-sonnet-20241022", "anthropic", "claude-3-5-sonnet-20241022", "no prefix, unchanged"},
		{"gpt-4o", "openai", "gpt-4o", "no prefix, unchanged"},

		// Prefix doesn't match upstream — KEEP (aggregator scenario).
		{"anthropic/claude-3-5-sonnet", "openrouter", "anthropic/claude-3-5-sonnet", "anthropic prefix routed via openrouter — keep prefix for sub-route"},
		{"openai/gpt-4o", "openrouter", "openai/gpt-4o", "openai prefix via openrouter — keep"},

		// Case-insensitive prefix match.
		{"Anthropic/Claude-3-5-Sonnet", "anthropic", "Claude-3-5-Sonnet", "case-insensitive prefix match"},

		// Empty inputs — defensive returns.
		{"", "anthropic", "", "empty model"},
		{"claude-3-5-sonnet", "", "claude-3-5-sonnet", "empty upstream"},
		{"/claude-3-5-sonnet", "anthropic", "/claude-3-5-sonnet", "leading slash without prefix is left alone"},
	}
	for _, c := range cases {
		got := NormalizeModelForUpstream(c.raw, c.upstream)
		if got != c.want {
			t.Errorf("NormalizeModelForUpstream(%q, %q) = %q, want %q (%s)",
				c.raw, c.upstream, got, c.want, c.why)
		}
	}
}

// TestIsOpenAIWireCompatible pins which upstream provider codes are
// treated as "OpenAI wire" for translator fast-path purposes (B addition
// 2026-05-21). Catches accidental list shrinkage.
func TestIsOpenAIWireCompatible(t *testing.T) {
	cases := []struct {
		code string
		want bool
	}{
		// OpenAI canonical
		{"openai", true},
		// Direct OpenAI-compatible providers
		{"kimi", true},
		{"moonshot", true},
		{"deepseek", true},
		{"qwen", true},
		{"groq", true},
		{"together", true},
		{"perplexity", true},
		{"fireworks", true},
		{"deepinfra", true},
		{"siliconflow", true},
		{"siliconflow-cn", true},
		{"zhipu", true},
		{"doubao", true},
		{"01ai", true},
		// Aggregator gateways (OpenAI wire forward)
		{"openrouter", true},
		{"openrouter-ai", true},
		{"litellm", true},
		{"portkey", true},

		// NOT OpenAI wire — these have native APIs needing translation
		{"anthropic", false},
		{"gemini", false},
		{"bedrock", false},
		{"vertex_ai", false},

		// Case-insensitive
		{"Kimi", true},
		{"OPENAI", true},
		{"Anthropic", false},

		// Unknown / empty → false (defensive)
		{"unknown-provider", false},
		{"", false},
	}
	for _, c := range cases {
		got := IsOpenAIWireCompatible(c.code)
		if got != c.want {
			t.Errorf("IsOpenAIWireCompatible(%q) = %v, want %v", c.code, got, c.want)
		}
	}
}

// TestInferUpstreamFromModel_EdgeCases covers the boundary conditions
// that broke me during earlier iterations — keep them as regression pins.
func TestInferUpstreamFromModel_EdgeCases(t *testing.T) {
	// Standalone "claude" (no version suffix) — not matched. Real Claude
	// models always have a version suffix; bare "claude" is almost
	// certainly a typo and we don't want to silently route it.
	if got := InferUpstreamFromModel("claude"); got != "" {
		t.Errorf(`InferUpstreamFromModel("claude") = %q, want "" (bare name not matched)`, got)
	}
	// Underscore-style names (some Bedrock / Azure deployments use these).
	if got := InferUpstreamFromModel("claude_3_5_sonnet"); got != "anthropic" {
		t.Errorf(`underscore variant should match: got %q`, got)
	}
	// Mixed-case + cloud prefix
	if got := InferUpstreamFromModel("Bedrock/anthropic.Claude-3-Sonnet"); got != "anthropic" {
		t.Errorf(`mixed-case cloud prefix not normalized: got %q`, got)
	}
}
