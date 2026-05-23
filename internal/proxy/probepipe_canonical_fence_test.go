package proxy

import "testing"

// Fence tests for the Probe pipeline's provider-canonical comparison
// (proxy.go::handleProbePipeline Stage 4). See SPEC
// `workflow/CI/requirements/2026-05-23-credential-mode-architecture.md` §1.3.
//
// Background — 2026-05-23 E2E findings:
//
// Vault `provider_accounts.provider` historically stores brand alias
// strings ("claude", "gpt", "kimi") whereas `provider.InferUpstreamFromModel`
// always returns canonical codes ("anthropic", "openai", "kimi_code"). The
// initial probe-pipeline implementation compared these raw — false positives
// (real-world: OAuth `claude` row vs inferred `anthropic` returned
// PROBE_PROVIDER_MISMATCH 400 instead of forwarding the request upstream).
//
// The fix wraps both sides of the comparison in providerCanonicalCode so
// the existing canonical-alias table is the single source of truth. These
// fence tests pin the alias pairs that matter most in production so a
// future refactor of providerCanonicalCode can't silently re-introduce
// the bug.

// Anthropic / Claude — the exact pair that caused the production miss
// (FreySilvaqzs@qualityservice.com vault row had provider="claude", body.model
// resolves to "anthropic"; the comparison must agree both are anthropic).
func TestProbeCanonicalAlias_ClaudeAndAnthropic(t *testing.T) {
	if got := providerCanonicalCode("claude"); got != "anthropic" {
		t.Fatalf("providerCanonicalCode(\"claude\") = %q, want %q — probe pipeline OAuth-claude rows would PROBE_PROVIDER_MISMATCH", got, "anthropic")
	}
	if got := providerCanonicalCode("anthropic"); got != "anthropic" {
		t.Fatalf("providerCanonicalCode(\"anthropic\") = %q, want %q — probe pipeline body-model inferred anthropic would drift", got, "anthropic")
	}
}

// OpenAI / GPT / ChatGPT / Codex — same alias family; the probe pipeline
// must treat all four as a single upstream when comparing binding vs
// inferred provider.
func TestProbeCanonicalAlias_OpenAIFamily(t *testing.T) {
	for _, in := range []string{"gpt", "chatgpt", "codex", "openai"} {
		if got := providerCanonicalCode(in); got != "openai" {
			t.Errorf("providerCanonicalCode(%q) = %q, want %q", in, got, "openai")
		}
	}
}

// Google / Gemini — symmetric to the claude/anthropic pair; pin so future
// OAuth additions for Gemini don't drift.
func TestProbeCanonicalAlias_GoogleGemini(t *testing.T) {
	if got := providerCanonicalCode("gemini"); got != "google" {
		t.Errorf("providerCanonicalCode(\"gemini\") = %q, want %q", got, "google")
	}
	if got := providerCanonicalCode("google"); got != "google" {
		t.Errorf("providerCanonicalCode(\"google\") = %q, want %q", got, "google")
	}
}
