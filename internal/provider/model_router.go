package provider

import "strings"

// model_router.go — body.model → upstream provider inference.
//
// Phase 2 Day 7 (2026-05-21): replaces the URL `<protocol>` segment as
// the routing signal. The OpenAI SDK at the client side has no way to
// declare "I want Anthropic upstream" — the only signal that flows from
// LangChain ChatOpenAI / openai-python through to the proxy is the
// `model` field in the request body. AiKey's App pipeline reads it, infers
// the upstream, and looks up the binding for that upstream.
//
// Why hardcoded (vs configurable table):
//   - LiteLLM's `model_prices.json` is also community-maintained hardcoded
//     (~1000 entries, quarterly updates); industry pattern matches
//   - Most model families have stable name prefixes (claude-*, gpt-*, ...)
//   - When a new family lands (e.g. gpt-5), we add one entry and rebuild;
//     no migration / schema concern
//   - User-overrides for ambiguous models can be added later via
//     `aikey app route --upstream X --model-prefix ...` when there's
//     real demand (YAGNI for阶段 0)
//
// Reference: roadmap20260320/技术实现/protocol-translator/langchain-wire-protocol-research.md
// (industry survey of how LiteLLM / OpenRouter / Portkey / Kong route).

// InferUpstreamFromModel returns the upstream provider code for the given
// model name. Returns "" if the model name cannot be confidently mapped
// to a known upstream — the caller (apppipe/resolve.go) treats empty as
// "model not recognized; user must add a binding or use a recognized
// model name" (UPSTREAM_UNINFERRABLE error).
//
// The match is case-insensitive (some clients normalize model names to
// lowercase, others preserve casing). Prefix match — a model id like
// "claude-3-5-sonnet-20241022" matches the "claude-" prefix and resolves
// to "anthropic".
//
// Order of evaluation matters for prefixes that could be ambiguous:
//   - "moonshot-*" must precede "*" wildcards (currently no conflict, but
//     future-proof the ordering)
//   - Bedrock / Azure / cloud-prefixed model ids (e.g.
//     "bedrock/anthropic.claude-...", "azure/gpt-4o") are recognized too;
//     they go to the same translator pair (since the wire shape from the
//     pair's POV is determined by the upstream provider, not the cloud)
//
// Tests in model_router_test.go pin the matrix.
func InferUpstreamFromModel(model string) string {
	if model == "" {
		return ""
	}
	lower := strings.ToLower(model)

	// Strip cloud-prefix forms ("bedrock/...", "azure/...", "anthropic/...")
	// — these are LiteLLM-style explicit-upstream tags. The leading word
	// IS the upstream when it's a known provider; if it's a cloud host
	// like "bedrock" or "azure", we fall through to the suffix model id.
	if idx := strings.Index(lower, "/"); idx > 0 {
		prefix := lower[:idx]
		switch prefix {
		case "openai", "anthropic", "gemini":
			return prefix
		case "bedrock", "vertex_ai", "azure":
			// Cloud-host prefix — peel it and re-infer on the suffix. The
			// suffix is either:
			//   (a) Bedrock-style "<vendor>.<modelid>" (e.g.
			//       "anthropic.claude-3-haiku-20240307") — the vendor name
			//       IS the upstream; return it directly if known.
			//   (b) Plain model id (e.g. "gpt-4o-eu", "gemini-1.5-flash") —
			//       fall through to the prefix table below.
			lower = lower[idx+1:]
			// Only treat the leading "." as a vendor-namespacing separator
			// if it appears BEFORE any "-" (Bedrock convention is
			// "<vendor>.<modelid>" where modelid uses "-" for the version).
			// "gemini-1.5-flash" has dots inside the version string — those
			// must NOT be treated as vendor separators.
			if dot := strings.Index(lower, "."); dot > 0 {
				dash := strings.Index(lower, "-")
				if dash == -1 || dot < dash {
					vendor := lower[:dot]
					switch vendor {
					case "openai", "anthropic", "gemini":
						return vendor
					default:
						// Other Bedrock vendors (amazon / meta / mistral /
						// cohere / etc.) — no first-party AiKey upstream
						// today. Strip the vendor and try the suffix; if
						// it doesn't match, the fall-through returns ""
						// (UPSTREAM_UNINFERRABLE).
						lower = lower[dot+1:]
					}
				}
			}
		}
	}

	// Prefix table. Add entries here as new model families ship.
	switch {
	case strings.HasPrefix(lower, "claude-"),
		strings.HasPrefix(lower, "claude_"):
		return "anthropic"
	case strings.HasPrefix(lower, "gpt-"),
		strings.HasPrefix(lower, "gpt_"),
		strings.HasPrefix(lower, "o1-"),
		strings.HasPrefix(lower, "o3-"),
		strings.HasPrefix(lower, "o4-"),
		strings.HasPrefix(lower, "chatgpt-"),
		strings.HasPrefix(lower, "text-davinci-"),
		strings.HasPrefix(lower, "text-curie-"),
		strings.HasPrefix(lower, "text-babbage-"),
		strings.HasPrefix(lower, "text-ada-"),
		strings.HasPrefix(lower, "davinci-"),
		strings.HasPrefix(lower, "babbage-"):
		return "openai"
	case strings.HasPrefix(lower, "gemini-"),
		strings.HasPrefix(lower, "gemini_"):
		return "gemini"
	case strings.HasPrefix(lower, "moonshot-"),
		strings.HasPrefix(lower, "moonshot_"),
		strings.HasPrefix(lower, "kimi-"),
		strings.HasPrefix(lower, "kimi_"):
		return "kimi"
	case strings.HasPrefix(lower, "deepseek-"),
		strings.HasPrefix(lower, "deepseek_"):
		return "deepseek"
	case strings.HasPrefix(lower, "qwen-"),
		strings.HasPrefix(lower, "qwen_"):
		return "qwen"
	}
	return ""
}

// IsOpenAIWireCompatible reports whether the named upstream provider
// speaks OpenAI Chat Completions wire format natively.
//
// Why this matters for the App pipeline: the translator's "translate or
// fast-path" decision is based on wire family equality, NOT provider-code
// string equality. Kimi / DeepSeek / Qwen / Groq / Together / Perplexity
// / OpenRouter / SiliconFlow are all OpenAI-wire-compatible — clients
// using ChatOpenAI(base_url=AiKey, model=...) hit `/chat/completions`,
// AiKey doesn't need to rewrite the body, and the upstream returns the
// same Chat Completion JSON shape. Only the URL (base_url) + auth header
// differ — handled by the per-provider adapter (`internal/provider/X.go`),
// not by the translator.
//
// Without this helper, the translator would treat (FormatOpenAI, "kimi")
// as a cross-wire request and try to find a translator pair, returning
// 501 TRANSLATION_PAIR_NOT_REGISTERED — wrong, because nothing needs to
// be translated.
//
// The list mirrors the OpenAI-API-compatible provider catalog at industry
// scale. Adding new entries here is safe — the only effect is "do not
// look for a translator pair", which is the correct behavior for any
// OpenAI-compatible upstream.
//
// Not in this list (NOT OpenAI-wire-compatible): "anthropic" (different
// wire shape), "gemini" (different wire shape), "bedrock" (Bedrock has
// its own ConverseAPI which differs from OpenAI).
func IsOpenAIWireCompatible(upstreamCode string) bool {
	switch strings.ToLower(upstreamCode) {
	case
		// OpenAI itself.
		"openai",
		// Tier-1 OpenAI-compatible direct providers (publicly documented as
		// "drop-in replacement for OpenAI").
		"kimi", "moonshot", "deepseek", "qwen",
		"groq", "together", "perplexity", "fireworks", "deepinfra",
		"siliconflow", "siliconflow-cn", "zhipu", "doubao", "01ai",
		// Aggregator gateways that forward OpenAI-wire to backends.
		"openrouter", "openrouter-ai", "litellm", "portkey":
		return true
	}
	return false
}

// NormalizeModelForUpstream rewrites a `provider/model` prefix-style model
// id into the form the chosen upstream expects. Fix for G1 (see
// `roadmap20260320/技术实现/protocol-translator/known-gaps.md`).
//
// Rule: if the model id starts with `<X>/` where X equals the binding's
// upstream provider code, strip that segment. Otherwise leave the model
// id unchanged.
//
// Examples (upstreamCode → input → output):
//
//	anthropic   → "anthropic/claude-3-5-sonnet" → "claude-3-5-sonnet"        (direct, strip)
//	anthropic   → "claude-3-5-sonnet"           → "claude-3-5-sonnet"        (no prefix, unchanged)
//	openai      → "openai/gpt-4o"               → "gpt-4o"                   (direct, strip)
//	openrouter  → "openrouter/openai/gpt-5"     → "openai/gpt-5"             (aggregator, strip outer)
//	openrouter  → "anthropic/claude-3-5-sonnet" → "anthropic/claude-3-5-sonnet" (prefix ≠ upstream, keep — OpenRouter sub-route)
//	siliconflow-cn → "siliconflow-cn/Pro/zai-org/GLM-4.7" → "Pro/zai-org/GLM-4.7"
//	bedrock     → "bedrock/anthropic.claude-3"  → "anthropic.claude-3"       (Bedrock vendor.model form preserved)
//
// Why "exactly equals" (not "is a known prefix"): the user binds to a
// specific upstream provider via `aikey app route`. The vault row's
// ProviderCode is the truth source. If the model prefix doesn't match,
// the user is likely using an aggregator-style sub-prefix (anthropic/...
// via openrouter) and we shouldn't strip — the aggregator needs that
// prefix to route internally.
//
// Edge case (case insensitivity): provider codes are written in vault
// as lowercase by `aikey add --provider X`; user-typed model prefixes
// may be in any case. We compare case-insensitively but preserve the
// original case of the remaining model id (some upstreams are sensitive
// to model name case).
func NormalizeModelForUpstream(rawModel, upstreamCode string) string {
	if rawModel == "" || upstreamCode == "" {
		return rawModel
	}
	idx := strings.Index(rawModel, "/")
	if idx <= 0 {
		// No prefix — nothing to strip.
		return rawModel
	}
	prefix := rawModel[:idx]
	if strings.EqualFold(prefix, upstreamCode) {
		// Strip the leading "<upstream>/" — what's left is what upstream
		// actually expects.
		return rawModel[idx+1:]
	}
	return rawModel
}
