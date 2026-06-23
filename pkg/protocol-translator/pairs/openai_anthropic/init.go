// Package openai_anthropic translates OpenAI Chat Completions API
// requests + non-stream responses to/from Anthropic Messages API.
//
// Phase 2 阶段 0 MVP scope (this package's current state):
//
//	✅ Top-level field mapping (model / max_tokens / temperature cap /
//	   top_p / top_k / stop / reasoning_effort → thinking / user → metadata)
//	⏳ Messages normalization (system extraction / user-start / role
//	   alternation / same-role merge / empty text filter) — Day 4
//	⏳ tools / tool_choice (incl. type=none + parallel_tool_calls reverse) — Day 4
//	✅ response_format=json_object → forced tool-call — Day 5
//	✅ Non-stream response (Anthropic → OpenAI) — Day 6
//	❌ Streaming SSE response (Anthropic → OpenAI chunk state machine) — 阶段 1
//	❌ json_schema variant (complex schema passthrough) — 阶段 1
//
// Import for side-effect to register the pair with the default Registry:
//
//	import _ "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator/pairs/openai_anthropic"
//
// The package's init() registers ConvertRequest + ConvertNonStream (when
// implemented) with translator.DefaultRegistry() under (openai, anthropic).
package openai_anthropic

import (
	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
)

// init registers this pair with the default Registry. Pair packages are
// typically blank-imported by the proxy main() so the side effect fires
// at process startup before any request dispatches.
//
// 阶段 0 MVP: ConvertRequest + ConvertNonStreamResponse are wired;
// Stream transform lands in 阶段 1.
func init() {
	translator.DefaultRegistry().Register(
		translator.FormatOpenAI,
		translator.FormatAnthropic,
		ConvertRequest,
		translator.ResponseTransforms{
			NonStream: ConvertNonStreamResponse,
			// Stream: nil — 阶段 1 milestone
		},
	)
}
