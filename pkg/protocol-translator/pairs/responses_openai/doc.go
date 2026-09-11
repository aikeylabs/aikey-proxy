// Package responses_openai translates the OpenAI Responses API to the OpenAI
// Chat Completions API — the reverse of the openai_responses pair.
//
// # Why both directions exist
//
// The two dialects are not "old" and "new" with traffic flowing one way. Which
// one a hop speaks is a property of each side independently:
//
//   - a ChatGPT OAuth (codex) upstream serves ONLY Responses;
//   - most OpenAI-compatible relays and self-hosted gateways serve ONLY Chat
//     Completions;
//   - clients are split the same way (codex speaks Responses, everything else
//     speaks Chat Completions).
//
// So all four combinations occur in the field, and the two that differ need a
// translator each. This package is the Responses-client → Chat-Completions-
// upstream half.
//
// # The asymmetry that makes this direction harder than the other one
//
// Responses is a STATEFUL protocol and Chat Completions is not.
//
//   - `previous_response_id` says "continue from the turn the server still
//     holds". A Chat Completions upstream has no such memory and no way to
//     fetch it. Forwarding the request without it is not a lossy translation,
//     it is a DIFFERENT conversation: the model sees only the current turn.
//     The request still succeeds and still returns prose, so nothing surfaces
//     the truncation. It is refused here for exactly that reason.
//   - `store`, `include` and `truncation` are likewise server-side behaviors
//     with no client-side equivalent.
//
// The forward direction has no equivalent hazard, because Chat Completions
// carries its whole history in every request.
//
// # Streaming
//
// Chat Completions streams one frame type; Responses streams a typed lifecycle
// (created → item added → content part added → deltas → done → completed).
// Going this way means SYNTHESIZING events the source never sent, which is why
// the stream transform is a state machine rather than a per-frame rewrite: the
// opening lifecycle can only be emitted once the first chunk reveals the id and
// model, and the closing `response.completed` has to carry the fully
// accumulated output that Chat Completions only ever sent incrementally.
//
// # Scope
//
//	✅ Request:  instructions + input[] → messages[], tools, tool calls,
//	             tool results, sampling params, multimodal image parts
//	✅ Response: non-stream Chat Completions → Responses (text + tool calls)
//	✅ Response: streaming chat.completion.chunk → Responses SSE lifecycle
//	❌ previous_response_id / include / truncation / text.format — refused,
//	   with the parameter named (see the stateful-protocol note above)
//
// Import for side effect to register the pair:
//
//	import _ "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator/pairs/responses_openai"
package responses_openai
