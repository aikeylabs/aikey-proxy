// Package openai_responses translates between the OpenAI Chat Completions
// API (the dialect virtually every OpenAI-ecosystem client speaks) and the
// OpenAI Responses API (the ONLY dialect chatgpt.com/backend-api/codex
// serves).
//
// # Why this package exists
//
// A team's ChatGPT subscription is reachable through AiKey as an OAuth
// account pool, but its upstream — chatgpt.com/backend-api/codex — has a
// single route, POST /responses, and a request/response shape that is not
// Chat Completions. Before this package the proxy refused the mismatch
// outright (`oauthUpstreamRejectsPath`, 2026-07-13): a client calling
// /v1/chat/completions got a 400 explaining that only /responses is served.
// That was the honest answer at the time — the alternative then was letting
// the path be appended verbatim to the codex base, which produced ChatGPT's
// own misleading "invalid x-api-key" and sent users debugging credentials
// for hours (that failure mode is what the refusal replaced, and it must not
// come back).
//
// The refusal is honest but it is also a product ceiling: it means the only
// clients that can consume a team ChatGPT subscription are Responses-API
// clients (codex). Translating instead of refusing is what turns the team
// OAuth feature into a general "subscription to API" surface — the client
// keeps speaking Chat Completions, AiKey speaks Responses upstream.
//
// # Design decisions worth knowing before you edit this
//
//  1. The inbound URL path is the ONLY switch. `/v1/chat/completions` engages
//     translation; `/v1/responses` stays a byte-for-byte passthrough. There is
//     no config flag, no new field, no new endpoint — the discriminator the
//     client already sends is sufficient, and a second source of truth for
//     "which dialect is this" is exactly how the two halves drift apart.
//
//  2. Translation is client-facing ONLY. On the response leg the proxy wraps
//     this pair OUTSIDE the stream drainer, so usage extraction, the
//     conversation-audit observer and the collector keep seeing the original
//     Responses frames. Token accounting and the billing ledger are therefore
//     byte-identical to the untranslated path — a translation bug can corrupt
//     what the client reads, never what the customer is charged.
//
//  3. Unsupported request fields are REJECTED, not dropped. `stop`, `n>1` and
//     the sampling penalties have no Responses equivalent; silently discarding
//     them would change the model's behaviour in a way the caller cannot see.
//     A loud 400 naming the parameter is the lesser harm (CLAUDE.md 失败要显眼).
//
// # Scope
//
//	✅ Request:  messages → instructions + input[], tools, tool_calls,
//	             tool results, sampling params, multimodal image parts
//	✅ Response: non-stream Responses → Chat Completions (text + tool calls)
//	✅ Response: streaming Responses SSE → chat.completion.chunk SSE
//	❌ response_format / json_schema (rejected with a named param)
//	❌ logprobs (no Responses equivalent; rejected)
//
// Import for side effect to register the pair:
//
//	import _ "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator/pairs/openai_responses"
package openai_responses
