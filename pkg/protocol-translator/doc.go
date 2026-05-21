// Package translator converts LLM API requests + responses between
// different vendor protocols (OpenAI Chat Completions ↔ Anthropic Messages
// ↔ Gemini generateContent ↔ ...). Concrete (from, to) "pair"
// implementations register transform functions with a `Registry`; the
// App pipeline looks up the appropriate transform at request time based
// on the inbound URL protocol + the binding's upstream provider.
//
// Why this package exists (Phase 2 / 主方案 §6):
//
// The App pipeline lets a third-party Agent point at an OpenAI-style URL
// (e.g. /apps/<slug>/openai/v1/chat/completions) while the user's actual
// upstream is Anthropic / Gemini / etc. The translator is the layer that
// makes that work without the Agent knowing — it rewrites the OpenAI
// request body into whatever the upstream expects, then rewrites the
// upstream response back into OpenAI shape. Without translator, the App
// pipeline would have to either (a) refuse cross-protocol pairings, or
// (b) inline the conversion logic into the App pipeline itself,
// creating an N×M-line source-of-truth split between pipelines.
//
// Status (2026-05-20): **阶段 0 MVP** — non-streaming OpenAI → Anthropic
// only. Lives inside aikey-proxy (no split). Streaming SSE translation
// + Gemini pair + repo split land in subsequent stages (see
// roadmap20260320/技术实现/阶段4-增值版/OpenAI-Anthropic协议翻译模块设计.md
// §15).
//
// Public API:
//
//   - Format constants (openai / anthropic / gemini / bedrock)
//   - Endpoint type (default "" for chat-like, reserved for embed / audio / image)
//   - Registry (Register / TranslateRequest / TranslateNonStream)
//   - TranslateError (typed error with HTTP status + OpenAI shape rendering)
//
// What this package is NOT:
//
//   - It is NOT a credential layer; the caller (apppipe / proxy) handles
//     auth, binding lookup, and credential injection. Translator only
//     touches the body shape.
//   - It is NOT a transport layer; no http.Client lives here. The caller
//     forwards the translated body to the upstream.
//   - It is NOT a streaming buffer; the StreamState type is defined for
//     阶段 1, but阶段 0 only exposes non-stream transforms.
//
// Reference architecture: borrows the Registry pattern from CLIProxyAPI
// (MIT license, /Users/jake/Projects/github/CLIProxyAPI/sdk/translator/registry.go)
// with five deltas (error returns, context.Context, typed StreamState,
// hidden Endpoint dimension, DefaultRegistry naming).
// See 2026-05-20-Phase2-Day1-spike.md §2 for the deltas table.
package translator
