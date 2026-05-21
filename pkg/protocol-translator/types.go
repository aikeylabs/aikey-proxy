package translator

import (
	"context"
	"strings"
)

// Format identifies an LLM API protocol family. The Registry keys are
// (from-Format, to-Format) tuples; each (from, to) pair has at most one
// RequestTransform + one NonStreamTransform (StreamTransform is added in
// 阶段 1).
//
// Why a typed string rather than an enum: forward-compatibility — adding
// a new protocol requires only defining a new constant, no codegen, no
// API break. Custom Format values from third-party pair implementations
// (e.g. `Format("my-private-protocol")`) are deliberately allowed; the
// Registry doesn't validate Format membership.
type Format string

// Built-in Format values. New formats can be added without breaking
// existing pairs because Registry lookup is exact string match.
const (
	// FormatOpenAI is the OpenAI Chat Completions API
	// (POST /v1/chat/completions, request body has `messages[]` +
	// `model` + tool calls in `assistant.tool_calls`).
	FormatOpenAI Format = "openai"

	// FormatOpenAIResponses is the newer OpenAI Responses API.
	// Reserved for 阶段 4+; not implemented in MVP.
	FormatOpenAIResponses Format = "openai-responses"

	// FormatAnthropic is the Anthropic Messages API
	// (POST /v1/messages, system as top-level array, content blocks,
	// tool_use / tool_result in content[]).
	FormatAnthropic Format = "anthropic"

	// FormatGemini is the Google Gemini generateContent API.
	// Reserved for 阶段 2 (validation of Registry pluggability).
	FormatGemini Format = "gemini"

	// FormatBedrock is the AWS Bedrock Converse API.
	// Reserved for 阶段 4+ (enterprise AWS customers).
	FormatBedrock Format = "bedrock"
)

// Endpoint is the API surface within a Format (chat-like vs embeddings
// vs audio vs image). 阶段 0 MVP only handles chat-like, so this type
// is defined but the Registry's public API hides the Endpoint dimension
// — Register / Translate* methods implicitly use EndpointDefault. The
// type is kept exported so阶段 3 can promote it to a first-class
// dimension without an API break.
//
// Hidden by design: exposing Endpoint at阶段 0 would force every caller
// to pass `EndpointDefault` constants, adding noise to the dominant
// (chat-like) use case. The internal Registry storage IS three-tuple
// keyed, so the upgrade is mechanical.
type Endpoint string

// EndpointDefault is chat-like (the only Endpoint阶段 0 supports).
const EndpointDefault Endpoint = ""

// RequestTransform converts a request body from `from` Format to `to`
// Format. It is the only direction pairs MUST implement (response
// translation is technically optional, since some pairs may forward
// the upstream response shape unmodified).
//
// Signature contract:
//
//   - ctx — for tracing / deadline / cancellation. Pairs SHOULD honor
//     ctx.Done() if they do any non-trivial work; for pure JSON-rewriting
//     pairs it's safe to ignore.
//
//   - model — the canonical model name to use upstream (after any
//     alias / brand mapping the caller did). Pairs MUST set this in
//     the output body's `model` field even if the inbound body didn't
//     have one; this normalizes client behaviors that pass model via
//     header / query.
//
//   - body — the raw inbound request bytes. Pairs SHOULD use gjson/sjson
//     for byte-level edits (faster than full parse + re-marshal at MVP
//     scale; sanitizer uses parse + re-marshal because it touches
//     arbitrary metadata depth, but translator only touches known fields).
//
//   - stream — true iff the client wants SSE. 阶段 0 MVP transforms
//     don't differ by stream value (request body shape is the same);
//     stream-aware response handling lives in StreamChunkTransform
//     (阶段 1).
//
// Returns: translated body bytes + nil on success, OR nil + *TranslateError
// on rejection (e.g. unsupported field, malformed input). NEVER both
// non-nil — caller writes the error directly to the http.ResponseWriter.
type RequestTransform func(
	ctx context.Context,
	model string,
	body []byte,
	stream bool,
) ([]byte, *TranslateError)

// NonStreamTransform converts a non-streaming response body from the
// upstream's native shape (e.g. Anthropic Messages response) back to
// the inbound Format's expected shape (e.g. OpenAI Chat Completion
// response). Pairs MUST implement this if they accept non-stream
// requests (almost all do at MVP).
//
// The `from` and `to` direction in NonStreamTransform are REVERSED
// relative to RequestTransform: a request from openai going to
// anthropic generates an anthropic response which must be translated
// FROM anthropic TO openai. The Registry handles this swap internally
// so pair authors register both transforms under the same (request-side)
// (from, to) pair.
type NonStreamTransform func(
	ctx context.Context,
	body []byte,
) ([]byte, *TranslateError)

// StreamChunkTransform converts one Anthropic SSE chunk into zero or
// more OpenAI SSE chunks (Anthropic emits more frame types than OpenAI,
// notably content_block_start / content_block_stop, which don't have a
// direct OpenAI equivalent).
//
// 阶段 0 MVP does NOT implement any StreamChunkTransform — pairs only
// register NonStream transforms. 阶段 1 introduces the full state-machine
// design (see design doc §10). The type is defined here so pair
// implementations and tests can be drafted against the final signature.
//
// Why typed StreamState instead of CLIProxyAPI's `param *any`:
// see 2026-05-20-Phase2-Day1-spike.md §2 #3. Typed state prevents the
// "state field mismatch" bug class CLIProxyAPI's untyped param
// exposed (where one transform writes a string and another tries to
// read a slice from the same param slot).
type StreamChunkTransform func(
	ctx context.Context,
	st *StreamState,
	chunk []byte,
) (outChunks [][]byte, err *TranslateError)

// ResponseTransforms bundles the non-stream + (eventual) stream
// transforms for a given (from, to) pair. Pair authors register both
// together so the Registry can validate they're consistent
// (e.g. if NonStream is provided then Stream is recommended but not
// required at 阶段 0; conversely, registering only Stream is rejected
// because there's no fallback for non-stream clients).
type ResponseTransforms struct {
	// Stream is the SSE chunk transform. 阶段 0 MVP pairs leave this nil.
	Stream StreamChunkTransform
	// NonStream is the full-body response transform. REQUIRED for any
	// pair that accepts non-stream requests (almost all pairs at MVP).
	NonStream NonStreamTransform
}

// StreamState accumulates state across chunks of a single streaming
// response. Pairs MUST instantiate one per request (NOT one per process)
// and pass it as `st` to every StreamChunkTransform call for that request.
//
// 阶段 0 MVP does not invoke any StreamChunkTransforms, so the
// Registry won't construct StreamState instances. The type is defined
// here for pair implementations to draft against the final signature.
//
// Why each field exists:
//
//   - ResponseID / Model / CreatedAt: OpenAI SSE chunks all carry these
//     in each chunk's top-level (`id`, `model`, `created`); they're
//     fixed per response, so cache once and stamp every chunk.
//
//   - HasResponseFormat / JSONFallbackName: when the inbound request
//     used `response_format=json_object` with a forced tool-call
//     workaround, the upstream's tool_use response must be UN-wrapped
//     back into a plain JSON string in `message.content`. The accumulator
//     needs to remember the synthetic tool name (`respond_in_json`)
//     so it can detect the right tool_use frames.
//
//   - ToolCallsAccum: SSE tool_calls arguments arrive as incremental
//     `input_json_delta` strings (Anthropic) but OpenAI expects them
//     as `function.arguments` deltas. The accumulator concatenates
//     deltas indexed by tool-call position; on `content_block_stop`
//     it can validate the accumulated string is valid JSON.
//
//   - InputUsage / OutputUsage: token counts arrive incrementally in
//     `message_delta` events; we accumulate to emit a final OpenAI
//     `usage` field on the closing chunk.
//
//   - Extra: per-pair escape hatch. Most pairs won't need it. Forward
//     compatibility — if a future Format needs a field StreamState
//     doesn't already model, the pair can stash it here instead of
//     extending the public struct.
type StreamState struct {
	// Stamped on every chunk emitted to the client.
	ResponseID string
	Model      string
	CreatedAt  int64

	// json_object forced tool-call workaround tracking. HasResponseFormat
	// is true iff the inbound request had response_format=json_object;
	// JSONFallbackName is the synthetic tool name (e.g. "respond_in_json").
	HasResponseFormat bool
	JSONFallbackName  string

	// Per-tool-call argument deltas, indexed by OpenAI tool_calls index
	// (not by Anthropic tool id, which can be hex-flavored).
	ToolCallsAccum map[int]*ToolCallAccum

	// Cumulative token counts across the stream.
	InputUsage  Usage
	OutputUsage Usage

	// Pair-specific scratch space. Translator core never reads Extra;
	// pair authors are responsible for namespacing keys to avoid
	// collisions when multiple pairs share a StreamState (rare but
	// possible in Endpoint-aware setups).
	Extra map[string]any
}

// ToolCallAccum accumulates one tool-call's incremental JSON arguments
// across stream chunks. Args is a strings.Builder so the per-chunk
// growth is O(1) amortized; on tool-call completion the pair calls
// Args.String() once to emit the final OpenAI chunk.
type ToolCallAccum struct {
	ID, Name string
	Args     strings.Builder
}

// Usage records token counts. All four fields are optional at the wire
// level (Anthropic + OpenAI both omit fields they don't track), so
// pairs MUST treat zero as "unknown / not reported" rather than
// "definitely zero". The TotalTokens field is computed (PromptTokens +
// CompletionTokens) by some upstreams + omitted by others; readers
// SHOULD compute it themselves if needed.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int

	// CacheReadTokens / CacheWriteTokens are Anthropic-specific. OpenAI
	// surfaces them under `prompt_tokens_details` in newer API versions.
	// Pairs MAY skip these fields if the upstream doesn't report them.
	CacheReadTokens  int
	CacheWriteTokens int
}
