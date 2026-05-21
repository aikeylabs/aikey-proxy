package openai_anthropic

import (
	"context"
	"strings"
	"time"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// response.go — Anthropic Messages response → OpenAI Chat Completion
// response. Day 6 of Phase 2 阶段 0 MVP.
//
// Anthropic shape (the fields we read):
//
//	{
//	  "id":          "msg_01ABCDEF...",
//	  "type":        "message",
//	  "role":        "assistant",
//	  "model":       "claude-3-5-sonnet-20241022",
//	  "content": [
//	    {"type": "text",     "text": "Hello!"},
//	    {"type": "tool_use", "id": "toolu_01...", "name": "get_weather",
//	                         "input": {"location": "SF"}}
//	  ],
//	  "stop_reason":   "end_turn" | "max_tokens" | "stop_sequence" | "tool_use",
//	  "stop_sequence": null | "...",
//	  "usage": {
//	    "input_tokens": 25,
//	    "output_tokens": 50,
//	    "cache_read_input_tokens":     0,
//	    "cache_creation_input_tokens": 0
//	  }
//	}
//
// OpenAI shape (the envelope we emit):
//
//	{
//	  "id":      "<passthrough Anthropic id>",
//	  "object":  "chat.completion",
//	  "created": <unix_ts>,
//	  "model":   "...",
//	  "choices": [{
//	    "index":   0,
//	    "message": {
//	      "role":       "assistant",
//	      "content":    "Hello!" | null,
//	      "tool_calls": [{"id":"...","type":"function",
//	                     "function":{"name":"...","arguments":"<JSON str>"}}]
//	    },
//	    "finish_reason": "stop" | "length" | "tool_calls"
//	  }],
//	  "usage": {"prompt_tokens": 25, "completion_tokens": 50, "total_tokens": 75}
//	}
//
// Synthetic-tool reverse (response_format = json_object/json_schema):
//
//	If any content[] block is {type:"tool_use", name:"respond_in_json"},
//	the caller asked for JSON output (Day 5 forced tool-call). We unwrap
//	that block's `input` into message.content as a JSON STRING, drop the
//	tool_calls (the caller didn't really want a function call), and
//	normalize finish_reason: "tool_use" → "stop". The synthetic-name
//	heuristic is the same one used by LiteLLM — a user tool happening
//	to also be named "respond_in_json" would collide, but that's
//	acceptable given how unlikely the namespace clash is, and the
//	user-visible effect (JSON in message.content) is what they wanted
//	anyway.

// ConvertNonStreamResponse implements translator.NonStreamTransform for
// the (openai → anthropic) request pair. Note the direction: when an
// OpenAI client sent a request that was translated to Anthropic, the
// upstream returns an Anthropic-shaped body which this function maps
// back to the OpenAI shape the client expects.
//
// Errors:
//   - Invalid JSON: AIKEY_TRANSLATION_FAILED with 502 (upstream contract
//     violation; not the caller's fault).
//   - Anthropic error envelope ({"type":"error",...}): mapped to a
//     TranslateError with an appropriate HTTP status drawn from the
//     Anthropic error.type field. Caller surfaces this via its standard
//     error pipeline; we don't re-shape the body to "look like" an
//     OpenAI error here because that pipeline already knows how to do
//     it consistently from a TranslateError.
func ConvertNonStreamResponse(ctx context.Context, body []byte) ([]byte, *translator.TranslateError) {
	_ = ctx // tracing / deadline not used at MVP; pure JSON rewrite

	if !gjson.ValidBytes(body) {
		return nil, &translator.TranslateError{
			Code:       translator.CodeTranslationFailed,
			HTTPStatus: 502,
			Message:    "Anthropic upstream returned a body that is not valid JSON",
		}
	}
	in := gjson.ParseBytes(body)

	// ── Error envelope passthrough ────────────────────────────────────
	// Anthropic 4xx/5xx bodies look like {"type":"error","error":{...}}.
	// We translate them to a TranslateError so the caller produces a
	// consistent OpenAI-style error envelope at one place (not duplicated
	// here). HTTP status follows Anthropic's error.type taxonomy.
	if in.Get("type").String() == "error" {
		errType := in.Get("error.type").String()
		errMsg := in.Get("error.message").String()
		return nil, &translator.TranslateError{
			Code:       mapAnthropicErrorTypeToCode(errType),
			HTTPStatus: mapAnthropicErrorTypeToHTTP(errType),
			Message:    "Anthropic upstream error (" + errType + "): " + errMsg,
		}
	}

	// ── Header fields ────────────────────────────────────────────────
	id := in.Get("id").String()
	if id == "" {
		// Anthropic SHOULD always provide id; defensive fallback so
		// OpenAI clients that require non-empty id don't blow up.
		id = "chatcmpl-translated-fallback"
	}
	model := in.Get("model").String()

	// ── Content blocks → message.content + tool_calls ────────────────
	contentText, toolCalls, syntheticUsed := convertResponseContentBlocks(in.Get("content"))

	// ── stop_reason → finish_reason ─────────────────────────────────
	stopReason := in.Get("stop_reason").String()
	finishReason := mapStopReason(stopReason, len(toolCalls) > 0, syntheticUsed)

	// ── Compose envelope ─────────────────────────────────────────────
	// We build the JSON literal by hand (string concatenation through
	// strings.Builder) rather than marshalling a typed struct because
	// the message.content "null vs empty string" decision is shape-
	// dependent (null when there are tool_calls and no text; empty
	// string otherwise) and encoding/json's Marshaler interface doesn't
	// distinguish these cleanly without custom types.
	var out strings.Builder
	out.Grow(len(body) + 256)
	out.WriteByte('{')

	out.WriteString(`"id":`)
	out.WriteString(jsonQuote(id))

	out.WriteString(`,"object":"chat.completion"`)

	out.WriteString(`,"created":`)
	out.WriteString(strconvIToA(int(timeNowUnix())))

	out.WriteString(`,"model":`)
	out.WriteString(jsonQuote(model))

	out.WriteString(`,"choices":[{"index":0,"message":`)
	writeMessageObject(&out, contentText, toolCalls)
	out.WriteString(`,"finish_reason":`)
	out.WriteString(jsonQuote(finishReason))
	out.WriteString(`}]`)

	out.WriteString(`,"usage":`)
	writeUsage(&out, in.Get("usage"))

	out.WriteByte('}')
	return []byte(out.String()), nil
}

// writeMessageObject emits the OpenAI `message` sub-object. Rules:
//   - role: always "assistant".
//   - content: null when contentText == "" AND len(toolCalls) > 0
//     (pure tool-call response). Empty string when there's no text but
//     also no tool_calls — preserves "model returned nothing" semantics
//     vs null. JSON-quoted string in all other cases.
//   - tool_calls: omitted when empty (OpenAI doesn't emit the key for
//     plain-text responses).
func writeMessageObject(out *strings.Builder, contentText string, toolCalls []string) {
	out.WriteString(`{"role":"assistant"`)
	if contentText == "" && len(toolCalls) > 0 {
		out.WriteString(`,"content":null`)
	} else {
		out.WriteString(`,"content":`)
		out.WriteString(jsonQuote(contentText))
	}
	if len(toolCalls) > 0 {
		out.WriteString(`,"tool_calls":[`)
		for i, tc := range toolCalls {
			if i > 0 {
				out.WriteByte(',')
			}
			out.WriteString(tc)
		}
		out.WriteByte(']')
	}
	out.WriteByte('}')
}

// writeUsage emits the OpenAI usage sub-object. Anthropic's
// input_tokens/output_tokens become prompt_tokens/completion_tokens;
// total_tokens is computed because Anthropic doesn't emit it.
// cache_read/cache_creation tokens are dropped at MVP — the OpenAI
// `prompt_tokens_details` extension is too new to be reliable across
// client SDKs.
func writeUsage(out *strings.Builder, usage gjson.Result) {
	prompt := int(usage.Get("input_tokens").Int())
	completion := int(usage.Get("output_tokens").Int())
	total := prompt + completion
	out.WriteString(`{"prompt_tokens":`)
	out.WriteString(strconvIToA(prompt))
	out.WriteString(`,"completion_tokens":`)
	out.WriteString(strconvIToA(completion))
	out.WriteString(`,"total_tokens":`)
	out.WriteString(strconvIToA(total))
	out.WriteByte('}')
}

// convertResponseContentBlocks scans Anthropic content[] and returns:
//   - contentText: concatenated text blocks + synthetic-tool input JSON
//     (caller renders this as message.content).
//   - toolCalls: OpenAI-shape tool_calls JSON literals (one per real
//     tool_use block; the synthetic respond_in_json block is unwrapped
//     into contentText and NOT emitted here).
//   - syntheticUsed: true iff a respond_in_json tool_use block was
//     unwrapped; the caller uses this to override finish_reason.
//
// Blocks of unknown type are silently skipped. Anthropic's content array
// can contain server-tool-use / web-search-result frames that don't have
// OpenAI equivalents at MVP — better to drop them than 5xx the response.
func convertResponseContentBlocks(content gjson.Result) (string, []string, bool) {
	if !content.IsArray() {
		return "", nil, false
	}
	var textParts []string
	var toolCalls []string
	syntheticUsed := false
	for _, block := range content.Array() {
		blockType := block.Get("type").String()
		switch blockType {
		case "text":
			textParts = append(textParts, block.Get("text").String())
		case "tool_use":
			name := block.Get("name").String()
			inputRaw := block.Get("input").Raw
			if inputRaw == "" {
				// Anthropic should always emit input as at least {};
				// be defensive in case of partial-response edge.
				inputRaw = "{}"
			}
			if name == JSONResponseToolName {
				// Synthetic-tool reverse: unwrap input JSON into content.
				// Append the RAW JSON text (e.g. {"answer":42}) into the
				// text accumulator; the caller jsonQuote()s the whole
				// content string, so the inner JSON gets escaped properly.
				textParts = append(textParts, inputRaw)
				syntheticUsed = true
				continue
			}
			// Real tool call. arguments MUST be a JSON STRING in OpenAI
			// shape — quote inputRaw (which is JSON) as a string literal.
			id := block.Get("id").String()
			tc := `{"id":` + jsonQuote(id) +
				`,"type":"function","function":{"name":` + jsonQuote(name) +
				`,"arguments":` + jsonQuote(inputRaw) + `}}`
			toolCalls = append(toolCalls, tc)
		default:
			// Skip unsupported block types (server_tool_use, web_search,
			// document, image-in-response, etc.).
		}
	}
	return strings.Join(textParts, ""), toolCalls, syntheticUsed
}

// mapStopReason translates Anthropic stop_reason to OpenAI finish_reason.
//
//	end_turn       → stop
//	stop_sequence  → stop
//	max_tokens     → length
//	tool_use       → tool_calls (or "stop" if the only tool_use was the
//	                 synthetic respond_in_json — caller didn't really
//	                 want a tool call)
//	(unknown)      → stop (safe fallback; better than emitting an
//	                 OpenAI-illegal value)
func mapStopReason(anthropicReason string, hasToolCalls bool, syntheticUsed bool) string {
	switch anthropicReason {
	case "end_turn", "stop_sequence":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		if syntheticUsed && !hasToolCalls {
			// Only the synthetic tool was called → caller sees a normal
			// completion with JSON in message.content.
			return "stop"
		}
		return "tool_calls"
	default:
		// Unknown — most likely a new Anthropic stop_reason we haven't
		// seen yet. Falling back to "stop" is safer than emitting
		// arbitrary upstream value.
		return "stop"
	}
}

// mapAnthropicErrorTypeToHTTP picks the HTTP status to surface for an
// Anthropic error envelope. Mirrors the upstream's own HTTP status
// where Anthropic documents it; defaults to 500 for unknown types.
func mapAnthropicErrorTypeToHTTP(errType string) int {
	switch errType {
	case "invalid_request_error":
		return 400
	case "authentication_error":
		return 401
	case "permission_error":
		return 403
	case "not_found_error":
		return 404
	case "rate_limit_error":
		return 429
	case "api_error":
		return 500
	case "overloaded_error":
		return 529 // Anthropic's documented status for overload
	default:
		return 500
	}
}

// mapAnthropicErrorTypeToCode picks an AiKey translator error code for
// the Anthropic error type. Caller renders this into the OpenAI error
// envelope at the proxy edge.
func mapAnthropicErrorTypeToCode(errType string) string {
	switch errType {
	case "authentication_error":
		return translator.CodeUpstreamAuth
	case "rate_limit_error":
		return translator.CodeUpstreamRateLimit
	case "api_error", "overloaded_error":
		return translator.CodeUpstream5xx
	default:
		// Fall back to upstream 5xx for unknown — surface the upstream
		// type/message verbatim in the user-visible error.
		return translator.CodeUpstream5xx
	}
}

// timeNowUnix is a var rather than a direct call so tests can stub it
// to a fixed value for deterministic envelope comparison.
var timeNowUnix = func() int64 { return time.Now().Unix() }
