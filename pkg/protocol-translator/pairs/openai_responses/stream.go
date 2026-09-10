package openai_responses

import (
	"bytes"
	"context"
	"encoding/json"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// stream.go — Responses API SSE → Chat Completions SSE.
//
// # The shape of the problem
//
// The two dialects do not stream the same way. Chat Completions emits ONE
// frame type (`chat.completion.chunk`) whose `choices[0].delta` carries
// whatever changed, terminated by a literal `data: [DONE]`. The Responses API
// emits a typed event stream — creation, per-item lifecycle, text deltas,
// tool-argument deltas, completion — where most events have no Chat
// Completions counterpart at all.
//
// So this is not a field rename per frame: it is a small state machine that
// (a) remembers the response id / model / tool indices that Chat Completions
// repeats on every chunk but Responses states once, (b) synthesises the two
// frames Chat Completions requires and Responses never sends (the opening
// role delta and the closing finish_reason chunk), and (c) drops the events
// that have no counterpart rather than inventing one.
//
// # Why frames are dropped rather than passed through
//
// An untranslatable frame forwarded verbatim would reach an SDK that parses
// every `data:` line as a chat.completion.chunk. It would either throw or —
// worse — deserialize into an empty chunk and be counted as a real one. Both
// are worse than the event simply not existing in the target dialect.
//
// # Ordering contract this must preserve
//
// A Chat Completions consumer relies on: exactly one role delta first, then
// content/tool deltas in order, then exactly one chunk carrying a non-null
// finish_reason, then exactly one [DONE]. The upstream can legitimately end a
// stream in three different ways (completed / incomplete / failed) and some
// deployments also send their own [DONE]; `doneSent` collapses all of those
// into the single terminator the consumer expects.

// streamScratch is this pair's slice of translator.StreamState.Extra.
//
// It lives in Extra rather than as new StreamState fields because StreamState
// is shared by every pair, and its documented shape is Anthropic-flavoured
// (see its ToolCallsAccum comment). Growing the shared struct for one pair's
// bookkeeping is how a "typed state" contract turns back into a bag of
// loosely-related fields.
type streamScratch struct {
	// toolIndexByItem maps a Responses output-item id to the dense,
	// zero-based index Chat Completions uses to correlate tool-call deltas.
	// The two numbering schemes are unrelated: Responses ids are opaque and
	// its output_index counts ALL items (text included), while Chat
	// Completions indexes tool calls only.
	toolIndexByItem map[string]int
	nextToolIndex   int
	roleSent        bool
	sawToolCall     bool
	doneSent        bool
}

const scratchKey = "openai_responses.scratch"

func scratchOf(st *translator.StreamState) *streamScratch {
	if st.Extra == nil {
		st.Extra = map[string]any{}
	}
	if s, ok := st.Extra[scratchKey].(*streamScratch); ok {
		return s
	}
	s := &streamScratch{toolIndexByItem: map[string]int{}}
	st.Extra[scratchKey] = s
	return s
}

// doneSentinel is the literal payload that terminates a Chat Completions SSE
// stream. It is not JSON, which is why every parse path checks for it first.
var doneSentinel = []byte("[DONE]")

// ConvertStreamChunk translates one Responses SSE data payload into zero or
// more Chat Completions data payloads. Implements
// translator.StreamChunkTransform.
//
// `chunk` is the bytes after `data: ` for a single frame, with the SSE framing
// (and any `event:` line) already stripped by the caller — the caller owns
// framing, this function owns the dialect. Returning an empty slice means
// "this event has no counterpart"; the caller emits nothing and reads on.
func ConvertStreamChunk(ctx context.Context, st *translator.StreamState, chunk []byte) ([][]byte, *translator.TranslateError) {
	_ = ctx

	sc := scratchOf(st)
	trimmed := bytes.TrimSpace(chunk)
	if len(trimmed) == 0 {
		return nil, nil
	}

	// An upstream that sends its own terminator must not produce a second one.
	if bytes.Equal(trimmed, doneSentinel) {
		if sc.doneSent {
			return nil, nil
		}
		sc.doneSent = true
		return [][]byte{doneSentinel}, nil
	}

	if !gjson.ValidBytes(trimmed) {
		return nil, &translator.TranslateError{
			Code:       translator.CodeTranslationFailed,
			HTTPStatus: 502,
			Message:    "upstream SSE frame is not valid JSON",
		}
	}
	ev := gjson.ParseBytes(trimmed)

	switch ev.Get("type").String() {

	case "response.created", "response.in_progress":
		// Responses states id/model once; Chat Completions repeats them on
		// every chunk, so capture them here for the rest of the stream.
		if id := ev.Get("response.id").String(); id != "" && st.ResponseID == "" {
			st.ResponseID = chatCompletionID(id)
		}
		if m := ev.Get("response.model").String(); m != "" && st.Model == "" {
			st.Model = m
		}
		if st.CreatedAt == 0 {
			st.CreatedAt = responseCreatedAt(ev.Get("response"))
		}
		return sc.openingChunk(st), nil

	case "response.output_text.delta":
		out := sc.openingChunk(st)
		if delta := ev.Get("delta").String(); delta != "" {
			out = append(out, chunkBytes(st, chatDelta{Content: &delta}, nil, nil))
		}
		return out, nil

	case "response.output_item.added":
		item := ev.Get("item")
		if item.Get("type").String() != "function_call" {
			return nil, nil
		}
		sc.sawToolCall = true
		idx := sc.indexForItem(item.Get("id").String())
		out := sc.openingChunk(st)
		name := item.Get("name").String()
		callID := item.Get("call_id").String()
		empty := ""
		out = append(out, chunkBytes(st, chatDelta{
			ToolCalls: []chatToolCall{{
				Index:    &idx,
				ID:       callID,
				Type:     "function",
				Function: chatToolFunction{Name: name, Arguments: empty},
			}},
		}, nil, nil))
		return out, nil

	case "response.function_call_arguments.delta":
		delta := ev.Get("delta").String()
		if delta == "" {
			return nil, nil
		}
		sc.sawToolCall = true
		idx := sc.indexForItem(ev.Get("item_id").String())
		out := sc.openingChunk(st)
		out = append(out, chunkBytes(st, chatDelta{
			ToolCalls: []chatToolCall{{
				Index:    &idx,
				Function: chatToolFunction{Arguments: delta},
			}},
		}, nil, nil))
		return out, nil

	case "response.completed", "response.incomplete", "response.failed":
		return sc.terminate(st, ev), nil

	default:
		// Everything else — content_part.added/done, output_text.done,
		// output_item.done, reasoning summaries, refusal parts — carries no
		// information the Chat Completions wire can express. See the file
		// header for why dropping beats forwarding.
		return nil, nil
	}
}

// openingChunk returns the mandatory first chunk (role delta) the first time
// it is called and nothing thereafter.
//
// It is called from every event branch rather than only from response.created
// because that event is not guaranteed: a stream that begins mid-flight, or an
// upstream that omits it, would otherwise deliver content deltas before the
// role is announced — which SDKs read as a malformed stream.
func (sc *streamScratch) openingChunk(st *translator.StreamState) [][]byte {
	if sc.roleSent {
		return nil
	}
	sc.roleSent = true
	role := "assistant"
	empty := ""
	return [][]byte{chunkBytes(st, chatDelta{Role: role, Content: &empty}, nil, nil)}
}

// indexForItem assigns each function-call output item a stable, dense index in
// first-seen order.
func (sc *streamScratch) indexForItem(itemID string) int {
	if sc.toolIndexByItem == nil {
		sc.toolIndexByItem = map[string]int{}
	}
	if idx, ok := sc.toolIndexByItem[itemID]; ok {
		return idx
	}
	idx := sc.nextToolIndex
	sc.toolIndexByItem[itemID] = idx
	sc.nextToolIndex++
	return idx
}

// terminate emits the closing finish_reason chunk (plus usage, when the
// upstream reported any) and the [DONE] sentinel.
func (sc *streamScratch) terminate(st *translator.StreamState, ev gjson.Result) [][]byte {
	if sc.doneSent {
		return nil
	}
	out := sc.openingChunk(st)

	reason := finishReason(ev.Get("response"), sc.sawToolCall)
	usage := convertUsage(ev.Get("response.usage"))
	out = append(out, chunkBytes(st, chatDelta{}, &reason, usage))

	sc.doneSent = true
	return append(out, doneSentinel)
}

// chatDelta is the `choices[0].delta` object. Content is a pointer because the
// distinction between "no content field" (a pure tool-call or terminal chunk)
// and "an empty string" (the opening role chunk) is load-bearing for SDKs.
type chatDelta struct {
	Role      string         `json:"role,omitempty"`
	Content   *string        `json:"content,omitempty"`
	ToolCalls []chatToolCall `json:"tool_calls,omitempty"`
}

type chatChunk struct {
	ID      string            `json:"id"`
	Object  string            `json:"object"`
	Created int64             `json:"created"`
	Model   string            `json:"model"`
	Choices []chatChunkChoice `json:"choices"`
	Usage   *chatUsage        `json:"usage,omitempty"`
}

type chatChunkChoice struct {
	Index        int       `json:"index"`
	Delta        chatDelta `json:"delta"`
	FinishReason *string   `json:"finish_reason"`
}

// chunkBytes renders one chat.completion.chunk.
//
// Marshal cannot fail for these types (no channels, funcs or NaN reachable),
// and a streaming frame has no error channel back to the client anyway — the
// headers went out long ago. Returning bytes keeps every call site a single
// expression instead of an error check that can never fire.
func chunkBytes(st *translator.StreamState, delta chatDelta, finish *string, usage *chatUsage) []byte {
	b, _ := json.Marshal(chatChunk{
		ID:      st.ResponseID,
		Object:  "chat.completion.chunk",
		Created: st.CreatedAt,
		Model:   st.Model,
		Choices: []chatChunkChoice{{Index: 0, Delta: delta, FinishReason: finish}},
		Usage:   usage,
	})
	return b
}
