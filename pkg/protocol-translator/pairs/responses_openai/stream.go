package responses_openai

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// stream.go — Chat Completions SSE → Responses API SSE.
//
// # Why this is a state machine and not a per-frame rewrite
//
// Chat Completions streams ONE frame type and states almost nothing: no item
// boundaries, no content-part boundaries, no terminal snapshot. Responses
// streams a typed lifecycle where every delta is addressed to an item and a
// content part that must have been ANNOUNCED first, and where the final
// `response.completed` carries the whole assembled output.
//
// So going this way means synthesising events the source never sent, and it
// cannot be done frame-locally:
//
//   - the opening `response.created` needs the id and model, which only arrive
//     with the first chunk;
//   - `response.output_item.added` / `response.content_part.added` must be
//     emitted before the first delta of an item, and the source gives no signal
//     that an item started — the arrival of the first delta IS the signal;
//   - `response.completed` must contain the fully accumulated text and tool
//     arguments, which the source only ever sent incrementally, so this
//     transform has to keep them.
//
// # Terminator
//
// The stream ends at `response.completed`. The upstream's Chat Completions
// `[DONE]` sentinel is SWALLOWED rather than forwarded: it is not part of the
// Responses wire format, and a client parsing every data line as JSON would
// choke on it. `response.completed` is what this codebase's own Responses
// consumers key on (see conversation_audit's responsesAPIDone).

type streamScratch struct {
	// Tool calls keyed by the Chat Completions tool_calls index, which is the
	// only correlation the source provides.
	tools     map[int]*toolAccum
	toolOrder []int

	text       strings.Builder
	textItemID string

	// nextOutputIndex counts ALL output items (message + function calls), which
	// is the addressing Responses deltas use — distinct from the Chat
	// Completions tool index, which counts tool calls only.
	nextOutputIndex int
	textOutputIndex int

	openedLifecycle bool
	openedText      bool
	finished        bool
}

type toolAccum struct {
	itemID      string
	callID      string
	name        string
	args        strings.Builder
	outputIndex int
	opened      bool
}

const scratchKey = "responses_openai.scratch"

func scratchOf(st *translator.StreamState) *streamScratch {
	if st.Extra == nil {
		st.Extra = map[string]any{}
	}
	if s, ok := st.Extra[scratchKey].(*streamScratch); ok {
		return s
	}
	s := &streamScratch{tools: map[int]*toolAccum{}}
	st.Extra[scratchKey] = s
	return s
}

// ConvertStreamChunk turns one Chat Completions SSE data payload into zero or
// more Responses SSE data payloads. Implements translator.StreamChunkTransform.
func ConvertStreamChunk(ctx context.Context, st *translator.StreamState, chunk []byte) ([][]byte, *translator.TranslateError) {
	_ = ctx
	sc := scratchOf(st)

	trimmed := bytes.TrimSpace(chunk)
	if len(trimmed) == 0 {
		return nil, nil
	}
	// The Chat Completions terminator has no Responses counterpart; the stream
	// already ended at response.completed.
	if bytes.Equal(trimmed, []byte("[DONE]")) {
		return nil, nil
	}
	if !gjson.ValidBytes(trimmed) {
		return nil, &translator.TranslateError{
			Code:       translator.CodeTranslationFailed,
			HTTPStatus: 502,
			Message:    "upstream SSE frame is not valid JSON",
		}
	}
	ev := gjson.ParseBytes(trimmed)
	if sc.finished {
		return nil, nil
	}

	var out [][]byte

	if id := ev.Get("id").String(); id != "" && st.ResponseID == "" {
		st.ResponseID = responseID(id)
	}
	if m := ev.Get("model").String(); m != "" && st.Model == "" {
		st.Model = m
	}
	if c := ev.Get("created").Int(); c > 0 && st.CreatedAt == 0 {
		st.CreatedAt = c
	}
	out = append(out, sc.openLifecycle(st)...)

	// Usage can ride the final chunk (stream_options.include_usage) or a
	// dedicated trailing chunk with an empty choices array.
	if u := ev.Get("usage"); u.Exists() {
		st.OutputUsage.PromptTokens = int(u.Get("prompt_tokens").Int())
		st.OutputUsage.CompletionTokens = int(u.Get("completion_tokens").Int())
		st.OutputUsage.TotalTokens = int(u.Get("total_tokens").Int())
	}

	choice := ev.Get("choices.0")
	delta := choice.Get("delta")

	if content := delta.Get("content"); content.Exists() && content.String() != "" {
		out = append(out, sc.openTextItem(st)...)
		text := content.String()
		sc.text.WriteString(text)
		out = append(out, mustJSON(map[string]any{
			"type":          "response.output_text.delta",
			"item_id":       sc.textItemID,
			"output_index":  sc.textOutputIndex,
			"content_index": 0,
			"delta":         text,
		}))
	}

	for _, tc := range delta.Get("tool_calls").Array() {
		idx := int(tc.Get("index").Int())
		acc, isNew := sc.toolFor(st, idx)
		if n := tc.Get("function.name").String(); n != "" {
			acc.name = n
		}
		if id := tc.Get("id").String(); id != "" {
			acc.callID = id
		}
		if isNew || !acc.opened {
			// A tool item can only be announced once its name is known; Chat
			// Completions sends the name on the first chunk of the call, so
			// this is that chunk.
			acc.opened = true
			out = append(out, mustJSON(map[string]any{
				"type":         "response.output_item.added",
				"output_index": acc.outputIndex,
				"item": map[string]any{
					"id": acc.itemID, "type": "function_call", "status": "in_progress",
					"call_id": acc.callID, "name": acc.name, "arguments": "",
				},
			}))
		}
		if args := tc.Get("function.arguments").String(); args != "" {
			acc.args.WriteString(args)
			out = append(out, mustJSON(map[string]any{
				"type":         "response.function_call_arguments.delta",
				"item_id":      acc.itemID,
				"output_index": acc.outputIndex,
				"delta":        args,
			}))
		}
	}

	if fr := choice.Get("finish_reason"); fr.Exists() && fr.Type != gjson.Null && fr.String() != "" {
		out = append(out, sc.finish(st, fr.String())...)
	}
	return out, nil
}

// openLifecycle emits response.created + response.in_progress once.
func (sc *streamScratch) openLifecycle(st *translator.StreamState) [][]byte {
	if sc.openedLifecycle {
		return nil
	}
	sc.openedLifecycle = true
	if st.ResponseID == "" {
		st.ResponseID = responseID("")
	}
	shell := sc.responseShell(st, "in_progress", nil)
	return [][]byte{
		mustJSON(map[string]any{"type": "response.created", "response": shell}),
		mustJSON(map[string]any{"type": "response.in_progress", "response": shell}),
	}
}

// openTextItem announces the message item and its first content part. Chat
// Completions gives no "item started" signal, so the first non-empty content
// delta is what stands in for one.
func (sc *streamScratch) openTextItem(st *translator.StreamState) [][]byte {
	if sc.openedText {
		return nil
	}
	sc.openedText = true
	sc.textItemID = "msg_" + strings.TrimPrefix(st.ResponseID, "resp_")
	sc.textOutputIndex = sc.nextOutputIndex
	sc.nextOutputIndex++
	return [][]byte{
		mustJSON(map[string]any{
			"type":         "response.output_item.added",
			"output_index": sc.textOutputIndex,
			"item": map[string]any{
				"id": sc.textItemID, "type": "message", "status": "in_progress",
				"role": "assistant", "content": []any{},
			},
		}),
		mustJSON(map[string]any{
			"type":          "response.content_part.added",
			"item_id":       sc.textItemID,
			"output_index":  sc.textOutputIndex,
			"content_index": 0,
			"part":          map[string]any{"type": "output_text", "text": "", "annotations": []any{}},
		}),
	}
}

func (sc *streamScratch) toolFor(st *translator.StreamState, idx int) (*toolAccum, bool) {
	if acc, ok := sc.tools[idx]; ok {
		return acc, false
	}
	acc := &toolAccum{
		itemID:      functionCallItemID(st.ResponseID, idx),
		outputIndex: sc.nextOutputIndex,
	}
	sc.nextOutputIndex++
	sc.tools[idx] = acc
	sc.toolOrder = append(sc.toolOrder, idx)
	return acc, true
}

// finish closes every open item and emits the terminal response.completed.
func (sc *streamScratch) finish(st *translator.StreamState, finishReason string) [][]byte {
	if sc.finished {
		return nil
	}
	sc.finished = true
	var out [][]byte

	if sc.openedText {
		full := sc.text.String()
		out = append(out,
			mustJSON(map[string]any{
				"type": "response.output_text.done", "item_id": sc.textItemID,
				"output_index": sc.textOutputIndex, "content_index": 0, "text": full,
			}),
			mustJSON(map[string]any{
				"type": "response.content_part.done", "item_id": sc.textItemID,
				"output_index": sc.textOutputIndex, "content_index": 0,
				"part": map[string]any{"type": "output_text", "text": full, "annotations": []any{}},
			}),
			mustJSON(map[string]any{
				"type": "response.output_item.done", "output_index": sc.textOutputIndex,
				"item": sc.messageItem(full),
			}),
		)
	}
	for _, idx := range sc.toolOrder {
		acc := sc.tools[idx]
		args := acc.args.String()
		out = append(out,
			mustJSON(map[string]any{
				"type": "response.function_call_arguments.done", "item_id": acc.itemID,
				"output_index": acc.outputIndex, "arguments": args,
			}),
			mustJSON(map[string]any{
				"type": "response.output_item.done", "output_index": acc.outputIndex,
				"item": sc.functionCallItem(acc, args),
			}),
		)
	}

	status, incomplete := statusFor(finishReason)
	shell := sc.responseShell(st, status, incomplete)
	// The terminal event carries the assembled output; a client that ignored
	// every delta must still be able to read the whole answer from this frame.
	shell["output"] = sc.assembledOutput()
	shell["output_text"] = sc.text.String()

	eventType := "response.completed"
	if status == "incomplete" {
		eventType = "response.incomplete"
	}
	return append(out, mustJSON(map[string]any{"type": eventType, "response": shell}))
}

func (sc *streamScratch) messageItem(text string) map[string]any {
	return map[string]any{
		"id": sc.textItemID, "type": "message", "status": "completed", "role": "assistant",
		"content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}},
	}
}

func (sc *streamScratch) functionCallItem(acc *toolAccum, args string) map[string]any {
	return map[string]any{
		"id": acc.itemID, "type": "function_call", "status": "completed",
		"call_id": acc.callID, "name": acc.name, "arguments": args,
	}
}

func (sc *streamScratch) assembledOutput() []any {
	out := []any{}
	if sc.openedText {
		out = append(out, sc.messageItem(sc.text.String()))
	}
	for _, idx := range sc.toolOrder {
		acc := sc.tools[idx]
		out = append(out, sc.functionCallItem(acc, acc.args.String()))
	}
	return out
}

func (sc *streamScratch) responseShell(st *translator.StreamState, status string, incomplete *incompleteDetails) map[string]any {
	shell := map[string]any{
		"id": st.ResponseID, "object": "response", "created_at": st.CreatedAt,
		"model": st.Model, "status": status, "output": []any{},
	}
	if incomplete != nil {
		shell["incomplete_details"] = map[string]any{"reason": incomplete.Reason}
	}
	if st.OutputUsage.PromptTokens != 0 || st.OutputUsage.CompletionTokens != 0 {
		total := st.OutputUsage.TotalTokens
		if total == 0 {
			total = st.OutputUsage.PromptTokens + st.OutputUsage.CompletionTokens
		}
		shell["usage"] = map[string]any{
			"input_tokens":  st.OutputUsage.PromptTokens,
			"output_tokens": st.OutputUsage.CompletionTokens,
			"total_tokens":  total,
		}
	}
	return shell
}

// SSEEventName names the `event:` line for a payload this pair emits.
//
// Responses is a NAMED-event stream: every frame carries `event: <type>`
// alongside its data, and a client registering per-event listeners (rather than
// switching on the decoded `type` field) receives nothing at all without it.
// The name is always the payload's own `type`, so this stays a pure function of
// the frame and the IO layer needs no dialect knowledge of its own.
func SSEEventName(payload []byte) string {
	return gjson.GetBytes(payload, "type").String()
}

// mustJSON marshals a frame this package constructs itself.
//
// The inputs are literal maps of strings, ints and slices — no channels, funcs
// or NaN is reachable — so Marshal cannot fail here. A streaming frame also has
// no error channel back to the client: the headers left long ago. Returning
// bytes keeps every call site one expression instead of an error check that can
// never fire.
func mustJSON(v map[string]any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// FlushStream closes a stream the upstream ended without terminating.
//
// A Responses consumer keys on `response.completed`; the upstream only makes us
// emit one when it sends a chunk carrying finish_reason. An upstream that is
// cut off, times out, or simply stops sends none, and the client is then
// waiting on a connection that has already closed — and unlike Chat
// Completions there is no bare sentinel it could fall back to recognising.
//
// The frame carries the output accumulated so far, so a client that ignored
// every delta still reads a complete answer. Status is "completed" for the same
// reason the other direction reports "stop": nothing here knows why the stream
// ended, and the bytes delivered are real.
func FlushStream(ctx context.Context, st *translator.StreamState) ([][]byte, *translator.TranslateError) {
	_ = ctx
	sc := scratchOf(st)
	if sc.finished {
		return nil, nil
	}
	return sc.finish(st, "stop"), nil
}
