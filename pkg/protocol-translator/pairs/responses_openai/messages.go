package responses_openai

import (
	"strings"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// convertInput folds the Responses `instructions` + `input` pair into a Chat
// Completions `messages[]` array.
//
// # The shape mismatch this has to absorb
//
// Responses flattens a turn into SIBLING items: the assistant's prose is one
// item, each tool it invoked is another, each tool result is another again.
// Chat Completions instead nests — one assistant message carries BOTH its text
// and a `tool_calls` array, and parallel calls share that one message.
//
// So this is not a per-item rename. Consecutive `function_call` items have to
// be gathered onto the assistant message they belong to (creating one if the
// model called a tool without narrating first), or the upstream sees N separate
// assistant turns where the model took one. That misreads a single parallel
// tool call as a multi-turn exchange, and models condition on turn structure.
func convertInput(instructions, input gjson.Result) ([]chatMessage, *translator.TranslateError) {
	var msgs []chatMessage

	// instructions is the Responses system-prompt slot. Chat Completions has no
	// dedicated field, so it becomes the leading system message — the position
	// every OpenAI-compatible upstream reads it from.
	if s := instructions.String(); s != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: s})
	}

	switch {
	case !input.Exists():
		// instructions-only is legal in Responses; Chat Completions needs at
		// least one message, and the system one above satisfies that.
	case input.Type == gjson.String:
		// Single-turn shorthand.
		if s := input.String(); s != "" {
			msgs = append(msgs, chatMessage{Role: "user", Content: s})
		}
	case input.IsArray():
		items, tErr := convertInputItems(input.Array())
		if tErr != nil {
			return nil, tErr
		}
		msgs = append(msgs, items...)
	default:
		return nil, &translator.TranslateError{
			Code:       translator.CodeBadRequest,
			HTTPStatus: 400,
			Param:      "input",
			Message:    "`input` must be a string or an array of input items",
		}
	}

	if len(msgs) == 0 {
		return nil, &translator.TranslateError{
			Code:       translator.CodeBadRequest,
			HTTPStatus: 400,
			Param:      "input",
			Message:    "the request carries neither `instructions` nor any `input`, so there is nothing to send",
		}
	}
	return msgs, nil
}

func convertInputItems(items []gjson.Result) ([]chatMessage, *translator.TranslateError) {
	var out []chatMessage

	// attachToolCall appends a tool call to the trailing assistant message when
	// there is one, and otherwise opens a new assistant message with null
	// content. `content: null` (not "") is what Chat Completions expects on a
	// tool-call-only turn, and what the SDKs check before reading tool_calls.
	attachToolCall := func(tc chatToolCall) {
		if n := len(out); n > 0 && out[n-1].Role == "assistant" && out[n-1].ToolCallID == "" {
			out[n-1].ToolCalls = append(out[n-1].ToolCalls, tc)
			return
		}
		out = append(out, chatMessage{Role: "assistant", Content: nil, ToolCalls: []chatToolCall{tc}})
	}

	for _, it := range items {
		switch it.Get("type").String() {

		case "function_call":
			attachToolCall(chatToolCall{
				ID:   it.Get("call_id").String(),
				Type: "function",
				Function: chatToolFunction{
					Name:      it.Get("name").String(),
					Arguments: it.Get("arguments").String(),
				},
			})

		case "function_call_output":
			out = append(out, chatMessage{
				Role:       "tool",
				ToolCallID: it.Get("call_id").String(),
				Content:    it.Get("output").String(),
			})

		case "reasoning":
			// The model's private chain of thought. Chat Completions has no
			// field for it and replaying it as prose would put the reasoning
			// into the conversation as if the model had said it out loud.

		case "message", "":
			role := it.Get("role").String()
			if role == "" {
				return nil, &translator.TranslateError{
					Code:       translator.CodeBadRequest,
					HTTPStatus: 400,
					Param:      "input",
					Message:    "every message item in `input` must carry a `role`",
				}
			}
			content, tErr := convertContent(it.Get("content"))
			if tErr != nil {
				return nil, tErr
			}
			if content == nil {
				continue
			}
			// developer is the Responses spelling of an instruction turn;
			// system is what a Chat Completions upstream recognises.
			if role == "developer" {
				role = "system"
			}
			out = append(out, chatMessage{Role: role, Content: content})

		default:
			return nil, &translator.TranslateError{
				Code:       translator.CodeUnsupportedParam,
				HTTPStatus: 400,
				Param:      "input",
				Message: "input item of type " + it.Get("type").String() +
					" has no Chat Completions equivalent and cannot be forwarded to this credential's upstream",
			}
		}
	}
	return out, nil
}

// convertContent maps one item's content to a Chat Completions content value.
//
// Return shape is deliberately conditional. Text-only content becomes a PLAIN
// STRING because that is what every OpenAI-compatible relay accepts, including
// the older and smaller ones this direction exists to reach; the parts array is
// used only when an image forces it. Emitting parts unconditionally would be
// tidier here and would break exactly the upstreams this pair targets.
//
// nil means "this item contributes no message" (empty content), which the
// caller skips rather than sending an empty turn.
func convertContent(content gjson.Result) (any, *translator.TranslateError) {
	if content.Type == gjson.String {
		if content.String() == "" {
			return nil, nil
		}
		return content.String(), nil
	}
	if !content.IsArray() {
		if !content.Exists() || content.Type == gjson.Null {
			return nil, nil
		}
		return nil, &translator.TranslateError{
			Code:       translator.CodeBadRequest,
			HTTPStatus: 400,
			Param:      "input",
			Message:    "item `content` must be a string or an array of content parts",
		}
	}

	var text strings.Builder
	var parts []map[string]any
	hasNonText := false

	for _, p := range content.Array() {
		switch p.Get("type").String() {
		case "input_text", "output_text", "text", "summary_text":
			t := p.Get("text").String()
			if t == "" {
				continue
			}
			if text.Len() > 0 {
				text.WriteString("\n")
			}
			text.WriteString(t)
			parts = append(parts, map[string]any{"type": "text", "text": t})

		case "input_image", "image_url":
			url := p.Get("image_url").String()
			if url == "" {
				url = p.Get("image_url.url").String()
			}
			if url == "" {
				return nil, &translator.TranslateError{
					Code:       translator.CodeBadRequest,
					HTTPStatus: 400,
					Param:      "input",
					Message:    "image content part carries no URL",
				}
			}
			hasNonText = true
			parts = append(parts, map[string]any{
				"type":      "image_url",
				"image_url": map[string]any{"url": url},
			})

		case "refusal":
			// A refusal is the model's, not the caller's. Replaying it as user
			// or assistant text would put words in someone's mouth.

		default:
			return nil, &translator.TranslateError{
				Code:       translator.CodeUnsupportedParam,
				HTTPStatus: 400,
				Param:      "input",
				Message: "content part of type " + p.Get("type").String() +
					" cannot be forwarded to a Chat Completions upstream; only text and image parts are supported",
			}
		}
	}

	if hasNonText {
		return parts, nil
	}
	if text.Len() == 0 {
		return nil, nil
	}
	return text.String(), nil
}

// convertTools re-nests the tool declarations under `function`.
func convertTools(tools gjson.Result) ([]chatTool, *translator.TranslateError) {
	if !tools.Exists() || !tools.IsArray() || len(tools.Array()) == 0 {
		return nil, nil
	}
	var out []chatTool
	for _, t := range tools.Array() {
		typ := t.Get("type").String()
		if typ != "function" && typ != "" {
			// web_search / file_search / computer_use are server-side tools the
			// Responses API runs itself. A Chat Completions upstream has no such
			// capability, and forwarding the request without them would answer
			// without the search the caller asked for.
			return nil, &translator.TranslateError{
				Code:       translator.CodeUnsupportedParam,
				HTTPStatus: 400,
				Param:      "tools",
				Message: "tool type " + typ + " is a server-side Responses tool with no Chat Completions " +
					"equivalent; this credential's upstream cannot run it",
			}
		}
		name := t.Get("name").String()
		if name == "" {
			// Accept an already-nested declaration for the same reason the
			// forward pair accepts an already-flat one.
			name = t.Get("function.name").String()
		}
		if name == "" {
			return nil, &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "tools",
				Message:    "every function tool must declare a `name`",
			}
		}
		decl := chatToolDecl{Name: name}
		if d := t.Get("description"); d.Exists() {
			decl.Description = d.String()
		} else {
			decl.Description = t.Get("function.description").String()
		}
		if p := t.Get("parameters"); p.Exists() {
			decl.Parameters = []byte(p.Raw)
		} else if p := t.Get("function.parameters"); p.Exists() {
			decl.Parameters = []byte(p.Raw)
		}
		if s := t.Get("strict"); s.Exists() {
			b := s.Bool()
			decl.Strict = &b
		}
		out = append(out, chatTool{Type: "function", Function: decl})
	}
	return out, nil
}

// convertToolChoice re-nests the object form; the string forms are identical.
func convertToolChoice(tc gjson.Result) any {
	if !tc.Exists() {
		return nil
	}
	if tc.Type == gjson.String {
		return tc.String()
	}
	name := tc.Get("name").String()
	if name == "" {
		name = tc.Get("function.name").String()
	}
	if name == "" {
		return nil
	}
	return map[string]any{"type": "function", "function": map[string]string{"name": name}}
}
