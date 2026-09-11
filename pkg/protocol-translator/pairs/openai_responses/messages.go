package openai_responses

import (
	"strings"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// convertMessages splits a Chat Completions `messages[]` array into the two
// slots the Responses API uses: `instructions` (the system prompt) and
// `input[]` (everything else, in order).
//
// Role mapping, and why each one is what it is:
//
//   - system / developer → instructions. The Responses API has no system role
//     inside input[]; putting one there is rejected upstream. Several system
//     messages are joined with a blank line rather than "last one wins",
//     because agent harnesses routinely emit a base prompt plus per-turn
//     addenda and dropping the earlier ones silently removes instructions the
//     caller is relying on.
//
//   - user → input_text parts. Straight mapping.
//
//   - assistant with text → output_text parts. The tag differs from the user
//     turn on purpose: Responses tags content by who produced it, and sending
//     input_text for an assistant turn is rejected upstream.
//
//   - assistant with tool_calls → one `function_call` item PER call, emitted
//     after any text the same message carried. Chat Completions nests the
//     calls inside the assistant message; Responses makes them siblings.
//
//   - tool → `function_call_output`, correlated by tool_call_id. This is the
//     half that makes multi-turn agent loops work; without it the model sees
//     its own tool call with no result and calls the tool again.
func convertMessages(messages gjson.Result) (instructions string, items []inputItem, tErr *translator.TranslateError) {
	if !messages.Exists() || !messages.IsArray() {
		return "", nil, &translator.TranslateError{
			Code:       translator.CodeBadRequest,
			HTTPStatus: 400,
			Param:      "messages",
			Message:    "`messages` is required and must be an array",
		}
	}
	var systemParts []string
	items = []inputItem{}

	for _, m := range messages.Array() {
		role := m.Get("role").String()
		switch role {
		case "system", "developer":
			if text := joinTextContent(m.Get("content")); text != "" {
				systemParts = append(systemParts, text)
			}

		case "user":
			parts, err := convertUserContent(m.Get("content"))
			if err != nil {
				return "", nil, err
			}
			if len(parts) > 0 {
				items = append(items, inputItem{Role: "user", Content: parts})
			}

		case "assistant":
			if text := joinTextContent(m.Get("content")); text != "" {
				items = append(items, inputItem{
					Role:    "assistant",
					Content: []contentPart{{Type: "output_text", Text: text}},
				})
			}
			for _, tc := range m.Get("tool_calls").Array() {
				items = append(items, inputItem{
					Type:      "function_call",
					CallID:    tc.Get("id").String(),
					Name:      tc.Get("function.name").String(),
					Arguments: tc.Get("function.arguments").String(),
				})
			}

		case "tool", "function":
			items = append(items, inputItem{
				Type:   "function_call_output",
				CallID: m.Get("tool_call_id").String(),
				Output: joinTextContent(m.Get("content")),
			})

		case "":
			return "", nil, &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "messages",
				Message:    "every message must carry a `role`",
			}

		default:
			return "", nil, &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "messages",
				Message: "unknown message role " + role + "; expected one of " +
					"system, developer, user, assistant, tool",
			}
		}
	}
	return strings.Join(systemParts, "\n\n"), items, nil
}

// convertUserContent maps a user message's content to Responses input parts.
// Chat Completions allows a bare string or an array of typed parts; both
// shapes are common in the wild, so both are handled rather than normalized
// upstream of here.
func convertUserContent(content gjson.Result) ([]contentPart, *translator.TranslateError) {
	if content.Type == gjson.String {
		if content.String() == "" {
			return nil, nil
		}
		return []contentPart{{Type: "input_text", Text: content.String()}}, nil
	}
	if !content.IsArray() {
		if content.Exists() && content.Type != gjson.Null {
			return nil, &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "messages",
				Message:    "message `content` must be a string or an array of content parts",
			}
		}
		return nil, nil
	}
	var parts []contentPart
	for _, p := range content.Array() {
		switch p.Get("type").String() {
		case "text", "input_text":
			if t := p.Get("text").String(); t != "" {
				parts = append(parts, contentPart{Type: "input_text", Text: t})
			}
		case "image_url", "input_image":
			// Chat Completions nests the URL under image_url.url; the newer
			// part shape carries it flat. Accept both so a client that already
			// speaks Responses-flavored parts is not punished for it.
			url := p.Get("image_url.url").String()
			if url == "" {
				url = p.Get("image_url").String()
			}
			if url == "" {
				return nil, &translator.TranslateError{
					Code:       translator.CodeBadRequest,
					HTTPStatus: 400,
					Param:      "messages",
					Message:    "image content part carries no URL",
				}
			}
			parts = append(parts, contentPart{Type: "input_image", ImageURL: url})
		default:
			// Loud, not silent: dropping an audio or file part would answer a
			// question the caller did not ask (see rejectUnsupported).
			return nil, &translator.TranslateError{
				Code:       translator.CodeUnsupportedParam,
				HTTPStatus: 400,
				Param:      "messages",
				Message: "content part of type " + p.Get("type").String() +
					" cannot be forwarded to this credential's upstream; only text and image parts are supported",
			}
		}
	}
	return parts, nil
}

// joinTextContent flattens a content value to plain text, accepting the bare
// string form and the parts-array form. Used where the Responses API wants a
// single string (instructions, assistant text, tool output).
func joinTextContent(content gjson.Result) string {
	if content.Type == gjson.String {
		return content.String()
	}
	if !content.IsArray() {
		return ""
	}
	var b strings.Builder
	for _, p := range content.Array() {
		// `text` is the field name in every text-ish part shape in play
		// (text / input_text / output_text), so read it directly rather than
		// branching on the type tag.
		if t := p.Get("text").String(); t != "" {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(t)
		}
	}
	return b.String()
}

// convertTools flattens Chat Completions tool declarations into the Responses
// shape. Chat Completions wraps the schema in a `function` object; Responses
// hoists name/description/parameters to the top level of the tool.
func convertTools(tools gjson.Result) ([]responsTool, *translator.TranslateError) {
	if !tools.Exists() || !tools.IsArray() || len(tools.Array()) == 0 {
		return nil, nil
	}
	arr := tools.Array()
	out := make([]responsTool, 0, len(arr))
	for _, t := range arr {
		if typ := t.Get("type").String(); typ != "function" && typ != "" {
			return nil, &translator.TranslateError{
				Code:       translator.CodeUnsupportedParam,
				HTTPStatus: 400,
				Param:      "tools",
				Message:    "tool type " + typ + " is not supported; only `function` tools can be forwarded",
			}
		}
		fn := t.Get("function")
		name := fn.Get("name").String()
		if name == "" {
			// Already-flat declarations are accepted for the same reason the
			// image part is: a client that speaks the target shape should not
			// be penalized for it.
			name = t.Get("name").String()
		}
		if name == "" {
			return nil, &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "tools",
				Message:    "every function tool must declare a `name`",
			}
		}
		rt := responsTool{Type: "function", Name: name}
		if d := fn.Get("description"); d.Exists() {
			rt.Description = d.String()
		} else {
			rt.Description = t.Get("description").String()
		}
		if p := fn.Get("parameters"); p.Exists() {
			rt.Parameters = []byte(p.Raw)
		} else if p := t.Get("parameters"); p.Exists() {
			rt.Parameters = []byte(p.Raw)
		}
		if s := fn.Get("strict"); s.Exists() {
			b := s.Bool()
			rt.Strict = &b
		}
		out = append(out, rt)
	}
	return out, nil
}

// convertToolChoice maps the tool_choice value. The string forms
// (auto / none / required) are spelled identically in both APIs; the
// object form is un-nested the same way tool declarations are.
func convertToolChoice(tc gjson.Result) any {
	if !tc.Exists() {
		return nil
	}
	if tc.Type == gjson.String {
		return tc.String()
	}
	name := tc.Get("function.name").String()
	if name == "" {
		name = tc.Get("name").String()
	}
	if name == "" {
		return nil
	}
	return map[string]string{"type": "function", "name": name}
}
