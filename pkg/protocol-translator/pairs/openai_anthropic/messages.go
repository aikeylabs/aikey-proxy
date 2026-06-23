package openai_anthropic

import (
	"strings"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// messages.go — OpenAI messages[] → Anthropic system[] + messages[] normalization.
//
// Anthropic has 4 hard constraints OpenAI doesn't:
//
//  1. system messages live OUTSIDE messages[] in a top-level system[] array.
//     OpenAI puts {role: "system", content: "..."} inside messages[].
//
//  2. messages[] cannot be empty.
//
//  3. messages[0].role MUST be "user" (Anthropic 400 otherwise — common
//     gotcha when an Agent sends system + assistant + user expecting the
//     server to figure it out).
//
//  4. roles MUST strictly alternate user/assistant. Two assistants in a
//     row (e.g. assistant followed by tool-result) is rejected. We merge
//     same-role consecutive messages to repair this rather than reject —
//     LiteLLM does the same, and rejecting would break common patterns
//     like "system + 3 user messages from history".
//
// Additionally OpenAI's role="tool" messages need to be repacked as
// role="user" with a tool_result content block (Anthropic's tool flow).
//
// References:
//   - Anthropic Messages API field reference
//   - LiteLLM litellm/litellm_core_utils/prompt_templates/factory.py:2350
//     (anthropic_messages_pt) — oracle for the normalization order
//   - Design doc §6 messages 规范化 + §7 content blocks

// normalizeResult is the output of messages normalization, ready for
// inclusion in the Anthropic request body via sjson.SetRawBytes.
type normalizeResult struct {
	// SystemRaw is the JSON array literal for the top-level system field,
	// e.g. `[{"type":"text","text":"You are helpful"}]`. Empty when the
	// inbound request had no system messages.
	SystemRaw []byte

	// MessagesRaw is the JSON array literal for the messages field,
	// guaranteed to be a non-empty array starting with role=user and
	// strictly alternating. Guaranteed non-nil when err is nil.
	MessagesRaw []byte
}

// normalizeMessages reads OpenAI's messages[] from the inbound request
// and produces (system[], messages[]) in Anthropic shape, applying all
// 6 normalization rules from the design doc §6.
//
// Returns a TranslateError when input violates a rule that can't be
// auto-repaired (empty messages, message with no content after filter,
// unknown role).
func normalizeMessages(inMessages *gjson.Result) (*normalizeResult, *translator.TranslateError) {
	if !inMessages.Exists() || !inMessages.IsArray() {
		return nil, &translator.TranslateError{
			Code:       translator.CodeBadRequest,
			HTTPStatus: 400,
			Param:      "messages",
			Message:    "messages field is required and must be an array",
		}
	}

	// ── Pass 1: separate system messages from the rest ──────────────
	var (
		systemBlocks  []string // each entry is a JSON object literal for one system text block
		nonSystemMsgs []gjson.Result
	)
	for _, m := range inMessages.Array() {
		role := m.Get("role").String()
		switch role {
		case "system", "developer":
			// "developer" is OpenAI's newer alias for system (Aug 2024+).
			// Both map to Anthropic's top-level system[]. Each system
			// message becomes one text block, preserving order so
			// multi-system prompts (e.g. "guidelines" + "format hint")
			// keep their structure.
			contentNode := m.Get("content")
			text := contentToText(&contentNode)
			if text == "" {
				continue // skip empty system messages — same as empty user text
			}
			systemBlocks = append(systemBlocks, `{"type":"text","text":`+jsonQuote(text)+`}`)
		default:
			nonSystemMsgs = append(nonSystemMsgs, m)
		}
	}

	// ── Pass 2: transform tool messages, build typed message list ───
	//
	// At this stage we model each message as a Go struct because the
	// upcoming merge step compares roles + concatenates content blocks;
	// keeping messages in JSON literals would force re-parse on every
	// merge. After merging we re-serialize to JSON.
	var transformed []normalizedMsg
	for i, m := range nonSystemMsgs {
		role := m.Get("role").String()
		switch role {
		case "user":
			userContent := m.Get("content")
			blocks, err := convertContentBlocks(&userContent, "user")
			if err != nil {
				return nil, err
			}
			transformed = append(transformed, normalizedMsg{role: "user", blocks: blocks})
		case "assistant":
			assistantContent := m.Get("content")
			blocks, err := convertContentBlocks(&assistantContent, "assistant")
			if err != nil {
				return nil, err
			}
			// assistant.tool_calls (OpenAI shape) → content[type:tool_use] blocks
			if tcs := m.Get("tool_calls"); tcs.Exists() && tcs.IsArray() {
				for _, tc := range tcs.Array() {
					tcID := tc.Get("id").String()
					tcName := tc.Get("function.name").String()
					tcArgs := tc.Get("function.arguments").String() // OpenAI: JSON-string of an object
					// arguments may be empty string when the model emits an
					// arg-less tool call — Anthropic expects {} for input.
					if strings.TrimSpace(tcArgs) == "" {
						tcArgs = "{}"
					}
					// Validate arguments is valid JSON object — Anthropic
					// rejects with 400 otherwise.
					if !gjson.Valid(tcArgs) {
						return nil, &translator.TranslateError{
							Code:       translator.CodeBadRequest,
							HTTPStatus: 400,
							Param:      "messages",
							Message: "assistant.tool_calls[].function.arguments is not valid JSON (message " +
								strconvIToA(i) + ", tool_call " + tcID + ")",
						}
					}
					blocks = append(blocks, `{"type":"tool_use","id":`+jsonQuote(tcID)+
						`,"name":`+jsonQuote(tcName)+`,"input":`+tcArgs+`}`)
				}
			}
			transformed = append(transformed, normalizedMsg{role: "assistant", blocks: blocks})
		case "tool":
			// OpenAI: {role:"tool", tool_call_id:"...", content:"result text"}
			// Anthropic: {role:"user", content:[{type:"tool_result", tool_use_id:"...", content:[...]}]}
			toolCallID := m.Get("tool_call_id").String()
			if toolCallID == "" {
				return nil, &translator.TranslateError{
					Code:       translator.CodeBadRequest,
					HTTPStatus: 400,
					Param:      "messages",
					Message:    "tool message at index " + strconvIToA(i) + " missing tool_call_id",
				}
			}
			toolContent := m.Get("content")
			text := contentToText(&toolContent)
			block := `{"type":"tool_result","tool_use_id":` + jsonQuote(toolCallID) +
				`,"content":` + jsonQuote(text) + `}`
			transformed = append(transformed, normalizedMsg{role: "user", blocks: []string{block}})
		case "":
			return nil, &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "messages",
				Message:    "message at index " + strconvIToA(i) + " has no role field",
			}
		default:
			return nil, &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "messages",
				Message: "message at index " + strconvIToA(i) + " has unsupported role " +
					jsonQuote(role) + " (expected user/assistant/tool/system/developer)",
			}
		}
	}

	// ── Pass 3: ensure user-first (insert placeholder if needed) ────
	//
	// If the first message is assistant (e.g. some chat libraries
	// prepend a "primer" assistant turn), Anthropic 400s. LiteLLM
	// prepends a placeholder user message " " to satisfy the rule.
	// We mirror that — silent repair, since rejecting would break
	// legitimate cases where the user implicitly started the
	// conversation off-screen.
	if len(transformed) > 0 && transformed[0].role != "user" {
		transformed = append(
			[]normalizedMsg{{role: "user", blocks: []string{`{"type":"text","text":" "}`}}},
			transformed...,
		)
	}

	// ── Pass 4: merge same-role consecutive messages ────────────────
	//
	// Two adjacent messages with the same role get their blocks
	// concatenated into a single message. This collapses common
	// patterns like "system→user→user→user" (after system extraction
	// + tool rewrap) into a single user turn that Anthropic accepts.
	merged := mergeSameRole(transformed)

	// ── Pass 5: filter empty text blocks; reject all-empty messages ─
	//
	// Anthropic rejects content blocks where text="" with a 400. We
	// filter them out (rather than reject) because they typically
	// come from chat clients sending {role:"user", content:""} as a
	// "continue" signal — silent filter is the right UX.
	for i := range merged {
		merged[i].blocks = filterEmptyTextBlocks(merged[i].blocks)
		if len(merged[i].blocks) == 0 {
			return nil, &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "messages",
				Message: "message at index " + strconvIToA(i) +
					" has no content after empty-block filtering (Anthropic rejects empty messages)",
			}
		}
	}

	if len(merged) == 0 {
		return nil, &translator.TranslateError{
			Code:       translator.CodeBadRequest,
			HTTPStatus: 400,
			Param:      "messages",
			Message:    "messages array is empty after normalization (all entries were system or filtered)",
		}
	}

	// ── Defensive: alternation check (should be unreachable post-merge) ─
	for i := 1; i < len(merged); i++ {
		if merged[i].role == merged[i-1].role {
			return nil, &translator.TranslateError{
				Code:       translator.CodeTranslationFailed,
				HTTPStatus: 500,
				Param:      "messages",
				Message: "internal: post-merge same-role at index " + strconvIToA(i) +
					" — translator bug, please file an issue",
			}
		}
	}

	// ── Serialize to JSON literals for sjson.SetRawBytes ────────────
	out := &normalizeResult{}
	if len(systemBlocks) > 0 {
		out.SystemRaw = []byte("[" + strings.Join(systemBlocks, ",") + "]")
	}
	out.MessagesRaw = serializeNormalizedMessages(merged)
	return out, nil
}

// normalizedMsg is the intermediate shape used during messages
// normalization. blocks contains JSON object literals (each one is a
// complete content block ready for serialization).
type normalizedMsg struct {
	role   string   // "user" or "assistant" (post-tool-rewrap)
	blocks []string // each a JSON object literal
}

// contentToText flattens OpenAI's content (string OR block-array) into
// a single string. Used for system messages + tool result text — both
// of which Anthropic accepts as flat string. For multi-block content
// (rare on system), block texts are joined with "\n".
func contentToText(node *gjson.Result) string {
	if node.Type == gjson.String {
		return node.String()
	}
	if node.IsArray() {
		var parts []string
		for _, b := range node.Array() {
			if b.Get("type").String() == "text" {
				parts = append(parts, b.Get("text").String())
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// convertContentBlocks converts OpenAI's content (string OR block-array)
// into Anthropic content blocks (JSON object literals). roleHint helps
// produce role-appropriate diagnostics (e.g. tool_use blocks only valid
// on assistant role — but this function doesn't enforce that since
// roles are checked at the message-level caller).
//
// 阶段 0 MVP supported block types:
//   - text (passthrough)
//   - image_url (data: URL or http(s) URL) → image source
//
// NOT supported in MVP (Day 5 or 阶段 1):
//   - file → document (PDF passthrough)
//   - input_audio (Anthropic doesn't natively support)
//   - refusal blocks (newer OpenAI output)
func convertContentBlocks(content *gjson.Result, roleHint string) ([]string, *translator.TranslateError) {
	_ = roleHint // reserved for future role-specific block validation
	if content.Type == gjson.String {
		// Plain string content → single text block.
		s := content.String()
		if s == "" {
			// Empty string content — let Pass 5 reject it if no other
			// blocks accumulate. Returning empty slice (not nil) here
			// lets the caller distinguish "no content yet" from
			// "errored".
			return nil, nil
		}
		return []string{`{"type":"text","text":` + jsonQuote(s) + `}`}, nil
	}
	if !content.IsArray() {
		// Null or absent content is OK at this layer; assistant.tool_calls
		// path adds blocks even when content is null.
		return nil, nil
	}
	var blocks []string
	for i, b := range content.Array() {
		t := b.Get("type").String()
		switch t {
		case "text":
			txt := b.Get("text").String()
			if txt == "" {
				continue // filter empties (Pass 5 will catch all-empty later)
			}
			blocks = append(blocks, `{"type":"text","text":`+jsonQuote(txt)+`}`)
		case "image_url":
			imgBlock := b
			block, err := convertImageBlock(&imgBlock, i)
			if err != nil {
				return nil, err
			}
			blocks = append(blocks, block)
		case "input_text":
			// OpenAI Responses API uses input_text instead of text.
			// Same semantics — convert as text block.
			txt := b.Get("text").String()
			if txt == "" {
				continue
			}
			blocks = append(blocks, `{"type":"text","text":`+jsonQuote(txt)+`}`)
		default:
			// Unknown block type — reject loudly rather than silently
			// drop, so vendors integrating new block types see the
			// limit upfront. (LiteLLM silently drops; we prefer
			// CLAUDE.md "失败要显眼".)
			return nil, &translator.TranslateError{
				Code:       translator.CodeUnsupportedParam,
				HTTPStatus: 400,
				Param:      "messages",
				Message: "content block type " + jsonQuote(t) + " not supported (block index " +
					strconvIToA(i) + ", supported: text / image_url / input_text)",
			}
		}
	}
	return blocks, nil
}

// convertImageBlock translates OpenAI's image_url into Anthropic's
// image block. OpenAI sends:
//
//	{"type":"image_url","image_url":{"url":"data:image/png;base64,XYZ"}}
//	{"type":"image_url","image_url":{"url":"https://example.com/cat.png"}}
//
// Anthropic accepts EITHER format:
//
//	{"type":"image","source":{"type":"base64","media_type":"image/png","data":"XYZ"}}
//	{"type":"image","source":{"type":"url","url":"https://example.com/cat.png"}}
func convertImageBlock(b *gjson.Result, idx int) (string, *translator.TranslateError) {
	url := b.Get("image_url.url").String()
	if url == "" {
		return "", &translator.TranslateError{
			Code:       translator.CodeBadRequest,
			HTTPStatus: 400,
			Param:      "messages",
			Message:    "image_url block at index " + strconvIToA(idx) + " missing image_url.url",
		}
	}
	if strings.HasPrefix(url, "data:") {
		// data:image/png;base64,XYZ → source.type=base64
		colonIdx := strings.IndexByte(url, ',')
		if colonIdx < 0 {
			return "", &translator.TranslateError{
				Code:       translator.CodeBadRequest,
				HTTPStatus: 400,
				Param:      "messages",
				Message:    "image_url data URL at index " + strconvIToA(idx) + " malformed (missing comma)",
			}
		}
		header := url[5:colonIdx] // strip "data:"
		data := url[colonIdx+1:]
		// header e.g. "image/png;base64" or "image/png" (no ;base64 = no encoding spec)
		mediaType := header
		isBase64 := false
		if i := strings.Index(header, ";base64"); i >= 0 {
			mediaType = header[:i]
			isBase64 = true
		}
		if !isBase64 {
			// Anthropic only supports base64-encoded data URLs as inline
			// image sources. URL-encoded inline images are uncommon
			// (browsers usually convert; if they don't, the request is
			// off the supported path).
			return "", &translator.TranslateError{
				Code:       translator.CodeUnsupportedParam,
				HTTPStatus: 400,
				Param:      "messages",
				Message:    "image_url data URL at index " + strconvIToA(idx) + " must be base64-encoded",
			}
		}
		return `{"type":"image","source":{"type":"base64","media_type":` +
			jsonQuote(mediaType) + `,"data":` + jsonQuote(data) + `}}`, nil
	}
	// HTTP(S) URL — Anthropic supports source.type=url since 2024-Q3.
	return `{"type":"image","source":{"type":"url","url":` + jsonQuote(url) + `}}`, nil
}

// mergeSameRole concatenates blocks of adjacent same-role messages.
// O(N) single-pass. After this, the input MUST satisfy alternation
// (which the defensive check at the end of normalizeMessages verifies).
func mergeSameRole(in []normalizedMsg) []normalizedMsg {
	if len(in) <= 1 {
		return in
	}
	out := make([]normalizedMsg, 0, len(in))
	out = append(out, in[0])
	for _, m := range in[1:] {
		last := &out[len(out)-1]
		if last.role == m.role {
			last.blocks = append(last.blocks, m.blocks...)
			continue
		}
		out = append(out, m)
	}
	return out
}

// filterEmptyTextBlocks drops blocks where type=text AND text=="" — they
// trigger Anthropic 400 if forwarded. Whitespace-only text (e.g. " " as
// the user-first repair placeholder) is KEPT — Anthropic accepts it.
// Non-text blocks (image, tool_use, tool_result) are kept regardless.
//
// Design-doc rule 5 ("空字符串"): strict equality with "", not whitespace.
func filterEmptyTextBlocks(blocks []string) []string {
	out := blocks[:0]
	for _, b := range blocks {
		t := gjson.Get(b, "type").String()
		if t == "text" {
			if gjson.Get(b, "text").String() == "" {
				continue
			}
		}
		out = append(out, b)
	}
	return out
}

// serializeNormalizedMessages converts the internal struct slice back
// into a JSON array literal suitable for sjson.SetRawBytes.
func serializeNormalizedMessages(msgs []normalizedMsg) []byte {
	var b strings.Builder
	b.WriteByte('[')
	for i, m := range msgs {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"role":`)
		b.WriteString(jsonQuote(m.role))
		b.WriteString(`,"content":[`)
		for j, blk := range m.blocks {
			if j > 0 {
				b.WriteByte(',')
			}
			b.WriteString(blk)
		}
		b.WriteString(`]}`)
	}
	b.WriteByte(']')
	return []byte(b.String())
}

// strconvIToA — tiny int→string helper to avoid pulling strconv into
// this file's import list. Only used in error messages where the
// number is small (message indexes, usually < 100).
func strconvIToA(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = '0' + byte(i%10)
		i /= 10
	}
	if neg {
		return "-" + string(buf[pos:])
	}
	return string(buf[pos:])
}
