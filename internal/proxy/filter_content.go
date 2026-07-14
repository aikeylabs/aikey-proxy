// filter_content.go — L1 envelope content extraction for the filter dispatcher.
//
// The filter hook (ai-compliance-detector / DLP / …) must only ever see prompt
// CONTENT, never the JSON wire envelope (`{"model":…,"messages":[{"content":…}]}`).
// Otherwise masking text spans in the raw body can slice JSON delimiters and
// break the request structure — which is exactly what real Anthropic rejected
// with 400 "not valid JSON" before L1.
//
// Per the architecture (§line233 "ComplianceHook 截获 prompt → stdin pipe") the
// proxy owns the wire envelope (it already parses it for model/usage/translation)
// and hands the hook only the prompt text. This file extracts those content
// strings and provides setters to write the masked text back, so re-serializing
// preserves the envelope + escaping (handled by encoding/json).
//
// Scope (L1): inbound request bodies for the Anthropic /v1/messages and OpenAI
// /v1/chat/completions shapes — `messages[].content` (string or array of
// {type:"text", text:…} blocks) and top-level `system` (string or block array).
// Out of scope: outbound/streaming responses (DC4 "一阶段不做流式替换"), and
// structure preservation WITHIN a content value when the content itself is
// JSON/Markdown (that is H9 / L2, the child's Replacement Planner).
package proxy

import "encoding/json"

// contentPiece is one maskable text value located in the request envelope,
// paired with a setter that writes a replacement back into the parsed structure.
type contentPiece struct {
	setText func(string)
	text    string
}

// extractFilterableContent parses an LLM request body and returns the maskable
// content pieces plus the parsed structure (re-marshal it after mutating pieces).
//
// ok=false when the body is not a JSON object — the caller must then pass the
// request through unfiltered (fail-open; non-LLM bodies are not our concern).
// ok=true with zero pieces means a recognized-but-empty shape (no user text).
func extractFilterableContent(body []byte) (pieces []contentPiece, parsed map[string]any, ok bool) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, nil, false
	}

	// Anthropic top-level system prompt (string or block array). OpenAI carries
	// system inside messages[] instead, so this is simply absent there.
	collectContentField(m, "system", &pieces)

	// messages[].content for both Anthropic and OpenAI chat shapes.
	if msgs, isArr := m["messages"].([]any); isArr {
		for _, mi := range msgs {
			if msg, isObj := mi.(map[string]any); isObj {
				collectContentField(msg, "content", &pieces)
			}
		}
	}

	// OpenAI Responses API (codex): content lives in input[] / input string,
	// system in `instructions` (kept in scope here as the full extractor mirrors
	// system for masking symmetry). See extractUserContent for the live path.
	collectContentField(m, "instructions", &pieces)
	switch in := m["input"].(type) {
	case string:
		if in != "" {
			pieces = append(pieces, contentPiece{text: in, setText: func(s string) { m["input"] = s }})
		}
	case []any:
		for _, ii := range in {
			if item, isObj := ii.(map[string]any); isObj {
				collectContentField(item, "content", &pieces)
			}
		}
	}

	return pieces, m, true
}

// extractUserContent extracts the maskable text of EVERY user-role message — the
// user's own input across all turns (latest + history). This is the history-leak
// fix's scan set (2026-06-16): the user's earlier sensitive input lives in a HISTORY
// user message and must be re-masked every turn.
//
// It deliberately SKIPS:
//   - the system prompt (admin-authored instructions, not user input — masking it
//     would corrupt the agent's directives), and
//   - assistant / tool messages (the model's own RESPONSES = "returned content";
//     the inbound compliance filter governs user→LLM, it must NOT mask what the
//     model returned — 用户明确要求 2026-06-16).
//
// Skipping system + assistant also slashes the piece count (a big agent prompt is
// mostly system + history assistant turns), which is what kept the full scan within
// the detector budget (no per-piece timeout / fail-open on a 22-piece prompt).
//
// Fail-safe role handling: only EXPLICIT assistant/system/tool roles are skipped;
// a "user" or missing/empty role is scanned (never silently under-scan real input).
// ok=false only when the body is not a JSON object with a messages[] array → caller
// falls back to forwarding unfiltered (same fail-open as before for non-chat bodies).
func extractUserContent(body []byte) (pieces []contentPiece, parsed map[string]any, ok bool) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, nil, false
	}
	if msgs, isArr := m["messages"].([]any); isArr {
		collectUserTurns(msgs, &pieces)
		return pieces, m, true
	}
	// OpenAI Responses API (codex, /v1/responses): the request carries no
	// messages[]; user turns live in input[] and the system prompt in
	// `instructions` (skipped like `system`). input can be a bare string
	// (single-turn shorthand) or an item array whose message items mirror
	// chat messages but with input_text content parts. Without this branch
	// the whole request was "not filterable" → forwarded UNFILTERED, letting
	// codex prompts bypass the compliance scan while conversation audit (a
	// separate, Responses-aware path) still captured them (live incident
	// 2026-07-08; same wire-format class as the audit R20 fix).
	switch in := m["input"].(type) {
	case string:
		if in != "" {
			pieces = append(pieces, contentPiece{
				text:    in,
				setText: func(s string) { m["input"] = s },
			})
		}
		return pieces, m, true
	case []any:
		collectUserTurns(in, &pieces)
		return pieces, m, true
	}
	return nil, m, false
}

// collectUserTurns scans a chat-style item array (Anthropic/OpenAI messages[]
// or Responses API input[]) for USER-role text, applying the single skip policy
// (model responses / admin instructions / tool output are never user input).
func collectUserTurns(items []any, out *[]contentPiece) {
	for _, mi := range items {
		msg, isObj := mi.(map[string]any)
		if !isObj {
			continue
		}
		switch role, _ := msg["role"].(string); role {
		case "assistant", "system", "developer", "tool", "function":
			// model RESPONSE (assistant) / admin instructions (system, OpenAI
			// developer) / tool output (tool, OpenAI legacy function) — none are user
			// input, so the inbound compliance filter must not scan/mask them. Covers
			// Anthropic + OpenAI-family (Codex/Kimi) + OpenClaw roles uniformly.
			continue
		}
		collectContentField(msg, "content", out)
	}
}

// extractLatestUserContent extracts ONLY the latest user turn's text — the NEW
// content in a request that resends the full conversation (system + history)
// every turn (OpenClaw, Claude Code, Codex, Cursor all do this). It deliberately
// skips `system` (static, admin-authored) and all prior messages (already scanned
// on their own turn), so the detector scans a few-dozen-byte new message instead
// of re-scanning 10-28KB every request. See Proxy.filterIncremental for the why.
//
// SAFETY (never silently under-scan): returns ok=false — caller MUST fall back to
// a FULL extractFilterableContent scan — on any shape it can't confidently reduce
// to "the human's new input":
//   - non-JSON body,
//   - no messages array / empty,
//   - last message isn't role=="user" (assistant- or tool-terminated agent loop),
//   - last user message carries no scannable text (image / tool_result only).
//
// Mask write-back: the returned pieces' setText closures mutate parsed (the FULL
// body map) in place, so re-marshaling parsed yields the original request with
// only the latest user text masked — identical re-serialization path as the full
// scan.
func extractLatestUserContent(body []byte) (pieces []contentPiece, parsed map[string]any, ok bool) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, nil, false
	}
	msgs, isArr := m["messages"].([]any)
	if !isArr || len(msgs) == 0 {
		return nil, m, false
	}
	last, isObj := msgs[len(msgs)-1].(map[string]any)
	if !isObj {
		return nil, m, false
	}
	if role, _ := last["role"].(string); role != "user" {
		return nil, m, false
	}
	collectContentField(last, "content", &pieces)
	if len(pieces) == 0 {
		return nil, m, false
	}
	return pieces, m, true
}

// collectContentField appends maskable pieces for a field that is either a
// string ("content":"…") or an array of typed blocks ("content":[{"type":"text",
// "text":"…"}, …]). Non-text blocks (image / tool_use / tool_result / …) and
// null content are skipped — only natural-language text is sent to the hook.
func collectContentField(parent map[string]any, key string, out *[]contentPiece) {
	switch v := parent[key].(type) {
	case string:
		if v != "" {
			*out = append(*out, contentPiece{
				text:    v,
				setText: func(s string) { parent[key] = s },
			})
		}
	case []any:
		for _, bi := range v {
			block, isObj := bi.(map[string]any)
			if !isObj {
				continue
			}
			// "text" = Anthropic/OpenAI chat content block; "input_text" = OpenAI
			// Responses API user content part (codex). Both carry human text in
			// the same `text` field. Non-text blocks (image / input_image /
			// tool_use / output_text=model reply) are skipped.
			switch t, _ := block["type"].(string); t {
			case "text", "input_text":
			default:
				continue
			}
			txt, isStr := block["text"].(string)
			if !isStr || txt == "" {
				continue
			}
			b := block // capture this block for the setter closure
			*out = append(*out, contentPiece{
				text:    txt,
				setText: func(s string) { b["text"] = s },
			})
		}
	}
}

// topLevelKeys + messageCount are diagnostic helpers for the filter dispatcher's
// "no filterable content" skip log (proxy.filter.skipped). They expose the SHAPE
// of a request the extractor found nothing in — the key signal when a client
// (e.g. OpenClaw) sends a body that masks differently from a hand-rolled curl.
// Nil-safe: parsed is nil when the body was not JSON. (2026-06-13 form-② RCA.)
func topLevelKeys(m map[string]any) []string {
	if m == nil {
		return nil
	}
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func messageCount(m map[string]any) int {
	if m == nil {
		return 0
	}
	if msgs, ok := m["messages"].([]any); ok {
		return len(msgs)
	}
	return 0
}
