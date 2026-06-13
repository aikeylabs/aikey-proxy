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
	text    string
	setText func(string)
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

	// messages[].content for both Anthropic and OpenAI shapes.
	if msgs, isArr := m["messages"].([]any); isArr {
		for _, mi := range msgs {
			if msg, isObj := mi.(map[string]any); isObj {
				collectContentField(msg, "content", &pieces)
			}
		}
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
			if t, _ := block["type"].(string); t != "text" {
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
