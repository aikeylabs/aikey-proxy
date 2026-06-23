// Package conversation_audit is the proxy-bundled first-party Observer that
// captures full conversation turns (prompt + completion) for the enterprise
// Cluster edition's conversation-audit feature. It is a payload_level=full
// consumer of the observer framework (see pkg/observer): the assistant text is
// accumulated from the SSE frames every observer already receives, and the user
// prompt comes from the request body the framework now exposes when an observer
// declares WantsFullPayload.
//
// Privacy invariant (DC5/I2): captured content NEVER leaves the customer's
// trust boundary — it flows only to the customer's own Cluster master collector,
// gated by the org's conversation_audit_enabled policy flag.
//
// This file holds the pure, protocol-aware extractors (no I/O, no state) so they
// can be fixture-tested per wire format. observer.go owns the lifecycle/state.
package conversation_audit

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Protocol family values mirror observer.RequestContext.ProtocolFamily, which
// the proxy derives from the upstream provider's real wire format (NOT the
// inbound URL). Unknown families are deliberately not guessed — mis-parsing a
// body would store garbage as "the prompt".
const (
	protoAnthropic = "anthropic"
	protoOpenAI    = "openai_compatible"
	protoGemini    = "gemini"
)

// extractPrompt parses a client request body ONCE and returns the latest
// user-turn text (the increment stored per record — per the "按 session 存增量"
// design, earlier turns already live in earlier records), the system prompt
// (stored once per session, first-wins, at the collector), and the model
// (body.model for Anthropic/OpenAI; "" for Gemini which carries it in the URL).
//
// Parse-once: model is folded into this single Unmarshal rather than re-parsing
// the body — honoring the framework's parse-once philosophy (the proxy already
// caches model in the x-aikey-model header via extractModel; this observer only
// re-parses the body it MUST parse for prompt/system, getting model for free in
// the same pass). Returns zeroes on parse failure or unknown protocol — capture
// degrades rather than erroring or guessing.
func extractPrompt(protocolFamily string, body []byte) (userText, systemText, model string) {
	if len(body) == 0 {
		return "", "", ""
	}
	switch protocolFamily {
	case protoAnthropic:
		return extractAnthropicPrompt(body)
	case protoOpenAI:
		return extractOpenAIPrompt(body)
	case protoGemini:
		return extractGeminiPrompt(body)
	default:
		return "", "", ""
	}
}

// extractAssistantDelta returns the assistant text carried by ONE upstream SSE
// frame, or "" when the frame carries no text (control frames, usage frames,
// the [DONE] sentinel). Called once per frame in OnSSEEvent; the observer
// concatenates the non-empty results.
func extractAssistantDelta(protocolFamily, eventType string, payload []byte) string { //nolint:unparam // eventType kept for symmetry with isCompletionMarker + future event-type-aware extraction
	if len(payload) == 0 {
		return ""
	}
	switch protocolFamily {
	case protoAnthropic:
		var f struct {
			Type  string `json:"type"`
			Delta struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"delta"`
		}
		if json.Unmarshal(payload, &f) == nil && f.Type == "content_block_delta" && f.Delta.Type == "text_delta" {
			return f.Delta.Text
		}
		return ""
	case protoOpenAI:
		var f struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal(payload, &f) == nil && len(f.Choices) > 0 {
			return f.Choices[0].Delta.Content
		}
		return ""
	case protoGemini:
		var f struct {
			Candidates []struct {
				Content struct {
					Parts []geminiPart `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if json.Unmarshal(payload, &f) == nil && len(f.Candidates) > 0 {
			return joinParts(f.Candidates[0].Content.Parts)
		}
		return ""
	default:
		return ""
	}
}

// isCompletionMarker reports whether a frame marks a clean end-of-stream. The
// observer uses it to distinguish request_status "ok" (saw the marker) from
// "partial" (stream ended without it — client disconnect / upstream abort).
func isCompletionMarker(protocolFamily, eventType string, payload []byte) bool {
	switch protocolFamily {
	case protoAnthropic:
		return eventType == "message_stop" || bytes.Contains(payload, []byte(`"type":"message_stop"`))
	case protoOpenAI:
		return bytes.Equal(bytes.TrimSpace(payload), []byte("[DONE]"))
	case protoGemini:
		return bytes.Contains(payload, []byte(`"finishReason"`))
	default:
		return false
	}
}

// --- per-protocol request-body parsers -------------------------------------

type anthropicReq struct {
	Model    string          `json:"model"`
	System   json.RawMessage `json:"system"` // string | []block
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"` // string | []block
	} `json:"messages"`
}

func extractAnthropicPrompt(body []byte) (userText, systemText, model string) {
	var req anthropicReq
	if json.Unmarshal(body, &req) != nil {
		return "", "", ""
	}
	systemText = joinContent(req.System)
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			userText = joinContent(req.Messages[i].Content)
			break
		}
	}
	return userText, systemText, req.Model
}

type openaiReq struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"` // string | []part
	} `json:"messages"`
}

func extractOpenAIPrompt(body []byte) (userText, systemText, model string) {
	var req openaiReq
	if json.Unmarshal(body, &req) != nil {
		return "", "", ""
	}
	for _, m := range req.Messages {
		if (m.Role == "system" || m.Role == "developer") && systemText == "" {
			systemText = joinContent(m.Content)
		}
	}
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			userText = joinContent(req.Messages[i].Content)
			break
		}
	}
	return userText, systemText, req.Model
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiReq struct {
	SystemInstruction struct {
		Parts []geminiPart `json:"parts"`
	} `json:"systemInstruction"`
	Contents []struct {
		Role  string       `json:"role"`
		Parts []geminiPart `json:"parts"`
	} `json:"contents"`
}

func extractGeminiPrompt(body []byte) (userText, systemText, model string) {
	var req geminiReq
	if json.Unmarshal(body, &req) != nil {
		return "", "", ""
	}
	systemText = joinParts(req.SystemInstruction.Parts)
	for i := len(req.Contents) - 1; i >= 0; i-- {
		// Gemini omits role on single-turn requests; treat "" as the user turn.
		if req.Contents[i].Role == "user" || req.Contents[i].Role == "" {
			userText = joinParts(req.Contents[i].Parts)
			break
		}
	}
	// Gemini carries the model in the URL path, not the body — "" here; the
	// observer falls back to RequestContext's resolved/requested model.
	return userText, systemText, ""
}

// joinContent flattens an Anthropic/OpenAI content field that is either a plain
// string or an array of typed blocks ([{type,text}] / [{text}]) into text. Only
// text blocks contribute; tool_use / image blocks are skipped (the audit stores
// the conversational text, not binary attachments).
func joinContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) == nil {
		var b strings.Builder
		for _, blk := range blocks {
			if blk.Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(blk.Text)
		}
		return b.String()
	}
	return ""
}

func joinParts(parts []geminiPart) string {
	var b strings.Builder
	for _, p := range parts {
		if p.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(p.Text)
	}
	return b.String()
}
