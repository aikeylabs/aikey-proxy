package proxy

// canned_answer.go — 安全代答 (canned answer): synthesizing a protocol-legal
// success response for a request that was NEVER forwarded upstream.
//
// # What problem this solves
//
// A hit that ends in a bare 403 teaches the user to edit the sentence and retry
// until something gets through — and every retry pushes the remaining sensitive
// text at the boundary one more time. 代答 refuses in the shape of a normal
// reply: the request stops at the same short-circuit a block stops at, and the
// client receives text an administrator wrote and reviewed beforehand.
//
// # Why this file synthesizes from zero instead of reusing sse_restore
//
// sse_restore rewrites a stream that CAME FROM upstream. Here there is no
// upstream response — there was no upstream request. The two are opposite
// directions and must not share code: a rewriter has an inbound frame to
// preserve, a synthesizer has to produce a complete, terminated sequence out of
// nothing. What IS reused is the KNOWLEDGE of the three families' frame shapes
// (sse_restore.go's sseTextFieldPath documents the text channel of each), not
// its code. design.md §5.4a: 「合成器从零写，不复用 sse_restore」.
//
// # 🔴 Two red lines govern every byte written here
//
//  1. R-compliance-canned-answer-3 / design §6 invariant 12 — the text is
//     emitted VERBATIM. No Sprintf, no template, no substitution, no
//     concatenation with anything the detector found. `{{IDCARD_1}}` in the
//     stored text reaches the client as those exact 13 bytes. If interpolation
//     were possible here the guardrail would become the channel that echoes the
//     customer's ID-card number back to whoever sent it — 「原文不出客户信任边界」
//     breached from the other side. That is why this file contains no call to
//     any interpolation primitive at all: the text only ever travels as a struct
//     field handed to encoding/json.
//
//  2. R-compliance-canned-answer-1 / design §6 invariant 13 — this writer runs
//     ONLY on the request leg, at the same short-circuit as ActionBlock, and the
//     caller returns false immediately after. Nothing here may be reachable from
//     the response leg.
//
// # Why usage counts are zero and the finish signal is protocol-native
//
// Nothing was sent to a provider, so a non-zero token count would be invented
// billing data. And a downstream tool has to be able to tell a canned answer
// from a real one without knowing about AiKey, so the marker is each family's
// OWN filter signal (`finish_reason: content_filter` / `stop_reason: refusal` /
// `incomplete_details.reason: content_filter`) rather than a custom header
// (design.md Decision 代答是阻断的友好呈现变体, 「自定义响应头标注代答」: 否决).
//
// 需求包: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/ (task 3.6)
// 围栏: canned_answer_test.go — TestCannedAnswer_ShapeOpenAIChatNonStream ·
//       TestCannedAnswer_StreamSequenceClosesCleanly ·
//       TestCannedAnswer_TextIsNeverInterpolated ·
//       TestCannedAnswer_NoUpstreamRequestIssued ·
//       TestCannedAnswer_EmptyTextFallsBackToBlock
//
// ⚠️ The rules above are still PROPOSAL-layer (openspec/changes/…), so they are
// referenced by id rather than written as `spec:` anchors — a `spec:` anchor is
// read by check-spec-writeback as evidence the rule has landed. Upgrade both in
// the change that writes them back. Same convention as
// compliance_guardrail_response_fence_test.go.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// ProtocolKind is the client-facing API family a request arrived on. The canned
// answer must be synthesized in the SAME family the client spoke, or its SDK
// cannot parse the reply.
//
// Name and spelling are taken verbatim from design.md §4b's interface contract
// (`writeCannedAnswer(w http.ResponseWriter, proto ProtocolKind, streaming bool,
// model, text string) error`).
type ProtocolKind uint8

const (
	// ProtocolUnknown is the fail-closed zero value: a path this proxy cannot
	// classify gets NO synthesized answer. The caller degrades to a plain block
	// rather than guessing a shape — a guessed shape reaches the client as a
	// parse error, which reads as "the proxy is broken", not as "your content
	// was refused".
	ProtocolUnknown ProtocolKind = iota
	// ProtocolOpenAIChat — POST /v1/chat/completions (OpenAI-compatible).
	ProtocolOpenAIChat
	// ProtocolAnthropicMessages — POST /v1/messages.
	ProtocolAnthropicMessages
	// ProtocolOpenAIResponses — POST /v1/responses (OpenAI Responses API, codex).
	ProtocolOpenAIResponses
)

func (p ProtocolKind) String() string {
	switch p {
	case ProtocolOpenAIChat:
		return "openai_chat_completions"
	case ProtocolAnthropicMessages:
		return "anthropic_messages"
	case ProtocolOpenAIResponses:
		return "openai_responses"
	}
	return "unknown"
}

// protocolKindFromPath classifies a request path into an API family.
//
// 🔴 Suffix matching, not equality, and that is deliberate: the proxy serves the
// same families under provider path prefixes (`/anthropic/v1/messages`,
// `/groq/v1/chat/completions`, see extractProviderFromPath). Keyed on the same
// suffixes requestProtocolFromPath (middleware.go) already uses, so the two
// cannot disagree about what a path is — except that this one must separate
// /responses from /chat/completions, which that one deliberately merges into
// "openai_compatible" because for ROUTING they are the same and for RESPONSE
// SHAPE they are not.
func protocolKindFromPath(path string) ProtocolKind {
	switch {
	case strings.HasSuffix(path, "/messages"):
		return ProtocolAnthropicMessages
	case strings.HasSuffix(path, "/chat/completions"):
		return ProtocolOpenAIChat
	case strings.HasSuffix(path, "/responses"):
		return ProtocolOpenAIResponses
	}
	return ProtocolUnknown
}

// Protocol-native "the content was filtered" signals. Each family has one; none
// of them is an AiKey invention.
const (
	// OpenAI chat completions: a standard finish_reason value.
	finishReasonContentFilter = "content_filter"
	// Anthropic messages: a standard stop_reason value.
	stopReasonRefusal = "refusal"
	// OpenAI Responses: status=incomplete + incomplete_details.reason.
	responsesStatusIncomplete   = "incomplete"
	responsesIncompleteFiltered = "content_filter"
)

// errNoCannedAnswer is returned when this writer refuses to synthesize. The
// caller MUST fall back to the plain block; it must never forward and must never
// serve a partial body. Returned only BEFORE any byte is written (see
// writeCannedAnswer's ordering note).
var errNoCannedAnswer = errors.New("canned answer not synthesizable")

// writeCannedAnswer is THE single outlet for 代答 — three protocol families ×
// streaming/non-streaming = six shapes.
//
// 🔴 ORDERING CONTRACT: everything that can fail happens BEFORE the first byte
// reaches the client. Validation, then full body construction, then
// WriteHeader, then the write. An error after WriteHeader would leave the client
// holding a truncated 200 with no way for the caller to fall back to a refusal —
// the one outcome worse than either a block or an answer.
//
// The empty-text check here is defence in depth, not the policy: the policy
// lives at the call site (a resolved source of `none` degrades to ActionBlock
// before we get here, R-compliance-canned-answer-2.S2). Duplicated because an
// all-blank body reaches the user as 「模型什么也没说」 — indistinguishable from a
// broken proxy, and it teaches exactly the retry behaviour 代答 exists to stop.
func writeCannedAnswer(w http.ResponseWriter, proto ProtocolKind, streaming bool, model, text string) error {
	if strings.TrimSpace(text) == "" {
		return errNoCannedAnswer
	}
	if proto == ProtocolUnknown {
		return errNoCannedAnswer
	}

	now := time.Now()
	if streaming {
		frames, err := cannedAnswerStreamFrames(proto, now, model, text)
		if err != nil {
			return err
		}
		writeSSEHeaders(w)
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for _, frame := range frames {
			if _, err := w.Write(frame); err != nil {
				return err
			}
			if flusher != nil {
				// Flush per frame: a client that renders incrementally must see
				// the reply arrive the way a real stream arrives, and a buffered
				// single write would defeat the SDK's own progress handling.
				flusher.Flush()
			}
		}
		return nil
	}

	body, err := cannedAnswerBody(proto, now, model, text)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(body)
	return err
}

func writeSSEHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	// A reverse proxy that buffers SSE turns a stream into one late blob, which
	// for a refusal reads as "the tool hung".
	//
	// ⚠️ THIS IS THE ONLY SITE IN THIS REPOSITORY THAT SETS THIS HEADER (verified
	// by grep, 2026-09-13) — do not read it as an established convention. The
	// forwarded streaming path does not set it because it does not have to: the
	// cluster ingress already disables buffering server-side
	// (workflow/CD/installer/cluster-install/nginx/aikey-cluster.conf:91
	// `proxy_buffering off`). It is set here anyway because this response is
	// synthesized locally and may be served through an ingress nobody checked,
	// and the cost of being wrong in that direction is a refusal that looks like
	// a hang. Where buffering is already off it is a no-op.
	h.Set("X-Accel-Buffering", "no")
}

// -----------------------------------------------------------------------------
// Deciding whether a canned answer can be served at all.
// -----------------------------------------------------------------------------

// cannedAnswerPlan is everything writeCannedAnswer needs, resolved in one place
// BEFORE the guardrail commits to answering. Its existence is the answer to
// "what if we find out halfway through that we cannot do this?" — we find out
// beforehand or not at all.
type cannedAnswerPlan struct {
	proto     ProtocolKind
	streaming bool
	text      string
	source    string // rule | level | org — never "none" (that degrades to block)
}

// planCannedAnswer answers one question: can this Answer verdict be served as a
// real reply, right now, on this request? nil means NO, and the caller MUST then
// degrade to ActionBlock — never forward, never a bare 200.
//
// 🔴 EVERY nil PATH IS LOUD, under one event name
// (`proxy.filter.canned_answer_degraded`) with a `reason`. That shape is
// deliberate: an administrator who configured a canned answer and is getting
// hard blocks has no other way to learn why, and three separate event names
// would mean three separate things to know to grep for. It is the proxy-side
// counterpart of the detector's EventAnswerUndeliverable
// (actionpolicy/answer.go), which says the same thing from the other end.
//
// 🔴 THE TEXT IS NEVER LOGGED, only its length — it is administrator content,
// and logs travel further than the trust boundary the compliance channel guards.
// Same rule the detector's levelOf() comment states.
//
// spec: R-compliance-canned-answer-2.S2 三级皆空 → 退回阻断而非放行
//
//	R-compliance-canned-answer-6    未声明支持 / 读不懂 → 按阻断，不按放行
func planCannedAnswer(resp *apphook.Response, r *http.Request, bodyBytes []byte, logger *slog.Logger) *cannedAnswerPlan {
	degrade := func(reason string) *cannedAnswerPlan {
		logger.Warn("filter: canned-answer verdict could not be served; refusing as a plain block",
			"event.name", "proxy.filter.canned_answer_degraded",
			"reason", reason,
			"answer_source", resp.AnswerSource,
			"answer_text_len", len(resp.AnswerText),
			"path", r.URL.Path)
		return nil
	}

	// 1. Capability. Kept as a runtime question rather than assumed, so that a
	// build which ever makes 代答 opt-in per deployment cannot serve one by
	// accident — R-compliance-canned-answer-6 from the proxy's side.
	if !apphook.SupportsCannedAnswer() {
		return degrade("capability_not_declared")
	}

	// 2. Text. Whitespace-only counts as empty, matching ResolveAnswerText's own
	// hasText(): an all-blank "answer" reaches the user as a reply with nothing
	// in it, which reads as 「模型什么也没说」 — not as a refusal, and it teaches
	// exactly the retry behaviour 代答 exists to stop.
	text := resp.AnswerText
	if strings.TrimSpace(text) == "" {
		return degrade("no_answer_text")
	}

	// 3. Protocol. A shape we cannot classify gets no guess: a wrong shape
	// reaches the client as a parse error, which reads as "the proxy is broken"
	// rather than "your content was refused" — strictly worse than a 403, which
	// at least says something true.
	proto := protocolKindFromPath(r.URL.Path)
	if proto == ProtocolUnknown {
		return degrade("unrecognized_protocol")
	}

	// 4. Streaming. Read through the EXISTING single source of truth rather than
	// re-implementing the peek: isStreamingRequest re-buffers the body, so the
	// body is left exactly as the block path would leave it. A canned answer sent
	// non-streaming to a client that asked to stream is a hang, not an error.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	streaming := isStreamingRequest(r)

	source := resp.AnswerSource
	switch source {
	case "rule", "level", "org":
	default:
		// Not a reason to refuse: the ANSWER is valid, only its provenance label
		// is not. Dropping the label keeps the audit row honest (an absent
		// answer_source reads as "unknown", a wrong one reads as a lie), and
		// master would drop it anyway since 1.20 (200 + NULL + WARN).
		logger.Warn("filter: canned answer carries an answer_source outside the domain; dropping the label",
			"event.name", "proxy.filter.canned_answer_source_unknown",
			"answer_source", source)
		source = ""
	}

	return &cannedAnswerPlan{proto: proto, streaming: streaming, text: text, source: source}
}

// -----------------------------------------------------------------------------
// Non-streaming bodies.
// -----------------------------------------------------------------------------

func cannedAnswerBody(proto ProtocolKind, now time.Time, model, text string) ([]byte, error) {
	switch proto {
	case ProtocolOpenAIChat:
		return json.Marshal(openAIChatCompletion{
			ID:      newID("chatcmpl-"),
			Object:  "chat.completion",
			Created: now.Unix(),
			Model:   model,
			Choices: []openAIChatChoice{{
				Index:        0,
				Message:      openAIChatMessage{Role: "assistant", Content: text},
				FinishReason: finishReasonContentFilter,
			}},
			Usage: openAIUsage{},
		})
	case ProtocolAnthropicMessages:
		return json.Marshal(anthropicMessage{
			ID:         newID("msg_"),
			Type:       "message",
			Role:       "assistant",
			Model:      model,
			Content:    []anthropicTextBlock{{Type: "text", Text: text}},
			StopReason: stopReasonRefusal,
			Usage:      anthropicUsage{},
		})
	case ProtocolOpenAIResponses:
		itemID := newID("msg_")
		return json.Marshal(openAIResponsesResponse{
			ID:                newID("resp_"),
			Object:            "response",
			CreatedAt:         now.Unix(),
			Status:            responsesStatusIncomplete,
			IncompleteDetails: &responsesIncompleteDetails{Reason: responsesIncompleteFiltered},
			Model:             model,
			Output: []responsesOutputItem{{
				Type:    "message",
				ID:      itemID,
				Status:  "completed",
				Role:    "assistant",
				Content: []responsesOutputText{{Type: "output_text", Text: text, Annotations: []any{}}},
			}},
			Usage: &responsesUsage{},
		})
	}
	return nil, errNoCannedAnswer
}

// -----------------------------------------------------------------------------
// Streaming frame sequences.
//
// Each returns a COMPLETE, terminated sequence. "Terminated" is the requirement
// that matters: a stream that stops without its closing event does not error in
// an SDK, it HANGS — the worst possible outcome for a refusal, because the user
// concludes the tool is broken rather than that their content was withheld.
// -----------------------------------------------------------------------------

func cannedAnswerStreamFrames(proto ProtocolKind, now time.Time, model, text string) ([][]byte, error) {
	switch proto {
	case ProtocolOpenAIChat:
		return openAIChatStreamFrames(now, model, text)
	case ProtocolAnthropicMessages:
		return anthropicStreamFrames(model, text)
	case ProtocolOpenAIResponses:
		return openAIResponsesStreamFrames(now, model, text)
	}
	return nil, errNoCannedAnswer
}

// openAIChatStreamFrames: role chunk → content chunk → finish chunk → [DONE].
//
// Three chunks rather than two because the OpenAI wire opens the assistant
// message with a role-only delta; SDK accumulators that build a message from
// deltas key the message's role off that first chunk.
func openAIChatStreamFrames(now time.Time, model, text string) ([][]byte, error) {
	id := newID("chatcmpl-")
	created := now.Unix()
	chunk := func(delta openAIChatDelta, finish *string) openAIChatChunk {
		return openAIChatChunk{
			ID:      id,
			Object:  "chat.completion.chunk",
			Created: created,
			Model:   model,
			Choices: []openAIChatChunkChoice{{Index: 0, Delta: delta, FinishReason: finish}},
		}
	}
	filtered := finishReasonContentFilter
	var frames [][]byte
	for _, payload := range []any{
		chunk(openAIChatDelta{Role: "assistant"}, nil),
		chunk(openAIChatDelta{Content: text}, nil),
		chunk(openAIChatDelta{}, &filtered),
	} {
		f, err := sseFrame("", payload)
		if err != nil {
			return nil, err
		}
		frames = append(frames, f)
	}
	// The literal sentinel, not a JSON document. Every OpenAI-compatible client
	// stops on exactly these bytes.
	frames = append(frames, []byte("data: [DONE]\n\n"))
	return frames, nil
}

// anthropicStreamFrames: message_start → content_block_start →
// content_block_delta → content_block_stop → message_delta → message_stop.
//
// 🔴 The `event:` line and the payload's own `type` must agree — Anthropic SDKs
// dispatch on the event line and validate against the type, and a mismatch makes
// the reader drop the frame silently.
func anthropicStreamFrames(model, text string) ([][]byte, error) {
	id := newID("msg_")
	events := []struct {
		name    string
		payload any
	}{
		{"message_start", anthropicStreamMessageStart{
			Type: "message_start",
			Message: anthropicMessage{
				ID:      id,
				Type:    "message",
				Role:    "assistant",
				Model:   model,
				Content: []anthropicTextBlock{},
				Usage:   anthropicUsage{},
			},
		}},
		{"content_block_start", anthropicStreamBlockStart{
			Type:         "content_block_start",
			Index:        0,
			ContentBlock: anthropicTextBlock{Type: "text", Text: ""},
		}},
		{"content_block_delta", anthropicStreamBlockDelta{
			Type:  "content_block_delta",
			Index: 0,
			Delta: anthropicTextDelta{Type: "text_delta", Text: text},
		}},
		{"content_block_stop", anthropicStreamBlockStop{Type: "content_block_stop", Index: 0}},
		{"message_delta", anthropicStreamMessageDelta{
			Type:  "message_delta",
			Delta: anthropicMessageDeltaBody{StopReason: stopReasonRefusal},
			Usage: anthropicUsage{},
		}},
		{"message_stop", anthropicStreamMessageStop{Type: "message_stop"}},
	}
	var frames [][]byte
	for _, e := range events {
		f, err := sseFrame(e.name, e.payload)
		if err != nil {
			return nil, err
		}
		frames = append(frames, f)
	}
	return frames, nil
}

// openAIResponsesStreamFrames: the Responses API's lifecycle, closed on
// response.incomplete (its terminal event when content was filtered).
//
// 🔴 The text channel is the TOP-LEVEL `delta` string on
// response.output_text.delta — not choices[], not delta.text. Three files in
// this repository have missed that (usage extractor 2026-07-06, conversation
// audit 2026-07-07, sse_restore 2026-09-03); the fourth would be this one.
func openAIResponsesStreamFrames(now time.Time, model, text string) ([][]byte, error) {
	respID := newID("resp_")
	itemID := newID("msg_")
	created := now.Unix()
	seq := 0
	next := func() int { n := seq; seq++; return n }

	shell := func(status string, incomplete *responsesIncompleteDetails, output []responsesOutputItem) openAIResponsesResponse {
		return openAIResponsesResponse{
			ID:                respID,
			Object:            "response",
			CreatedAt:         created,
			Status:            status,
			IncompleteDetails: incomplete,
			Model:             model,
			Output:            output,
			Usage:             &responsesUsage{},
		}
	}
	part := responsesOutputText{Type: "output_text", Text: text, Annotations: []any{}}
	emptyPart := responsesOutputText{Type: "output_text", Text: "", Annotations: []any{}}
	doneItem := responsesOutputItem{
		Type: "message", ID: itemID, Status: "completed", Role: "assistant",
		Content: []responsesOutputText{part},
	}

	events := []struct {
		name    string
		payload any
	}{
		{"response.created", responsesStreamResponseEvent{
			Type: "response.created", SequenceNumber: next(),
			Response: shell("in_progress", nil, []responsesOutputItem{}),
		}},
		{"response.in_progress", responsesStreamResponseEvent{
			Type: "response.in_progress", SequenceNumber: next(),
			Response: shell("in_progress", nil, []responsesOutputItem{}),
		}},
		{"response.output_item.added", responsesStreamItemEvent{
			Type: "response.output_item.added", SequenceNumber: next(), OutputIndex: 0,
			Item: responsesOutputItem{
				Type: "message", ID: itemID, Status: "in_progress", Role: "assistant",
				Content: []responsesOutputText{},
			},
		}},
		{"response.content_part.added", responsesStreamPartEvent{
			Type: "response.content_part.added", SequenceNumber: next(),
			ItemID: itemID, OutputIndex: 0, ContentIndex: 0, Part: emptyPart,
		}},
		{"response.output_text.delta", responsesStreamTextDelta{
			Type: "response.output_text.delta", SequenceNumber: next(),
			ItemID: itemID, OutputIndex: 0, ContentIndex: 0, Delta: text,
		}},
		{"response.output_text.done", responsesStreamTextDone{
			Type: "response.output_text.done", SequenceNumber: next(),
			ItemID: itemID, OutputIndex: 0, ContentIndex: 0, Text: text,
		}},
		{"response.content_part.done", responsesStreamPartEvent{
			Type: "response.content_part.done", SequenceNumber: next(),
			ItemID: itemID, OutputIndex: 0, ContentIndex: 0, Part: part,
		}},
		{"response.output_item.done", responsesStreamItemEvent{
			Type: "response.output_item.done", SequenceNumber: next(), OutputIndex: 0, Item: doneItem,
		}},
		{"response.incomplete", responsesStreamResponseEvent{
			Type: "response.incomplete", SequenceNumber: next(),
			Response: shell(responsesStatusIncomplete,
				&responsesIncompleteDetails{Reason: responsesIncompleteFiltered},
				[]responsesOutputItem{doneItem}),
		}},
	}
	var frames [][]byte
	for _, e := range events {
		f, err := sseFrame(e.name, e.payload)
		if err != nil {
			return nil, err
		}
		frames = append(frames, f)
	}
	return frames, nil
}

// sseFrame renders one `event:`/`data:` frame.
//
// 🔴 The payload is MARSHALLED, never formatted. json.Marshal escaping is
// encoding, not interpolation: the client's decoder yields the original bytes,
// which is exactly what invariant 12 requires. Note there is no Sprintf anywhere
// in this file — the frame envelope is assembled from constants and the
// already-encoded payload.
func sseFrame(event string, payload any) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if event != "" {
		buf.WriteString("event: ")
		buf.WriteString(event)
		buf.WriteString("\n")
	}
	buf.WriteString("data: ")
	buf.Write(encoded)
	buf.WriteString("\n\n")
	return buf.Bytes(), nil
}

// newID mints a response id in the family's own shape. Random rather than
// derived from anything in the request: an id derived from content would be a
// (weak) channel back out of the trust boundary, and ids are only ever used by
// clients for correlation.
//
// crypto/rand.Read cannot fail on any platform this proxy supports; if it ever
// did, an empty suffix still yields a well-formed (if unhelpful) id, which is
// strictly better than failing a refusal.
func newID(prefix string) string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// -----------------------------------------------------------------------------
// Wire shapes. Plain structs with json tags — the text is always a FIELD,
// never a formatted string. See invariant 12 at the top of this file.
// -----------------------------------------------------------------------------

type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatChoice struct {
	Index        int               `json:"index"`
	Message      openAIChatMessage `json:"message"`
	FinishReason string            `json:"finish_reason"`
}

type openAIChatCompletion struct {
	ID      string             `json:"id"`
	Object  string             `json:"object"`
	Created int64              `json:"created"`
	Model   string             `json:"model"`
	Choices []openAIChatChoice `json:"choices"`
	Usage   openAIUsage        `json:"usage"`
}

type openAIChatDelta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

type openAIChatChunkChoice struct {
	Index int             `json:"index"`
	Delta openAIChatDelta `json:"delta"`
	// Pointer so the non-final chunks emit `"finish_reason":null` rather than
	// `""` — an empty string is not a legal finish_reason and strict clients
	// reject it, while null is what the real wire sends.
	FinishReason *string `json:"finish_reason"`
}

type openAIChatChunk struct {
	ID      string                  `json:"id"`
	Object  string                  `json:"object"`
	Created int64                   `json:"created"`
	Model   string                  `json:"model"`
	Choices []openAIChatChunkChoice `json:"choices"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type anthropicTextBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicMessage struct {
	ID      string               `json:"id"`
	Type    string               `json:"type"`
	Role    string               `json:"role"`
	Model   string               `json:"model"`
	Content []anthropicTextBlock `json:"content"`
	// Omitted on message_start (the message has not stopped yet) and set to
	// "refusal" on the non-streaming body. Anthropic's own wire omits it rather
	// than sending null inside message_start.
	StopReason   string         `json:"stop_reason,omitempty"`
	StopSequence *string        `json:"stop_sequence"`
	Usage        anthropicUsage `json:"usage"`
}

type anthropicStreamMessageStart struct {
	Type    string           `json:"type"`
	Message anthropicMessage `json:"message"`
}

type anthropicStreamBlockStart struct {
	Type         string             `json:"type"`
	Index        int                `json:"index"`
	ContentBlock anthropicTextBlock `json:"content_block"`
}

type anthropicTextDelta struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicStreamBlockDelta struct {
	Type  string             `json:"type"`
	Index int                `json:"index"`
	Delta anthropicTextDelta `json:"delta"`
}

type anthropicStreamBlockStop struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
}

type anthropicMessageDeltaBody struct {
	StopReason   string  `json:"stop_reason"`
	StopSequence *string `json:"stop_sequence"`
}

type anthropicStreamMessageDelta struct {
	Type  string                    `json:"type"`
	Delta anthropicMessageDeltaBody `json:"delta"`
	Usage anthropicUsage            `json:"usage"`
}

type anthropicStreamMessageStop struct {
	Type string `json:"type"`
}

type responsesIncompleteDetails struct {
	Reason string `json:"reason"`
}

type responsesOutputText struct {
	Type        string `json:"type"`
	Text        string `json:"text"`
	Annotations []any  `json:"annotations"`
}

type responsesOutputItem struct {
	Type    string                `json:"type"`
	ID      string                `json:"id"`
	Status  string                `json:"status"`
	Role    string                `json:"role"`
	Content []responsesOutputText `json:"content"`
}

type responsesUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

type openAIResponsesResponse struct {
	ID                string                      `json:"id"`
	Object            string                      `json:"object"`
	CreatedAt         int64                       `json:"created_at"`
	Status            string                      `json:"status"`
	IncompleteDetails *responsesIncompleteDetails `json:"incomplete_details"`
	Model             string                      `json:"model"`
	Output            []responsesOutputItem       `json:"output"`
	Usage             *responsesUsage             `json:"usage"`
}

type responsesStreamResponseEvent struct {
	Type           string                  `json:"type"`
	SequenceNumber int                     `json:"sequence_number"`
	Response       openAIResponsesResponse `json:"response"`
}

type responsesStreamItemEvent struct {
	Type           string              `json:"type"`
	SequenceNumber int                 `json:"sequence_number"`
	OutputIndex    int                 `json:"output_index"`
	Item           responsesOutputItem `json:"item"`
}

type responsesStreamPartEvent struct {
	Type           string              `json:"type"`
	SequenceNumber int                 `json:"sequence_number"`
	ItemID         string              `json:"item_id"`
	OutputIndex    int                 `json:"output_index"`
	ContentIndex   int                 `json:"content_index"`
	Part           responsesOutputText `json:"part"`
}

type responsesStreamTextDelta struct {
	Type           string `json:"type"`
	SequenceNumber int    `json:"sequence_number"`
	ItemID         string `json:"item_id"`
	OutputIndex    int    `json:"output_index"`
	ContentIndex   int    `json:"content_index"`
	Delta          string `json:"delta"`
}

type responsesStreamTextDone struct {
	Type           string `json:"type"`
	SequenceNumber int    `json:"sequence_number"`
	ItemID         string `json:"item_id"`
	OutputIndex    int    `json:"output_index"`
	ContentIndex   int    `json:"content_index"`
	Text           string `json:"text"`
}
