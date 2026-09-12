package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/tidwall/gjson"
)

// chat_completions_bridge_destream.go — answering a non-streaming client from
// an upstream that only streams.
//
// # The problem
//
// The Codex backend serves ONLY stream:true. This is measured, not assumed:
// the 2026-09-10 shape matrix (workflow/CI/research/codex-shape-matrix-2026-09,
// rows results/20260910T021253Z.tsv) sent 25 shapes through a live account and
// cells S03, S06 and S07 — stream:false, and stream absent — all came back
// 400 "Stream must be set to true".
//
// That collides with the whole point of the dialect bridge. The bridge exists
// to let Chat Completions clients use a ChatGPT OAuth credential, and the most
// common call in that entire ecosystem is the non-streaming one:
//
//	client.chat.completions.create(model=..., messages=[...])   # no stream=True
//
// Worse, Go's `json:"stream,omitempty"` means such a request translates to a
// Responses body with NO stream field at all — cell S07, the same 400.
//
// # What this does
//
// The request leg sends stream:true upstream regardless (translateRequestLeg,
// keyed on the destination being Codex). This file is the other half: it reads
// the whole event stream, takes the `response` object out of the terminal
// `response.completed` event, and translates that one object back to a
// non-streaming Chat Completions body. The client is answered in exactly the
// shape it asked for and never learns the hop streamed.
//
// No delta concatenation is involved, and that is not an optimisation: the
// `response.completed` event carries the FINAL assembled `output` and `usage`,
// so rebuilding the text from response.output_text.delta frames would be a
// second, weaker implementation of something the backend already sent us.
//
// # Why this is a lazy reader rather than an eager read in ModifyResponse
//
// Reading the body eagerly would let us set a proper status code when a stream
// ends without its completed event. It would also move WHEN the body is
// consumed relative to the stream drainer, which is what extracts usage and
// bills the request. Bridge invariant 3 says a defect here may corrupt what a
// client reads but must never change what is billed, and that property holds by
// construction only while this stays a pass-through reader wrapped outside the
// drainer. So an interrupted stream is reported in the body (and loudly in the
// log) rather than in the status line — the cheaper of the two failures.

// deStreamCompletedEvent is the terminal event whose payload carries the
// finished response. Codex emits it as the last event before the stream closes.
const (
	deStreamCompletedEvent = "response.completed"
	// deStreamDeltaEvent carries the text a streaming client actually renders.
	deStreamDeltaEvent = "response.output_text.delta"
	// deStreamItemDoneEvent carries each finished output item — message, reasoning,
	// function_call — as the upstream completes it. The real Codex backend sends its
	// function calls ONLY here: response.completed arrives with "output": [].
	deStreamItemDoneEvent = "response.output_item.done"
)

// newBridgedStreamingBody is the ONE client-facing wrapper for a bridged
// streaming upstream: it picks between frame-granular translation (the client
// asked to stream) and de-streaming (it did not), and adjusts resp's headers
// when the wire form changes underneath them.
//
// Returns body untouched when the bridge did not engage.
func newBridgedStreamingBody(
	ctx context.Context, resp *http.Response, body io.ReadCloser, logger *slog.Logger,
) io.ReadCloser {
	st := bridgeFromContext(ctx)
	contentType := resp.Header.Get("Content-Type")
	// 🔴 An ABSENT Content-Type is not the same statement as a non-SSE one.
	//
	// Both wrappers below decide "is this an event stream?" from Content-Type,
	// and for a header that is present that stays right: an explicit
	// application/json is an error envelope or a relay that ignored stream:true,
	// and must be forwarded verbatim. But the real ChatGPT Codex backend, reached
	// through the cluster worker's group lane, answers its event stream with NO
	// Content-Type header at all (measured on master2 staging 2026-09-11: the
	// worker logged content_type="" on every bridge_translate_failed event while
	// the body was a complete response.created → response.completed stream).
	// Treating absence as "not SSE" forwarded every bridged response untranslated:
	// a Chat Completions client received raw Responses frames, a non-streaming
	// client received an event stream instead of one JSON body. Every local test
	// missed it because every mock politely set text/event-stream.
	//
	// So only when the bridge is armed AND the header is absent, look at the first
	// bytes. Unarmed responses are never touched (switch-off stays byte-identical),
	// and an explicit Content-Type remains authoritative.
	// Bugfix: workflow/CI/bugfix/2026-09-11-bridge-sse-without-content-type.md
	// Fences: TestDeStream_CodexStreamWithoutContentTypeIsStillCollapsed,
	//         TestBridge_StreamingClientGetsFramesWhenUpstreamOmitsContentType,
	//         TestBridge_ContentTypeLessJSONErrorIsForwardedVerbatim,
	//         TestBridge_ExplicitJSONContentTypeIsAuthoritative,
	//         TestBridge_UnarmedResponseWithoutContentTypeIsUntouched
	if st != nil && strings.TrimSpace(contentType) == "" {
		var isSSE bool
		isSSE, body = sniffEventStream(body)
		if isSSE {
			contentType = "text/event-stream"
			resp.Header.Set("Content-Type", contentType)
			if logger != nil {
				logger.Info("dialect bridge: upstream sent an event stream without a Content-Type; treating it as one",
					"event.name", observability.EventProxyBridgeContentTypeSniffed,
					"de_streamed", st.deStream,
				)
			}
		}
	}
	if st == nil || !st.deStream {
		return newSSEChatCompletionsBridge(ctx, body, contentType, logger)
	}
	// Not an event stream: an upstream error envelope, or a relay that ignored
	// stream:true. Either way there are no frames to collapse, and consuming it
	// as if there were would hand the client zero bytes — the same defect the
	// sibling wrapper documents. Forward it verbatim, headers untouched.
	if !strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		if logger != nil {
			logger.Warn("dialect bridge: de-streamed request did not get an event stream; forwarding it untranslated",
				"event.name", observability.EventProxyBridgeTranslateFailed,
				"content_type", contentType,
			)
		}
		return body
	}
	// The wire form changes here, so the headers describing it have to change
	// with it. Content-Length would be the UPSTREAM's count for a body we are
	// about to replace, and its length is not knowable until the stream ends.
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Del("Content-Length")
	resp.Header.Del("Transfer-Encoding")
	resp.ContentLength = -1
	return &sseDeStreamer{upstream: body, ctx: ctx, logger: logger}
}

// sseFieldPrefixes are the ways a text/event-stream body can open: a field name
// followed by a colon, or a comment line that begins with the colon itself.
var sseFieldPrefixes = [][]byte{
	[]byte("event:"), []byte("data:"), []byte("id:"), []byte("retry:"), []byte(":"),
}

// sniffEventStream reports whether body opens like an event stream and returns a
// reader that still yields every byte — nothing peeked is consumed.
//
// It waits for exactly ONE upstream read, not for a fixed number of bytes: a
// stream that opens with a short keep-alive and then pauses must not have its
// first bytes held back while a larger peek window fills. A first chunk that is
// only whitespace classifies as not-SSE, which is the pre-existing verbatim
// forward, i.e. the safe default.
func sniffEventStream(body io.ReadCloser) (bool, io.ReadCloser) {
	br := bufio.NewReaderSize(body, 4096)
	if _, err := br.Peek(1); err != nil {
		return false, struct {
			io.Reader
			io.Closer
		}{br, body}
	}
	head, _ := br.Peek(br.Buffered())
	head = bytes.TrimLeft(head, "\ufeff \t\r\n")
	isSSE := false
	for _, prefix := range sseFieldPrefixes {
		if bytes.HasPrefix(head, prefix) {
			isSSE = true
			break
		}
	}
	return isSSE, struct {
		io.Reader
		io.Closer
	}{br, body}
}

// sseDeStreamer collapses a Responses event stream into one Chat Completions
// body on first read.
type sseDeStreamer struct {
	upstream io.ReadCloser
	ctx      context.Context
	logger   *slog.Logger

	out  bytes.Buffer
	done bool
	err  error
}

func (d *sseDeStreamer) Read(p []byte) (int, error) {
	if !d.done {
		d.collapse()
		d.done = true
	}
	if d.out.Len() > 0 {
		return d.out.Read(p)
	}
	if d.err != nil {
		return 0, d.err
	}
	return 0, io.EOF
}

func (d *sseDeStreamer) Close() error { return d.upstream.Close() }

// collapse drains the stream and fills out with the client-facing body.
func (d *sseDeStreamer) collapse() {
	stream, readErr := readCompletedResponse(d.upstream)
	completed, outputSource := fillOutput(stream)

	if completed == nil {
		// The stream ended without its terminal event: upstream cut off, or a
		// mid-stream error frame. Say so in the body — a client that gets 200
		// and an unparseable completion has no way to tell this from a bug in
		// its own code.
		reason := "the upstream event stream ended without a " + deStreamCompletedEvent + " event"
		if readErr != nil {
			reason += " (" + readErr.Error() + ")"
		}
		if d.logger != nil {
			d.logger.Error("dialect bridge: de-stream found no completed event",
				"event.name", observability.EventProxyBridgeTranslateFailed,
				"error.code", "BRIDGE_DESTREAM_INCOMPLETE",
				"error.message", reason,
			)
		}
		d.out.Write([]byte(`{"error":{"type":"server_error","code":"BRIDGE_DESTREAM_INCOMPLETE","message":"` +
			jsonEscapeForError("AiKey could not assemble a non-streaming answer: "+reason+
				". The request was served and billed upstream; retry, or send stream:true to receive the "+
				"answer as it is produced.") + `"}}`))
		return
	}

	// Same reversal the non-streaming leg performs, on the same pair — the
	// terminal event's `response` object IS a complete Responses response.
	body, tErr := translateBridgedResponse(d.ctx, completed, d.logger)
	if tErr != nil {
		d.out.Write([]byte(`{"error":{"type":"server_error","code":"` + tErr.Code +
			`","message":"` + jsonEscapeForError(tErr.Message) + `"}}`))
		return
	}
	d.out.Write(body)
	if d.logger != nil {
		if outputSource == deStreamOutputNone {
			// 🔴 Loud on purpose. The stream completed but carried neither a message
			// nor a tool call, so the client is about to receive 200 with an empty
			// answer — indistinguishable, from its side, from a model that chose to
			// say nothing. Until 2026-09-11 exactly this happened silently to every
			// non-streaming tool call on the Codex backend.
			// Bugfix: workflow/CI/bugfix/2026-09-11-bridge-destream-drops-tool-calls.md
			d.logger.Warn("dialect bridge: de-streamed answer carries no message or tool call",
				"event.name", observability.EventProxyBridgeEngaged,
				"bytes", len(body),
				"output_source", outputSource,
			)
			return
		}
		d.logger.Info("dialect bridge: de-streamed upstream answer for a non-streaming client",
			"event.name", observability.EventProxyBridgeEngaged,
			"bytes", len(body),
			"output_source", outputSource,
		)
	}
}

// collapsedStream is everything one upstream event stream contributes to a
// single non-streaming answer. fillOutput decides which part is authoritative.
type collapsedStream struct {
	envelope  []byte            // `response` of the last response.completed event (nil when absent)
	doneItems []json.RawMessage // `item` of every response.output_item.done, ordered by output_index
	deltaText string            // concatenated response.output_text.delta text
}

// indexedItem keeps an output item with its position while the stream is read.
type indexedItem struct {
	index int64
	raw   json.RawMessage
}

// readCompletedResponse scans an SSE stream and returns the `response` object
// from the last completed event (or nil), every finished output item, and the
// text assembled from the delta frames.
//
// 🔴 Why output items are collected (2026-09-11): the real ChatGPT Codex backend
// sends a function call ONLY as a response.output_item.done event; its
// response.completed carries "output": []. Reading just the completed event and
// the text deltas threw every tool call away, so a non-streaming client got
// 200, empty content, no tool_calls and finish_reason "stop" — silently, while
// a streaming client asking the same question got the call.
// Bugfix: workflow/CI/bugfix/2026-09-11-bridge-destream-drops-tool-calls.md
// Fences: TestDeStream_RealCodexToolCallSurvivesCollapse, TestDeStream_FillOutputPrecedence
//
// Frames are accumulated rather than matched line-by-line because SSE permits a
// payload to span several `data:` lines; a line-wise reader silently truncates
// exactly the large responses this is most useful for.
func readCompletedResponse(r io.Reader) (stream collapsedStream, err error) {
	var found []byte
	var deltas strings.Builder
	var items []indexedItem
	var data bytes.Buffer

	flush := func() {
		if data.Len() == 0 {
			return
		}
		payload := data.Bytes()
		switch gjson.GetBytes(payload, "type").String() {
		case deStreamCompletedEvent:
			if resp := gjson.GetBytes(payload, "response"); resp.Exists() {
				found = []byte(resp.Raw)
			}
		case deStreamDeltaEvent:
			deltas.WriteString(gjson.GetBytes(payload, "delta").String())
		case deStreamItemDoneEvent:
			if item := gjson.GetBytes(payload, "item"); item.IsObject() {
				items = append(items, indexedItem{
					index: gjson.GetBytes(payload, "output_index").Int(),
					raw:   json.RawMessage(item.Raw),
				})
			}
		}
		data.Reset()
	}

	sc := bufio.NewScanner(r)
	// Responses payloads carry the whole assembled answer, so the default 64KB
	// line cap is far too small: a long completion arrives as one `data:` line.
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			flush()
			continue
		}
		if v, ok := strings.CutPrefix(line, "data:"); ok {
			data.WriteString(strings.TrimPrefix(v, " "))
		}
	}
	flush() // a final frame with no terminating blank line is still a frame
	sort.SliceStable(items, func(i, j int) bool { return items[i].index < items[j].index })
	stream = collapsedStream{envelope: found, deltaText: deltas.String(), doneItems: make([]json.RawMessage, 0, len(items))}
	for _, it := range items {
		stream.doneItems = append(stream.doneItems, it.raw)
	}
	return stream, sc.Err()
}

// Where a collapsed answer came from — logged per request as output_source.
const (
	deStreamOutputEnvelope       = "envelope"
	deStreamOutputItems          = "output_items"
	deStreamOutputItemsAndDeltas = "output_items+deltas"
	deStreamOutputDeltas         = "deltas"
	deStreamOutputNone           = "none"
)

// deStreamAnswerItemTypes are the output item types that ARE an answer. A
// reasoning item on its own is not: a client handed only reasoning got nothing.
var deStreamAnswerItemTypes = map[string]bool{
	"message":          true,
	"function_call":    true,
	"custom_tool_call": true,
}

// fillOutput makes the collapsed envelope carry the answer, choosing in order:
//
//  1. the envelope's own `output`, when it already holds a message or tool call.
//     An upstream that sends a finished output array keeps ITS structure;
//  2. the response.output_item.done items — the only place the Codex backend
//     puts a function call, and a complete message when it sends one. A message
//     rebuilt from the text deltas is appended when no message item arrived;
//  3. the text deltas alone (an upstream that streams text but no items).
//
// Why the deltas stay authoritative for text (2026-09-10, found by the E2E): a
// STREAMING client's answer is the concatenation of the delta frames, so reading
// only the envelope made the non-streaming answer depend on an upstream property
// the streaming client never depended on — one of them came back empty.
//
// Why output items come before the deltas (2026-09-11, found on staging): a
// tool call has no text delta at all. Deltas-only rebuilt a message and dropped
// the call; items carry both the call and the message.
// Bugfix: workflow/CI/bugfix/2026-09-11-bridge-destream-drops-tool-calls.md
func fillOutput(s collapsedStream) (body []byte, source string) {
	if s.envelope == nil {
		return nil, deStreamOutputNone
	}
	if gjson.GetBytes(s.envelope, "output_text").Exists() || resultsCarryAnswer(gjson.GetBytes(s.envelope, "output").Array()) {
		return s.envelope, deStreamOutputEnvelope
	}
	items := make([]json.RawMessage, 0, len(s.doneItems)+1)
	items = append(items, s.doneItems...)
	source = deStreamOutputItems
	if !rawItemsContainType(s.doneItems, "message") && s.deltaText != "" {
		text, err := json.Marshal(s.deltaText)
		if err != nil {
			return s.envelope, deStreamOutputNone
		}
		items = append(items, json.RawMessage(`{"type":"message","role":"assistant","content":[{"type":"output_text","text":`+string(text)+`}]}`))
		source = deStreamOutputItemsAndDeltas
		if len(s.doneItems) == 0 {
			source = deStreamOutputDeltas
		}
	}
	if !rawItemsCarryAnswer(items) {
		return s.envelope, deStreamOutputNone
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(s.envelope, &envelope); err != nil || envelope == nil {
		return s.envelope, deStreamOutputNone
	}
	output, err := json.Marshal(items)
	if err != nil {
		return s.envelope, deStreamOutputNone
	}
	envelope["output"] = output
	merged, err := json.Marshal(envelope)
	if err != nil {
		return s.envelope, deStreamOutputNone
	}
	return merged, source
}

func resultsCarryAnswer(items []gjson.Result) bool {
	for _, it := range items {
		if deStreamAnswerItemTypes[it.Get("type").String()] {
			return true
		}
	}
	return false
}

func rawItemsCarryAnswer(items []json.RawMessage) bool {
	for _, it := range items {
		if deStreamAnswerItemTypes[gjson.GetBytes(it, "type").String()] {
			return true
		}
	}
	return false
}

func rawItemsContainType(items []json.RawMessage, typ string) bool {
	for _, it := range items {
		if gjson.GetBytes(it, "type").String() == typ {
			return true
		}
	}
	return false
}
