package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
)

// chat_completions_bridge_sse.go — the streaming half of the bridge.
//
// Framing lives here, dialect lives in the translator pair. This file only
// decides where one SSE frame ends and hands its `data:` payload to
// ConvertStreamChunk; it knows nothing about what the events mean. That split
// is what lets the App pipeline reuse the same pair later without inheriting
// this file's IO.
//
// # Placement
//
// Wrapped OUTSIDE the stream drainer AND outside the placeholder restorer, so:
//
//   - the drainer's token extraction still reads upstream-native Responses
//     frames (usage and billing untouched — bridge invariant 3), and
//   - the placeholder restorer still sees the Responses dialect it was written
//     and tested against (it recognizes response.output_text.delta explicitly).
//
// Everything downstream of this wrapper is Chat Completions; everything
// upstream of it is Responses. One boundary, not two.
//
// # Latency
//
// Frame-granular, like sseModelRewriter and ssePlaceholderRestorer: a frame is
// converted and released as soon as its terminating blank line arrives, so the
// added delay is at most one frame's assembly. The stream is never buffered
// whole — that would turn streaming into a slow non-streaming request, which
// is the entire reason agent clients stream in the first place.

// sseChatCompletionsBridge converts an upstream Responses SSE stream into a
// Chat Completions SSE stream as it is read.
type sseChatCompletionsBridge struct {
	upstream io.ReadCloser
	state    *translator.StreamState
	from, to translator.Format
	logger   *slog.Logger
	ctx      context.Context

	buf   bytes.Buffer // raw bytes not yet assembled into a complete frame
	frame []byte       // current frame's complete lines
	out   bytes.Buffer // converted bytes ready for the client

	upstrErr error
	eofSeen  bool
}

// newSSEChatCompletionsBridge wraps body when the bridge is armed for this
// request AND the upstream actually sent an event stream. Otherwise it returns
// body unchanged.
//
// # Why contentType decides this, and why it is not optional
//
// Whether the response leg streams is decided from the REQUEST (`"stream":true`
// in the body — isStreamingRequest), so a request that asked to stream takes
// the streaming path no matter what came back. Two common cases come back NOT
// as SSE:
//
//   - an upstream ERROR. 4xx/5xx bodies are JSON, and nothing above this point
//     returns early for them.
//   - a relay that ignores `stream:true` and answers with one whole JSON body.
//
// A frame reader finds no `data:` lines in either, so wrapping them
// unconditionally DROPS the entire body and hands the client zero bytes — the
// answer, or the reason it failed, silently gone while usage is still billed
// (the drainer read it upstream of here). Every other wrapper in this chain is
// a verbatim pass-through when it has nothing to do; this one has to be too.
func newSSEChatCompletionsBridge(ctx context.Context, body io.ReadCloser, contentType string, logger *slog.Logger) io.ReadCloser {
	st := bridgeFromContext(ctx)
	if st == nil {
		return body
	}
	if !strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		if logger != nil {
			logger.Warn("dialect bridge: upstream answered a streaming request without an event stream; forwarding it untranslated",
				"event.name", observability.EventProxyBridgeTranslateFailed,
				"content_type", contentType,
			)
		}
		return body
	}
	return &sseChatCompletionsBridge{
		upstream: body,
		state:    st.stream,
		from:     st.from,
		to:       st.to,
		logger:   logger,
		ctx:      ctx,
	}
}

func (b *sseChatCompletionsBridge) Read(p []byte) (int, error) {
	if b.out.Len() > 0 {
		return b.out.Read(p)
	}
	if b.eofSeen {
		if b.upstrErr != nil {
			return 0, b.upstrErr
		}
		return 0, io.EOF
	}
	tmp := make([]byte, 32*1024)
	for b.out.Len() == 0 {
		n, err := b.upstream.Read(tmp)
		if n > 0 {
			b.buf.Write(tmp[:n])
			b.assembleFrames()
		}
		if err != nil {
			b.eofSeen = true
			if err != io.EOF {
				b.upstrErr = err
			}
			// A trailing frame with no terminating blank line is still a
			// frame's worth of the model's answer. Convert it rather than
			// dropping it, so a stream that ends abruptly loses at most the
			// bytes the upstream never sent.
			if len(b.frame) > 0 {
				b.processFrame(b.frame)
				b.frame = nil
			}
			b.buf.Reset()
			// Close the turn if the upstream never did. Both dialects have a
			// mandatory terminator and a client that does not receive one waits
			// on a connection that has already closed. No-op when the stream
			// ended properly — the pair's flush is idempotent with its own
			// terminal path.
			b.flush()
			break
		}
	}
	if b.out.Len() > 0 {
		return b.out.Read(p)
	}
	if b.upstrErr != nil {
		return 0, b.upstrErr
	}
	return 0, io.EOF
}

func (b *sseChatCompletionsBridge) Close() error { return b.upstream.Close() }

// assembleFrames moves complete lines from buf into the current frame and
// converts each frame when its terminating blank line arrives.
func (b *sseChatCompletionsBridge) assembleFrames() {
	for {
		raw := b.buf.Bytes()
		idx := bytes.IndexByte(raw, '\n')
		if idx < 0 {
			return
		}
		line := make([]byte, idx+1)
		copy(line, raw[:idx+1])
		b.buf.Next(idx + 1)
		b.frame = append(b.frame, line...)
		if isBlankSSELine(line) {
			frame := b.frame
			b.frame = nil
			b.processFrame(frame)
		}
	}
}

// processFrame converts one assembled frame and appends the result to out.
//
// A frame the pair cannot parse is DROPPED with a WARN rather than forwarded.
// Forwarding it would hand a Responses-shaped payload to a client parsing
// every `data:` line as a chat.completion.chunk: SDKs either throw or
// deserialize it into an empty chunk and count it as real content. Dropping
// costs those bytes; forwarding corrupts the stream. Per
// principles/logging-conventions.md the drop is never silent.
func (b *sseChatCompletionsBridge) processFrame(frame []byte) {
	payload, ok := sseAnyDataPayload(frame)
	if !ok {
		// Comments, `event:`-only frames and keep-alive pings carry no data
		// line. They have no Chat Completions counterpart and no content.
		return
	}
	reg := translator.DefaultRegistry()
	chunks, tErr := reg.TranslateStreamChunk(b.ctx, b.from, b.to, b.state, payload)
	if tErr != nil {
		if b.logger != nil {
			b.logger.Warn("chat-completions bridge: dropped an untranslatable SSE frame",
				"event.name", observability.EventProxyBridgeTranslateFailed,
				"error.code", tErr.Code,
				"error.message", tErr.Message,
				"frame_len", len(frame),
			)
		}
		return
	}
	b.writeChunks(chunks)
}

// sseAnyDataPayload returns the payload of a frame's `data:` line.
//
// Deliberately NOT sseDataPayload (sse_restore.go): that one returns ok=false
// for anything not starting with '{', which excludes the `[DONE]` sentinel.
// The bridge must see [DONE] — it is how the pair knows an upstream already
// terminated the stream and suppresses its own duplicate terminator.
func sseAnyDataPayload(frame []byte) ([]byte, bool) {
	for start := 0; start < len(frame); {
		nl := bytes.IndexByte(frame[start:], '\n')
		end := len(frame)
		if nl >= 0 {
			end = start + nl + 1
		}
		trimmed := bytes.TrimRight(frame[start:end], "\r\n")
		switch {
		case bytes.HasPrefix(trimmed, []byte("data: ")):
			return trimmed[len("data: "):], true
		case bytes.HasPrefix(trimmed, []byte("data:")):
			// Some providers omit the space the SSE spec makes optional.
			return trimmed[len("data:"):], true
		}
		start = end
	}
	return nil, false
}

// flush asks the pair for any closing frames and appends them to out.
func (b *sseChatCompletionsBridge) flush() {
	chunks, tErr := translator.DefaultRegistry().FlushStream(b.ctx, b.from, b.to, b.state)
	if tErr != nil {
		if b.logger != nil {
			b.logger.Warn("dialect bridge: could not close an interrupted stream",
				"event.name", observability.EventProxyBridgeTranslateFailed,
				"error.code", tErr.Code,
			)
		}
		return
	}
	b.writeChunks(chunks)
}

// writeChunks renders converted payloads as SSE frames.
//
// A dialect whose clients register per-event listeners (the Responses API is
// one) delivers NOTHING to them without the `event:` line, so the name is asked
// of the pair rather than assumed absent. Dialects that stream unnamed frames
// (Chat Completions, Anthropic) return "" and the frame is written bare.
func (b *sseChatCompletionsBridge) writeChunks(chunks [][]byte) {
	reg := translator.DefaultRegistry()
	for _, c := range chunks {
		if name := reg.StreamEventName(b.from, b.to, c); name != "" {
			b.out.WriteString("event: ")
			b.out.WriteString(name)
			b.out.WriteString("\n")
		}
		b.out.WriteString("data: ")
		b.out.Write(c)
		b.out.WriteString("\n\n")
	}
}
