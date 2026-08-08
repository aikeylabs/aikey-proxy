// sse_restore.go — B3 streaming placeholder restoration (SSE 滑窗跨 chunk 还原).
//
// Restores numbered mask placeholders (e.g. "[地址#1(已隐藏)]") back to the
// user's original text inside a streaming LLM response. This is the streaming
// half of the ONLY sanctioned response-direction rewrite (spec 2026-06-04
// 合规过滤方向 规则 2 唯一例外); the non-streaming half is
// restoreMaskedResponseBody (filter_restore.go).
//
// Design — frame-buffered + cross-frame text holdback:
//
//   - The stream is processed at SSE FRAME granularity (lines until a blank
//     line), mirroring sseModelRewriter's line discipline: a frame is emitted
//     as soon as its terminating blank line arrives, so added latency is at
//     most one frame's assembly — no full-stream buffering ever.
//   - Placeholders live inside the JSON text-delta fields and, because LLMs
//     stream token-sized deltas, a placeholder ROUTINELY spans multiple delta
//     frames. A raw byte-window over the wire could never match those (SSE/JSON
//     framing bytes sit between the halves), so the sliding window operates on
//     the DECODED text channel: each text frame's delta is prepended with the
//     held-back carry, replaced, and the longest suffix that could still be a
//     placeholder prefix (window = 最长占位符长度-1, st.holdback) is withheld
//     until the next frame.
//   - Withheld text is never lost: on the next text frame it is prepended; on
//     a NON-text frame (content_block_stop, message_delta, [DONE], …) or EOF it
//     is flushed FIRST as a synthesized text-delta frame cloned from the last
//     text frame (same index/框架 → SSE 帧结构与事件顺序保持合法), so the
//     client receives every byte in order before the boundary event.
//   - Recognized text channels: Anthropic content_block_delta text/thinking
//     deltas and OpenAI chat-completions choices.0.delta.content. Frames of any
//     other shape pass through byte-verbatim (with a carry flush before them);
//     placeholders split across frames of unrecognized shapes are NOT restored
//     (fail-open: the client sees the placeholder — degraded, never corrupted).
//
// Placement: wrapped OUTSIDE the streamDrainer (client-facing side only), so
// token extraction and the conversation-audit observer keep seeing the MASKED
// placeholders — the restored originals exist only on the wire back to the
// user, mirroring the request side where audit sees the masked prompt. The
// per-request mapping itself is memory-only and never logged (B3 拍板).
package proxy

import (
	"bytes"
	"io"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ssePlaceholderRestorer implements the frame-buffered restore. Mirrors the
// Read/Close skeleton of sseModelRewriter (line-buffered, no full-stream
// buffering, upstream error replay after pending output drains).
type ssePlaceholderRestorer struct {
	upstream io.ReadCloser
	st       *maskRestore
	upstrErr error

	buf   bytes.Buffer // raw bytes not yet assembled into a complete frame
	frame []byte       // current frame's assembled lines (complete lines only)
	out   bytes.Buffer // processed bytes ready for the client

	carry string // decoded text withheld because it may be a placeholder prefix

	// template is a byte copy of the last recognized text frame + the gjson
	// path of its text field — the cloning base for carry-flush synthesis.
	template     []byte
	templatePath string

	eofSeen bool
}

// newSSEPlaceholderRestorer wraps body; returns body unchanged when there is
// nothing to restore (nil state), so the common path pays a single nil check.
func newSSEPlaceholderRestorer(body io.ReadCloser, st *maskRestore) io.ReadCloser {
	if st == nil || len(st.keys) == 0 {
		return body
	}
	return &ssePlaceholderRestorer{upstream: body, st: st}
}

func (r *ssePlaceholderRestorer) Read(p []byte) (int, error) {
	if r.out.Len() > 0 {
		return r.out.Read(p)
	}
	if r.eofSeen {
		if r.upstrErr != nil {
			return 0, r.upstrErr
		}
		return 0, io.EOF
	}
	tmp := make([]byte, 32*1024)
	for r.out.Len() == 0 {
		n, err := r.upstream.Read(tmp)
		if n > 0 {
			r.buf.Write(tmp[:n])
			r.assembleFrames()
		}
		if err != nil {
			r.eofSeen = true
			if err != io.EOF {
				r.upstrErr = err
			}
			// Stream over: withheld text first (order-preserving), then any
			// incomplete trailing lines verbatim.
			r.flushCarry()
			if len(r.frame) > 0 {
				r.out.Write(r.frame)
				r.frame = nil
			}
			if r.buf.Len() > 0 {
				r.out.Write(r.buf.Bytes())
				r.buf.Reset()
			}
			break
		}
	}
	if r.out.Len() > 0 {
		return r.out.Read(p)
	}
	if r.upstrErr != nil {
		return 0, r.upstrErr
	}
	return 0, io.EOF
}

func (r *ssePlaceholderRestorer) Close() error { return r.upstream.Close() }

// assembleFrames moves complete lines from buf into the current frame and
// processes each frame when its terminating blank line arrives.
func (r *ssePlaceholderRestorer) assembleFrames() {
	for {
		raw := r.buf.Bytes()
		idx := bytes.IndexByte(raw, '\n')
		if idx < 0 {
			return
		}
		line := make([]byte, idx+1)
		copy(line, raw[:idx+1])
		r.buf.Next(idx + 1)
		r.frame = append(r.frame, line...)
		if isBlankSSELine(line) {
			frame := r.frame
			r.frame = nil
			r.processFrame(frame)
		}
	}
}

func isBlankSSELine(line []byte) bool {
	for _, c := range line {
		if c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

// processFrame rewrites a text-delta frame (carry + replace + holdback) or
// passes any other frame through verbatim after flushing pending carry.
func (r *ssePlaceholderRestorer) processFrame(frame []byte) {
	payload, lineStart, lineEnd, ok := sseDataPayload(frame)
	if ok {
		if path := sseTextFieldPath(payload); path != "" {
			text := gjson.GetBytes(payload, path).String()
			combined := r.carry + text
			replaced := r.st.restore(combined)
			hold := r.st.holdback(replaced)
			// Passthrough fast path: no pending carry, nothing replaced, nothing
			// to hold → the frame is untouched, forward the upstream bytes
			// verbatim (keeps placeholder-free traffic byte-identical instead of
			// re-encoding through sjson). Template still updates so a later
			// carry flush can clone this frame's shape.
			if r.carry == "" && hold == "" && replaced == combined {
				r.template = bytes.Clone(frame)
				r.templatePath = path
				r.out.Write(frame)
				return
			}
			emit := replaced[:len(replaced)-len(hold)]
			patched, err := sjson.SetBytes(bytes.Clone(payload), path, emit)
			if err == nil {
				r.carry = hold
				// Template BEFORE patching text, so a later carry flush clones the
				// frame shape (index, type, terminators) and only swaps the text.
				r.template = bytes.Clone(frame)
				r.templatePath = path
				r.out.Write(frame[:lineStart])
				r.out.Write([]byte("data: "))
				r.out.Write(patched)
				r.out.Write(frameLineTerminator(frame[lineStart:lineEnd]))
				r.out.Write(frame[lineEnd:])
				return
			}
			// sjson failure (shouldn't happen on a decoded-ok payload): forward the
			// frame untouched and keep carry unconsumed — degraded, never corrupted.
		}
	}
	// Non-text frame (or unparseable): withheld text must reach the client
	// BEFORE this boundary event to keep text order.
	r.flushCarry()
	r.out.Write(frame)
}

// flushCarry emits withheld text as a synthesized clone of the last text frame.
// No template can only happen if carry is empty (carry is only ever set by a
// successfully processed text frame, which also sets the template).
func (r *ssePlaceholderRestorer) flushCarry() {
	if r.carry == "" || len(r.template) == 0 {
		r.carry = ""
		return
	}
	payload, lineStart, lineEnd, ok := sseDataPayload(r.template)
	if !ok {
		r.carry = ""
		return
	}
	patched, err := sjson.SetBytes(bytes.Clone(payload), r.templatePath, r.carry)
	r.carry = ""
	if err != nil {
		return
	}
	r.out.Write(r.template[:lineStart])
	r.out.Write([]byte("data: "))
	r.out.Write(patched)
	r.out.Write(frameLineTerminator(r.template[lineStart:lineEnd]))
	r.out.Write(r.template[lineEnd:])
}

// sseDataPayload finds the first `data:` line of a frame. Returns the JSON
// payload (without prefix/terminators) plus the line's [start,end) offsets in
// the frame. ok=false when the frame has no JSON data line ([DONE], comments,
// event-only frames).
func sseDataPayload(frame []byte) (payload []byte, lineStart, lineEnd int, ok bool) {
	for start := 0; start < len(frame); {
		nl := bytes.IndexByte(frame[start:], '\n')
		end := len(frame)
		if nl >= 0 {
			end = start + nl + 1
		}
		line := frame[start:end]
		trimmed := bytes.TrimRight(line, "\r\n")
		var body []byte
		switch {
		case bytes.HasPrefix(trimmed, []byte("data: ")):
			body = trimmed[len("data: "):]
		case bytes.HasPrefix(trimmed, []byte("data:")):
			// Some providers omit the space (bug family: 2026 provider SSE 兼容).
			body = trimmed[len("data:"):]
		}
		if body != nil {
			if len(body) > 0 && body[0] == '{' {
				return body, start, end, true
			}
			return nil, 0, 0, false // data: [DONE] etc.
		}
		start = end
	}
	return nil, 0, 0, false
}

// frameLineTerminator returns the CR/LF suffix of a data line so the rewritten
// line re-emits byte-exact terminators.
func frameLineTerminator(line []byte) []byte {
	i := len(line)
	for i > 0 && (line[i-1] == '\n' || line[i-1] == '\r') {
		i--
	}
	return line[i:]
}

// sseTextFieldPath recognizes the streamed text channel of a data payload.
// Anthropic: content_block_delta text/thinking deltas. OpenAI chat completions:
// choices.0.delta.content. Empty string = not a text frame (pass through; a
// per-frame generic restore is deliberately NOT attempted for unknown shapes —
// without a known channel there is no sound cross-frame holdback, and a
// half-restored split placeholder is worse than an intact one).
func sseTextFieldPath(payload []byte) string {
	switch gjson.GetBytes(payload, "type").String() {
	case "content_block_delta":
		switch gjson.GetBytes(payload, "delta.type").String() {
		case "text_delta":
			return "delta.text"
		case "thinking_delta":
			return "delta.thinking"
		}
		return ""
	}
	if d := gjson.GetBytes(payload, "choices.0.delta.content"); d.Exists() && d.Type == gjson.String {
		return "choices.0.delta.content"
	}
	return ""
}
