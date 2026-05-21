package observer

import "bytes"

// SSEParser is a minimal Server-Sent-Events frame parser sized for the
// observer fan-out hot path. It is stateful: callers feed in raw bytes
// from upstream's response body via Parse(), and the parser returns
// zero-or-more complete frames per call. Partial frames at the end of
// the chunk are buffered internally and concatenated with the next
// Parse() call.
//
// Why we wrote this rather than pulling a library:
//
//  1. We need byte-identical fidelity to upstream framing — observers
//     (degrade-detector rhythm) measure timing per frame, so any
//     library-level buffering / coalescing would silently corrupt
//     timing data. Most Go SSE libraries are client-oriented and
//     batch frames or strip whitespace; this parser does neither.
//
//  2. The parser sits in the streaming hot path. A library dependency
//     would re-allocate per frame; this implementation reuses a single
//     internal buffer and copies only when emitting to the observer
//     boundary (where copy is required for payload-aliasing safety —
//     see registry.NotifySSEEvent).
//
//  3. SSE wire format is simple enough (~80 lines including tests)
//     that a focused in-house implementation is easier to audit than
//     pulling 1k+ lines of generic library code into the dependency
//     graph.
//
// Spec reference: https://html.spec.whatwg.org/multipage/server-sent-events.html
// Anthropic SSE shape (which degrade-detector consumes):
//
//	event: content_block_delta
//	data: {"type":"content_block_delta","index":0,"delta":{...}}
//	<blank line>
//
// We support the three line endings per spec (\n, \r\n, \r) and
// multi-line data fields. Comments (lines starting with ":") are
// silently dropped per spec.
//
// Concurrency: NOT safe for concurrent use. Each request gets its own
// SSEParser instance (constructed in streamDrainer when an observer
// registry is attached + ProtocolFamily is known).
type SSEParser struct {
	// buf accumulates bytes across Parse() calls; reset to zero-length
	// (without freeing underlying storage) after each Parse drains its
	// frames, so allocations amortize across the stream.
	buf []byte
}

// NewSSEParser returns a fresh parser. The initial buf capacity (8 KiB)
// is sized to hold a typical Anthropic frame (~1-2 KiB JSON) plus a
// few partial-frame remainders without resize. Streams that exceed it
// trigger a single Go append-grow; not worth pre-sizing larger.
func NewSSEParser() *SSEParser {
	return &SSEParser{buf: make([]byte, 0, 8*1024)}
}

// SSEFrame is one complete server-sent event.
//
// Data is the concatenation of all `data:` lines in the frame, joined
// by '\n' per spec (multi-line data is rare but legal — Anthropic
// emits single-line `data:` lines exclusively, but we honor the spec
// so future upstreams don't surprise us).
//
// EventType is the value of the (last) `event:` line in the frame,
// trimmed of one leading space if present (per spec). Empty when no
// `event:` line was present — observers should fall back to inferring
// from data (e.g. parse the JSON's `"type":...` field for Anthropic).
type SSEFrame struct {
	EventType string
	Data      []byte
}

// Parse feeds new bytes into the parser and returns any complete
// frames now available. The returned slice may be empty (chunk did
// not contain a frame boundary); the underlying frames' Data slices
// reference parser-owned storage — callers must copy before retaining
// across Parse() calls (the observer.Registry.NotifySSEEvent already
// does this copy for downstream fan-out, so the typical drainer path
// is correct by construction).
//
// Empty input is a no-op (returns nil). Nil input is a no-op.
func (p *SSEParser) Parse(chunk []byte) []SSEFrame {
	if len(chunk) == 0 {
		return nil
	}
	p.buf = append(p.buf, chunk...)

	var out []SSEFrame
	for {
		boundary, sepLen := findFrameBoundary(p.buf)
		if boundary < 0 {
			break
		}
		frame := p.buf[:boundary]
		if f, ok := parseFrame(frame); ok {
			out = append(out, f)
		}
		// Advance buf past the boundary. Use copy + slice-shrink so the
		// underlying allocation is reused on next append.
		remaining := p.buf[boundary+sepLen:]
		n := copy(p.buf[:cap(p.buf)], remaining)
		p.buf = p.buf[:n]
	}
	return out
}

// Reset clears any buffered partial-frame bytes. Called when the
// upstream stream ends (after which any remainder is incomplete data
// that the spec says we drop on the floor — partial frames at stream
// close don't represent real events).
//
// Idempotent. Safe to call from the drainer's deferred close path.
func (p *SSEParser) Reset() {
	p.buf = p.buf[:0]
}

// ---------------------------------------------------------------------------
// Internal helpers (unexported — tests exercise via Parse()).
// ---------------------------------------------------------------------------

// findFrameBoundary returns the index of the first end-of-frame
// separator in buf and its length, or (-1, 0) if none. SSE separates
// frames by a single blank line, which can take any of these wire
// forms (per spec):
//
//   - "\n\n"      (LF + blank LF)
//   - "\r\n\r\n"  (CRLF + blank CRLF)
//   - "\r\r"      (CR + blank CR; legacy Mac-style, rare but legal)
//   - "\n\r\n"    (mixed)
//   - "\r\n\n"    (mixed)
//
// We search for the four primary forms in order of frequency. Mixed
// forms fall through to a per-byte scan only when the primary search
// misses (very rare).
func findFrameBoundary(buf []byte) (int, int) {
	if i := bytes.Index(buf, []byte("\n\n")); i >= 0 {
		// Also check for preceding \r (CRLF before blank LF): rewind
		// one byte if so, so the boundary covers the full \r\n\n.
		if i > 0 && buf[i-1] == '\r' {
			return i - 1, 3
		}
		return i, 2
	}
	if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
		return i, 4
	}
	if i := bytes.Index(buf, []byte("\r\r")); i >= 0 {
		return i, 2
	}
	return -1, 0
}

// parseFrame splits a single frame (the slice up to but excluding the
// separator) into (eventType, data) per the SSE spec field rules:
//
//   - lines starting with ':' are comments — drop them
//   - lines with no ':' are field-name-only (value empty per spec)
//   - lines with ':' split on the first colon; if value starts with a
//     space, strip exactly one (per spec — multiple leading spaces stay)
//   - field "event" → set eventType (last wins if repeated)
//   - field "data" → append to data with '\n' separator
//   - other fields ("id", "retry", custom) are ignored at this layer
//     (observers that care can extend the parser or peek at raw bytes)
//
// Returns ok=false when the frame is entirely comments / empty —
// callers should drop these rather than emit empty SSEFrames upstream.
func parseFrame(frame []byte) (SSEFrame, bool) {
	var (
		eventType string
		data      []byte
		any       bool // any non-comment field seen
	)
	for _, line := range splitLines(frame) {
		if len(line) == 0 {
			continue // empty line inside a frame is technically not part of the spec but we tolerate it
		}
		if line[0] == ':' {
			continue // comment
		}
		any = true
		field, value := splitField(line)
		switch field {
		case "event":
			eventType = value
		case "data":
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, value...)
		}
	}
	if !any {
		return SSEFrame{}, false
	}
	return SSEFrame{EventType: eventType, Data: data}, true
}

// splitLines breaks frame bytes on any line terminator (\n, \r\n, \r)
// without including the terminators in the output slices. Empty
// trailing lines are dropped — the caller already trimmed the
// boundary separator.
func splitLines(frame []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(frame); i++ {
		switch frame[i] {
		case '\n':
			lines = append(lines, frame[start:i])
			start = i + 1
		case '\r':
			lines = append(lines, frame[start:i])
			if i+1 < len(frame) && frame[i+1] == '\n' {
				i++ // skip the LF half of CRLF
			}
			start = i + 1
		}
	}
	if start < len(frame) {
		lines = append(lines, frame[start:])
	}
	return lines
}

// splitField splits an SSE line on the first ':' into (field, value)
// per the SSE spec. The value has a single leading space stripped if
// present (also per spec — "data: foo" yields value "foo", but
// "data:  foo" yields value " foo").
func splitField(line []byte) (string, string) {
	colon := bytes.IndexByte(line, ':')
	if colon < 0 {
		// Field-name-only line; value is the empty string per spec.
		return string(line), ""
	}
	field := string(line[:colon])
	value := line[colon+1:]
	if len(value) > 0 && value[0] == ' ' {
		value = value[1:]
	}
	return field, string(value)
}
