package proxy

// P3.3 (design D-5/D-6): streaming response model restoration. Rewrites the
// `message.model` field in the FIRST SSE `message_start` event back to the
// client's original model name (e.g. glm-4.6 → claude-opus-4-8), so a streaming
// client (Claude Code) sees its own model. Line-buffered — never buffers the
// whole stream (D-6: no full-stream buffering). Mirrors sseToolNameRewriter.
//
// 🚫 Never substitutes a hardcoded constant — only the exact client string
// stashed by the request-leg mapping (cc-switch #3600 anti-pattern).

import (
	"bytes"
	"io"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type sseModelRewriter struct {
	upstream    io.ReadCloser
	upstrErr    error
	clientModel string
	done        bool // model rewritten (message_start is the first event → once)
	buf, out    bytes.Buffer
	eofSeen     bool
}

// newSSEModelRewriter wraps body to restore the streaming response model. When
// clientModel is empty (no mapping happened) it returns body unchanged, so the
// non-mapped hot path pays nothing.
func newSSEModelRewriter(body io.ReadCloser, clientModel string) io.ReadCloser {
	if clientModel == "" {
		return body
	}
	return &sseModelRewriter{upstream: body, clientModel: clientModel}
}

func (r *sseModelRewriter) Read(p []byte) (int, error) {
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
			r.processCompleteLines()
		}
		if err != nil {
			r.eofSeen = true
			if err != io.EOF {
				r.upstrErr = err
			}
			if r.buf.Len() > 0 { // flush trailing partial line unchanged
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

func (r *sseModelRewriter) Close() error { return r.upstream.Close() }

func (r *sseModelRewriter) processCompleteLines() {
	for {
		bufBytes := r.buf.Bytes()
		idx := bytes.IndexByte(bufBytes, '\n')
		if idx < 0 {
			return
		}
		line := make([]byte, idx+1)
		copy(line, bufBytes[:idx+1])
		r.buf.Next(idx + 1)
		r.out.Write(r.rewriteModelLine(line))
	}
}

// rewriteModelLine rewrites message.model in the first message_start data line;
// everything else passes through byte-for-byte (line terminators preserved).
func (r *sseModelRewriter) rewriteModelLine(line []byte) []byte {
	if r.done || len(line) == 0 {
		return line
	}
	// Peel trailing CR/LF for byte-exact re-emit.
	trailing := []byte{}
	tail := line
	for len(tail) > 0 {
		c := tail[len(tail)-1]
		if c != '\n' && c != '\r' {
			break
		}
		trailing = append([]byte{c}, trailing...)
		tail = tail[:len(tail)-1]
	}
	if !bytes.HasPrefix(tail, []byte("data: ")) {
		return line
	}
	payload := tail[len("data: "):]
	if len(payload) == 0 || payload[0] != '{' {
		return line // `data: [DONE]` etc.
	}
	if gjson.GetBytes(payload, "type").String() != "message_start" {
		return line
	}
	if !gjson.GetBytes(payload, "message.model").Exists() {
		return line
	}
	patched, err := sjson.SetBytes(payload, "message.model", r.clientModel)
	if err != nil {
		return line
	}
	r.done = true
	out := make([]byte, 0, len("data: ")+len(patched)+len(trailing))
	out = append(out, "data: "...)
	out = append(out, patched...)
	out = append(out, trailing...)
	return out
}
