// Tool-name rewriter for Anthropic OAuth requests originating from non-Claude-CLI
// clients (opencode, Cursor, Cline, ...).
//
// Background
// ----------
// Beyond the WAF body fingerprint (handled in oauth_inject_waf_full.go),
// Anthropic's OAuth path applies a *third-party gate* on top: requests
// identified as "third-party app" are forced to draw from extra-usage rather
// than the user's plan quota. When the org has overage disabled, the request
// returns HTTP 400 with `Anthropic-Ratelimit-Unified-Overage-Disabled-Reason:
// org_level_disabled` and the message "Third-party apps now draw from your
// extra usage...".
//
// Bisection (research/oauth-token-response-identity/v2 R0..R9, 2026-05-06)
// pinpointed `tools[].name` initial-character case as the gating signal.
// Anthropic accepts any name whose first byte is uppercase ASCII (`Bash`,
// `Read_file`, `WebFetch`, …) and rejects everything else (`bash`, `read`,
// `question`). Schema content is NOT inspected. The simplest fix is to
// TitleCase the first byte of every tool name forward to upstream and to
// reverse the rename in tool_use blocks of the response body so the client
// sees its original tool names.
//
// Scope
// -----
// This file owns:
//
//   - rewriteToolNamesForward(req): forward step. Mutates body.tools[].name
//     and any historical tool_use blocks under body.messages[].content[],
//     records the proxy→client mapping into the request context.
//
//   - rewriteToolNamesReverseJSON(body, mapping): reverse step for non-
//     streaming JSON responses. Walks `content[]` for tool_use blocks.
//
//   - sseToolNameRewriter (newSSEToolNameRewriter): line-buffered
//     io.ReadCloser wrapper that reverses the rename in streaming SSE
//     `content_block_start` events.
//
// Both reverse paths look up the mapping via toolNameMappingFrom(ctx),
// which returns nil for any request where forward didn't run (i.e. real
// Claude CLI traffic): reverse becomes a no-op automatically — no need to
// re-derive whether the request was CLI-origin in ModifyResponse.

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// toolNameMappingKeyType is a private context-key type to avoid string
// collisions with other context keys in the proxy.
type toolNameMappingKeyType struct{}

var toolNameMappingKey = toolNameMappingKeyType{}

// rewriteToolNamesForward TitleCases the first byte of every tool name found
// in the request body and stores a {titleCased: original} mapping in the
// request context for the reverse step. Idempotent: names already starting
// with an uppercase byte are unchanged and don't enter the mapping.
//
// No-op safe at every failure mode (nil body, body read error, non-JSON
// body, no tools / no name change needed). The original body is restored
// when any step fails so downstream injectors still see the same bytes.
func rewriteToolNamesForward(req *http.Request) {
	if req.Body == nil {
		return
	}
	originalBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}
	_ = req.Body.Close()

	var body map[string]any
	if json.Unmarshal(originalBytes, &body) != nil {
		setRequestBody(req, originalBytes)
		return
	}

	mapping := make(map[string]string)

	if tools, ok := body["tools"].([]any); ok {
		for _, t := range tools {
			tool, ok := t.(map[string]any)
			if !ok {
				continue
			}
			name, _ := tool["name"].(string)
			if cased, changed := titleCaseLeadingASCII(name); changed {
				tool["name"] = cased
				mapping[cased] = name
			}
		}
	}

	// History inside messages[] may carry tool_use blocks from prior assistant
	// turns. Their `name` must match the tools[] table or upstream rejects on
	// referential consistency (so we transform both sides together).
	if msgs, ok := body["messages"].([]any); ok {
		for _, m := range msgs {
			msg, ok := m.(map[string]any)
			if !ok {
				continue
			}
			content, ok := msg["content"].([]any)
			if !ok {
				continue
			}
			for _, b := range content {
				blk, ok := b.(map[string]any)
				if !ok {
					continue
				}
				if blk["type"] != "tool_use" {
					continue
				}
				name, _ := blk["name"].(string)
				if cased, changed := titleCaseLeadingASCII(name); changed {
					blk["name"] = cased
					mapping[cased] = name
				}
			}
		}
	}

	if len(mapping) == 0 {
		// Nothing to rewrite; preserve original bytes byte-for-byte.
		setRequestBody(req, originalBytes)
		return
	}

	rewritten, err := json.Marshal(body)
	if err != nil {
		setRequestBody(req, originalBytes)
		return
	}
	setRequestBody(req, rewritten)

	ctx := context.WithValue(req.Context(), toolNameMappingKey, mapping)
	*req = *req.WithContext(ctx)
}

// titleCaseLeadingASCII uppercases the first byte if it's an ASCII lowercase
// letter; returns (newString, true) when a change was made. Non-ASCII or
// already-uppercase names pass through unchanged with changed=false.
//
// Why first-byte-only (not snake→PascalCase): bisect probe v2 R8 confirmed
// names like `Read_file` (only first char uppercased, underscore preserved)
// pass Anthropic's gate. R9 (full PascalCase) returned a real rate-limit
// error before reaching the gate, so it provides no extra information.
// First-byte-only is lossless invertible per a known forward mapping table,
// avoiding any need to recover word boundaries on the reverse path.
func titleCaseLeadingASCII(s string) (string, bool) {
	if s == "" {
		return s, false
	}
	c := s[0]
	if c < 'a' || c > 'z' {
		return s, false
	}
	return string(c-32) + s[1:], true
}

// toolNameMappingFrom returns the request-scoped {titleCased: original}
// mapping if the forward step ran, or nil otherwise. ModifyResponse uses
// this to decide whether to engage the reverse step at all.
func toolNameMappingFrom(ctx context.Context) map[string]string {
	if v, ok := ctx.Value(toolNameMappingKey).(map[string]string); ok {
		return v
	}
	return nil
}

// rewriteToolNamesReverseJSON reverses the forward rename inside a non-
// streaming JSON response. It walks `content[]` for tool_use blocks and
// renames any `name` found in mapping. Returns the original byte slice
// unchanged when nothing matches; otherwise returns a freshly-marshaled
// copy.
//
// Defensive: bodies that aren't JSON or lack a top-level `content` array
// pass through untouched — typical for error envelopes and non-message
// endpoints.
func rewriteToolNamesReverseJSON(body []byte, mapping map[string]string) []byte {
	if len(mapping) == 0 || len(body) == 0 {
		return body
	}
	var resp map[string]any
	if json.Unmarshal(body, &resp) != nil {
		return body
	}
	content, ok := resp["content"].([]any)
	if !ok {
		return body
	}
	changed := false
	for _, b := range content {
		blk, ok := b.(map[string]any)
		if !ok {
			continue
		}
		if blk["type"] != "tool_use" {
			continue
		}
		proxyName, _ := blk["name"].(string)
		if orig, ok := mapping[proxyName]; ok && orig != proxyName {
			blk["name"] = orig
			changed = true
		}
	}
	if !changed {
		return body
	}
	out, err := json.Marshal(resp)
	if err != nil {
		return body
	}
	return out
}

// sseToolNameRewriter wraps an upstream SSE response body and rewrites
// tool_use.name fields inside `content_block_start` events back to the
// client's original tool names.
//
// It is line-buffered: chunks from upstream may straddle line boundaries,
// so we accumulate into `buf` until '\n' is observed, then emit the
// (possibly transformed) line via `out`. A trailing partial line at EOF
// is flushed unchanged so we don't drop data on early termination.
//
// Why line-by-line JSON unmarshal (not a byte-level state machine):
// Anthropic's SSE protocol emits each event as a single `data: <json>` line
// followed by `\n\n`. tool_use.name only appears in content_block_start
// events and never spans multiple data lines — a reasonable invariant
// enforced by Anthropic's serializer for years. If Anthropic ever ships
// multi-line data values for an event, the JSON parse on the partial line
// will fail and the line is forwarded unchanged (graceful degradation).
type sseToolNameRewriter struct {
	upstream io.ReadCloser
	mapping  map[string]string
	buf      bytes.Buffer
	out      bytes.Buffer
	eofSeen  bool
	upstrErr error
}

// newSSEToolNameRewriter wraps body for tool_use.name reverse rewrite.
// When mapping is empty, returns body unchanged (no allocation overhead
// for the common no-rewrite path: claude CLI traffic, or non-tool
// responses).
func newSSEToolNameRewriter(body io.ReadCloser, mapping map[string]string) io.ReadCloser {
	if len(mapping) == 0 {
		return body
	}
	return &sseToolNameRewriter{upstream: body, mapping: mapping}
}

func (r *sseToolNameRewriter) Read(p []byte) (int, error) {
	// Drain anything already prepared.
	if r.out.Len() > 0 {
		return r.out.Read(p)
	}
	if r.eofSeen {
		if r.upstrErr != nil {
			return 0, r.upstrErr
		}
		return 0, io.EOF
	}

	// Pull more upstream bytes until we have at least one rewritten line
	// to return. Bounded by upstream's natural chunking — no busy-loop.
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
			// Flush trailing partial line unchanged so callers don't lose
			// data on EOF/error mid-line.
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

func (r *sseToolNameRewriter) Close() error {
	return r.upstream.Close()
}

// processCompleteLines splits accumulated bytes on '\n' and emits each
// complete line (transformed or not) into r.out. Anything past the last
// '\n' stays in r.buf to be combined with the next read.
func (r *sseToolNameRewriter) processCompleteLines() {
	for {
		bufBytes := r.buf.Bytes()
		idx := bytes.IndexByte(bufBytes, '\n')
		if idx < 0 {
			return
		}
		line := make([]byte, idx+1)
		copy(line, bufBytes[:idx+1])
		r.buf.Next(idx + 1)
		r.out.Write(rewriteSSELine(line, r.mapping))
	}
}

// rewriteSSELine inspects a single SSE line. Only `data: {...}` lines
// containing a content_block_start event whose content_block.type is
// `tool_use` and whose `name` is in mapping are rewritten; everything
// else (event: lines, blank separators, [DONE], non-tool blocks) is
// passed through byte-for-byte.
//
// Trailing CR/LF is preserved exactly so downstream consumers see the
// same line terminators upstream produced.
func rewriteSSELine(line []byte, mapping map[string]string) []byte {
	if len(line) == 0 {
		return line
	}
	// Separate trailing line terminator(s) for byte-exact preservation
	// when we re-emit a transformed payload.
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
		// `data: [DONE]` or any non-JSON payload — pass through.
		return line
	}

	var event map[string]any
	if json.Unmarshal(payload, &event) != nil {
		return line
	}
	if event["type"] != "content_block_start" {
		return line
	}
	cb, ok := event["content_block"].(map[string]any)
	if !ok || cb["type"] != "tool_use" {
		return line
	}
	proxyName, _ := cb["name"].(string)
	origName, ok := mapping[proxyName]
	if !ok || origName == proxyName {
		return line
	}
	cb["name"] = origName

	newPayload, err := json.Marshal(event)
	if err != nil {
		return line
	}
	out := bytes.NewBuffer(nil)
	out.WriteString("data: ")
	out.Write(newPayload)
	out.Write(trailing)
	return out.Bytes()
}
