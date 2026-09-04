package proxy

// sse_restore_test.go — B3 (2026-08-08) SSE streaming placeholder restoration.
// Locks the 滑窗跨 chunk contract: placeholders split across TCP chunks AND
// across SSE delta frames are restored; withheld text is flushed in order
// before boundary events; placeholder-free streams pass through byte-identical.
//
// P2 (2026-08-08) updated the LABEL SPELLING ONLY, from the P1-retired
// "{{ADDR_1}}" to the shipped "{{ADDR_1}}" (方案 §3.1). Split points were
// re-cut so each case still severs the placeholder mid-token — the contract
// under test (cross-frame holdback, in-order flush, byte-identical passthrough,
// [DONE]/usage frames untouched, error replay) is unchanged. L3 tolerant
// variants over the SSE path are fenced separately in filter_restore_l3_test.go.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// chunkReader feeds its payload in fixed-size chunks to exercise partial-frame
// assembly (占位符被切成两半的 chunk 序列 at the BYTE level).
type chunkReader struct {
	data  []byte
	chunk int
	off   int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.off >= len(c.data) {
		return 0, io.EOF
	}
	n := c.chunk
	if n > len(p) {
		n = len(p)
	}
	if c.off+n > len(c.data) {
		n = len(c.data) - c.off
	}
	copy(p, c.data[c.off:c.off+n])
	c.off += n
	return n, nil
}
func (c *chunkReader) Close() error { return nil }

func sseTestState(labels map[string]string) *maskRestore {
	st := newMaskRestore()
	for k, v := range labels {
		st.add(k, v)
	}
	return st
}

func anthropicTextFrame(text string) string {
	b := sjsonSetForTest(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":""}}`, text)
	return "event: content_block_delta\ndata: " + b + "\n\n"
}

// sjsonSetForTest avoids importing sjson twice with helpers; simple manual set.
func sjsonSetForTest(payload, text string) string {
	// tests only set delta.text — inline replace keeps the fixture readable.
	const marker = `"text":""`
	enc := jsonMarshalString(text)
	return strings.Replace(payload, marker, `"text":`+enc, 1)
}

func jsonMarshalString(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		default:
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

func drainAll(t *testing.T, rc io.ReadCloser) string {
	t.Helper()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	return string(b)
}

// concatTextDeltas re-parses the OUTPUT stream and joins every recognized text
// field — the client-visible text, independent of how frames were re-chunked.
func concatTextDeltas(t *testing.T, stream string) string {
	t.Helper()
	var sb strings.Builder
	for _, line := range strings.Split(stream, "\n") {
		line = strings.TrimSuffix(line, "\r")
		var payload string
		switch {
		case strings.HasPrefix(line, "data: "):
			payload = line[len("data: "):]
		case strings.HasPrefix(line, "data:"):
			payload = line[len("data:"):]
		default:
			continue
		}
		if payload == "" || payload[0] != '{' {
			continue
		}
		if p := sseTextFieldPath([]byte(payload)); p != "" {
			sb.WriteString(gjson.Get(payload, p).String())
		}
	}
	return sb.String()
}

func TestSSERestore_PlaceholderWithinOneDelta(t *testing.T) {
	orig := "北京市朝阳区建国路88号"
	st := sseTestState(map[string]string{"{{ADDR_1}}": orig})
	in := anthropicTextFrame("好的，送到{{ADDR_1}}没问题。") +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
	out := drainAll(t, newSSEPlaceholderRestorer(&chunkReader{data: []byte(in), chunk: len(in)}, st))
	if got := concatTextDeltas(t, out); got != "好的，送到"+orig+"没问题。" {
		t.Fatalf("restored text = %q", got)
	}
	if strings.Contains(out, "{{ADDR") {
		t.Fatalf("placeholder survived: %s", out)
	}
}

// The core B3 case: the placeholder is split across MULTIPLE delta frames (the
// LLM streams token-sized deltas) and the stream arrives in 3-byte TCP chunks.
func TestSSERestore_PlaceholderSplitAcrossDeltasAndChunks(t *testing.T) {
	orig := "上海市浦东新区世纪大道100号"
	st := sseTestState(map[string]string{"{{ADDR_1}}": orig})
	in := anthropicTextFrame("寄到{{AD") +
		anthropicTextFrame("DR_") +
		anthropicTextFrame("1}}即可") +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}\n\n"
	out := drainAll(t, newSSEPlaceholderRestorer(&chunkReader{data: []byte(in), chunk: 3}, st))
	if got := concatTextDeltas(t, out); got != "寄到"+orig+"即可" {
		t.Fatalf("cross-frame restore failed, text = %q", got)
	}
	if strings.Contains(out, "{{ADDR") || strings.Contains(out, "DR_1}}") {
		t.Fatalf("placeholder fragments survived: %s", out)
	}
	// usage frame passes through untouched (token extraction unaffected).
	if !strings.Contains(out, `"output_tokens":9`) {
		t.Fatalf("non-text frame corrupted: %s", out)
	}
}

// A prefix that never completes must be flushed BEFORE the boundary event as a
// synthesized text frame — the client receives every byte, in order.
func TestSSERestore_UnfinishedPrefixFlushedBeforeBoundary(t *testing.T) {
	st := sseTestState(map[string]string{"{{ADDR_1}}": "x"})
	in := anthropicTextFrame("结尾是半个占位{{ADDR_") +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
	out := drainAll(t, newSSEPlaceholderRestorer(&chunkReader{data: []byte(in), chunk: 7}, st))
	if got := concatTextDeltas(t, out); got != "结尾是半个占位{{ADDR_" {
		t.Fatalf("held text lost/dup: %q", got)
	}
	// Order: the flushed text frame must appear BEFORE content_block_stop.
	flushIdx := strings.LastIndex(out, "content_block_delta")
	stopIdx := strings.Index(out, "content_block_stop")
	if flushIdx < 0 || stopIdx < 0 || flushIdx > stopIdx {
		t.Fatalf("carry not flushed before boundary: %s", out)
	}
}

// 无占位符时零改动直通: with a mapping present but nothing matching, the whole
// stream must come out byte-identical (fast path skips re-encoding).
func TestSSERestore_NoPlaceholderByteIdentical(t *testing.T) {
	st := sseTestState(map[string]string{"{{ADDR_1}}": "x"})
	in := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"m\"}}\n\n" +
		anthropicTextFrame("plain text answer") +
		anthropicTextFrame("第二段，无敏感内容") +
		"data: [DONE]\n\n"
	out := drainAll(t, newSSEPlaceholderRestorer(&chunkReader{data: []byte(in), chunk: 5}, st))
	if out != in {
		t.Fatalf("placeholder-free stream must be byte-identical:\n got %q\nwant %q", out, in)
	}
}

// Nil state (the overwhelming common case) returns the SAME reader — zero wrap.
func TestSSERestore_NilStateIdentity(t *testing.T) {
	rc := io.NopCloser(bytes.NewReader([]byte("data: x\n\n")))
	if got := newSSEPlaceholderRestorer(rc, nil); got != rc {
		t.Fatal("nil restore state must return the body unchanged")
	}
	// The serveRoute wiring passes maskRestoreFromContext(ctx) — absent ctx
	// value must mean identity too.
	if maskRestoreFromContext(context.Background()) != nil {
		t.Fatal("empty context must yield nil state")
	}
}

// OpenAI chat-completions wire shape: choices.0.delta.content, split across
// deltas, no event: lines.
func TestSSERestore_OpenAIDeltaSplit(t *testing.T) {
	orig := "广州市天河区体育西路5号"
	st := sseTestState(map[string]string{"{{ADDR_1}}": orig})
	in := "data: {\"choices\":[{\"delta\":{\"content\":\"送{{ADDR\"}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"_1}}吧\"}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n"
	out := drainAll(t, newSSEPlaceholderRestorer(&chunkReader{data: []byte(in), chunk: 4}, st))
	if got := concatTextDeltas(t, out); got != "送"+orig+"吧" {
		t.Fatalf("openai delta restore failed: %q", got)
	}
	if !strings.Contains(out, "data: [DONE]") {
		t.Fatalf("[DONE] frame lost: %s", out)
	}
}

// spec: R-compliance-filter-direction-and-scope-2 响应方向唯一例外：占位符→原文还原
// (workflow/CI/requirements/2026-06-04-compliance-filter-direction-and-scope.md, 规则 2)
//
// OpenAI Responses API wire shape (codex, chatgpt.com/backend-api/codex):
// text streams as `response.output_text.delta` frames whose text is the
// TOP-LEVEL `delta` string — not choices[].delta.content, not
// content_block_delta. A placeholder split across two such frames must be
// restored exactly like the two older channels.
//
// 🔴 Live incident 2026-09-03 (winpc2, codex): request leg masked
// 13812345678 → {{PHONE_1}} correctly, the model echoed the placeholder, and
// the CLIENT rendered "{{PHONE_1}}" — diagnostics read
// placeholders_issued=11 / placeholders_restored=0. sseTextFieldPath knew only
// the Anthropic and chat-completions channels, so every Responses frame was a
// "non-text frame" and passed through verbatim. Third file in the same
// wire-format family to miss Responses: usage extractor knew it (07-06),
// conversation_audit was fixed for it (bugfix
// 2026-07-07-conversation-audit-codex-responses-api-not-captured.md), the
// restorer did not. This test is RED against the pre-fix sseTextFieldPath.
func TestSSERestore_ResponsesAPIDeltaSplit(t *testing.T) {
	orig := "13812345678"
	st := sseTestState(map[string]string{"{{PHONE_1}}": orig})
	in := "event: response.created\n" +
		"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"status\":\"in_progress\"}}\n\n" +
		"event: response.output_text.delta\n" +
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"记下 {{PHO\"}\n\n" +
		"event: response.output_text.delta\n" +
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"NE_1}} 了\"}\n\n" +
		"event: response.completed\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n\n"
	out := drainAll(t, newSSEPlaceholderRestorer(&chunkReader{data: []byte(in), chunk: 4}, st))
	if got := concatTextDeltas(t, out); got != "记下 "+orig+" 了" {
		t.Fatalf("responses-api delta restore failed: %q\nstream:\n%s", got, out)
	}
	if !strings.Contains(out, `"type":"response.completed"`) {
		t.Fatalf("response.completed frame lost: %s", out)
	}
	// The placeholder must not survive anywhere on the client-facing wire.
	if strings.Contains(out, "{{PHONE_1}}") || strings.Contains(out, "{{PHO") {
		t.Fatalf("placeholder leaked to client: %s", out)
	}
}

// `response.output_text.done` carries the COMPLETE text of the item in one
// frame (the real chatgpt.com backend emits it after the deltas; the in-repo
// mock does not). It is restored whole, with no carry prepended (carry belongs
// to the delta channel and is flushed first to keep text order), and it is
// never used as the carry-flush template (wrong shape to clone a delta from).
// A client that renders the final text from `.done` instead of from the deltas
// would otherwise flash the restored number and then revert to the placeholder.
func TestSSERestore_ResponsesAPIDoneFrameRestoredWhole(t *testing.T) {
	orig := "13812345678"
	st := sseTestState(map[string]string{"{{PHONE_1}}": orig})
	in := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"记下 {{PHO\"}\n\n" +
		"data: {\"type\":\"response.output_text.done\",\"text\":\"记下 {{PHONE_1}} 了\"}\n\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n\n"
	out := drainAll(t, newSSEPlaceholderRestorer(&chunkReader{data: []byte(in), chunk: 4}, st))

	// Locate the .done frame at its LINE start (the type string sits mid-line;
	// slicing at the raw index would hand the parsers a line with no `data: `
	// prefix and read back an empty text — which is exactly the mistake the
	// first draft of this test made).
	typeIdx := strings.Index(out, `"response.output_text.done"`)
	if typeIdx < 0 {
		t.Fatalf(".done frame lost: %s", out)
	}
	doneLineStart := strings.LastIndex(out[:typeIdx], "\n") + 1
	// 1. The withheld delta carry ("{{PHO") is flushed BEFORE the .done frame.
	if got := concatTextDeltas(t, out[:doneLineStart]); got != "记下 {{PHO" {
		// Nothing to restore in the delta channel here (placeholder never
		// completed), so the carry is flushed verbatim — but it must be
		// flushed, and before .done.
		t.Fatalf("delta carry not flushed before .done: %q\nstream:\n%s", got, out)
	}
	// 2. The .done text is restored whole and in place.
	var doneText string
	for _, line := range strings.Split(out[doneLineStart:], "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"response.output_text.done"`) {
			doneText = gjson.Get(line[len("data: "):], "text").String()
			break
		}
	}
	if doneText != "记下 "+orig+" 了" {
		t.Fatalf(".done text not restored whole: %q\nstream:\n%s", doneText, out)
	}
	if strings.Contains(out[doneLineStart:], "{{PHONE_1}}") {
		t.Fatalf("placeholder leaked in/after .done: %s", out)
	}
}

// Multiple placeholders in one stream (multi-address request).
func TestSSERestore_MultiplePlaceholders(t *testing.T) {
	a1, a2 := "地址一号", "地址二号"
	st := sseTestState(map[string]string{
		"{{ADDR_1}}": a1,
		"{{ADDR_2}}": a2,
	})
	in := anthropicTextFrame("先送{{ADDR_") +
		anthropicTextFrame("1}}，再送{{AD") +
		anthropicTextFrame("DR_2}}。") +
		"data: [DONE]\n\n"
	out := drainAll(t, newSSEPlaceholderRestorer(&chunkReader{data: []byte(in), chunk: 9}, st))
	if got := concatTextDeltas(t, out); got != "先送"+a1+"，再送"+a2+"。" {
		t.Fatalf("multi-placeholder restore failed: %q", got)
	}
}

// Upstream error after partial data: pending carry + partial frame still reach
// the client, then the error is replayed (drainer semantics preserved).
func TestSSERestore_UpstreamErrorReplayedAfterFlush(t *testing.T) {
	st := sseTestState(map[string]string{"{{ADDR_1}}": "x"})
	in := anthropicTextFrame("尾巴{{ADDR_")
	r := &errAfterReader{data: []byte(in)}
	rc := newSSEPlaceholderRestorer(r, st)
	b, err := io.ReadAll(rc)
	if err == nil || err.Error() != "upstream broke" {
		t.Fatalf("expected upstream error replay, got %v", err)
	}
	if got := concatTextDeltas(t, string(b)); got != "尾巴{{ADDR_" {
		t.Fatalf("held text lost on error: %q", got)
	}
}

type errAfterReader struct {
	data []byte
	done bool
}

func (r *errAfterReader) Read(p []byte) (int, error) {
	if !r.done {
		n := copy(p, r.data)
		r.done = true
		return n, nil
	}
	return 0, errSSEUpstreamBroke{}
}
func (r *errAfterReader) Close() error { return nil }

type errSSEUpstreamBroke struct{}

func (errSSEUpstreamBroke) Error() string { return "upstream broke" }
