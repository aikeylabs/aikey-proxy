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
