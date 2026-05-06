package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTitleCaseLeadingASCII pins the per-byte capitalisation rule. ASCII
// lowercase → uppercase, everything else (already uppercase, digits, non-
// ASCII, empty) returns unchanged with changed=false.
func TestTitleCaseLeadingASCII(t *testing.T) {
	cases := []struct {
		in        string
		want      string
		changed   bool
		commentary string
	}{
		{"bash", "Bash", true, "lowercase single word"},
		{"read_file", "Read_file", true, "snake_case — only first byte changes"},
		{"question", "Question", true, "lowercase multi-byte word"},
		{"Bash", "Bash", false, "already uppercase — no change"},
		{"WebFetch", "WebFetch", false, "already PascalCase — no change"},
		{"123tool", "123tool", false, "leading digit — no change"},
		{"_underscored", "_underscored", false, "leading underscore — no change"},
		{"", "", false, "empty"},
		{"中文", "中文", false, "non-ASCII leading byte — pass-through"},
	}
	for _, tc := range cases {
		t.Run(tc.in+"_"+tc.commentary, func(t *testing.T) {
			out, changed := titleCaseLeadingASCII(tc.in)
			if out != tc.want {
				t.Errorf("titleCaseLeadingASCII(%q) = %q, want %q", tc.in, out, tc.want)
			}
			if changed != tc.changed {
				t.Errorf("titleCaseLeadingASCII(%q) changed = %v, want %v", tc.in, changed, tc.changed)
			}
		})
	}
}

// TestRewriteToolNamesForward_TitleCasesToolsArray verifies the forward step
// uppercases the leading byte of every tools[].name and stores the reverse
// mapping in the request context.
func TestRewriteToolNamesForward_TitleCasesToolsArray(t *testing.T) {
	body := map[string]any{
		"model": "claude-opus-4-7",
		"tools": []any{
			map[string]any{"name": "bash", "input_schema": map[string]any{"type": "object"}},
			map[string]any{"name": "read", "input_schema": map[string]any{"type": "object"}},
			map[string]any{"name": "Bash", "input_schema": map[string]any{"type": "object"}}, // already capped — no-op
		},
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}
	req := newJSONRequest("POST", "/v1/messages", body)
	rewriteToolNamesForward(req)

	got := readBodyJSON(t, req)
	tools := got["tools"].([]any)
	if name := tools[0].(map[string]any)["name"]; name != "Bash" {
		t.Errorf("tools[0].name = %v; want Bash", name)
	}
	if name := tools[1].(map[string]any)["name"]; name != "Read" {
		t.Errorf("tools[1].name = %v; want Read", name)
	}
	if name := tools[2].(map[string]any)["name"]; name != "Bash" {
		t.Errorf("tools[2].name = %v; want Bash (idempotent)", name)
	}

	mapping := toolNameMappingFrom(req.Context())
	if got, ok := mapping["Bash"]; !ok || got != "bash" {
		t.Errorf("mapping[Bash] = %q; want bash", got)
	}
	if got, ok := mapping["Read"]; !ok || got != "read" {
		t.Errorf("mapping[Read] = %q; want read", got)
	}
	if _, has := mapping["Bash"]; has && len(mapping) != 2 {
		// Bash→Bash (already capped) must NOT enter mapping.
		t.Errorf("mapping should have exactly 2 entries; got %d: %v", len(mapping), mapping)
	}
}

// TestRewriteToolNamesForward_RewritesHistoryToolUseBlocks verifies tool_use
// blocks inside messages[].content[] (i.e. prior assistant turns) also get
// renamed, so referential consistency to the rewritten tools[] table holds.
func TestRewriteToolNamesForward_RewritesHistoryToolUseBlocks(t *testing.T) {
	body := map[string]any{
		"tools": []any{
			map[string]any{"name": "bash", "input_schema": map[string]any{"type": "object"}},
		},
		"messages": []any{
			map[string]any{"role": "user", "content": "do something"},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "tool_use", "id": "toolu_x", "name": "bash", "input": map[string]any{"cmd": "ls"}},
			}},
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": "toolu_x", "content": "..."},
			}},
		},
	}
	req := newJSONRequest("POST", "/v1/messages", body)
	rewriteToolNamesForward(req)
	got := readBodyJSON(t, req)
	msg1 := got["messages"].([]any)[1].(map[string]any)
	tu := msg1["content"].([]any)[0].(map[string]any)
	if name := tu["name"]; name != "Bash" {
		t.Errorf("history tool_use.name = %v; want Bash", name)
	}
}

// TestRewriteToolNamesForward_NoMappingWhenNothingChanges verifies bodies
// where every tool name is already TitleCased don't write a context mapping
// (so the reverse step stays a no-op).
func TestRewriteToolNamesForward_NoMappingWhenNothingChanges(t *testing.T) {
	body := map[string]any{
		"tools": []any{
			map[string]any{"name": "Bash"},
			map[string]any{"name": "Read"},
		},
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}
	req := newJSONRequest("POST", "/v1/messages", body)
	rewriteToolNamesForward(req)
	if mapping := toolNameMappingFrom(req.Context()); mapping != nil {
		t.Errorf("expected no mapping when nothing changes, got %v", mapping)
	}
}

// TestRewriteToolNamesForward_NonJSONBodyPreserved verifies non-JSON bodies
// (e.g. SSE pings, raw bytes) survive unchanged with no mapping written.
func TestRewriteToolNamesForward_NonJSONBodyPreserved(t *testing.T) {
	originalBody := []byte("event: ping\ndata: {}\n\n")
	req := httptest.NewRequest("POST", "/v1/messages", bytes.NewReader(originalBody))
	req.ContentLength = int64(len(originalBody))
	rewriteToolNamesForward(req)
	got, _ := io.ReadAll(req.Body)
	if string(got) != string(originalBody) {
		t.Errorf("non-JSON body should be preserved.\n  before: %q\n  after:  %q", originalBody, got)
	}
	if mapping := toolNameMappingFrom(req.Context()); mapping != nil {
		t.Errorf("non-JSON body should not produce a mapping, got %v", mapping)
	}
}

// TestRewriteToolNamesForward_NoToolsField verifies bodies without `tools`
// key still pass through; mapping is empty.
func TestRewriteToolNamesForward_NoToolsField(t *testing.T) {
	body := map[string]any{
		"model":    "claude-opus-4-7",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
	}
	req := newJSONRequest("POST", "/v1/messages", body)
	rewriteToolNamesForward(req)
	if mapping := toolNameMappingFrom(req.Context()); mapping != nil {
		t.Errorf("body without tools should not produce mapping, got %v", mapping)
	}
}

// TestRewriteToolNamesReverseJSON_RestoresOriginal verifies the response-side
// reverse rename swaps `Bash` (proxy form) back to `bash` (client form).
func TestRewriteToolNamesReverseJSON_RestoresOriginal(t *testing.T) {
	respBody, _ := json.Marshal(map[string]any{
		"id":   "msg_x",
		"role": "assistant",
		"content": []any{
			map[string]any{"type": "text", "text": "I'll run a command."},
			map[string]any{"type": "tool_use", "id": "toolu_x", "name": "Bash", "input": map[string]any{"command": "ls"}},
			map[string]any{"type": "tool_use", "id": "toolu_y", "name": "Read", "input": map[string]any{"path": "/etc/hosts"}},
		},
	})
	mapping := map[string]string{"Bash": "bash", "Read": "read"}
	out := rewriteToolNamesReverseJSON(respBody, mapping)
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	content := parsed["content"].([]any)
	if name := content[1].(map[string]any)["name"]; name != "bash" {
		t.Errorf("content[1].name = %v; want bash", name)
	}
	if name := content[2].(map[string]any)["name"]; name != "read" {
		t.Errorf("content[2].name = %v; want read", name)
	}
}

// TestRewriteToolNamesReverseJSON_EmptyMappingByteEqual verifies the no-op
// path returns the original byte slice (not just a re-marshalled equivalent),
// avoiding allocation churn for the common claude-CLI traffic case.
func TestRewriteToolNamesReverseJSON_EmptyMappingByteEqual(t *testing.T) {
	in := []byte(`{"id":"msg_x","content":[{"type":"text","text":"hi"}]}`)
	out := rewriteToolNamesReverseJSON(in, nil)
	if &in[0] != &out[0] {
		t.Errorf("empty mapping should return same slice header (no-op), got fresh allocation")
	}
}

// TestSSEToolNameRewriter_RewritesContentBlockStart verifies tool_use.name
// inside a content_block_start event is reversed back to the client name.
func TestSSEToolNameRewriter_RewritesContentBlockStart(t *testing.T) {
	stream := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_x"}}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_x","name":"Bash","input":{}}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")
	upstream := io.NopCloser(strings.NewReader(stream))
	mapping := map[string]string{"Bash": "bash"}
	r := newSSEToolNameRewriter(upstream, mapping)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read err: %v", err)
	}
	gs := string(got)
	if !strings.Contains(gs, `"name":"bash"`) {
		t.Errorf("expected reversed name 'bash' in stream, got:\n%s", gs)
	}
	if strings.Contains(gs, `"name":"Bash"`) {
		t.Errorf("expected NO 'Bash' (proxy form) in stream, got:\n%s", gs)
	}
	// Other events should be passed through verbatim.
	if !strings.Contains(gs, `"type":"message_start"`) {
		t.Errorf("message_start event missing from output")
	}
	if !strings.Contains(gs, `"type":"input_json_delta"`) {
		t.Errorf("content_block_delta event missing from output")
	}
	if !strings.Contains(gs, `data: [DONE]`) {
		t.Errorf("[DONE] sentinel missing from output")
	}
}

// TestSSEToolNameRewriter_HandlesChunkBoundary confirms that an upstream
// chunk straddling line boundaries doesn't break the line-by-line parser.
func TestSSEToolNameRewriter_HandlesChunkBoundary(t *testing.T) {
	full := strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"x","name":"Bash","input":{}}}`,
		``,
	}, "\n") + "\n"
	// Split mid-JSON intentionally.
	cut := len(full) / 2
	upstream := io.NopCloser(&chunkedReader{chunks: []string{full[:cut], full[cut:]}})
	mapping := map[string]string{"Bash": "bash"}
	r := newSSEToolNameRewriter(upstream, mapping)
	got, _ := io.ReadAll(r)
	if !strings.Contains(string(got), `"name":"bash"`) {
		t.Errorf("expected reversed name 'bash' across chunk boundary, got:\n%s", got)
	}
}

// TestSSEToolNameRewriter_TrailingPartialFlushed confirms a partial line at
// EOF is forwarded unchanged so we don't drop bytes upstream produced.
func TestSSEToolNameRewriter_TrailingPartialFlushed(t *testing.T) {
	// Note: no trailing newline.
	stream := "event: ping\ndata: trailing-no-newline"
	upstream := io.NopCloser(strings.NewReader(stream))
	r := newSSEToolNameRewriter(upstream, map[string]string{"Bash": "bash"})
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read err: %v", err)
	}
	if string(got) != stream {
		t.Errorf("trailing partial line should pass through.\n  before: %q\n  after:  %q", stream, got)
	}
}

// TestSSEToolNameRewriter_PassThroughWhenEmptyMapping verifies the wrapper
// short-circuits to the underlying body when mapping is empty (the common
// claude-CLI traffic path) — no line buffering or JSON parse cost.
func TestSSEToolNameRewriter_PassThroughWhenEmptyMapping(t *testing.T) {
	original := io.NopCloser(strings.NewReader("anything"))
	wrapped := newSSEToolNameRewriter(original, nil)
	if wrapped != original {
		t.Errorf("empty mapping should return body unchanged (same interface value)")
	}
}

// TestRewriteSSELine_NonToolUseBlocksUnchanged covers content_block_start
// events whose content_block is not a tool_use (e.g. text block) — they
// must pass through bit-for-bit even when mapping has matching names.
func TestRewriteSSELine_NonToolUseBlocksUnchanged(t *testing.T) {
	line := []byte(`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n")
	out := rewriteSSELine(line, map[string]string{"Bash": "bash"})
	if !bytes.Equal(out, line) {
		t.Errorf("text content_block should pass through.\n  before: %q\n  after:  %q", line, out)
	}
}

// chunkedReader is a test helper that delivers strings from `chunks` one
// per Read call, simulating upstream chunked delivery.
type chunkedReader struct {
	chunks []string
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := r.chunks[0]
	r.chunks = r.chunks[1:]
	n := copy(p, chunk)
	if n < len(chunk) {
		// Put back the remainder.
		r.chunks = append([]string{chunk[n:]}, r.chunks...)
	}
	return n, nil
}
