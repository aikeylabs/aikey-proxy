package provider

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// Regression tests for the 2026-05-07 codex/Responses-API silent-zero bug:
// codex calls /responses with `wire_api: "responses"` and the response uses
// `input_tokens`/`output_tokens` instead of Chat Completions' `prompt_tokens`/
// `completion_tokens`. Before the fix the extractor returned (0, 0) silently;
// after the fix it (a) extracts the tokens correctly, and (b) emits a WARN
// with event.name=proxy.extraction.shape_mismatch on every silent-fail path.
//
// Per principles/logging-conventions.md every extractor change must come with
// fixture-based tests covering each supported wire format AND assertions on
// WARN emission for failure paths.

// captureLog returns a logger writing to a buffer + the buffer for assertion.
// Uses TextHandler at WARN level so we can grep the output deterministically.
func captureLog() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	h := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	return slog.New(h), buf
}

// ---- Responses API: non-streaming ----

func TestOpenAI_Responses_NonStreaming(t *testing.T) {
	body := []byte(`{
		"id": "resp_abc",
		"object": "response",
		"output": [{"type": "message", "content": [{"type": "output_text", "text": "hi"}]}],
		"usage": {"input_tokens": 1234, "output_tokens": 56}
	}`)
	logger, buf := captureLog()
	in, out := (&OpenAI{}).ExtractTokens(body, false, logger)
	if in != 1234 || out != 56 {
		t.Fatalf("Responses non-streaming: want (1234, 56), got (%d, %d)", in, out)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no WARN on success path, got: %s", buf.String())
	}
}

// ---- Responses API: streaming ----
//
// Real codex Responses-API streams emit `response.completed` carrying the
// full response object, including embedded `usage`.

func TestOpenAI_Responses_Streaming(t *testing.T) {
	sse := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_1"}}`,
		`data: {"type":"response.output_text.delta","delta":"hi"}`,
		`data: {"type":"response.completed","response":{"id":"resp_1","usage":{"input_tokens":2222,"output_tokens":99}}}`,
		`data: [DONE]`,
		``,
	}, "\n")
	logger, buf := captureLog()
	in, out := (&OpenAI{}).ExtractTokens([]byte(sse), true, logger)
	if in != 2222 || out != 99 {
		t.Fatalf("Responses streaming: want (2222, 99), got (%d, %d)", in, out)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no WARN on success path, got: %s", buf.String())
	}
}

// ---- Chat Completions still works (regression guard) ----

func TestOpenAI_ChatCompletions_NonStreaming_StillWorks(t *testing.T) {
	body := []byte(`{"id":"chatcmpl-1","usage":{"prompt_tokens":42,"completion_tokens":7}}`)
	logger, buf := captureLog()
	in, out := (&OpenAI{}).ExtractTokens(body, false, logger)
	if in != 42 || out != 7 {
		t.Fatalf("Chat Completions non-streaming: want (42, 7), got (%d, %d)", in, out)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no WARN on success path, got: %s", buf.String())
	}
}

// ---- WARN path assertions (the primary diagnostic gap that hid the bug) ----

func TestOpenAI_Warn_OnUnmarshalError(t *testing.T) {
	logger, buf := captureLog()
	in, out := (&OpenAI{}).ExtractTokens([]byte(`not-json-at-all`), false, logger)
	if in != 0 || out != 0 {
		t.Fatalf("malformed body: want (0, 0), got (%d, %d)", in, out)
	}
	got := buf.String()
	if !strings.Contains(got, "unmarshal failed") {
		t.Errorf("expected WARN to mention 'unmarshal failed', got: %s", got)
	}
	if !strings.Contains(got, "proxy.extraction.shape_mismatch") {
		t.Errorf("expected WARN event.name=proxy.extraction.shape_mismatch, got: %s", got)
	}
	if !strings.Contains(got, "USAGE_EXTRACTION_FAILED") {
		t.Errorf("expected WARN error.code=USAGE_EXTRACTION_FAILED, got: %s", got)
	}
}

func TestOpenAI_Warn_OnUsageMissing(t *testing.T) {
	logger, buf := captureLog()
	in, out := (&OpenAI{}).ExtractTokens([]byte(`{"id":"chatcmpl-1"}`), false, logger)
	if in != 0 || out != 0 {
		t.Fatalf("missing usage: want (0, 0), got (%d, %d)", in, out)
	}
	got := buf.String()
	if !strings.Contains(got, "usage field missing") {
		t.Errorf("expected WARN to mention 'usage field missing', got: %s", got)
	}
	if !strings.Contains(got, "proxy.extraction.shape_mismatch") {
		t.Errorf("expected WARN event.name, got: %s", got)
	}
}

// This is the exact shape that hid the codex bug pre-fix: usage object is
// present but uses the Responses-API field names. Before the fix:
//   - parser found `usage` non-nil
//   - extracted `prompt_tokens`/`completion_tokens` (both zero)
//   - returned (0, 0) with no log
//
// After the fix: Resolve() picks up input_tokens/output_tokens. So this case
// no longer emits a WARN — it succeeds. Verify that.
func TestOpenAI_Responses_NoLongerSilentZero(t *testing.T) {
	body := []byte(`{"usage":{"input_tokens":10,"output_tokens":3}}`)
	logger, buf := captureLog()
	in, out := (&OpenAI{}).ExtractTokens(body, false, logger)
	if in != 10 || out != 3 {
		t.Fatalf("Responses-shaped usage: want (10, 3), got (%d, %d)", in, out)
	}
	if buf.Len() != 0 {
		t.Errorf("Responses-shaped usage should NOT trigger WARN any more, got: %s", buf.String())
	}
}

// True silent-zero check: a usage object present but with neither field set
// (e.g. a future wire format we haven't seen). Should still WARN.
func TestOpenAI_Warn_OnUsageAllZero(t *testing.T) {
	body := []byte(`{"usage":{"foo":"bar"}}`) // usage present but no recognized fields
	logger, buf := captureLog()
	in, out := (&OpenAI{}).ExtractTokens(body, false, logger)
	if in != 0 || out != 0 {
		t.Fatalf("unknown wire format: want (0, 0), got (%d, %d)", in, out)
	}
	got := buf.String()
	if !strings.Contains(got, "all token fields zero") {
		t.Errorf("expected WARN about all-zero tokens, got: %s", got)
	}
}

func TestOpenAI_Warn_OnEmptyStream(t *testing.T) {
	logger, buf := captureLog()
	in, out := (&OpenAI{}).ExtractTokens([]byte(""), true, logger)
	if in != 0 || out != 0 {
		t.Fatalf("empty stream: want (0, 0), got (%d, %d)", in, out)
	}
	if !strings.Contains(buf.String(), "no usage chunk found in stream") {
		t.Errorf("expected WARN about missing stream usage, got: %s", buf.String())
	}
}

// nil logger is allowed (falls back to slog.Default()) — assert no panic.
// We don't assert log content because slog.Default() goes to stderr.
func TestOpenAI_NilLoggerSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil logger should not panic, got: %v", r)
		}
	}()
	_, _ = (&OpenAI{}).ExtractTokens([]byte(`bad`), false, nil)
}
