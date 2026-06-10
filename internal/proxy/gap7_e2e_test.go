package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// gap7 E2E regression — drives REAL streaming requests through the full proxy
// (Handle → route resolve → serveRoute → newStreamDrainer's incremental
// StreamAccumulator → Collector → store) and asserts the RECORDED UsageEvent has
// correct token counts. Complements the existing TestProxy_Streaming_RecordsTokens_*
// by covering the OpenAI accumulator family, a large multi-frame body (the gap7
// memory scenario, validated functionally — correct tokens with no whole-body
// buffer), and the model+cache fields. Live-event acceptance per
// principles/e2e-acceptance-live-events.md: trigger a real request, then assert
// the data the pipeline actually recorded — not just HTTP 200.

// TestProxy_Streaming_RecordsTokens_OpenAI: OpenAI SSE (usage in the FINAL frame,
// model on every chunk, cached prompt tokens) must record pure input
// (prompt − cached), output, and the upstream-resolved model.
func TestProxy_Streaming_RecordsTokens_OpenAI(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		chunks := []string{
			`data: {"id":"c1","model":"gpt-4o-mini","choices":[{"delta":{"content":"Hel"}}]}`,
			`data: {"id":"c1","model":"gpt-4o-mini","choices":[{"delta":{"content":"lo"}}]}`,
			`data: {"id":"c1","model":"gpt-4o-mini","choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":15,"completion_tokens":40,"prompt_tokens_details":{"cached_tokens":5}}}`,
			`data: [DONE]`,
		}
		for _, c := range chunks {
			w.Write([]byte(c + "\n\n"))
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	store := newCapturingStore()
	p := setupTestProxyWithStore(t, upstream.URL, store)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer aikey_team_openai_test")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	p.Handle(rec, req)

	// Client half of the chain: the stream is forwarded intact.
	respBody, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(respBody), "Hel") || !strings.Contains(string(respBody), "[DONE]") {
		t.Fatalf("forwarded stream truncated: %q", string(respBody))
	}

	// Billing half of the chain: recorded event via the incremental path.
	ev := store.waitEvent(t, 3*time.Second)
	if ev.InputTokens != 10 { // pure = prompt(15) − cached(5)
		t.Errorf("InputTokens = %d, want 10 (15 prompt − 5 cached)", ev.InputTokens)
	}
	if ev.OutputTokens != 40 {
		t.Errorf("OutputTokens = %d, want 40", ev.OutputTokens)
	}
	if ev.Model != "gpt-4o-mini" {
		t.Errorf("Model = %q, want gpt-4o-mini (upstream-resolved)", ev.Model)
	}
	if !ev.IsStreaming {
		t.Error("IsStreaming should be true")
	}
}

// TestProxy_Streaming_RecordsModelAndCache_Anthropic: Anthropic message_start
// carries model + cache fields (input at the START of the stream), message_delta
// carries output (at the END). The incremental accumulator must capture both ends
// and report PURE input (cache excluded) with the upstream model.
func TestProxy_Streaming_RecordsModelAndCache_Anthropic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		chunks := []string{
			`data: {"type":"message_start","message":{"model":"claude-sonnet-4-5-20250929","usage":{"input_tokens":3,"cache_read_input_tokens":1200,"cache_creation_input_tokens":50}}}`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"yo"}}`,
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":77}}`,
			`data: [DONE]`,
		}
		for _, c := range chunks {
			w.Write([]byte(c + "\n\n"))
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	store := newCapturingStore()
	p := setupTestProxyWithStore(t, upstream.URL, store)

	body := `{"model":"claude-sonnet-4-5-20250929","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	req.Header.Set("x-api-key", "aikey_team_anthropic_test")
	req.Header.Set("Content-Type", "application/json")

	p.Handle(httptest.NewRecorder(), req)

	ev := store.waitEvent(t, 3*time.Second)
	if ev.InputTokens != 3 { // 方案 A: pure uncached input
		t.Errorf("InputTokens = %d, want 3 (pure uncached)", ev.InputTokens)
	}
	if ev.OutputTokens != 77 {
		t.Errorf("OutputTokens = %d, want 77", ev.OutputTokens)
	}
	if ev.Model != "claude-sonnet-4-5-20250929" {
		t.Errorf("Model = %q, want claude-sonnet-4-5-20250929", ev.Model)
	}
}

// TestProxy_Streaming_LargeBody_RecordsTokens is the functional counterpart to
// the chaos-gap7 memory experiment: a large multi-frame stream (≈thousands of
// frames) must still record correct tokens AND forward the full body — proving
// the incremental parse-and-discard path neither truncates nor loses the
// start-frame input / end-frame output even though the whole body is never
// buffered.
func TestProxy_Streaming_LargeBody_RecordsTokens(t *testing.T) {
	const nChunks = 3000
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		// input at the very start
		w.Write([]byte(`data: {"type":"message_start","message":{"usage":{"input_tokens":123}}}` + "\n\n"))
		flusher.Flush()
		for i := 0; i < nChunks; i++ {
			fmt.Fprintf(w, `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"chunk %d padding padding padding"}}`+"\n\n", i)
			if i%256 == 0 {
				flusher.Flush()
			}
		}
		flusher.Flush()
		// output at the very end
		w.Write([]byte(`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":456}}` + "\n\n"))
		w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	store := newCapturingStore()
	p := setupTestProxyWithStore(t, upstream.URL, store)

	body := `{"model":"claude-sonnet-4-5-20250929","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	req.Header.Set("x-api-key", "aikey_team_anthropic_test")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	p.Handle(rec, req)

	respBody, _ := io.ReadAll(rec.Result().Body)
	// Full body forwarded: first chunk, a middle chunk, and the terminator all present.
	for _, want := range []string{"chunk 0 ", "chunk 2999 ", "[DONE]"} {
		if !strings.Contains(string(respBody), want) {
			t.Fatalf("large stream forwarding lost %q (body len=%d)", want, len(respBody))
		}
	}
	if len(respBody) < 200_000 {
		t.Fatalf("expected a large forwarded body, got only %d bytes", len(respBody))
	}

	ev := store.waitEvent(t, 5*time.Second)
	if ev.InputTokens != 123 {
		t.Errorf("InputTokens = %d, want 123 (start frame, captured incrementally)", ev.InputTokens)
	}
	if ev.OutputTokens != 456 {
		t.Errorf("OutputTokens = %d, want 456 (end frame, captured incrementally)", ev.OutputTokens)
	}
}
