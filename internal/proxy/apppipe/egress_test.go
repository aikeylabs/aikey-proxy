package apppipe

// AKL-206 — sanitizer tests. Per Day 3 §6 R1 these are fixture-based:
// each test names a concrete inbound JSON shape an Agent might send
// (taken from OpenAI SDK / Anthropic SDK examples) and pins what the
// sanitizer outputs. If a future refactor changes the strip semantics,
// this file is the regression net.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// SanitizeRequestBody — happy passthrough.
// ---------------------------------------------------------------------------

func TestSanitize_PassThroughCleanRequest(t *testing.T) {
	// A "perfectly clean" OpenAI request — no aikey, no metadata, no
	// rejected fields. Output equals input modulo JSON re-marshal (which
	// sorts keys alphabetically — that's fine).
	in := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)

	out, ctx, err := SanitizeRequestBody(in)
	if err != nil {
		t.Fatalf("expected no error on clean body, got %+v", err)
	}
	if ctx == nil {
		t.Fatal("expected non-nil ctx")
	}
	if ctx.AikeyField != nil || ctx.Metadata != nil {
		t.Errorf("clean body produced ctx.AikeyField=%v ctx.Metadata=%v", ctx.AikeyField, ctx.Metadata)
	}
	if len(ctx.Warnings) != 0 {
		t.Errorf("clean body should produce 0 warnings, got %v", ctx.Warnings)
	}
	// Round-trip semantic equality (key order may differ).
	assertJSONEqual(t, out, in)
}

// ---------------------------------------------------------------------------
// Strip aikey + metadata fields.
// ---------------------------------------------------------------------------

func TestSanitize_StripsAikeyField(t *testing.T) {
	in := []byte(`{
		"model": "gpt-4o",
		"messages": [{"role":"user","content":"hi"}],
		"aikey": {"task": "summarize", "phase": "draft"}
	}`)

	out, ctx, err := SanitizeRequestBody(in)
	if err != nil {
		t.Fatalf("unexpected error: %+v", err)
	}
	// `aikey` must be GONE from outbound.
	if hasJSONField(t, out, "aikey") {
		t.Errorf("aikey field leaked to outbound: %s", string(out))
	}
	// `aikey` value must be CAPTURED in ctx for usage event emission.
	if ctx.AikeyField == nil {
		t.Fatal("ctx.AikeyField must capture the stripped aikey value")
	}
	if ctx.AikeyField["task"] != "summarize" || ctx.AikeyField["phase"] != "draft" {
		t.Errorf("ctx.AikeyField = %+v, want {task:summarize, phase:draft}", ctx.AikeyField)
	}
}

func TestSanitize_StripsMetadataField(t *testing.T) {
	// 主方案 §5.2: "Agent 传入的 metadata 默认不透传"; provider adapter
	// is the only party allowed to inject metadata upstream.
	in := []byte(`{
		"model": "claude-sonnet-4-5",
		"messages": [{"role":"user","content":"hi"}],
		"metadata": {"user_id": "agent-supplied", "session": "abc"}
	}`)

	out, ctx, err := SanitizeRequestBody(in)
	if err != nil {
		t.Fatalf("unexpected error: %+v", err)
	}
	if hasJSONField(t, out, "metadata") {
		t.Errorf("metadata leaked to outbound: %s", string(out))
	}
	if ctx.Metadata == nil {
		t.Fatal("ctx.Metadata must capture the stripped metadata value")
	}
	if ctx.Metadata["user_id"] != "agent-supplied" {
		t.Errorf("ctx.Metadata user_id passthrough wrong: %+v", ctx.Metadata)
	}
}

func TestSanitize_StripsBothAikeyAndMetadata(t *testing.T) {
	// Agent can populate either or both — independent fields.
	in := []byte(`{
		"model": "gpt-4o",
		"messages": [{"role":"user","content":"hi"}],
		"aikey": {"task":"X"},
		"metadata": {"M":"Y"}
	}`)

	out, ctx, err := SanitizeRequestBody(in)
	if err != nil {
		t.Fatalf("unexpected error: %+v", err)
	}
	if hasJSONField(t, out, "aikey") || hasJSONField(t, out, "metadata") {
		t.Errorf("aikey or metadata leaked: %s", string(out))
	}
	if ctx.AikeyField == nil || ctx.Metadata == nil {
		t.Errorf("both ctx fields should be captured: AikeyField=%+v Metadata=%+v", ctx.AikeyField, ctx.Metadata)
	}
}

// ---------------------------------------------------------------------------
// Hard rejects.
// ---------------------------------------------------------------------------

func TestSanitize_RejectsNGreaterThan1(t *testing.T) {
	in := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"n":3}`)

	out, ctx, err := SanitizeRequestBody(in)
	if out != nil || ctx != nil {
		t.Errorf("expected nil out + ctx on hard reject, got out=%v ctx=%v", out, ctx)
	}
	if err == nil {
		t.Fatal("expected SanitizeError for n>1")
	}
	if err.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want 400", err.StatusCode)
	}
	if err.ErrorCode != "UNSUPPORTED_PARAMETER" {
		t.Errorf("ErrorCode = %q, want UNSUPPORTED_PARAMETER", err.ErrorCode)
	}
	if !strings.Contains(err.Message, "n must be 1") {
		t.Errorf("message must explain the rule, got: %s", err.Message)
	}
}

func TestSanitize_AcceptsNEqualTo1(t *testing.T) {
	// n=1 is the default; we shouldn't trip the reject path.
	in := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"n":1}`)

	_, _, err := SanitizeRequestBody(in)
	if err != nil {
		t.Errorf("n=1 must NOT be rejected, got %+v", err)
	}
}

func TestSanitize_AcceptsNAbsent(t *testing.T) {
	// n unspecified → defaults to 1 upstream-side, sanitizer doesn't care.
	in := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)

	_, _, err := SanitizeRequestBody(in)
	if err != nil {
		t.Errorf("n absent must NOT be rejected, got %+v", err)
	}
}

func TestSanitize_PassesThroughResponseFormatJSONObject(t *testing.T) {
	// Phase 2 Day 5: sanitizer no longer rejects response_format. The
	// protocol-translator (pairs/openai_anthropic/response_format.go)
	// converts json_object into a forced tool-call against a synthetic
	// "respond_in_json" tool. Sanitizer is the protocol-agnostic
	// security layer — translation is downstream.
	in := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_object"}}`)

	out, _, err := SanitizeRequestBody(in)
	if err != nil {
		t.Fatalf("response_format=json_object must pass through to translator, got %+v", err)
	}
	if !strings.Contains(string(out), `"response_format"`) {
		t.Errorf("sanitized body must preserve response_format for downstream translator; got: %s", string(out))
	}
}

func TestSanitize_PassesThroughResponseFormatJSONSchema(t *testing.T) {
	// Same rationale — translator handles json_schema (auto-injecting
	// "type":"object" when missing).
	in := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"x","schema":{"type":"object"}}}}`)

	out, _, err := SanitizeRequestBody(in)
	if err != nil {
		t.Fatalf("response_format=json_schema must pass through, got %+v", err)
	}
	if !strings.Contains(string(out), `"json_schema"`) {
		t.Errorf("sanitized body must preserve json_schema details for translator; got: %s", string(out))
	}
}

func TestSanitize_AcceptsResponseFormatText(t *testing.T) {
	// response_format={type:text} is the OpenAI default — pass-through.
	in := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"text"}}`)

	_, _, err := SanitizeRequestBody(in)
	if err != nil {
		t.Errorf("response_format=text must pass through, got %+v", err)
	}
}

// ---------------------------------------------------------------------------
// Silent drops (logprobs / top_logprobs / seed).
// ---------------------------------------------------------------------------

func TestSanitize_DropsLogprobsSilentlyWithWarning(t *testing.T) {
	in := []byte(`{
		"model":"gpt-4o",
		"messages":[{"role":"user","content":"hi"}],
		"logprobs":true,
		"top_logprobs":3
	}`)

	out, ctx, err := SanitizeRequestBody(in)
	if err != nil {
		t.Fatalf("logprobs should be silent-dropped, NOT rejected: %+v", err)
	}
	if hasJSONField(t, out, "logprobs") || hasJSONField(t, out, "top_logprobs") {
		t.Errorf("logprobs/top_logprobs leaked: %s", string(out))
	}
	if !containsWarning(ctx.Warnings, "logprobs_dropped") {
		t.Errorf("expected logprobs_dropped warning, got %v", ctx.Warnings)
	}
}

func TestSanitize_DropsSeedSilentlyWithWarning(t *testing.T) {
	in := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"seed":42}`)

	out, ctx, err := SanitizeRequestBody(in)
	if err != nil {
		t.Fatalf("seed should be silent-dropped: %+v", err)
	}
	if hasJSONField(t, out, "seed") {
		t.Errorf("seed leaked: %s", string(out))
	}
	if !containsWarning(ctx.Warnings, "seed_dropped") {
		t.Errorf("expected seed_dropped warning, got %v", ctx.Warnings)
	}
}

func TestSanitize_LogprobsTopLogprobsSingleWarning(t *testing.T) {
	// top_logprobs is meaningful only with logprobs; a single warning
	// covers both for the user signal — but BOTH must be stripped.
	in := []byte(`{
		"model":"gpt-4o",
		"messages":[{"role":"user","content":"hi"}],
		"logprobs":true,
		"top_logprobs":5
	}`)

	out, ctx, err := SanitizeRequestBody(in)
	if err != nil {
		t.Fatalf("unexpected error: %+v", err)
	}
	if hasJSONField(t, out, "logprobs") {
		t.Error("logprobs not stripped")
	}
	if hasJSONField(t, out, "top_logprobs") {
		t.Error("top_logprobs not stripped (orphan field leaked)")
	}
	logprobsCount := 0
	for _, w := range ctx.Warnings {
		if w == "logprobs_dropped" {
			logprobsCount++
		}
	}
	if logprobsCount != 1 {
		t.Errorf("expected exactly 1 logprobs_dropped warning, got %d (%v)", logprobsCount, ctx.Warnings)
	}
}

// ---------------------------------------------------------------------------
// Malformed bodies.
// ---------------------------------------------------------------------------

func TestSanitize_EmptyBodyReturnsMalformed(t *testing.T) {
	_, _, err := SanitizeRequestBody(nil)
	if err == nil || err.ErrorCode != "MALFORMED_REQUEST_BODY" {
		t.Errorf("expected MALFORMED_REQUEST_BODY for nil body, got %+v", err)
	}

	_, _, err = SanitizeRequestBody([]byte{})
	if err == nil || err.ErrorCode != "MALFORMED_REQUEST_BODY" {
		t.Errorf("expected MALFORMED_REQUEST_BODY for empty body, got %+v", err)
	}
}

func TestSanitize_InvalidJSONReturnsMalformed(t *testing.T) {
	cases := [][]byte{
		[]byte(`{not json}`),
		[]byte(`{"unclosed":`),
		[]byte(`{"trailing":,}`),
		[]byte(`[]`), // valid JSON but not an object — should fail at unmarshal into map
	}
	for i, c := range cases {
		_, _, err := SanitizeRequestBody(c)
		if err == nil || err.ErrorCode != "MALFORMED_REQUEST_BODY" {
			t.Errorf("case %d (%s): expected MALFORMED_REQUEST_BODY, got %+v", i, c, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Realistic agent fixtures — these mirror what OpenAI SDK / Anthropic
// SDK / claude code actually send. If a future change breaks one of
// these, real agents would be affected.
// ---------------------------------------------------------------------------

func TestSanitize_RealisticClaudeCodeRequest(t *testing.T) {
	// Shape mirroring what `claude code` sends (Anthropic-style request
	// with system block + tools). Sanitizer should pass through tools,
	// system, messages — only strip the AiKey control-plane fields.
	in := []byte(`{
		"model": "claude-sonnet-4-5-20250929",
		"max_tokens": 4096,
		"system": [{"type":"text","text":"You are a helpful coder."}],
		"messages": [
			{"role":"user","content":[{"type":"text","text":"Fix this bug"}]}
		],
		"tools": [{"name":"read_file","description":"Read","input_schema":{"type":"object"}}],
		"aikey": {"task":"bugfix","phase":"diagnose"},
		"metadata": {"user_id":"should-not-leak"}
	}`)

	out, ctx, err := SanitizeRequestBody(in)
	if err != nil {
		t.Fatalf("realistic Claude Code request must sanitize cleanly: %+v", err)
	}

	// Stripped fields must be gone.
	if hasJSONField(t, out, "aikey") || hasJSONField(t, out, "metadata") {
		t.Errorf("control-plane fields leaked: %s", string(out))
	}
	// Real-protocol fields must survive.
	for _, kept := range []string{"model", "max_tokens", "system", "messages", "tools"} {
		if !hasJSONField(t, out, kept) {
			t.Errorf("real protocol field %q was incorrectly stripped: %s", kept, string(out))
		}
	}
	// Context captures.
	if ctx.AikeyField == nil || ctx.AikeyField["task"] != "bugfix" {
		t.Errorf("ctx.AikeyField wrong: %+v", ctx.AikeyField)
	}
	if ctx.Metadata == nil || ctx.Metadata["user_id"] != "should-not-leak" {
		t.Errorf("ctx.Metadata wrong: %+v", ctx.Metadata)
	}
}

// ---------------------------------------------------------------------------
// StripResponseHeaders.
// ---------------------------------------------------------------------------

func TestStripResponseHeaders_RemovesXAiKeyFamily(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-AiKey-Trace-Id", "should-strip")
	h.Set("X-Aikey-Route-Source", "should-strip") // lowercase variant
	h.Set("X-AIKEY-LOWER-CHECK", "should-strip")  // uppercase variant
	h.Set("X-Other-Header", "should-keep")

	StripResponseHeaders(h)

	if h.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type was incorrectly stripped")
	}
	if h.Get("X-Other-Header") != "should-keep" {
		t.Errorf("Unrelated X-* header was stripped")
	}
	for _, k := range []string{"X-AiKey-Trace-Id", "X-Aikey-Route-Source", "X-AIKEY-LOWER-CHECK"} {
		if h.Get(k) != "" {
			t.Errorf("X-AiKey-* header %q was NOT stripped (value: %q)", k, h.Get(k))
		}
	}
}

func TestStripResponseHeaders_NilSafe(t *testing.T) {
	// Defensive — must not panic on nil header map.
	StripResponseHeaders(nil)
}

// ---------------------------------------------------------------------------
// Helpers for assertions.
// ---------------------------------------------------------------------------

func hasJSONField(t *testing.T, body []byte, key string) bool {
	t.Helper()
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("hasJSONField: body is not valid JSON: %v", err)
	}
	_, ok := parsed[key]
	return ok
}

func assertJSONEqual(t *testing.T, a, b []byte) {
	t.Helper()
	var av, bv map[string]interface{}
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatalf("assertJSONEqual: a is not JSON: %v\n%s", err, a)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatalf("assertJSONEqual: b is not JSON: %v\n%s", err, b)
	}
	if !jsonDeepEqual(av, bv) {
		t.Errorf("JSON values differ:\n a=%s\n b=%s", a, b)
	}
}

func jsonDeepEqual(a, b interface{}) bool {
	// Tiny recursive comparator that ignores map key order. Sufficient
	// for sanitizer test assertions; no need to pull in github.com/x/y.
	switch av := a.(type) {
	case map[string]interface{}:
		bv, ok := b.(map[string]interface{})
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, v := range av {
			if !jsonDeepEqual(v, bv[k]) {
				return false
			}
		}
		return true
	case []interface{}:
		bv, ok := b.([]interface{})
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !jsonDeepEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

func containsWarning(warnings []string, target string) bool {
	for _, w := range warnings {
		if w == target {
			return true
		}
	}
	return false
}
