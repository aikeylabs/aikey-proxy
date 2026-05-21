package translator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

// ── Helpers ────────────────────────────────────────────────────────────────

// echoRequest is the simplest possible RequestTransform — returns the
// input bytes verbatim, normalizing the model field. Used by tests that
// don't care about translation correctness, only Registry plumbing.
func echoRequest(_ context.Context, model string, body []byte, _ bool) ([]byte, *TranslateError) {
	if len(body) == 0 {
		return []byte(`{"model":"` + model + `"}`), nil
	}
	return body, nil
}

func echoNonStream(_ context.Context, body []byte) ([]byte, *TranslateError) {
	return body, nil
}

// ── NewRegistry / DefaultRegistry ──────────────────────────────────────────

func TestNewRegistry_IsEmptyAndIsolated(t *testing.T) {
	r1 := NewRegistry()
	r2 := NewRegistry()
	if r1 == r2 {
		t.Fatal("NewRegistry() returned the same pointer twice — isolation broken")
	}
	if r1.HasPair(FormatOpenAI, FormatAnthropic) {
		t.Errorf("brand-new Registry should have no pairs")
	}
	// Register on r1; r2 must remain empty.
	r1.Register(FormatOpenAI, FormatAnthropic, echoRequest, ResponseTransforms{NonStream: echoNonStream})
	if r2.HasPair(FormatOpenAI, FormatAnthropic) {
		t.Errorf("Register on r1 leaked into r2 — isolation broken")
	}
}

func TestDefaultRegistry_SingletonAcrossCalls(t *testing.T) {
	d1 := DefaultRegistry()
	d2 := DefaultRegistry()
	if d1 != d2 {
		t.Fatal("DefaultRegistry() returned different pointers — not a singleton")
	}
}

// ── Register + HasPair ─────────────────────────────────────────────────────

func TestRegister_StoresPairUnderEndpointDefault(t *testing.T) {
	r := NewRegistry()
	r.Register(FormatOpenAI, FormatAnthropic, echoRequest, ResponseTransforms{NonStream: echoNonStream})

	if !r.HasPair(FormatOpenAI, FormatAnthropic) {
		t.Errorf("HasPair returned false for the just-registered pair")
	}
	// Reverse direction is NOT auto-registered. Pair authors must
	// register both directions explicitly; one of the deltas vs
	// CLIProxyAPI (which had implicit reverse-lookup quirks).
	if r.HasPair(FormatAnthropic, FormatOpenAI) {
		t.Errorf("reverse direction (anthropic→openai) should NOT be auto-registered")
	}
}

func TestRegister_OverwritePreviousPair(t *testing.T) {
	r := NewRegistry()
	called1, called2 := false, false
	r.Register(FormatOpenAI, FormatAnthropic,
		func(_ context.Context, _ string, body []byte, _ bool) ([]byte, *TranslateError) {
			called1 = true
			return body, nil
		},
		ResponseTransforms{NonStream: echoNonStream},
	)
	r.Register(FormatOpenAI, FormatAnthropic,
		func(_ context.Context, _ string, body []byte, _ bool) ([]byte, *TranslateError) {
			called2 = true
			return body, nil
		},
		ResponseTransforms{NonStream: echoNonStream},
	)
	_, err := r.TranslateRequest(context.Background(), FormatOpenAI, FormatAnthropic, "m", []byte(`{}`), false)
	if err != nil {
		t.Fatalf("translate after overwrite failed: %+v", err)
	}
	if called1 {
		t.Errorf("overwrite did not replace the original transform")
	}
	if !called2 {
		t.Errorf("overwrite's new transform was not invoked")
	}
}

// ── TranslateRequest ───────────────────────────────────────────────────────

func TestTranslateRequest_NoPairRegistered_ReturnsTranslationFailed(t *testing.T) {
	r := NewRegistry()
	out, err := r.TranslateRequest(context.Background(), FormatOpenAI, FormatAnthropic, "m", []byte(`{}`), false)
	if out != nil {
		t.Errorf("expected nil output on missing pair, got %s", out)
	}
	if err == nil {
		t.Fatal("expected *TranslateError, got nil")
	}
	if err.Code != CodeTranslationFailed {
		t.Errorf("Code = %q, want CodeTranslationFailed", err.Code)
	}
	if err.HTTPStatus != 500 {
		t.Errorf("HTTPStatus = %d, want 500", err.HTTPStatus)
	}
	if !strings.Contains(err.Message, "openai") || !strings.Contains(err.Message, "anthropic") {
		t.Errorf("error message should name both Formats, got: %s", err.Message)
	}
}

func TestTranslateRequest_InvokesRegisteredTransformWithArgs(t *testing.T) {
	r := NewRegistry()
	var (
		gotModel  string
		gotBody   []byte
		gotStream bool
	)
	r.Register(FormatOpenAI, FormatAnthropic,
		func(_ context.Context, model string, body []byte, stream bool) ([]byte, *TranslateError) {
			gotModel = model
			gotBody = body
			gotStream = stream
			return []byte(`{"translated":true}`), nil
		},
		ResponseTransforms{NonStream: echoNonStream},
	)
	out, err := r.TranslateRequest(context.Background(), FormatOpenAI, FormatAnthropic,
		"claude-sonnet-4-5", []byte(`{"model":"gpt-4o","messages":[]}`), true)
	if err != nil {
		t.Fatalf("expected success, got %+v", err)
	}
	if string(out) != `{"translated":true}` {
		t.Errorf("output passthrough wrong: %s", out)
	}
	if gotModel != "claude-sonnet-4-5" {
		t.Errorf("model not passed: got %q", gotModel)
	}
	if string(gotBody) != `{"model":"gpt-4o","messages":[]}` {
		t.Errorf("body not passed verbatim: got %s", gotBody)
	}
	if !gotStream {
		t.Errorf("stream flag not passed: got false")
	}
}

func TestTranslateRequest_PropagatesTransformError(t *testing.T) {
	r := NewRegistry()
	r.Register(FormatOpenAI, FormatAnthropic,
		func(_ context.Context, _ string, _ []byte, _ bool) ([]byte, *TranslateError) {
			return nil, &TranslateError{
				Code:       CodeBadRequest,
				HTTPStatus: 400,
				Message:    "messages array is empty",
				Param:      "messages",
			}
		},
		ResponseTransforms{NonStream: echoNonStream},
	)
	out, err := r.TranslateRequest(context.Background(), FormatOpenAI, FormatAnthropic, "m", []byte(`{}`), false)
	if out != nil {
		t.Errorf("expected nil out when transform errors, got %s", out)
	}
	if err == nil || err.Code != CodeBadRequest {
		t.Fatalf("expected CodeBadRequest, got %+v", err)
	}
	if err.Param != "messages" {
		t.Errorf("Param passthrough wrong: %q", err.Param)
	}
}

func TestTranslateRequest_HonorsContextCancellation(t *testing.T) {
	// Pin the contract that pairs receive ctx — pairs themselves may
	// or may not check it, but the Registry shouldn't strip it. This
	// test asserts ctx is delivered, not that the Registry pre-checks
	// (pre-checking would be a layering violation: Registry can't know
	// whether a pair's work is non-trivial enough to honor cancel).
	r := NewRegistry()
	var gotCtx context.Context
	r.Register(FormatOpenAI, FormatAnthropic,
		func(ctx context.Context, _ string, body []byte, _ bool) ([]byte, *TranslateError) {
			gotCtx = ctx
			return body, nil
		},
		ResponseTransforms{NonStream: echoNonStream},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = r.TranslateRequest(ctx, FormatOpenAI, FormatAnthropic, "m", []byte(`{}`), false)
	if gotCtx == nil {
		t.Fatal("ctx was not delivered to the transform")
	}
	if !errors.Is(gotCtx.Err(), context.Canceled) {
		t.Errorf("ctx delivered to transform but it was not the canceled one passed in")
	}
}

// ── TranslateNonStream ─────────────────────────────────────────────────────

func TestTranslateNonStream_InvokesResponseTransform(t *testing.T) {
	r := NewRegistry()
	r.Register(FormatOpenAI, FormatAnthropic, echoRequest,
		ResponseTransforms{
			NonStream: func(_ context.Context, body []byte) ([]byte, *TranslateError) {
				// Simulate Anthropic → OpenAI shape rewrite by transforming a marker.
				out := strings.Replace(string(body), `"type":"message"`, `"object":"chat.completion"`, 1)
				return []byte(out), nil
			},
		},
	)
	out, err := r.TranslateNonStream(context.Background(), FormatOpenAI, FormatAnthropic,
		[]byte(`{"type":"message","content":[]}`))
	if err != nil {
		t.Fatalf("translate non-stream failed: %+v", err)
	}
	if !strings.Contains(string(out), `"object":"chat.completion"`) {
		t.Errorf("response transform did not run: %s", out)
	}
}

func TestTranslateNonStream_NoResponseTransformRegistered_ReturnsTranslationFailed(t *testing.T) {
	r := NewRegistry()
	// Register pair with ONLY request transform — no NonStream.
	r.Register(FormatOpenAI, FormatAnthropic, echoRequest, ResponseTransforms{})
	out, err := r.TranslateNonStream(context.Background(), FormatOpenAI, FormatAnthropic, []byte(`{}`))
	if out != nil {
		t.Errorf("expected nil out, got %s", out)
	}
	if err == nil || err.Code != CodeTranslationFailed {
		t.Fatalf("expected CodeTranslationFailed, got %+v", err)
	}
}

// ── Concurrency ────────────────────────────────────────────────────────────

func TestRegistry_ConcurrentTranslateRequest_NoRace(t *testing.T) {
	// Pin the contract that Translate* is safe for concurrent callers.
	// Run -race detects map-concurrency-write issues if the
	// implementation regresses.
	r := NewRegistry()
	r.Register(FormatOpenAI, FormatAnthropic, echoRequest, ResponseTransforms{NonStream: echoNonStream})

	const N = 50
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.TranslateRequest(context.Background(), FormatOpenAI, FormatAnthropic, "m", []byte(`{}`), false)
			if err != nil {
				t.Errorf("concurrent translate errored: %+v", err)
			}
		}()
	}
	wg.Wait()
}

// ── TranslateError.ToOpenAIShape ──────────────────────────────────────────

func TestTranslateError_ToOpenAIShape_RendersStandardKeys(t *testing.T) {
	e := &TranslateError{
		Code:       CodeBadRequest,
		HTTPStatus: 400,
		Message:    "n must be 1",
		Param:      "n",
	}
	raw := e.ToOpenAIShape()
	var parsed struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
			Param   string `json:"param"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("ToOpenAIShape produced invalid JSON: %v\n%s", err, raw)
	}
	if parsed.Error.Message != "n must be 1" {
		t.Errorf("Message passthrough wrong: %q", parsed.Error.Message)
	}
	if parsed.Error.Type != "invalid_request_error" {
		t.Errorf("Type = %q, want invalid_request_error", parsed.Error.Type)
	}
	if parsed.Error.Code != CodeBadRequest {
		t.Errorf("Code = %q, want %s", parsed.Error.Code, CodeBadRequest)
	}
	if parsed.Error.Param != "n" {
		t.Errorf("Param passthrough wrong: %q", parsed.Error.Param)
	}
}

func TestTranslateError_ToOpenAIShape_TypeMapping(t *testing.T) {
	cases := []struct {
		code     string
		wantType string
	}{
		{CodeBadRequest, "invalid_request_error"},
		{CodeUnsupportedParam, "invalid_request_error"},
		{CodeStreamNotSupported, "invalid_request_error"},
		{CodeUpstreamAuth, "authentication_error"},
		{CodeUpstreamRateLimit, "rate_limit_error"},
		{CodeUpstream5xx, "server_error"},
		{CodeTranslationFailed, "server_error"},
		{"AIKEY_UNKNOWN_CODE", "server_error"}, // unknown defaults to server_error
	}
	for _, c := range cases {
		e := &TranslateError{Code: c.code, HTTPStatus: 500, Message: "x"}
		raw := e.ToOpenAIShape()
		var parsed struct {
			Error struct {
				Type string `json:"type"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &parsed)
		if parsed.Error.Type != c.wantType {
			t.Errorf("Code=%s → Type=%q, want %q", c.code, parsed.Error.Type, c.wantType)
		}
	}
}

func TestTranslateError_Error_StringFormat(t *testing.T) {
	e := &TranslateError{
		Code:       CodeUpstream5xx,
		HTTPStatus: 502,
		Upstream:   "overloaded_error",
		Message:    "Anthropic is overloaded",
	}
	s := e.Error()
	// Pin that the standard error() output contains the diagnostics
	// fields callers' structured loggers might dump. The exact format
	// is not stable; only the values matter.
	for _, frag := range []string{"AIKEY_UPSTREAM_5XX", "http=502", "overloaded_error", "overloaded"} {
		if !strings.Contains(s, frag) {
			t.Errorf("error string missing %q: %s", frag, s)
		}
	}
}
