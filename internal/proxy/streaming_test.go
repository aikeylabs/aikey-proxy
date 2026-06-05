package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestInjectStreamUsageOption_AddsOption(t *testing.T) {
	body := `{"model":"moonshot-v1-8k","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := newReqWithBody(body)

	injectStreamUsageOption(req)

	result := readBody(t, req)
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("invalid JSON after injection: %v", err)
	}

	so, ok := parsed["stream_options"]
	if !ok {
		t.Fatal("stream_options not injected")
	}
	var opts map[string]interface{}
	if err := json.Unmarshal(so, &opts); err != nil {
		t.Fatalf("invalid stream_options: %v", err)
	}
	if v, ok := opts["include_usage"].(bool); !ok || !v {
		t.Fatalf("include_usage not set to true: %v", opts)
	}

	// Original fields must be preserved.
	if _, ok := parsed["model"]; !ok {
		t.Fatal("original 'model' field lost")
	}
	if _, ok := parsed["messages"]; !ok {
		t.Fatal("original 'messages' field lost")
	}
}

func TestInjectStreamUsageOption_AlreadyPresent(t *testing.T) {
	body := `{"model":"gpt-4","stream":true,"stream_options":{"include_usage":true}}`
	req := newReqWithBody(body)

	injectStreamUsageOption(req)

	result := readBody(t, req)
	// Body should be unchanged (no double injection).
	if !bytes.Equal(result, []byte(body)) {
		t.Fatalf("body modified when include_usage already present:\n  got:  %s\n  want: %s", result, body)
	}
}

func TestInjectStreamUsageOption_MergesExistingStreamOptions(t *testing.T) {
	body := `{"model":"gpt-4","stream":true,"stream_options":{"other_flag":true}}`
	req := newReqWithBody(body)

	injectStreamUsageOption(req)

	result := readBody(t, req)
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	var opts map[string]interface{}
	if err := json.Unmarshal(parsed["stream_options"], &opts); err != nil {
		t.Fatalf("invalid stream_options: %v", err)
	}
	if v, ok := opts["include_usage"].(bool); !ok || !v {
		t.Fatal("include_usage not added to existing stream_options")
	}
	if v, ok := opts["other_flag"].(bool); !ok || !v {
		t.Fatal("existing other_flag lost during merge")
	}
}

func TestInjectStreamUsageOption_InvalidJSON(t *testing.T) {
	body := `not-json`
	req := newReqWithBody(body)

	injectStreamUsageOption(req)

	result := readBody(t, req)
	if string(result) != body {
		t.Fatalf("invalid JSON body was modified: got %s", result)
	}
}

func TestInjectStreamUsageOption_NilBody(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions", nil)
	injectStreamUsageOption(req) // should not panic
}

func newReqWithBody(body string) *http.Request {
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/v1/chat/completions",
		io.NopCloser(bytes.NewReader([]byte(body))))
	req.ContentLength = int64(len(body))
	return req
}

func readBody(t *testing.T, req *http.Request) []byte {
	t.Helper()
	b, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	return b
}
