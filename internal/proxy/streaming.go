package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// isStreamingRequest peeks at the request body to check for "stream": true.
// It re-buffers the body so it can still be forwarded upstream.
func isStreamingRequest(req *http.Request) bool {
	if req.Body == nil {
		return false
	}
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return false
	}
	// Re-buffer the body for upstream forwarding.
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))

	return bytes.Contains(bodyBytes, []byte(`"stream":true`)) ||
		bytes.Contains(bodyBytes, []byte(`"stream": true`))
}

// injectStreamUsageOption ensures the request body contains
// "stream_options":{"include_usage":true} so that OpenAI-compatible providers
// return token usage in the final SSE chunk before [DONE].
//
// Why: without this flag, streaming responses omit usage data entirely,
// causing all token counts to be recorded as 0. Anthropic uses a different
// mechanism (message_start/message_delta events) and does not need this.
//
// The function is a no-op if the body already contains "include_usage".
func injectStreamUsageOption(req *http.Request) {
	if req.Body == nil {
		return
	}
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return
	}

	// Skip if already present.
	if bytes.Contains(bodyBytes, []byte(`"include_usage"`)) {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		return
	}

	// Parse, inject, re-serialize.
	var body map[string]json.RawMessage
	if json.Unmarshal(bodyBytes, &body) != nil {
		// Not valid JSON — leave as-is.
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		return
	}

	// Merge into existing stream_options or create a new one.
	so := map[string]interface{}{"include_usage": true}
	if existing, ok := body["stream_options"]; ok {
		var existingMap map[string]interface{}
		if json.Unmarshal(existing, &existingMap) == nil {
			existingMap["include_usage"] = true
			so = existingMap
		}
	}
	soBytes, _ := json.Marshal(so)
	body["stream_options"] = json.RawMessage(soBytes)

	newBody, err := json.Marshal(body)
	if err != nil {
		// Serialization failed — leave original body.
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		return
	}

	req.Body = io.NopCloser(bytes.NewReader(newBody))
	req.ContentLength = int64(len(newBody))
}

// isSSEResponse checks if the response is a Server-Sent Events stream.
func isSSEResponse(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/event-stream")
}
