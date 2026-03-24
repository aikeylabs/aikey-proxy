package proxy

import (
	"bytes"
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

// isSSEResponse checks if the response is a Server-Sent Events stream.
func isSSEResponse(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/event-stream")
}
