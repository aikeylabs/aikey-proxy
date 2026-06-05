package server

import (
	"bufio"
	"net"
	"net/http"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// recoverMiddleware wraps the mux with panic recovery. Any panic in an HTTP
// handler is captured, logged, and dumped via observability.RecoverHTTP,
// and a 500 response is written (if headers have not already been flushed).
// The proxy process keeps running — one bad request must not kill the mux
// for everyone else. This closes the default net/http behavior where
// server.go's recover swallows the panic silently without logging or dump.
func recoverMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tw := &trackedWriter{ResponseWriter: w}
		rr := &tryWriter{tw: tw}
		defer observability.RecoverHTTP(rr, r.URL.Path)
		h.ServeHTTP(tw, r)
	})
}

// trackedWriter is a minimal ResponseWriter wrapper that remembers whether
// anything has been written to the response yet. It also passes through
// Flusher, CloseNotifier, and Hijacker so streaming handlers
// (httputil.ReverseProxy SSE, stream_drainer watcher, etc.) keep their
// behavior unchanged.
type trackedWriter struct {
	http.ResponseWriter
	wrote bool
}

func (tw *trackedWriter) WriteHeader(code int) {
	tw.wrote = true
	tw.ResponseWriter.WriteHeader(code)
}

func (tw *trackedWriter) Write(p []byte) (int, error) {
	tw.wrote = true
	return tw.ResponseWriter.Write(p)
}

// Flush — required for SSE. Degrades to no-op when the underlying writer
// does not support flushing (HTTP/2 push buffers, test recorders).
func (tw *trackedWriter) Flush() {
	if f, ok := tw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// CloseNotify — required for proxy.go's mid-stream disconnect watcher.
// Returns nil when the underlying does not implement it; callers that do
// `w.(http.CloseNotifier)` then select on the channel will see nil, which
// select treats as "never ready" (never triggers cancel, which is the old
// behavior for handlers that couldn't detect disconnect).
//
//nolint:staticcheck // CloseNotifier is deprecated but still the reliable HTTP/1.1 disconnect signal
func (tw *trackedWriter) CloseNotify() <-chan bool {
	//nolint:staticcheck
	if cn, ok := tw.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	return nil
}

// Hijack — some callers may want to upgrade. Pass through when available.
func (tw *trackedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := tw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// tryWriter adapts trackedWriter to observability.httpResponder.
type tryWriter struct{ tw *trackedWriter }

func (x *tryWriter) TryWrite500() {
	if x.tw == nil || x.tw.wrote {
		// Headers already flushed (e.g., mid-stream). We cannot send a 500
		// status now; the best we can do is let the connection close and
		// the client will see a truncated response. The panic was already
		// logged + dumped by observability.RecoverHTTP.
		return
	}
	x.tw.Header().Set("Content-Type", "application/json")
	x.tw.WriteHeader(http.StatusInternalServerError)
	_, _ = x.tw.Write([]byte(`{"error":"internal_error","code":"HANDLER_PANIC"}`))
}
