// Package observability provides structured logging, trace context, and
// health snapshot primitives for aikey-proxy.
//
// Design goals:
//   - W3C Trace Context compatible (traceparent header)
//   - Low-invasion: wraps slog with async JSONL file output
//   - Flush on normal shutdown and recoverable panics
package observability

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// TraceContext holds W3C-compatible trace identifiers for one request or operation.
type TraceContext struct {
	TraceID      string // 16-byte hex (32 chars), W3C trace-id
	SpanID       string // 8-byte hex (16 chars), W3C parent-id
	ParentSpanID string // span-id of the caller, empty when this is the root
	Traceparent  string // full W3C traceparent header value
	RequestID    string // unique per-HTTP-request, may differ from SpanID
}

// newHex generates n cryptographically random bytes encoded as lowercase hex.
func newHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a deterministic placeholder so the caller is never blocked.
		return strings.Repeat("0", n*2)
	}
	return hex.EncodeToString(b)
}

// NewTraceID returns a new 128-bit (16-byte) random trace ID as 32 hex chars.
func NewTraceID() string { return newHex(16) }

// NewSpanID returns a new 64-bit (8-byte) random span ID as 16 hex chars.
func NewSpanID() string { return newHex(8) }

// NewID returns a new random 64-bit ID (alias for NewSpanID).
// Use for request_id, reload_id, command_id, incident_id, etc.
func NewID() string { return newHex(8) }

// buildTraceparent constructs a W3C traceparent value from its components.
// flags "01" means sampled.
func buildTraceparent(traceID, spanID string) string {
	return fmt.Sprintf("00-%s-%s-01", traceID, spanID)
}

// NewTrace creates a fresh root TraceContext with new random IDs.
func NewTrace() TraceContext {
	traceID := NewTraceID()
	spanID := NewSpanID()
	return TraceContext{
		TraceID:     traceID,
		SpanID:      spanID,
		Traceparent: buildTraceparent(traceID, spanID),
		RequestID:   NewID(),
	}
}

// ChildSpan creates a child TraceContext that inherits trace_id but has a new span_id.
// The caller's span_id becomes parent_span_id.
func (tc TraceContext) ChildSpan() TraceContext {
	spanID := NewSpanID()
	return TraceContext{
		TraceID:      tc.TraceID,
		SpanID:       spanID,
		ParentSpanID: tc.SpanID,
		Traceparent:  buildTraceparent(tc.TraceID, spanID),
		RequestID:    NewID(),
	}
}

// parseTraceparent extracts trace_id and span_id from a W3C traceparent header.
// Returns ok=false when the value is missing or malformed.
func parseTraceparent(tp string) (traceID, spanID string, ok bool) {
	parts := strings.Split(tp, "-")
	if len(parts) != 4 || parts[0] != "00" {
		return "", "", false
	}
	if len(parts[1]) != 32 || len(parts[2]) != 16 {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// ExtractOrCreate reads the traceparent header from an HTTP request and
// continues the trace (new child span). If no valid header is present, a new
// root trace is created.
func ExtractOrCreate(r *http.Request) TraceContext {
	tp := r.Header.Get("traceparent")
	if tp != "" {
		if traceID, parentSpan, ok := parseTraceparent(tp); ok {
			spanID := NewSpanID()
			reqID := r.Header.Get("x-request-id")
			if reqID == "" {
				reqID = NewID()
			}
			return TraceContext{
				TraceID:      traceID,
				SpanID:       spanID,
				ParentSpanID: parentSpan,
				Traceparent:  buildTraceparent(traceID, spanID),
				RequestID:    reqID,
			}
		}
	}
	// No valid traceparent — start a fresh root trace.
	tc := NewTrace()
	if reqID := r.Header.Get("x-request-id"); reqID != "" {
		tc.RequestID = reqID
	}
	return tc
}
