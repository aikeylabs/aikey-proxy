package proxy

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
)

// streamDrainer wraps an upstream SSE response body. A background goroutine
// reads from upstream, forwards data to the client via a pipe, and records
// token usage when the stream ends.
//
// On client disconnect, upstream is closed immediately through three
// complementary mechanisms so the provider stops generation (no unnecessary
// billing). Token usage accumulated before the disconnect is still recorded.
//
//  1. streamDrainer.Close() is called by httputil.ReverseProxy when
//     copyResponse detects a client write error.  Closing upstream here
//     unblocks any in-flight upstream.Read() without waiting for context
//     propagation.
//
//  2. A watcher goroutine calls upstream.Close() as soon as reqCtx is
//     cancelled (Go HTTP server detects client disconnect via backgroundRead).
//
//  3. The select at the top of the read loop catches reqCtx cancellation
//     between Read calls.
type streamDrainer struct {
	pr       *io.PipeReader
	upstream io.ReadCloser
}

func (d *streamDrainer) Read(p []byte) (int, error) { return d.pr.Read(p) }

// Close is called by httputil.ReverseProxy when the client write fails
// (e.g. client disconnected mid-stream).  Closing upstream here is the most
// direct trigger: it unblocks any pending upstream.Read() in the drainer
// goroutine so the upstream TCP connection is released immediately.
func (d *streamDrainer) Close() error {
	d.upstream.Close() // unblock drainer goroutine
	return d.pr.Close()
}

// newStreamDrainer creates a streamDrainer and starts the background goroutine.
// baseEvent is the pre-populated usage event (without token counts); the
// goroutine fills InputTokens / OutputTokens from whatever SSE data was
// received before the stream ended or the client disconnected.
//
// reqCtx is cancelled when the client disconnects (or proxyCtx when shutting
// down).  Either cancellation closes upstream and unblocks the drainer.
// reporterCallback is called when the stream ends to report usage.
// completion captures how the stream terminated:
//   - "complete":    upstream reached normal EOF and we forwarded all bytes
//   - "partial":     client disconnected before EOF; recorded tokens reflect
//                    only the prefix we successfully forwarded
//   - "interrupted": proxy was shutting down (proxyCtx cancelled) or the
//                    upstream read errored mid-stream
// Nil means no reporting.
type reporterCallback func(inputTokens, outputTokens int, completion string)

func newStreamDrainer(
	upstream io.ReadCloser,
	baseEvent events.UsageEvent,
	prov provider.Provider,
	collector *events.Collector,
	proxyCtx context.Context,
	reqCtx context.Context,
	onComplete reporterCallback,
) *streamDrainer {
	pr, pw := io.Pipe()

	// Watcher: close upstream as soon as the client disconnects or the proxy
	// shuts down. Complements the Close() path for cases where the ReverseProxy
	// does not call Close() before the context is cancelled.
	go func() {
		select {
		case <-reqCtx.Done():
			upstream.Close()
		case <-proxyCtx.Done():
			upstream.Close()
		}
	}()

	go func() {
		defer upstream.Close() // idempotent: safe if already closed above

		var acc bytes.Buffer
		buf := make([]byte, 32*1024)

		// Default to "complete"; the loop below downgrades to "partial" or
		// "interrupted" when it detects the corresponding exit paths.
		completion := "complete"

	outer:
		for {
			// Proxy shutdown or client disconnect: abort between reads.
			select {
			case <-proxyCtx.Done():
				pw.CloseWithError(proxyCtx.Err())
				if onComplete != nil {
					// Early exit without token recording — still emit a
					// callback so callers know the request never finished.
					onComplete(0, 0, "interrupted")
				}
				return
			case <-reqCtx.Done():
				// Client disconnected between reads.
				completion = "partial"
				break outer
			default:
			}

			n, readErr := upstream.Read(buf)
			if n > 0 {
				if _, writeErr := pw.Write(buf[:n]); writeErr != nil {
					// Client disconnected mid-write. Stop draining immediately
					// so the upstream TCP connection is released and the
					// provider stops generation. Token usage accumulated so
					// far is still recorded below.
					completion = "partial"
					break outer
				}
				// Only accumulate bytes that were successfully forwarded.
				acc.Write(buf[:n])
			}
			if readErr != nil {
				// io.EOF is the happy path and leaves completion as "complete".
				// Any other error means upstream cut us off mid-stream.
				if readErr != io.EOF {
					completion = "interrupted"
				}
				break outer
			}
		}

		// Signal end-of-stream to the client (no-op if already disconnected).
		pw.Close()

		// Record token usage from however much of the stream was received.
		inputTokens, outputTokens := prov.ExtractTokens(acc.Bytes(), true)
		ev := baseEvent
		ev.InputTokens = inputTokens
		ev.OutputTokens = outputTokens
		ev.DurationMs = time.Since(baseEvent.Timestamp).Milliseconds()
		collector.Record(ev)
		if onComplete != nil {
			onComplete(inputTokens, outputTokens, completion)
		}
	}()

	return &streamDrainer{pr: pr, upstream: upstream}
}
