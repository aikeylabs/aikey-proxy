package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
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
//     canceled (Go HTTP server detects client disconnect via backgroundRead).
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
// reqCtx is canceled when the client disconnects (or proxyCtx when shutting
// down).  Either cancellation closes upstream and unblocks the drainer.
// reporterCallback is called when the stream ends to report usage.
// completion captures how the stream terminated:
//   - "complete":    upstream reached normal EOF and we forwarded all bytes
//   - "partial":     client disconnected before EOF; recorded tokens reflect
//                    only the prefix we successfully forwarded
//   - "interrupted": proxy was shutting down (proxyCtx canceled) or the
//                    upstream read errored mid-stream
// Nil means no reporting.
type reporterCallback func(breakdown provider.TokenBreakdown, completion string)

func newStreamDrainer(
	upstream io.ReadCloser,
	baseEvent events.UsageEvent,
	prov provider.Provider,
	collector *events.Collector,
	proxyCtx context.Context,
	reqCtx context.Context,
	logger *slog.Logger,
	onComplete reporterCallback,
	// Phase 4 M2 plugin observer hooks (optional). Both must be non-nil
	// for per-frame NotifySSEEvent dispatch to fire — the drainer
	// checks this once per read and short-circuits otherwise, so legacy
	// (no-observer) callers pay one nil-check per chunk and zero
	// allocations. The two arguments are kept separate (rather than
	// bundled into a single struct) so the existing legacy callers can
	// pass `nil, nil` without constructing wrapper values.
	obsRegistry *observer.Registry,
	obsReqCtx *observer.RequestContext,
) *streamDrainer {
	if logger == nil {
		logger = slog.Default()
	}
	pr, pw := io.Pipe()

	// SSEParser is allocated only when observer dispatch is wired —
	// avoids the 8 KiB buf cost on legacy streams that don't use it.
	// Nil parser inside the read loop is the "skip observer" signal.
	var sseParser *observer.SSEParser
	if obsRegistry != nil && obsReqCtx != nil {
		sseParser = observer.NewSSEParser()
	}

	// Watcher: close upstream as soon as the client disconnects or the proxy
	// shuts down. Complements the Close() path for cases where the ReverseProxy
	// does not call Close() before the context is canceled.
	// Isolated: per-stream goroutine; a panic here must not kill the whole
	// proxy for every other caller.
	observability.GoSafe("proxy.stream_drainer.watcher", observability.Isolated, func() {
		select {
		case <-reqCtx.Done():
			upstream.Close()
		case <-proxyCtx.Done():
			upstream.Close()
		}
	})

	// Isolated: per-stream SSE drainer. The 2026-04-22 nil-collector panic
	// here crashed the entire proxy process; with GoSafe the panic is now
	// logged + dumped and the rest of the proxy keeps serving.
	observability.GoSafe("proxy.stream_drainer.run", observability.Isolated, func() {
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
					onComplete(provider.TokenBreakdown{}, "interrupted")
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

				// Phase 4 M2 observer dispatch: feed the just-read bytes
				// to the SSE parser and emit any complete frames before
				// the next upstream.Read. ORDERING INVARIANT (per
				// plugin-架构设计.md §5.1 + proxy.go's doc-anchor):
				// observers see byte-identical upstream frames BEFORE
				// any ResponseTransform reshapes them. This loop is
				// the only place that satisfies that — pw.Write above
				// only forwards bytes to the client pipe; the
				// translator's response-side hook (if armed) runs
				// downstream of THIS loop in serveRoute's
				// ModifyResponse path.
				//
				// NotifySSEEvent is non-blocking (per its docstring's
				// P0-2 invariant). A slow / panicking observer can
				// drop frames or auto-disable itself but cannot stall
				// this drainer.
				if sseParser != nil {
					for _, frame := range sseParser.Parse(buf[:n]) {
						obsRegistry.NotifySSEEvent(reqCtx, obsReqCtx, frame.EventType, frame.Data)
					}
				}
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
		breakdown := prov.ExtractTokenBreakdown(acc.Bytes(), true, logger)
		// Caller-side double defense per principles/logging-conventions.md.
		// Only fires when the stream completed normally — partial / interrupted
		// streams legitimately have zero tokens because we never reached the
		// usage frame.
		if completion == "complete" &&
			acc.Len() > 100 &&
			breakdown.InputTokens == 0 && breakdown.OutputTokens == 0 {
			logger.Warn("streaming: complete stream with non-empty body but extractor produced zero tokens",
				"event.name", observability.EventProxyExtractionEmpty,
				"error.code", observability.ErrCodeUsageExtractionFailed,
				"provider", prov.Name(),
				"body_len", acc.Len(),
			)
		}
		ev := baseEvent
		ev.InputTokens = breakdown.InputTokens
		ev.OutputTokens = breakdown.OutputTokens
		ev.DurationMs = time.Since(baseEvent.Timestamp).Milliseconds()
		// 2026-05-09 response-first model: prefer the upstream-resolved
		// model id (e.g. claude-opus-4-7-20251015) carried in the
		// stream's first frame over the request-body model
		// (claude-opus-4-7) buildBaseEvent captured. Fall back to the
		// request-side value when the stream cut early or the extractor
		// didn't see a model frame (rare).
		if breakdown.Model != "" {
			ev.Model = breakdown.Model
		}
		// Collector is nil for probe traffic (see proxy.go::Handle stream branch):
		// X-Aikey-Probe: 1 requests shouldn't produce usage events. Without
		// this guard, nil deref here crashes the whole proxy process AFTER
		// a successful streaming response — observed as "chat ok" in CLI
		// followed by connection-refused on the next request (2026-04-22).
		if collector != nil {
			collector.Record(ev)
		}
		if onComplete != nil {
			onComplete(breakdown, completion)
		}
	})

	return &streamDrainer{pr: pr, upstream: upstream}
}
