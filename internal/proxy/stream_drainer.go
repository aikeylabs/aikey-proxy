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
// reads the full stream from upstream and forwards data to the client via a
// pipe. If the client disconnects mid-stream, the goroutine continues draining
// the upstream response so that token consumption is accurately recorded.
type streamDrainer struct {
	pr *io.PipeReader
}

func (d *streamDrainer) Read(p []byte) (int, error) { return d.pr.Read(p) }
func (d *streamDrainer) Close() error               { return d.pr.Close() }

// newStreamDrainer creates a streamDrainer and starts the background goroutine.
//
// baseEvent is the pre-populated usage event (without token counts); the
// goroutine fills InputTokens / OutputTokens and calls collector.Record when
// the upstream stream ends, whether or not the client is still connected.
func newStreamDrainer(
	upstream io.ReadCloser,
	baseEvent events.UsageEvent,
	prov provider.Provider,
	collector *events.Collector,
	proxyCtx context.Context,
) *streamDrainer {
	pr, pw := io.Pipe()

	go func() {
		defer upstream.Close()

		var acc bytes.Buffer
		buf := make([]byte, 32*1024)
		clientGone := false

		for {
			// Respect proxy shutdown: stop reading and unblock the client pipe.
			select {
			case <-proxyCtx.Done():
				pw.CloseWithError(proxyCtx.Err())
				return
			default:
			}

			n, readErr := upstream.Read(buf)
			if n > 0 {
				acc.Write(buf[:n])
				if !clientGone {
					if _, writeErr := pw.Write(buf[:n]); writeErr != nil {
						// Client disconnected; keep draining upstream silently.
						clientGone = true
					}
				}
			}
			if readErr != nil {
				break
			}
		}

		// Signal end-of-stream to the client (no-op if already disconnected).
		pw.Close()

		// Parse and record token usage from the accumulated SSE stream.
		inputTokens, outputTokens := prov.ExtractTokens(acc.Bytes(), true)
		ev := baseEvent
		ev.InputTokens = inputTokens
		ev.OutputTokens = outputTokens
		ev.DurationMs = time.Since(baseEvent.Timestamp).Milliseconds()
		collector.Record(ev)
	}()

	return &streamDrainer{pr: pr}
}
