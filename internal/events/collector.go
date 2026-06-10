package events

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// EventInserter is the interface for batch-inserting events.
type EventInserter interface {
	Insert(events []UsageEvent) error
}

// Collector asynchronously collects usage events and batch-writes them
// to the store. It uses a buffered channel to avoid blocking the proxy
// request path.
type Collector struct {
	store         EventInserter
	ch            chan UsageEvent
	batchSize     int
	flushInterval time.Duration
	done          chan struct{}
	wg            sync.WaitGroup

	// dropped counts usage events discarded because the buffer was full.
	// Mirrors Reporter.dropped so /admin/metrics exposes both discard paths
	// (queue-full here, no-route in the reporter) — billing loss must be
	// externally observable, never log-only (health-signal-surface).
	dropped atomic.Int64
}

// CollectorMetrics holds observable collector counters. Surfaced via
// /admin/metrics alongside ReporterMetrics so an operator can see usage events
// lost to backpressure without scraping logs.
type CollectorMetrics struct {
	Dropped int64 `json:"usage_events_dropped_total"`
}

// Metrics returns a snapshot of the collector's counters.
func (c *Collector) Metrics() CollectorMetrics {
	return CollectorMetrics{Dropped: c.dropped.Load()}
}

// NewCollector creates and starts an async event collector.
func NewCollector(store EventInserter, batchSize int, flushInterval time.Duration) *Collector {
	c := &Collector{
		store:         store,
		ch:            make(chan UsageEvent, 1000),
		batchSize:     batchSize,
		flushInterval: flushInterval,
		done:          make(chan struct{}),
	}
	c.wg.Add(1)
	// Fatal: if the collector loop dies, usage events silently stop being
	// persisted — a visible billing correctness risk. Exit(2) and let the
	// supervisor restart.
	observability.GoSafe("events.collector.run", observability.Fatal, c.run)
	return c
}

// Record enqueues a usage event. Non-blocking by design (must never block the
// proxy request path). On buffer overflow the event is dropped, but loudly:
// a billing event lost to backpressure is a correctness risk, so we increment
// an externally-readable counter AND emit a structured WARN with the trace
// correlation captured at request entry (logging-conventions, fail-loud).
func (c *Collector) Record(event UsageEvent) {
	select {
	case c.ch <- event:
	default:
		dropped := c.dropped.Add(1)
		slog.Warn("events collector: buffer full, dropping usage event",
			"event.name", "usage.collector.buffer_full_drop",
			"error.code", "USAGE_COLLECTOR_BUFFER_FULL",
			"trace_id", event.TraceID,
			"span_id", event.SpanID,
			"request_id", event.RequestID,
			"virtual_key_id", event.VirtualKeyID,
			"provider", event.Provider,
			"model", event.Model,
			"session_id", event.SessionID,
			"dropped_total", dropped,
		)
	}
}

// Close stops the collector and flushes remaining events.
func (c *Collector) Close() error {
	close(c.done)
	c.wg.Wait()
	return nil
}

func (c *Collector) run() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.flushInterval)
	defer ticker.Stop()

	var batch []UsageEvent

	for {
		select {
		case event := <-c.ch:
			batch = append(batch, event)
			if len(batch) >= c.batchSize {
				c.flush(batch)
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				c.flush(batch)
				batch = nil
			}
		case <-c.done:
			// Drain remaining events from channel.
			for {
				select {
				case event := <-c.ch:
					batch = append(batch, event)
				default:
					if len(batch) > 0 {
						c.flush(batch)
					}
					return
				}
			}
		}
	}
}

func (c *Collector) flush(batch []UsageEvent) {
	if err := c.store.Insert(batch); err != nil {
		slog.Error("events collector: flush failed", "count", len(batch), "error", err)
	} else {
		slog.Debug("events collector: flushed", "count", len(batch))
	}
}
