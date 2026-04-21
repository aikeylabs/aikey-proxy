package events

import (
	"log/slog"
	"sync"
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

// Record enqueues a usage event. Non-blocking; drops event if buffer is full.
func (c *Collector) Record(event UsageEvent) {
	select {
	case c.ch <- event:
	default:
		slog.Warn("events collector: buffer full, dropping event")
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
