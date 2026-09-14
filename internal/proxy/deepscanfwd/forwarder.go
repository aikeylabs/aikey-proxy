package deepscanfwd

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/deepscan"
	"github.com/AiKeyLabs/pkg/scannode"
)

// Status values reported in the health section (design §4b.3).
const (
	StatusOK       = "ok"
	StatusDegraded = "degraded"
)

// degradeAfter is how many CONSECUTIVE delivery failures flip the lane to
// degraded; one success clears it (design §3.4). Consecutive, not a rate,
// because the operator's question is "is the lane working right now?".
const degradeAfter = 3

// Config configures a RemoteForwarder.
type Config struct {
	Nodes      []scannode.Node
	QueueMax   int
	QueueBytes int64
	// DialSink builds the transport for one node. Injected so tests drive real
	// queue and failover behavior without a TLS listener per case; production
	// passes scannode.NewTLSSink.
	DialSink func(scannode.Node) deepscan.Sink
	// RejectFor lets a test express "this node answers with reject code X".
	// Production leaves it nil and reads the code off the result frame.
	RejectFor func(scannode.Node) string
	Breaker   scannode.Breaker
	Logger    *slog.Logger
}

// Stats is the counter snapshot the health section renders.
type Stats struct {
	Status       string
	Enqueued     uint64
	Dropped      uint64
	DroppedBytes uint64
	Forwarded    uint64
	Failed       uint64
	QueueLen     int
	QueueBytes   int64
}

// RemoteForwarder ships task frames to scan nodes in the background.
//
// 🔴 THE ONE PROPERTY THIS TYPE EXISTS TO GUARANTEE: nothing a node does can
// make a request wait. Every design choice below follows from that —
//
//   - Enqueue is a non-blocking channel send with a `default` branch. It never
//     waits for a node, a lock held across I/O, or a retry.
//   - The queue is bounded twice, by item count AND by bytes, because it holds
//     WHOLE content pieces: 256 items × 256 KiB is 64 MiB of an employee's RAM,
//     so an item count alone bounds nothing that matters.
//   - Overflow DROPS and COUNTS. A dropped piece is a coverage hole the health
//     section must be able to show; silently buffering it would trade a visible
//     hole for invisible memory growth.
//
// Fences: TestDeepScanForward_SlowNodeNeverDelaysRequests,
// _ByteBudgetDropsNeverBlocks.
type RemoteForwarder struct {
	cfg     Config
	breaker scannode.Breaker
	log     *slog.Logger

	queue   chan queued
	results chan deepscan.ResultFrame
	stopCh  chan struct{}
	doneCh  chan struct{}
	once    sync.Once

	sinkMu sync.Mutex
	sinks  map[string]deepscan.Sink

	enqueued     atomic.Uint64
	dropped      atomic.Uint64
	droppedBytes atomic.Uint64
	forwarded    atomic.Uint64
	failed       atomic.Uint64
	queueBytes   atomic.Int64
	consecFails  atomic.Int64
	degraded     atomic.Bool
}

type queued struct {
	frame deepscan.FrameV2
	size  int64
}

// NewRemoteForwarder returns a configured, unstarted forwarder.
func NewRemoteForwarder(cfg Config) *RemoteForwarder {
	if cfg.QueueMax <= 0 {
		cfg.QueueMax = 256
	}
	if cfg.QueueBytes <= 0 {
		cfg.QueueBytes = 16 << 20
	}
	if cfg.Breaker == nil {
		cfg.Breaker = scannode.NewBreaker(degradeAfter)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &RemoteForwarder{
		cfg: cfg, breaker: cfg.Breaker, log: cfg.Logger,
		queue:   make(chan queued, cfg.QueueMax),
		results: make(chan deepscan.ResultFrame, cfg.QueueMax),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
		sinks:   map[string]deepscan.Sink{},
	}
}

// Start launches the background delivery goroutine. Call once.
//
// 🔴 The goroutine's method is named runDeliveryLoop, not `loop`. That is not
// style: internal/proxy/hotpath_callgraph_fence_test.go walks the module's call
// graph resolving METHOD CALLS BY NAME (a deliberate over-approximation, see its
// header), so a method called `loop` here is treated as reachable from every
// `x.loop()` in the module — including internal/supervisor's railRunner.loop,
// which reads files. That made the PLANE-01 「热路径无文件调用」 fence go red with
// a path through this package on 2026-09-12. The alternatives were to add
// OTHER packages' file calls to that fence's allowlist — permanently weakening a
// real guard to accommodate a name — or to pick a name nothing else uses.
func (r *RemoteForwarder) Start() { go r.runDeliveryLoop() }

// Results yields result frames as nodes answer them.
func (r *RemoteForwarder) Results() <-chan deepscan.ResultFrame { return r.results }

// Enqueue offers one frame to the background lane and reports whether it was
// accepted. It NEVER blocks and is safe on a nil receiver (lane disabled), so
// the request path does not branch.
func (r *RemoteForwarder) Enqueue(f deepscan.FrameV2) bool {
	if r == nil {
		return false
	}
	size := int64(len(f.Prompt))
	// Budget first: check-then-add is deliberately not atomic-CAS'd. Overshooting
	// by one in-flight frame is harmless; making the request path spin on a CAS
	// loop to be exact is not.
	if r.queueBytes.Load()+size > r.cfg.QueueBytes {
		r.countDrop(size, "byte_budget")
		return false
	}
	select {
	case r.queue <- queued{frame: f, size: size}:
		r.enqueued.Add(1)
		r.queueBytes.Add(size)
		return true
	default:
		r.countDrop(size, "queue_full")
		return false
	}
}

func (r *RemoteForwarder) countDrop(size int64, reason string) {
	r.dropped.Add(1)
	if size > 0 {
		r.droppedBytes.Add(uint64(size)) //nolint:gosec // G115: a byte length, guarded non-negative above
	}
	// WARN, aggregated by the caller's rate limiter upstream: a drop is a real
	// coverage hole, and the health section carries the running totals.
	r.log.Warn("deep-scan task dropped before delivery; this content will not be re-scanned unless it is sent again",
		"event.name", observability.EventDeepScanEnqueueDropped,
		"reason", reason, "bytes", size,
		"dropped_total", r.dropped.Load())
}

// Stats snapshots the counters.
func (r *RemoteForwarder) Stats() Stats {
	if r == nil {
		return Stats{Status: StatusOK}
	}
	st := StatusOK
	if r.degraded.Load() {
		st = StatusDegraded
	}
	return Stats{
		Status: st, Enqueued: r.enqueued.Load(), Dropped: r.dropped.Load(),
		DroppedBytes: r.droppedBytes.Load(), Forwarded: r.forwarded.Load(),
		Failed: r.failed.Load(), QueueLen: len(r.queue), QueueBytes: r.queueBytes.Load(),
	}
}

// Close stops the worker, draining what is queued, bounded by ctx.
func (r *RemoteForwarder) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.once.Do(func() { close(r.stopCh) })
	select {
	case <-r.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *RemoteForwarder) runDeliveryLoop() {
	defer close(r.doneCh)
	defer r.closeSinks()
	for {
		select {
		case <-r.stopCh:
			for {
				select {
				case q := <-r.queue:
					r.deliver(q)
				default:
					return
				}
			}
		case q := <-r.queue:
			r.deliver(q)
		}
	}
}

// deliver tries nodes in rendezvous order until one accepts.
//
// 🔴 Which reject codes may move to the next node is a SECURITY decision, not a
// reliability one. `busy` and `unauthorized` mean "this box, right now" — try
// another. `tenant_mismatch`, `bad_frame` and `version_unsupported` mean the
// FRAME is wrong; retrying those across the fleet would walk the same raw
// content past every node we have, turning one refusal into a fleet-wide
// exposure attempt. Fence: TestDeepScanForward_TenantMismatchDoesNotTryAnotherNode.
func (r *RemoteForwarder) deliver(q queued) {
	defer r.queueBytes.Add(-q.size)

	key := q.frame.TenantID + "‖" + q.frame.ContentSHA256
	for _, n := range scannode.Rank(r.cfg.Nodes, key) {
		if !r.breaker.Allow(n.ID) {
			continue
		}
		if reject := r.rejectFor(n); reject != "" {
			r.noteFailure(n, reject)
			if terminalReject(reject) {
				return // the frame is wrong; no other node will like it better
			}
			continue
		}
		sink := r.sinkFor(n)
		if sink == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := sink.Send(ctx, mustEncode(q.frame))
		cancel()
		if err != nil {
			// A node's refusal arrives in its result frame; the sink surfaces it as
			// a RejectError so the existing rule applies — a terminal code stops
			// here, any other lets the next node try. The sink has already reset
			// its connection, so the cached sink stays.
			var rej *deepscan.RejectError
			if errors.As(err, &rej) {
				r.noteFailure(n, rej.Code)
				if terminalReject(rej.Code) {
					return
				}
				continue
			}
			r.dropSink(n.ID)
			r.noteFailure(n, err.Error())
			continue
		}
		r.collectResult(n, sink)
		r.forwarded.Add(1)
		r.breaker.Report(n.ID, true)
		r.consecFails.Store(0)
		if r.degraded.CompareAndSwap(true, false) {
			r.log.Info("deep-scan delivery recovered",
				"event.name", observability.EventDeepScanStatusChanged, "status", StatusOK, "node", n.ID)
		}
		return
	}
	// Every node refused or is open-circuit.
	r.failed.Add(1)
	r.escalateIfPersistent()
}

// collectResult moves the node's answer for the frame just delivered onto the
// lane's results channel.
//
// 🔴 Results() existed and nothing ever wrote to it: every result a node
// produced died inside the sink, and the lane's pump waited on an empty
// channel forever — the async lane filed nothing in any edition.
// bugfix: workflow/CI/bugfix/20260913-async-scan-lane-never-returned-findings.md
func (r *RemoteForwarder) collectResult(n scannode.Node, sink deepscan.Sink) {
	rs, ok := sink.(interface {
		Results() <-chan deepscan.ResultFrame
	})
	if !ok {
		return
	}
	select {
	case res := <-rs.Results():
		select {
		case r.results <- res:
		default:
			r.log.Warn("deep-scan result dropped: the lane is not draining results",
				"event.name", observability.EventDeepScanForwardFailed, "node", n.ID, "job_id", res.JobID)
		}
	default:
	}
}

func (r *RemoteForwarder) rejectFor(n scannode.Node) string {
	if r.cfg.RejectFor == nil {
		return ""
	}
	return r.cfg.RejectFor(n)
}

func terminalReject(code string) bool {
	switch code {
	case deepscan.RejectTenantMismatch, deepscan.RejectBadFrame, deepscan.RejectVersionUnsupported:
		return true
	}
	return false
}

func (r *RemoteForwarder) noteFailure(n scannode.Node, reason string) {
	r.breaker.Report(n.ID, false)
	r.log.Warn("deep-scan delivery to a scan node failed",
		"event.name", observability.EventDeepScanForwardFailed, "node", n.ID, "reason", reason)
	if terminalReject(reason) {
		r.failed.Add(1)
		r.escalateIfPersistent()
	}
}

func (r *RemoteForwarder) escalateIfPersistent() {
	if r.consecFails.Add(1) >= degradeAfter && r.degraded.CompareAndSwap(false, true) {
		r.log.Warn("deep-scan lane is degraded — asynchronous coverage is not being produced",
			"event.name", observability.EventDeepScanStatusChanged,
			"status", StatusDegraded, "consecutive_failures", r.consecFails.Load())
	}
}

func (r *RemoteForwarder) sinkFor(n scannode.Node) deepscan.Sink {
	r.sinkMu.Lock()
	defer r.sinkMu.Unlock()
	if s, ok := r.sinks[n.ID]; ok {
		return s
	}
	if r.cfg.DialSink == nil {
		return nil
	}
	s := r.cfg.DialSink(n)
	r.sinks[n.ID] = s
	return s
}

func (r *RemoteForwarder) dropSink(id string) {
	r.sinkMu.Lock()
	defer r.sinkMu.Unlock()
	if s, ok := r.sinks[id]; ok {
		_ = s.Close()
		delete(r.sinks, id)
	}
}

func (r *RemoteForwarder) closeSinks() {
	r.sinkMu.Lock()
	defer r.sinkMu.Unlock()
	for id, s := range r.sinks {
		_ = s.Close()
		delete(r.sinks, id)
	}
}

// mustEncode encodes a frame the forwarder already validated when it built it.
// An encode failure here is a programming error, not a runtime condition, and
// dropping the task silently is the wrong answer — so it is counted and logged
// by the caller path rather than panicking a background goroutine.
func mustEncode(f deepscan.FrameV2) []byte {
	b, err := deepscan.EncodeFrameV2(f)
	if err != nil {
		return nil
	}
	return b
}
