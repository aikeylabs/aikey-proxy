package asyncscan

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/deepscanfwd"
	"github.com/AiKeyLabs/pkg/deepscan"
)

// PieceJob is the unit both lanes carry. Aliased from deepscanfwd so the local
// executor and the remote forwarder cannot drift into two shapes of "one piece
// of work" — the whole point of the local lane is that it produces results a
// remote node would have produced.
type PieceJob = deepscanfwd.PieceJob

// Executor states reported in the health section (design §4b.3).
const (
	ExecutorAbsent  = "absent"  // no child running (the normal resting state)
	ExecutorIdle    = "idle"    // child alive, nothing queued
	ExecutorRunning = "running" // child alive and working
)

// LocalExecutorConfig configures the on-machine background lane.
type LocalExecutorConfig struct {
	QueueMax   int
	QueueBytes int64
	// IdleStop is how long the child may sit unused before it is shut down.
	IdleStop time.Duration
	// DetectTimeout bounds ONE chunk.
	DetectTimeout time.Duration
	Logger        *slog.Logger
	// OnChildStopped is a test seam for observing the idle shutdown.
	OnChildStopped func()
}

// ExecutorStats is the health projection.
type ExecutorStats struct {
	Executor     string
	Queued       int
	Dropped      uint64
	DroppedBytes uint64
	Completed    uint64
	Failed       uint64
}

// LocalExecutor runs the rule back-scan on THIS machine, in its own detector
// child, for content that has no scan node to go to: Personal and Trial always,
// personal-routed pieces anywhere, and team pieces when `team_async_scan` says
// local.
//
// 🔴 ITS OWN CHILD, NOT THE REQUEST POOL (design §3.8, DEC-scan-node-deepscan-15).
// A 256 KiB piece is 16 chunks at ~11 ms each — ~180 ms of detector time
// (measured, baseline-forensics §F8 ②). The request path's detect budget is 1 ms.
// Sharing the pool would mean every request arriving during a background piece
// times out, the hook flips degraded, and traffic is forwarded UNFILTERED. The
// background lane would have switched off synchronous compliance in bursts.
//
// 🔴 ON DEMAND, AND IT GOES AWAY. The child costs 163 MB resident and 235 MB
// while working (measured on macOS arm64, baseline-forensics §F8 ③ — 3.6–5.2x the
// 45 MB the design assumed). That is a lot to ask of an employee laptop for a lane
// that is idle most of the time, so the child is spawned on the first job and shut
// down after IdleStop.
type LocalExecutor struct {
	cfg   LocalExecutorConfig
	spawn func() (apphook.Hook, error)
	log   *slog.Logger

	queue  chan PieceJob
	stopCh chan struct{}
	doneCh chan struct{}
	once   sync.Once

	mu    sync.Mutex
	child apphook.Hook

	state        atomic.Value // string
	queueBytes   atomic.Int64
	dropped      atomic.Uint64
	droppedBytes atomic.Uint64
	completed    atomic.Uint64
	failed       atomic.Uint64

	results chan deepscan.ResultFrame
}

// NewLocalExecutor returns a started executor. spawn builds the background child
// — injected rather than constructed here because building a detector child needs
// the supervisor's vault-derived env (design §3.8), which this package must not
// reach into.
func NewLocalExecutor(cfg LocalExecutorConfig, spawn func() (apphook.Hook, error)) *LocalExecutor {
	if cfg.QueueMax <= 0 {
		cfg.QueueMax = 256
	}
	if cfg.QueueBytes <= 0 {
		cfg.QueueBytes = 16 << 20
	}
	if cfg.IdleStop <= 0 {
		cfg.IdleStop = 300 * time.Second
	}
	if cfg.DetectTimeout <= 0 {
		// 2000 ms, not the request path's 150 ms: measured worst chunk is 17.7 ms,
		// so this is ~100x headroom for a loaded laptop. The request-path default
		// would make the background pool trip, report degraded and restart in a
		// loop on any slow machine (childhook.go:637-653).
		cfg.DetectTimeout = 2000 * time.Millisecond
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	x := &LocalExecutor{
		cfg: cfg, spawn: spawn, log: cfg.Logger,
		queue:   make(chan PieceJob, cfg.QueueMax),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
		results: make(chan deepscan.ResultFrame, cfg.QueueMax),
	}
	x.state.Store(ExecutorAbsent)
	go x.runExecutorLoop()
	return x
}

// Results yields the results this lane produced.
func (x *LocalExecutor) Results() <-chan deepscan.ResultFrame { return x.results }

// Submit offers one job. NEVER blocks; safe on a nil receiver.
func (x *LocalExecutor) Submit(job PieceJob) bool {
	if x == nil {
		return false
	}
	size := int64(len(job.Text))
	if x.queueBytes.Load()+size > x.cfg.QueueBytes {
		x.countDrop(size, "byte_budget")
		return false
	}
	select {
	case x.queue <- job:
		x.queueBytes.Add(size)
		return true
	default:
		x.countDrop(size, "queue_full")
		return false
	}
}

func (x *LocalExecutor) countDrop(size int64, reason string) {
	x.dropped.Add(1)
	x.droppedBytes.Add(uint64(size))
	x.log.Warn("local async scan dropped a piece; its tail will not be scanned unless the content is sent again",
		"event.name", observability.EventAsyncScanExecutorSaturated,
		"reason", reason, "bytes", size, "dropped_total", x.dropped.Load())
}

// Stats snapshots the counters.
func (x *LocalExecutor) Stats() ExecutorStats {
	if x == nil {
		return ExecutorStats{Executor: ExecutorAbsent}
	}
	state, _ := x.state.Load().(string)
	return ExecutorStats{
		Executor: state, Queued: len(x.queue),
		Dropped: x.dropped.Load(), DroppedBytes: x.droppedBytes.Load(),
		Completed: x.completed.Load(), Failed: x.failed.Load(),
	}
}

// Close stops the lane and its child.
func (x *LocalExecutor) Close(ctx context.Context) error {
	if x == nil {
		return nil
	}
	x.once.Do(func() { close(x.stopCh) })
	select {
	case <-x.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runExecutorLoop is the single background worker.
//
// Named runExecutorLoop rather than `loop` for the same reason
// deepscanfwd.runDeliveryLoop is: the hot-path call-graph fence resolves method
// calls by NAME across the module, and a `loop` here would be treated as reachable
// from every `x.loop()` in the proxy — including supervisor loops that read files,
// which turns PLANE-01 red with a bogus path. See that fence's header.
func (x *LocalExecutor) runExecutorLoop() {
	defer close(x.doneCh)
	defer x.stopChild()

	idle := time.NewTimer(x.cfg.IdleStop)
	defer idle.Stop()

	for {
		select {
		case <-x.stopCh:
			return
		case job := <-x.queue:
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			x.state.Store(ExecutorRunning)
			x.run(job)
			x.queueBytes.Add(-int64(len(job.Text)))
			x.state.Store(ExecutorIdle)
			idle.Reset(x.cfg.IdleStop)
		case <-idle.C:
			// Nothing for IdleStop — give the memory back.
			x.stopChild()
			idle.Reset(x.cfg.IdleStop)
		}
	}
}

// run scans one piece, chunk by chunk, on the background child.
func (x *LocalExecutor) run(job PieceJob) {
	hook, err := x.childHook()
	if err != nil {
		x.failed.Add(1)
		x.log.Warn("local async scan could not start its detector child; the tail of this content is not scanned",
			"event.name", observability.EventAsyncScanExecutorSaturated, "error", err)
		return
	}
	// 🔴 The local lane builds its frame with the SAME function the remote lane
	// uses (deepscanfwd.BuildFrame), and scans exactly the chunks that frame
	// carries. Chunking the piece a second way here would mean a piece scanned
	// locally and the same piece scanned on a node could disagree about what was
	// covered — and the whole premise of falling back to the local lane is that
	// its answer is interchangeable with a node's. The empty token is deliberate:
	// there is no node to authorize against on this path.
	frame, cov := deepscanfwd.BuildFrame(job, "", deepscanfwd.DefaultMaxPieceBytes)

	res := deepscan.ResultFrame{
		JobID: job.JobID, Status: cov.Status, Reason: cov.Reason,
		ScannedBytes: cov.ScannedBytes, TotalBytes: cov.TotalBytes,
	}
	if res.Status == "" {
		res.Status = deepscan.StatusComplete
	}
	for _, c := range frame.RuleChunks {
		if c.Start < 0 || c.End > len(frame.Prompt) || c.Start >= c.End {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), x.cfg.DetectTimeout)
		resp := hook.Detect(ctx, &apphook.Request{
			Direction:  apphook.DirectionInbound,
			Payload:    []byte(frame.Prompt[c.Start:c.End]),
			RouteClass: apphook.RouteClassTeam, // team class = "return the event", never upload
		})
		cancel()
		if resp == nil || resp.Degraded {
			// A degraded chunk is NOT a clean chunk. Marking the result partial is
			// the difference between "we looked and found nothing" and "we could
			// not look" — the distinction scan_coverage exists to carry.
			res.Status = deepscan.StatusPartial
			res.Reason = deepscan.ReasonTransient
			continue
		}
		res.Engines.Rules.Chunks++
	}
	res.Engines.Rules.Status = res.Status
	x.completed.Add(1)
	select {
	case x.results <- res:
	default:
		// Nobody is draining results — count it rather than block the worker.
		x.failed.Add(1)
	}
}

func (x *LocalExecutor) childHook() (apphook.Hook, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.child != nil {
		return x.child, nil
	}
	h, err := x.spawn()
	if err != nil {
		return nil, err
	}
	x.child = h
	return h, nil
}

func (x *LocalExecutor) stopChild() {
	x.mu.Lock()
	had := x.child != nil
	x.child = nil
	x.mu.Unlock()
	if !had {
		return
	}
	x.state.Store(ExecutorAbsent)
	if x.cfg.OnChildStopped != nil {
		x.cfg.OnChildStopped()
	}
}
