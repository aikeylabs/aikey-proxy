// childhook.go — a Hook implementation that spawns a long-running child binary
// and talks to it over stdin/stdout via length-prefixed binary frames.
//
// This is the ONE place where proxy interacts with the child IPC. Any business
// logic about WHAT the child does belongs to the child itself (it's a separate
// binary). proxy just spawns, pipes, and respects the contract.
//
// The wire format itself is NOT defined here. It lives in
// github.com/AiKeyLabs/pkg/pipewire, imported by this repo AND by
// ai-compliance-detector, so a protocol change breaks the build on both sides
// instead of mis-parsing at runtime. Until 2026-08-10 this file carried its own
// hand-written copy of the frame header, the response offsets, the op codes and
// the MaskMeta JSON tags — five such copies existed across three repos and the
// protocol drifted on two of its three bumps. Do not reintroduce a local copy:
// add to pipewire and bump ProtocolVersion there.
//
// Concurrency model (v3, 2026-06-06 — the "A" half of 双进程+A):
//   - One dedicated reader goroutine per spawn drains the child's stdout and
//     demuxes each response to its waiting request by a 4-byte request-id.
//   - Detect/ListPacks are ASYNC: assign a req-id, register a pending channel,
//     write the request (the pipeSession's write permit serializes the pipe
//     write), then wait on that channel. BOTH halves — getting the request out
//     and waiting for the reply — are bounded by the per-call timeout; the write
//     half being unbounded was the 2026-08-13 P0. Many Detects can be in flight at
//     once on a single pipe, so the child (with its own internal worker pool) can
//     process them concurrently and reply out of order.
//   - Degraded fallback on any IO error; bounded lazy self-heal on the next call.
//
// One ChildHook == one child process == one pipe. The FilterPool (filterpool.go)
// wraps M of these for cross-process fan-out + isolation (the "C" half).
package apphook

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/pkg/aikeycompat"
	"github.com/AiKeyLabs/pkg/pipewire"
)

// ChildHookConfig configures a ChildHook.
type ChildHookConfig struct {
	Name       string   // app name, e.g. "ai-compliance-detector"
	BinaryPath string   // absolute path to child binary
	BinaryArgs []string // extra args to pass to child (e.g. --rules ...)
	// ExtraEnv are "KEY=VALUE" entries appended to the child's environment (on
	// top of the proxy's inherited env). Used to pass per-app runtime config
	// the proxy derives from vault — e.g. AIKEY_COMPLIANCE_RECORD_ALLOW from the
	// app_records.filter_record_allow flag. The child re-reads these at spawn,
	// so a flag change → vault change_seq → proxy reload → re-spawn picks it up.
	ExtraEnv           []string
	Timeout            time.Duration // per-Detect deadline (default 1ms)
	ReadyTimeout       time.Duration // how long to wait for ready sentinel (default 5s)
	RestartMaxAttempts int           // 0 = unlimited (default 3)
	RestartBaseDelay   time.Duration // initial backoff (default 100ms)
	RestartMaxDelay    time.Duration // backoff cap (default 30s)
	ProtocolVersion    byte          // expected — must match child's wire version
}

func (c *ChildHookConfig) applyDefaults() {
	if c.Timeout == 0 {
		c.Timeout = 1 * time.Millisecond
	}
	if c.ProtocolVersion == 0 {
		// Single source of truth — do NOT hand-write the number here. This used
		// to be a literal `4` maintained in parallel with the detector's own
		// constant, with nothing asserting the two matched.
		c.ProtocolVersion = pipewire.ProtocolVersion
	}
	if c.ReadyTimeout == 0 {
		c.ReadyTimeout = 5 * time.Second
	}
	if c.RestartMaxAttempts == 0 {
		c.RestartMaxAttempts = 3
	}
	if c.RestartBaseDelay == 0 {
		c.RestartBaseDelay = 100 * time.Millisecond
	}
	if c.RestartMaxDelay == 0 {
		c.RestartMaxDelay = 30 * time.Second
	}
}

// childResponse is a decoded response frame, delivered to the waiting caller by
// the reader goroutine via the pending map.
type childResponse struct {
	findings []byte // ActionMask → masked payload; ListPacks → JSON report; else per-op
	maskmeta []byte // v4: restorable-mask JSON (offsets only); empty unless the mask is restorable
	event    []byte // team-routed compliance event for the proxy to forward; empty otherwise
	action   byte
}

// wireMaskMeta is the detector's v4 restorable-mask JSON contract.
//
// It used to be a hand-retyped mirror of pipe.MaskMeta living in this file,
// justified by "proxy and detector ship in lockstep". That justification was
// wrong in a way the version byte cannot catch: the frame version guards the
// BINARY layout, never the JSON field names inside MaskMeta, so a renamed tag
// would have decoded to zero values silently. It is now an alias of the shared
// type, which makes any change a compile error on both sides.
type wireMaskMeta = pipewire.MaskMeta

// pipeSession owns ONE spawn generation's stdin channel: the buffered writer,
// the OS pipe FD, and the single-slot permit that serializes frame writes.
//
// WHY this is a per-generation value instead of the (stdin + stdinPipe +
// writeMu) triple that used to live on ChildHook —
// workflow/CI/bugfix/20260813-childhook-write-before-deadline-wedges-main-path.md
// (P0, 2026-08-13):
//
// A child that is ALIVE BUT NOT READING (ai-compliance-detector takes its worker
// semaphore INSIDE the stdin read loop, and AIKEY_COMPLIANCE_WORKERS defaults to
// 1, so a single in-flight detection stops it draining stdin) fills the OS pipe
// buffer, after which write(2) blocks forever. When that blocking state lived on
// the hook it poisoned the hook itself: Shutdown and restart both had to take the
// same writeMu to close the FD, so process exit and self-heal were wedged
// together with the user's request — one sick side-car welded the whole main path
// shut.
//
// Scoping the state to a session gives two properties that fix that structurally:
//
//   - A stuck writer can only ever poison the generation it belongs to, and that
//     generation is retired the moment a write deadline trips. Nothing a new
//     generation needs is held by the old one.
//   - close() deliberately takes no permit, so closing the FD is never blocked by
//     an in-flight write. Closing the write end is also what UNBLOCKS that write
//     (Go's poller evicts pending I/O on Close), so the abandoned write goroutine
//     returns instead of leaking.
type pipeSession struct {
	w    *bufio.Writer
	pipe io.WriteCloser
	// writeSlot is a 1-capacity semaphore rather than a sync.Mutex because
	// acquiring it MUST be abortable by the caller's ctx: with a Mutex, the second
	// caller queued behind a wedged writer blocks in Lock() with no deadline of
	// its own — that is how "the 4th request onward hangs forever" happened.
	writeSlot chan struct{}
	// broken marks the frame stream unusable. Set when a write is abandoned
	// mid-frame: an unknown prefix of that frame may already sit in the pipe, so
	// every later frame would be parsed at the wrong offset by the child. A broken
	// session is never written to again — it is torn down and respawned.
	broken    atomic.Bool
	closeOnce sync.Once
}

// close shuts the write end of the pipe. Idempotent and permit-free — see the
// type comment: being callable while a write is stuck is the whole point.
func (s *pipeSession) close() {
	s.closeOnce.Do(func() { _ = s.pipe.Close() })
}

// ChildHook is a generic Hook that delegates to a spawned child binary.
type ChildHook struct {
	cmd     *exec.Cmd
	pending map[uint32]chan *childResponse
	// session is the current generation's stdin channel, swapped atomically on
	// spawn/restart/shutdown so readers of it never block behind a stuck write.
	session atomic.Pointer[pipeSession]
	// status is atomically swapped so Status() is wait-free.
	status atomic.Pointer[Status]
	// contentVersion is the fingerprint of the child's effective CONTENT set (its
	// hot-swappable ruleset), refreshed by a background poll. nil = unknown.
	// Deliberately separate from status.Version, which describes the BINARY and
	// therefore cannot move when the child swaps packs in place. See
	// contentversion.go for the whole mechanism.
	contentVersion atomic.Pointer[string]
	// contentVersionReason records WHY contentVersion is nil, as one of the
	// contentVersionReason* constants. nil = never polled.
	//
	// WHY a separate reason and not just "unknown": the two unknown causes have
	// OPPOSITE operator actions. A child that is degraded needs a restart; a child
	// that is alive and simply too old to answer op=ListPacks needs an UPGRADE,
	// and until then the proxy runs with its verdict cache switched off (96% hit
	// rate → 0) as a pure, silent latency regression (review finding B6). Both
	// used to collapse into the same nil pointer, so the endpoint could report
	// "cache off" but never "and here is the one command that fixes it".
	contentVersionReason atomic.Pointer[string]
	// pollStop / pollOnce / stopPollOnce own the content-version poll's lifetime.
	// It is started once on the first successful spawn and stopped once on
	// Shutdown; both entry points are idempotent because their callers are.
	pollStop     chan struct{}
	pollOnce     sync.Once
	stopPollOnce sync.Once
	cfg          ChildHookConfig
	gen    atomic.Uint64 // spawn generation; the reader tied to an older gen won't clobber a newer spawn's state
	// lastRecoverAt (unix nano) gates the lazy self-heal: when degraded, the next
	// request synchronously restarts the child, but a storm of requests must not
	// hammer respawns — only one attempt per recoverCooldown (CAS-guarded).
	lastRecoverAt atomic.Int64
	// mu protects spawn/exit state transitions (cmd, generation).
	mu sync.Mutex
	// pending holds in-flight requests keyed by request-id. The reader delivers
	// each response to pending[id]; a timed-out caller removes its own entry.
	pendingMu sync.Mutex
	nextReqID atomic.Uint32
	// degraded is set when child is unusable; cleared on successful restart.
	degraded atomic.Bool
}

// NewChildHook creates a ChildHook in DISABLED state. Caller must call Start
// to launch the child.
func NewChildHook(in *ChildHookConfig) *ChildHook {
	cfg := *in // copy so applyDefaults never mutates the caller's value
	cfg.applyDefaults()
	h := &ChildHook{cfg: cfg, pending: make(map[uint32]chan *childResponse), pollStop: make(chan struct{})}
	h.degraded.Store(true) // start degraded; flip after successful Start
	h.status.Store(&Status{
		Healthy:        false,
		DegradedReason: DegradeReasonNotStarted,
		BinaryPath:     cfg.BinaryPath,
	})
	return h
}

// Start spawns the child. Returns nil on success (child responded with ready
// sentinel within ReadyTimeout), error otherwise.
//
// On error, hook stays degraded — caller should still register it; Detect will
// return degraded responses safely.
func (h *ChildHook) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.spawnLocked(ctx)
}

func (h *ChildHook) spawnLocked(ctx context.Context) error {
	// Sanity check
	if _, err := os.Stat(h.cfg.BinaryPath); err != nil {
		h.markDegraded("not_installed: " + err.Error())
		return fmt.Errorf("apphook %s: binary not found at %s: %w", h.cfg.Name, h.cfg.BinaryPath, err)
	}

	cmd := exec.Command(h.cfg.BinaryPath, h.cfg.BinaryArgs...) //nolint:gosec // operator-configured app-hook binary, path stat-verified above; args from trusted vault/config, never request input
	// Never flash a console window on Windows: the proxy runs console-less,
	// so a console-subsystem hook child would otherwise pop a visible
	// terminal window for its whole lifetime (same class as the 2026-07-07
	// web-bridge window-flash bug). No-op on Unix; stdio pipes unaffected.
	aikeycompat.HideSpawnConsole(cmd)
	// Inherit the proxy's env (the child relies on it for AIKEY_* config) and
	// append any per-app ExtraEnv the supervisor derived from vault.
	if len(h.cfg.ExtraEnv) > 0 {
		cmd.Env = append(os.Environ(), h.cfg.ExtraEnv...)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		h.markDegraded("pipe_setup_failed")
		return fmt.Errorf("apphook %s: stdin pipe: %w", h.cfg.Name, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		h.markDegraded("pipe_setup_failed")
		return fmt.Errorf("apphook %s: stdout pipe: %w", h.cfg.Name, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		h.markDegraded("pipe_setup_failed")
		return fmt.Errorf("apphook %s: stderr pipe: %w", h.cfg.Name, err)
	}

	if err := cmd.Start(); err != nil {
		h.markDegraded("spawn_failed: " + err.Error())
		return fmt.Errorf("apphook %s: spawn: %w", h.cfg.Name, err)
	}

	// Wait for ready sentinel on stderr — child writes a line containing
	// "ready" (and version info) once its pipe is set up.
	readyCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		sentReady := false
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			if !sentReady && containsReadySentinel(line) {
				select {
				case readyCh <- line:
				default:
				}
				sentReady = true
				continue // KEEP draining — do NOT return (see below)
			}
			if sentReady {
				// Drain + surface child stderr for the life of this generation. WHY
				// (2026-06-13 form-② filter-degrade RCA): the old code `return`ed
				// here, so after startup the child's stderr was NEVER read. Two harms:
				// (1) a 64KB pipe buffer eventually FILLS and the child BLOCKS on its
				// next stderr write → it can't service Detect → every call times out →
				// silent fail-open; (2) the child's own warnings/errors (the degrade
				// reason) were discarded — a diagnosis blind spot. Draining fixes the
				// deadlock; logging makes the child's voice visible link-side.
				slog.Warn("apphook: child stderr",
					"event.name", "proxy.apphook.child_stderr",
					"name", h.cfg.Name, "line", line)
			}
		}
	}()

	select {
	case version := <-readyCh:
		h.cmd = cmd
		gen := h.gen.Add(1) // bump generation; the reader below is tied to it
		h.session.Store(&pipeSession{
			w:         bufio.NewWriterSize(stdin, 64*1024),
			pipe:      stdin,
			writeSlot: make(chan struct{}, 1),
		})
		h.degraded.Store(false)
		h.status.Store(&Status{
			Healthy:       true,
			BinaryPath:    h.cfg.BinaryPath,
			Version:       version,
			LastSpawnedAt: time.Now(),
			RestartCount:  h.status.Load().RestartCount,
		})
		// Reader owns its own stdout reader for this generation. It exits when the
		// pipe closes (process killed on restart/shutdown); a stale (older-gen)
		// reader exiting won't clobber a newer spawn (gen check in readLoop).
		go h.readLoop(bufio.NewReaderSize(stdout, 64*1024), gen)
		// Track the child's hot-swappable content set from here on. Started after
		// the pipe is live (it talks over the same pipe) and only once: the poll
		// outlives spawn generations because a restart replaces the pipe, not the
		// content set. See contentversion.go.
		h.startContentVersionPoll()
		return nil
	case <-time.After(h.cfg.ReadyTimeout):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		h.markDegraded("ready_timeout")
		return fmt.Errorf("apphook %s: child did not signal ready within %s", h.cfg.Name, h.cfg.ReadyTimeout)
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		h.markDegraded("startup_canceled")
		return ctx.Err()
	}
}

// readLoop drains one generation's stdout, demuxing each response frame to its
// waiting caller by request-id. It returns when the pipe errors (child died /
// restart / shutdown). If no newer generation has spawned, it marks the hook
// degraded so the next call lazily self-heals. In-flight callers are NOT failed
// here — they time out via their own ctx (fail-open), which avoids racing a
// concurrent restart's fresh requests.
func (h *ChildHook) readLoop(r *bufio.Reader, gen uint64) {
	for {
		payload, err := h.readFrame(r)
		if err != nil {
			if h.gen.Load() == gen {
				h.markDegraded("read_failed: " + err.Error())
			}
			return
		}
		reqID, resp, ok := decodeChildResponsePayload(payload)
		if !ok {
			continue // malformed; drop (a real desync surfaces as a read error next)
		}
		h.pendingMu.Lock()
		ch, ok := h.pending[reqID]
		if ok {
			delete(h.pending, reqID)
		}
		h.pendingMu.Unlock()
		if ok {
			ch <- resp // buffered (cap 1); never blocks even if the caller timed out
		}
	}
}

// decodeChildResponsePayload adapts the shared wire decoder into this package's
// internal childResponse. The layout itself is owned by pipewire.DecodeResponse
// (the same function the detector encodes with), so the offsets cannot drift.
// ok=false on malformed lengths — the caller drops the frame.
func decodeChildResponsePayload(payload []byte) (reqID uint32, resp *childResponse, ok bool) {
	decoded, err := pipewire.DecodeResponse(payload)
	if err != nil {
		return 0, nil, false
	}
	return decoded.ReqID, &childResponse{
		action:   decoded.Action,
		findings: decoded.Findings,
		maskmeta: decoded.MaskMeta,
		event:    decoded.Event,
	}, true
}

func (h *ChildHook) removePending(reqID uint32) {
	h.pendingMu.Lock()
	delete(h.pending, reqID)
	h.pendingMu.Unlock()
}

func (h *ChildHook) markDegraded(reason string) {
	// Swap returns the PRIOR value: log only on the healthy→degraded transition,
	// not on every failed call (avoids spam while still surfacing the reason).
	wasHealthy := !h.degraded.Swap(true)
	old := h.status.Load()
	h.status.Store(&Status{
		Healthy:        false,
		DegradedReason: reason,
		BinaryPath:     h.cfg.BinaryPath,
		Version:        old.Version,
		LastSpawnedAt:  old.LastSpawnedAt,
		RestartCount:   old.RestartCount,
		LastErrorAt:    time.Now(),
	})
	if wasHealthy {
		// Why: the dispatcher only logs a generic "hook degraded" with NO reason —
		// the WHY (read_failed/write_failed/ready_timeout/listpacks_failed/child
		// detect failed) was computed here but never recorded, making field
		// root-cause impossible. Surface it. (2026-06-13 form-② filter-degrade RCA.)
		slog.Warn("apphook: child hook degraded",
			"event.name", "proxy.apphook.degraded",
			"name", h.cfg.Name, "reason", reason)
	}
}

// recoverCooldown bounds how often the lazy self-heal will attempt a respawn,
// and lazyRestartBound caps how long a hot-path request stalls waiting for the
// child to come back (don't use the full ReadyTimeout — a user request must not
// hang that long; a slower-than-bound restart is finished by the next request).
const (
	recoverCooldown  = 2 * time.Second
	lazyRestartBound = 2 * time.Second
)

// restart kills the current (crashed / pipe-desynced) child and re-spawns a
// fresh one. The doc-comment's "background restart" was never implemented; this
// is the on-demand equivalent — recover when a request actually needs the
// filter, not proactively (a compliance detector is only needed under traffic).
func (h *ChildHook) restart(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
		_ = h.cmd.Wait()
		h.cmd = nil
	}
	// Retire the old generation's pipe. Swapping to nil makes writes fail fast
	// ("stdin closed") until spawnLocked installs a fresh session, and close()
	// needs no write permit — so a child wedged mid-write can no longer block its
	// own replacement, which is what made the self-heal path unreachable
	// (bugfix 20260813-childhook-write-before-deadline-wedges-main-path.md).
	//
	// Not marked `broken`: that flag means "frame stream desynced by an abandoned
	// write", and a caller racing this restart deserves the accurate
	// "write_failed: file already closed" rather than a fabricated write timeout.
	if s := h.session.Swap(nil); s != nil {
		s.close()
	}
	old := h.status.Load()
	h.status.Store(&Status{
		Healthy:        false,
		DegradedReason: DegradeReasonRestarting,
		BinaryPath:     h.cfg.BinaryPath,
		Version:        old.Version,
		LastSpawnedAt:  old.LastSpawnedAt,
		RestartCount:   old.RestartCount + 1,
	})
	return h.spawnLocked(ctx) // clears degraded on success
}

// lazyRecover is the synchronous self-heal, called (without holding any lock)
// when the child is degraded. CAS-guarded so a storm of concurrent Detects
// triggers at most one respawn per recoverCooldown; time-bounded so a hot
// request stalls ≤ lazyRestartBound. On success h.degraded is cleared and the
// caller proceeds with a fresh pipe; on failure the caller fails open and the
// next request (after the cooldown) retries.
// nudgeRecover is THE trigger for the request-driven self-heal. Every caller
// that observes a degraded child goes through here; nobody starts lazyRecover
// directly.
//
// 🔴 WHY IT IS A NAMED ENTRY POINT AND NOT AN INLINE `go h.lazyRecover()`
// (2026-08-14, review finding B39). The self-heal used to be reachable from
// exactly one place — roundtrip, i.e. a request that was ALREADY being handed
// to the broken child. Once FilterPool.pick() stopped routing user content to
// degraded workers (which it had to: that content was being forwarded upstream
// un-inspected), that single trigger would have disappeared with it and a
// transient degrade would have become a permanent amputation. Splitting the
// TRIGGER from the PAYLOAD is what resolves that: the pool nudges the workers it
// skips, so traffic still drives recovery — it just no longer pays for it with a
// request's worth of un-inspected content.
//
// Non-blocking and self-throttling: the cooldown is checked before the goroutine
// is created (pick() calls this on the hot path, so a storm of requests against
// a dead pool must not become a storm of goroutines), and lazyRecover re-checks
// it under CAS so this pre-check can never over-admit.
func (h *ChildHook) nudgeRecover() {
	if !h.degraded.Load() || !h.recoverDue() {
		return
	}
	go h.lazyRecover()
}

// recoverDue reports whether the cooldown since the last respawn attempt has
// elapsed. Advisory only — lazyRecover re-tests it under CAS.
func (h *ChildHook) recoverDue() bool {
	return time.Now().UnixNano()-h.lastRecoverAt.Load() >= int64(recoverCooldown)
}

func (h *ChildHook) lazyRecover() {
	now := time.Now().UnixNano()
	last := h.lastRecoverAt.Load()
	if now-last < int64(recoverCooldown) {
		return // recently attempted — fail open until the cooldown elapses
	}
	if !h.lastRecoverAt.CompareAndSwap(last, now) {
		return // another goroutine won the recovery slot
	}
	rctx, cancel := context.WithTimeout(context.Background(), lazyRestartBound)
	defer cancel()
	_ = h.restart(rctx) // failure path stays degraded (logged via markDegraded)
}

// Name implements Hook.
func (h *ChildHook) Name() string { return h.cfg.Name }

// roundtrip sends one request and waits for its response (or the ctx deadline).
// Concurrency-safe: many roundtrips can be in flight at once, demuxed by req-id.
func (h *ChildHook) roundtrip(ctx context.Context, op, routeClass byte, body []byte) (*childResponse, error) {
	// Lazy self-heal: if degraded, kick a bounded respawn off in the BACKGROUND
	// and fail open immediately. The restart must NOT run on the hot path —
	// lazyRecover uses context.Background()+lazyRestartBound (2s), ignoring this
	// request's ctx, so calling it synchronously stalled the very first Detect
	// after a child died for up to 2s, violating the AppHook fail-open invariant
	// (a degraded/unreachable child must never block a user request). lazyRecover
	// is cooldown/CAS-guarded, so concurrent Detects spawn at most one restart;
	// once it clears `degraded`, the NEXT Detect uses the recovered child.
	if h.degraded.Load() {
		h.nudgeRecover()
		return nil, errDegraded
	}

	s := h.session.Load()
	if s == nil {
		h.markDegraded("write_failed: stdin closed")
		return nil, errStdinClosed
	}

	reqID := h.nextReqID.Add(1)
	ch := make(chan *childResponse, 1)
	h.pendingMu.Lock()
	h.pending[reqID] = ch
	h.pendingMu.Unlock()

	payload := pipewire.EncodeRequest(&pipewire.Request{
		Op:         op,
		RouteClass: routeClass,
		ReqID:      reqID,
		Prompt:     string(body),
	})
	if err := h.writeFrame(ctx, s, payload); err != nil {
		h.removePending(reqID)
		return nil, err
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		h.removePending(reqID) // a late response from the reader is dropped
		return nil, ctx.Err()
	}
}

// The Status().DegradedReason values a ChildHook sets on its own. EXPORTED as
// of 2026-08-13 because they stopped being an internal log label: they are now
// projected onto GET /v1/diagnostics/pipeline and `ak doctor` branches on them
// to choose between "restart the proxy" and "the child never started", so they
// are an external contract and belong in an enum rather than as literals at the
// raise site (logging-conventions: reasons are enumerated).
//
// Not exhaustive — the dynamic causes stay prefixed free-form strings
// (`not_installed: <stat error>`, `write_failed: …`, `listpacks_failed: …`)
// because the operator needs the underlying OS error verbatim. Readers must
// therefore match these constants exactly and treat anything else as
// "degraded, cause as reported", never as "unknown state".
const (
	// DegradeReasonWriteTimeout: the request frame could not be handed to the
	// child within the call deadline — the child is ALIVE but has stopped reading
	// its pipe, so the OS buffer filled up (bugfix
	// 20260813-childhook-write-before-deadline-wedges-main-path). Distinct from a
	// crash: the process is still there and `ps` shows it running.
	DegradeReasonWriteTimeout = "write_timeout"
	// DegradeReasonNotStarted: the hook was constructed but Start has never
	// succeeded. NOT the same failure as a wedge — nothing was ever spawned —
	// and conflating the two was exactly what `ak doctor` had to do while
	// `available:false` was the only external signal.
	DegradeReasonNotStarted = "not_started"
	// DegradeReasonRestarting: a restart is in flight. Transient by construction;
	// a surface that renders it as a hard fault will flap.
	DegradeReasonRestarting = "restarting"
)

var (
	errDegraded    = errors.New("apphook: child degraded")
	errStdinClosed = errors.New("apphook: stdin closed")
	// errWriteTimeout means the request frame could not be pushed into the child's
	// pipe before the deadline — the child is alive but has stopped reading, so
	// the OS pipe buffer is full. Distinct from a plain ctx.DeadlineExceeded
	// because it also implies the frame stream is no longer trustworthy.
	errWriteTimeout = errors.New("apphook: write to child timed out (pipe wedged — child alive but not reading)")
)

// writeFrame hands one frame to the child under the caller's deadline and owns
// what happens when that deadline expires.
//
// WHY the whole session is retired on timeout rather than just failing the call
// (bugfix 20260813-childhook-write-before-deadline-wedges-main-path.md):
//
//   - Frame integrity: the abandoned write may have pushed an arbitrary PREFIX of
//     the frame into the pipe. Reusing the stream would make the child parse every
//     subsequent frame at the wrong offset. There is no way to resynchronise a
//     byte-stream protocol from the writer side, so the only correct move is to
//     declare the pipe dead and rebuild it.
//   - Self-heal: markDegraded is the ONLY trigger for lazyRecover, and it used to
//     fire exclusively on a write ERROR. A blocked write returns no error, so a
//     wedged child stayed marked healthy forever and kept being fed requests.
//   - Liveness: close() is what makes the abandoned write return, so this is also
//     the goroutine-leak guard.
//
// s is passed in (rather than re-read from h.session) so a concurrent restart
// that already installed a FRESH session cannot be torn down by a stale timeout.
func (h *ChildHook) writeFrame(ctx context.Context, s *pipeSession, payload []byte) error {
	err := s.writeFrame(ctx, payload)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errWriteTimeout):
		// Order is load-bearing: broken BEFORE close. The stuck writer releases the
		// permit only after close() unblocks its syscall, so any caller still queued
		// for that permit is guaranteed to observe broken == true when it wakes up,
		// and reports write_timeout instead of a confusing "file already closed".
		s.broken.Store(true)
		s.close()
		h.markDegraded(DegradeReasonWriteTimeout)
	default:
		h.markDegraded("write_failed: " + err.Error())
	}
	return err
}

// Detect implements Hook. Async: writes a request and waits for the matching
// response, allowing many concurrent in-flight Detects on one pipe.
func (h *ChildHook) Detect(ctx context.Context, req *Request) *Response {
	ctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()

	start := time.Now()
	resp, err := h.roundtrip(ctx, pipewire.OpDetect, req.RouteClass, req.Payload)
	if err != nil {
		reason := "child degraded"
		if !errors.Is(err, errDegraded) {
			reason = "child detect failed: " + err.Error()
		}
		return &Response{Action: ActionAllow, Degraded: true, Reason: reason}
	}

	res := &Response{
		Action:          Action(resp.action),
		LatencyObserved: time.Since(start),
	}
	if res.Action == ActionMask && len(resp.findings) > 0 {
		res.MutatedPayload = resp.findings
		// v4 restorable-mask metadata. Parse errors are fail-open in the SAFE
		// direction: the mask itself stands, only response-side restore is lost.
		// Loud (失败要显眼) but content-free — maskmeta describes masked spans, so
		// even offsets stay out of the log line.
		if len(resp.maskmeta) > 0 {
			var meta wireMaskMeta
			if err := json.Unmarshal(resp.maskmeta, &meta); err != nil {
				slog.Warn("apphook: restorable-mask metadata unparseable; mask kept, restore disabled",
					"event.name", "proxy.apphook.maskmeta_invalid",
					"name", h.cfg.Name, "error", err, "meta_bytes", len(resp.maskmeta))
			} else {
				for _, r := range meta.Restorables {
					res.Restorables = append(res.Restorables, RestorableMask{
						Token:          r.Token,
						NumberedPrefix: r.NumberedPrefix,
						NumberedSuffix: r.NumberedSuffix,
						Spans:          r.Spans,
					})
				}
			}
		}
	}
	if len(resp.event) > 0 {
		res.Event = resp.event
	}

	// Update status (cheap atomic swap).
	old := h.status.Load()
	h.status.Store(&Status{
		Healthy:       true,
		BinaryPath:    old.BinaryPath,
		Version:       old.Version,
		LastSpawnedAt: old.LastSpawnedAt,
		RestartCount:  old.RestartCount,
		LastDetectAt:  time.Now(),
	})

	return res
}

// ErrPacksUnavailable means the child could not report its effective packs
// (degraded, or an older child that doesn't implement op=4). Admin maps it to a
// "packs unavailable" response — never an error that affects the data plane.
var ErrPacksUnavailable = errors.New("apphook: effective packs unavailable")

// ListPacks queries the child for its currently-effective compliance packs
// (op=4: built-in baseline + pulled packs). Returns the raw JSON report payload.
// Shares the multiplexed pipe (its own req-id), so it never blocks a Detect.
func (h *ChildHook) ListPacks(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()
	return h.listPacks(ctx, true)
}

// listPacks is the shared core. markOnErr distinguishes the two callers:
//
//   - ListPacks (operator-initiated, GET /admin/compliance/packs) passes true —
//     someone asked a direct question and got no answer, which is a health signal
//     about this child and belongs in DegradedReason.
//   - the content-version poll (contentversion.go) passes false. It runs every
//     15s on its own schedule, and a transient failure there must not re-label a
//     child that is happily serving Detect as degraded, which would take it out
//     of the FilterPool's healthy set and trigger a respawn on the data plane.
//     Its own failure signal is EventAppHookContentVersionUnknown plus the
//     caller's cache going fail-safe — both louder than a reused status string.
//
// ctx must already carry the caller's deadline.
func (h *ChildHook) listPacks(ctx context.Context, markOnErr bool) ([]byte, error) {
	resp, err := h.roundtrip(ctx, pipewire.OpListPacks, pipewire.RouteClassPersonal, nil)
	if err != nil {
		if errors.Is(err, errDegraded) {
			return nil, ErrPacksUnavailable
		}
		if markOnErr && !errors.Is(err, errWriteTimeout) {
			// A write timeout already recorded its own precise reason
			// (DegradeReasonWriteTimeout) inside writeFrame; re-marking here would
			// bury the actual cause under a generic "listpacks_failed" label and cost
			// the operator the one clue that says "the child stopped reading".
			h.markDegraded("listpacks_failed: " + err.Error())
		}
		return nil, err
	}
	// A child that doesn't implement op=4 returns an empty report → unavailable.
	if len(resp.findings) == 0 {
		return nil, ErrPacksUnavailable
	}
	return resp.findings, nil
}

// Status implements Hook.
//
// The stored snapshot describes the PROCESS; the content-version fields are
// composed here from the poll's own atomics rather than stored, because every
// spawn/restart/degrade path rebuilds the snapshot from scratch and a stored
// copy would be dropped by whichever path a future change forgets to carry it
// through. Returning a copy also stops a caller from mutating shared state.
func (h *ChildHook) Status() *Status {
	s := *h.status.Load()
	s.ContentVersion, s.ContentVersionReason = h.contentVersionState()
	return &s
}

// eligibleForDispatch reports whether this child should be handed user content
// right now. It is the dispatch-side reading of the SAME `Healthy` bit that
// Status() publishes and that /v1/diagnostics/pipeline renders as
// `workers[i].healthy`, so the endpoint can never say "worker 1 is down" while
// the dispatcher keeps feeding worker 1 (review finding B39: it used to say
// exactly that).
//
// 🔴 Why the raw `status` pointer and not Status(): Status() copies the struct
// and derives the content-version fields, i.e. it allocates. This runs on the
// hot path once per candidate worker per request, where a plain atomic load
// must stay a plain atomic load. Same bit, no allocation.
//
// Restart windows resolve in the safe direction on their own: restart() stores
// Healthy=false / DegradeReasonRestarting before spawning, so a child being
// replaced is skipped for exactly as long as it is unusable, and re-enters
// rotation on the spawn that sets Healthy=true. The opposite window (Healthy
// still true for the microseconds between the child dying and the read loop
// noticing) is not new and is absorbed by the existing fail-open path.
func (h *ChildHook) eligibleForDispatch() bool { return h.status.Load().Healthy }

// Shutdown closes the pipe and waits for the child to exit. Idempotent.
func (h *ChildHook) Shutdown(ctx context.Context) error {
	// Stop the content-version poll BEFORE the early return: a hook that never
	// spawned still has to release its goroutine, and a hook that did must not
	// keep polling a pipe we are about to close (which would only manufacture a
	// spurious "cannot state its content set" WARN on the way out).
	h.stopContentVersionPoll()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cmd == nil {
		return nil
	}
	h.gen.Add(1) // invalidate the reader so its exit won't markDegraded over the shutdown
	// Closing the OS pipe (not merely forgetting the buffered writer) triggers
	// EOF in the child's read loop. The detector uses that EOF to flush its
	// compliance intake queue before exit. Sending SIGINT first skips Go's
	// normal return path and can lose an already-applied Mask/Block audit event.
	if s := h.session.Swap(nil); s != nil {
		// Best-effort flush, acquired NON-BLOCKINGLY. Two reasons, both mandatory:
		// (a) if a write is in flight the buffer may hold half a frame, and pushing
		// that out would hand the child a corrupt prefix — skipping is the correct
		// behavior, not a shortcut; (b) a wedged writer holds the permit forever,
		// and blocking here is precisely the P0 (`Shutdown` never returned, leaving
		// `kill -9` as the only way to restart the proxy). Every completed
		// writeFrame flushes on its own, so on the normal path the buffer is
		// already empty and this is belt-and-braces.
		select {
		case s.writeSlot <- struct{}{}:
			_ = s.w.Flush()
			<-s.writeSlot
		default:
		}
		s.close()
	}

	// Bind the process to a local BEFORE handing it to the waiter goroutine. The
	// goroutine used to dereference h.cmd itself, which races with the `h.cmd = nil`
	// below whenever the reaper does not win the select — and a child that ignores
	// stdin EOF (the wedged case this whole file now guards against) is exactly the
	// child that makes the timeout/ctx branches the normal outcome. Latent since
	// the reaper goroutine was introduced; only observable once a test shut down a
	// child that does not exit on EOF. Caught by
	// TestChildHook_WedgedChildIsReplacedByLazyRecover under -race.
	cmd := h.cmd
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		return ctx.Err()
	}

	h.cmd = nil
	h.markDegraded("shutdown")
	return nil
}

// writeFrame writes [version][len][payload] then flushes, bounded by ctx.
//
// WHY the deadline lives HERE and not only around the reply wait
// (bugfix 20260813-childhook-write-before-deadline-wedges-main-path.md): a child
// that stopped draining stdin fills the OS pipe buffer and write(2) blocks with
// no error and no timeout of its own. roundtrip() used to write unconditionally
// and only then select on ctx, so the configured Timeout guarded the half of the
// exchange that could not hang and left the half that could completely unguarded.
//
// Two structural consequences are deliberate:
//
//   - The permit is released ONLY by the goroutine that actually finishes the
//     write, never by an abandoning caller. A second writer must not be able to
//     interleave its bytes into a half-written frame.
//   - Returning errWriteTimeout is a statement about the STREAM, not about this
//     one call: the caller must retire the session (see roundtrip). Do not
//     "downgrade" this to a retry.
func (s *pipeSession) writeFrame(ctx context.Context, payload []byte) error {
	if len(payload) > math.MaxUint32 {
		return fmt.Errorf("payload too large for frame header: %d bytes", len(payload))
	}
	if s.broken.Load() {
		return errWriteTimeout
	}
	select {
	case s.writeSlot <- struct{}{}:
	case <-ctx.Done():
		// The permit holder is stuck mid-frame; the stream is unusable regardless
		// of how long we wait, so report the same verdict rather than a generic
		// deadline error.
		return errWriteTimeout
	}
	if s.broken.Load() { // retired while we queued for the permit
		<-s.writeSlot
		return errWriteTimeout
	}

	done := make(chan error, 1) // buffered: an abandoned write must not leak on send
	go func() {
		// pipewire stamps the version we compiled against. cfg.ProtocolVersion is
		// the version we EXPECT BACK from the child (checked in readFrame) — the two
		// are the same value today, and separating them keeps "what we speak" owned
		// by the shared contract rather than by a proxy-side config knob.
		_, err := s.w.Write(pipewire.EncodeFrame(payload))
		if err == nil {
			err = s.w.Flush()
		}
		<-s.writeSlot
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return errWriteTimeout
	}
}

// readFrame reads [version][len][payload] from r (the reader goroutine's stdout)
// and enforces the version byte — a child speaking a different protocol must
// fail loud rather than have its bytes mis-parsed at the wrong offsets.
func (h *ChildHook) readFrame(r *bufio.Reader) ([]byte, error) {
	version, payload, err := pipewire.ReadFrame(r)
	if err != nil {
		return nil, err
	}
	if version != h.cfg.ProtocolVersion {
		return nil, fmt.Errorf("protocol version mismatch: child=%d expected=%d", version, h.cfg.ProtocolVersion)
	}
	return payload, nil
}

func containsReadySentinel(line string) bool {
	// Child's ready message contains "ready" — generous match to allow
	// version info to follow.
	for i := 0; i+5 <= len(line); i++ {
		if line[i:i+5] == "ready" {
			return true
		}
	}
	return false
}
