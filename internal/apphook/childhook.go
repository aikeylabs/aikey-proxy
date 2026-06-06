// childhook.go — a Hook implementation that spawns a long-running child binary
// and talks to it over stdin/stdout via length-prefixed binary frames.
//
// This is the ONE place where proxy interacts with the child IPC. Any business
// logic about WHAT the child does belongs to the child itself (it's a separate
// binary). proxy just spawns, pipes, and respects the contract.
//
// Concurrency model (v3, 2026-06-06 — the "A" half of 双进程+A):
//   - One dedicated reader goroutine per spawn drains the child's stdout and
//     demuxes each response to its waiting request by a 4-byte request-id.
//   - Detect/ListPacks are ASYNC: assign a req-id, register a pending channel,
//     write the request (writeMu serializes the pipe write), then wait on the
//     channel up to the per-call timeout. Many Detects can be in flight at once
//     on a single pipe, so the child (with its own internal worker pool) can
//     process them concurrently and reply out of order.
//   - Degraded fallback on any IO error; bounded lazy self-heal on the next call.
//
// One ChildHook == one child process == one pipe. The FilterPool (filterpool.go)
// wraps M of these for cross-process fan-out + isolation (the "C" half).
package apphook

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// ChildHookConfig configures a ChildHook.
type ChildHookConfig struct {
	Name               string        // app name, e.g. "ai-compliance-detector"
	BinaryPath         string        // absolute path to child binary
	BinaryArgs         []string      // extra args to pass to child (e.g. --rules ...)
	Timeout            time.Duration // per-Detect deadline (default 1ms)
	ProtocolVersion    byte          // expected — must match child's wire version
	ReadyTimeout       time.Duration // how long to wait for ready sentinel (default 5s)
	RestartMaxAttempts int           // 0 = unlimited (default 3)
	RestartBaseDelay   time.Duration // initial backoff (default 100ms)
	RestartMaxDelay    time.Duration // backoff cap (default 30s)
	// ExtraEnv are "KEY=VALUE" entries appended to the child's environment (on
	// top of the proxy's inherited env). Used to pass per-app runtime config
	// the proxy derives from vault — e.g. AIKEY_COMPLIANCE_RECORD_ALLOW from the
	// app_records.filter_record_allow flag. The child re-reads these at spawn,
	// so a flag change → vault change_seq → proxy reload → re-spawn picks it up.
	ExtraEnv []string
}

func (c *ChildHookConfig) applyDefaults() {
	if c.Timeout == 0 {
		c.Timeout = 1 * time.Millisecond
	}
	if c.ProtocolVersion == 0 {
		c.ProtocolVersion = 3 // v3: request-id multiplexing (concurrent in-flight Detects)
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
	action   byte
	findings []byte // ActionMask → masked payload; ListPacks → JSON report; else per-op
	event    []byte // team-routed compliance event for the proxy to forward; empty otherwise
}

// ChildHook is a generic Hook that delegates to a spawned child binary.
type ChildHook struct {
	cfg ChildHookConfig

	// mu protects spawn/exit state transitions (cmd, generation).
	mu  sync.Mutex
	cmd *exec.Cmd
	gen atomic.Uint64 // spawn generation; the reader tied to an older gen won't clobber a newer spawn's state

	// writeMu serializes frame writes to the child's stdin AND guards the stdin
	// pointer (replaced on spawn/restart). Reads happen on a separate pipe owned
	// by the reader goroutine, so writes and reads never contend.
	writeMu sync.Mutex
	stdin   *bufio.Writer

	// pending holds in-flight requests keyed by request-id. The reader delivers
	// each response to pending[id]; a timed-out caller removes its own entry.
	pendingMu sync.Mutex
	pending   map[uint32]chan *childResponse
	nextReqID atomic.Uint32

	// status is atomically swapped so Status() is wait-free.
	status atomic.Pointer[Status]

	// degraded is set when child is unusable; cleared on successful restart.
	degraded atomic.Bool

	// lastRecoverAt (unix nano) gates the lazy self-heal: when degraded, the next
	// request synchronously restarts the child, but a storm of requests must not
	// hammer respawns — only one attempt per recoverCooldown (CAS-guarded).
	lastRecoverAt atomic.Int64
}

// NewChildHook creates a ChildHook in DISABLED state. Caller must call Start
// to launch the child.
func NewChildHook(cfg ChildHookConfig) *ChildHook {
	cfg.applyDefaults()
	h := &ChildHook{cfg: cfg, pending: make(map[uint32]chan *childResponse)}
	h.degraded.Store(true) // start degraded; flip after successful Start
	h.status.Store(&Status{
		Healthy:        false,
		DegradedReason: "not_started",
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

	cmd := exec.Command(h.cfg.BinaryPath, h.cfg.BinaryArgs...)
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
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" && containsReadySentinel(line) {
				select {
				case readyCh <- line:
				default:
				}
				return
			}
		}
	}()

	select {
	case version := <-readyCh:
		h.cmd = cmd
		gen := h.gen.Add(1) // bump generation; the reader below is tied to it
		h.writeMu.Lock()
		h.stdin = bufio.NewWriterSize(stdin, 64*1024)
		h.writeMu.Unlock()
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
		// Response payload (v3): [req_id 4B][action 1B][findings_len 4B][findings][event]
		if len(payload) < 9 {
			continue // malformed; drop (a real desync surfaces as a read error next)
		}
		reqID := binary.LittleEndian.Uint32(payload[0:4])
		flen := int(binary.LittleEndian.Uint32(payload[5:9]))
		if 9+flen > len(payload) {
			continue
		}
		resp := &childResponse{
			action:   payload[4],
			findings: payload[9 : 9+flen],
			event:    payload[9+flen:],
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

func (h *ChildHook) removePending(reqID uint32) {
	h.pendingMu.Lock()
	delete(h.pending, reqID)
	h.pendingMu.Unlock()
}

func (h *ChildHook) markDegraded(reason string) {
	h.degraded.Store(true)
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
	h.writeMu.Lock()
	h.stdin = nil // old reader will EOF and exit; writes fail until spawnLocked sets a fresh stdin
	h.writeMu.Unlock()
	old := h.status.Load()
	h.status.Store(&Status{
		Healthy:        false,
		DegradedReason: "restarting",
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
	// Lazy self-heal: if degraded, try a bounded respawn now; if it still can't
	// recover, fail open for this request.
	if h.degraded.Load() {
		h.lazyRecover()
		if h.degraded.Load() {
			return nil, errDegraded
		}
	}

	reqID := h.nextReqID.Add(1)
	ch := make(chan *childResponse, 1)
	h.pendingMu.Lock()
	h.pending[reqID] = ch
	h.pendingMu.Unlock()

	// Request frame payload (v3): [op][route_class][req_id 4B][body]
	payload := make([]byte, 6+len(body))
	payload[0] = op
	payload[1] = routeClass
	binary.LittleEndian.PutUint32(payload[2:6], reqID)
	copy(payload[6:], body)
	if err := h.writeFrame(payload); err != nil {
		h.removePending(reqID)
		h.markDegraded("write_failed: " + err.Error())
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

var errDegraded = errors.New("apphook: child degraded")

// Detect implements Hook. Async: writes a request and waits for the matching
// response, allowing many concurrent in-flight Detects on one pipe.
func (h *ChildHook) Detect(ctx context.Context, req *Request) *Response {
	ctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()

	start := time.Now()
	resp, err := h.roundtrip(ctx, 1, req.RouteClass, req.Payload) // op=1 = Detect
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

	resp, err := h.roundtrip(ctx, 4, 0, nil) // op=4 = ListPacks
	if err != nil {
		if errors.Is(err, errDegraded) {
			return nil, ErrPacksUnavailable
		}
		h.markDegraded("listpacks_failed: " + err.Error())
		return nil, err
	}
	// A child that doesn't implement op=4 returns an empty report → unavailable.
	if len(resp.findings) == 0 {
		return nil, ErrPacksUnavailable
	}
	return resp.findings, nil
}

// Status implements Hook.
func (h *ChildHook) Status() *Status {
	return h.status.Load()
}

// Shutdown closes the pipe and waits for the child to exit. Idempotent.
func (h *ChildHook) Shutdown(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cmd == nil {
		return nil
	}
	h.gen.Add(1) // invalidate the reader so its exit won't markDegraded over the shutdown
	// Closing stdin triggers EOF in child's read loop → graceful exit.
	h.writeMu.Lock()
	if h.stdin != nil {
		_ = h.stdin.Flush()
	}
	h.stdin = nil
	h.writeMu.Unlock()
	if h.cmd.Process != nil {
		_ = h.cmd.Process.Signal(os.Interrupt)
	}

	done := make(chan error, 1)
	go func() { done <- h.cmd.Wait() }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = h.cmd.Process.Kill()
	case <-ctx.Done():
		_ = h.cmd.Process.Kill()
		return ctx.Err()
	}

	h.cmd = nil
	h.markDegraded("shutdown")
	return nil
}

// writeFrame writes [version][len][payload] then flushes, under writeMu (which
// also guards the stdin pointer against spawn/restart replacement).
func (h *ChildHook) writeFrame(payload []byte) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	w := h.stdin
	if w == nil {
		return errors.New("stdin closed")
	}
	header := make([]byte, 5)
	header[0] = h.cfg.ProtocolVersion
	binary.LittleEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return w.Flush()
}

// readFrame reads [version][len][payload] from r (the reader goroutine's stdout).
func (h *ChildHook) readFrame(r *bufio.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if header[0] != h.cfg.ProtocolVersion {
		return nil, fmt.Errorf("protocol version mismatch: child=%d expected=%d", header[0], h.cfg.ProtocolVersion)
	}
	length := binary.LittleEndian.Uint32(header[1:])
	if length > 65536 {
		return nil, fmt.Errorf("frame too large: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
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
