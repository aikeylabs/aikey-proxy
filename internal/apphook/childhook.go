// childhook.go — a Hook implementation that spawns a long-running child binary
// and talks to it over stdin/stdout via length-prefixed binary frames.
//
// This is the ONE place where proxy interacts with the child IPC. Any business
// logic about WHAT the child does belongs to the child itself (it's a separate
// binary). proxy just spawns, pipes, and respects the contract.
//
// Stage A scope:
//   - Spawn + pipe setup + protocol version handshake (via child's ready
//     sentinel on stderr)
//   - Single-flight Detect (single in-flight request, sync write/read)
//   - Degraded fallback on any IO error
//   - Background restart with exponential backoff
//
// Stage B+ extensions (out of scope for A):
//   - Worker pool for concurrent Detect (currently single-flight, sufficient
//     for client-side proxy QPS < 1000)
//   - Streaming inbound/outbound (for response body inspection)
//   - User-role forwarding via Request metadata
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
		c.ProtocolVersion = 2 // v2: RouteClass in request + length-prefixed findings + Event in response
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

// ChildHook is a generic Hook that delegates to a spawned child binary.
type ChildHook struct {
	cfg ChildHookConfig

	// Mutex protects spawn/exit state transitions.
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  *bufio.Writer
	stdout *bufio.Reader

	// status is atomically swapped so Status() is wait-free.
	status atomic.Pointer[Status]

	// detectMu serializes Detect calls so we get clean request/response pairs
	// on the single pipe. Stage A: sufficient; Stage B+: consider worker pool.
	detectMu sync.Mutex

	// degraded is set when child is unusable; cleared on successful restart.
	degraded atomic.Bool
}

// NewChildHook creates a ChildHook in DISABLED state. Caller must call Start
// to launch the child.
func NewChildHook(cfg ChildHookConfig) *ChildHook {
	cfg.applyDefaults()
	h := &ChildHook{cfg: cfg}
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
			if line != "" && (containsReadySentinel(line)) {
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
		h.stdin = bufio.NewWriterSize(stdin, 64*1024)
		h.stdout = bufio.NewReaderSize(stdout, 64*1024)
		h.degraded.Store(false)
		h.status.Store(&Status{
			Healthy:       true,
			BinaryPath:    h.cfg.BinaryPath,
			Version:       version,
			LastSpawnedAt: time.Now(),
			RestartCount:  h.status.Load().RestartCount,
		})
		return nil
	case <-time.After(h.cfg.ReadyTimeout):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		h.markDegraded("ready_timeout")
		return fmt.Errorf("apphook %s: child did not signal ready within %s", h.cfg.Name, h.cfg.ReadyTimeout)
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		h.markDegraded("startup_cancelled")
		return ctx.Err()
	}
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

// Name implements Hook.
func (h *ChildHook) Name() string { return h.cfg.Name }

// Detect implements Hook. Single-flight: serializes via detectMu.
func (h *ChildHook) Detect(ctx context.Context, req *Request) *Response {
	if h.degraded.Load() {
		return &Response{Action: ActionAllow, Degraded: true, Reason: "child degraded"}
	}

	// Enforce internal timeout cap (even if caller passes a longer ctx).
	ctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()

	h.detectMu.Lock()
	defer h.detectMu.Unlock()

	// Recheck after acquiring lock (state may have changed).
	if h.degraded.Load() {
		return &Response{Action: ActionAllow, Degraded: true, Reason: "child degraded (post-lock)"}
	}

	start := time.Now()

	// Write request frame (v2): [version][len LE 4B] | [op=1][route_class][payload]
	payload := append([]byte{1, req.RouteClass}, req.Payload...) // op=1 = Detect
	if err := h.writeFrame(payload); err != nil {
		h.markDegraded("write_failed: " + err.Error())
		return &Response{Action: ActionAllow, Degraded: true, Reason: "child write failed"}
	}

	// Read response frame (v2): [version][len LE 4B] | [action 1B][findings_len 4B][findings][event]
	respPayload, err := h.readFrame()
	if err != nil {
		h.markDegraded("read_failed: " + err.Error())
		return &Response{Action: ActionAllow, Degraded: true, Reason: "child read failed"}
	}

	if len(respPayload) < 5 {
		h.markDegraded("short_response")
		return &Response{Action: ActionAllow, Degraded: true, Reason: "short response"}
	}

	flen := int(binary.LittleEndian.Uint32(respPayload[1:5]))
	if 5+flen > len(respPayload) {
		h.markDegraded("malformed_response")
		return &Response{Action: ActionAllow, Degraded: true, Reason: "malformed response framing"}
	}
	findings := respPayload[5 : 5+flen] // ActionMask → masked payload; else per-op
	event := respPayload[5+flen:]       // team-routed compliance event for the proxy to forward

	res := &Response{
		Action:          Action(respPayload[0]),
		LatencyObserved: time.Since(start),
	}
	if res.Action == ActionMask && len(findings) > 0 {
		res.MutatedPayload = findings
	}
	if len(event) > 0 {
		res.Event = event
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
//
// Design (Option A): shares the Detect pipe under detectMu, held ONLY for the
// brief write+read of this bounded query. The child's handler is lock-free +
// non-blocking (atomic snapshot + static manifest), so it can't stall a real
// Detect. A crashed/wedged child surfaces as a write/read error → degraded,
// same failure mode Detect already has (no new risk). Backward compatible: an
// old child returns Allow + empty payload for the unknown op → we return
// ErrPacksUnavailable, which the admin layer maps to "packs unavailable".
func (h *ChildHook) ListPacks(ctx context.Context) ([]byte, error) {
	if h.degraded.Load() {
		return nil, ErrPacksUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
	defer cancel()
	_ = ctx // timeout intent; pipe I/O failure (crash) surfaces as read/write error

	h.detectMu.Lock()
	defer h.detectMu.Unlock()
	if h.degraded.Load() {
		return nil, ErrPacksUnavailable
	}

	if err := h.writeFrame([]byte{4}); err != nil { // op=4 = ListPacks
		h.markDegraded("listpacks_write_failed: " + err.Error())
		return nil, err
	}
	respPayload, err := h.readFrame()
	if err != nil {
		h.markDegraded("listpacks_read_failed: " + err.Error())
		return nil, err
	}
	// Response (v2): [action 1B][findings_len 4B][JSON report][event]. The report
	// is the length-prefixed findings slice; ignore the action byte and trailing
	// event (empty for ListPacks). A child that doesn't implement op=4 returns an
	// empty report → unavailable. (A v1 child fails earlier on version mismatch.)
	if len(respPayload) < 5 {
		return nil, ErrPacksUnavailable
	}
	flen := int(binary.LittleEndian.Uint32(respPayload[1:5]))
	if flen == 0 || 5+flen > len(respPayload) {
		return nil, ErrPacksUnavailable
	}
	return respPayload[5 : 5+flen], nil
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
	// Closing stdin triggers EOF in child's read loop → graceful exit.
	if h.stdin != nil {
		_ = h.stdin.Flush()
	}
	if h.cmd.Process != nil {
		// We don't have direct access to the underlying pipe (it's wrapped in
		// bufio.Writer). Send SIGTERM as a fallback.
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
	h.stdin = nil
	h.stdout = nil
	h.markDegraded("shutdown")
	return nil
}

// writeFrame writes [version][len][payload] then flushes. Caller must hold detectMu.
func (h *ChildHook) writeFrame(payload []byte) error {
	if h.stdin == nil {
		return errors.New("stdin closed")
	}
	header := make([]byte, 5)
	header[0] = h.cfg.ProtocolVersion
	binary.LittleEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := h.stdin.Write(header); err != nil {
		return err
	}
	if _, err := h.stdin.Write(payload); err != nil {
		return err
	}
	return h.stdin.Flush()
}

// readFrame reads [version][len][payload]. Caller must hold detectMu.
func (h *ChildHook) readFrame() ([]byte, error) {
	if h.stdout == nil {
		return nil, errors.New("stdout closed")
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(h.stdout, header); err != nil {
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
	if _, err := io.ReadFull(h.stdout, payload); err != nil {
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
