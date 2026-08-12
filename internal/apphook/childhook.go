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

// ChildHook is a generic Hook that delegates to a spawned child binary.
type ChildHook struct {
	cmd       *exec.Cmd
	stdin     *bufio.Writer
	stdinPipe io.WriteCloser
	pending   map[uint32]chan *childResponse
	// status is atomically swapped so Status() is wait-free.
	status atomic.Pointer[Status]
	cfg    ChildHookConfig
	gen    atomic.Uint64 // spawn generation; the reader tied to an older gen won't clobber a newer spawn's state
	// lastRecoverAt (unix nano) gates the lazy self-heal: when degraded, the next
	// request synchronously restarts the child, but a storm of requests must not
	// hammer respawns — only one attempt per recoverCooldown (CAS-guarded).
	lastRecoverAt atomic.Int64
	// mu protects spawn/exit state transitions (cmd, generation).
	mu sync.Mutex
	// writeMu serializes frame writes to the child's stdin AND guards the stdin
	// pointer (replaced on spawn/restart). Reads happen on a separate pipe owned
	// by the reader goroutine, so writes and reads never contend.
	writeMu sync.Mutex
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
		h.writeMu.Lock()
		h.stdin = bufio.NewWriterSize(stdin, 64*1024)
		h.stdinPipe = stdin
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
	h.writeMu.Lock()
	if h.stdinPipe != nil {
		_ = h.stdinPipe.Close()
	}
	h.stdin = nil // writes fail until spawnLocked sets a fresh stdin
	h.stdinPipe = nil
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
	// Lazy self-heal: if degraded, kick a bounded respawn off in the BACKGROUND
	// and fail open immediately. The restart must NOT run on the hot path —
	// lazyRecover uses context.Background()+lazyRestartBound (2s), ignoring this
	// request's ctx, so calling it synchronously stalled the very first Detect
	// after a child died for up to 2s, violating the AppHook fail-open invariant
	// (a degraded/unreachable child must never block a user request). lazyRecover
	// is cooldown/CAS-guarded, so concurrent Detects spawn at most one restart;
	// once it clears `degraded`, the NEXT Detect uses the recovered child.
	if h.degraded.Load() {
		go h.lazyRecover()
		return nil, errDegraded
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

	resp, err := h.roundtrip(ctx, pipewire.OpListPacks, pipewire.RouteClassPersonal, nil)
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
	// Closing the OS pipe (not merely forgetting the buffered writer) triggers
	// EOF in the child's read loop. The detector uses that EOF to flush its
	// compliance intake queue before exit. Sending SIGINT first skips Go's
	// normal return path and can lose an already-applied Mask/Block audit event.
	h.writeMu.Lock()
	if h.stdin != nil {
		_ = h.stdin.Flush()
	}
	if h.stdinPipe != nil {
		_ = h.stdinPipe.Close()
	}
	h.stdin = nil
	h.stdinPipe = nil
	h.writeMu.Unlock()

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
	if len(payload) > math.MaxUint32 {
		return fmt.Errorf("payload too large for frame header: %d bytes", len(payload))
	}
	// pipewire stamps the version we compiled against. cfg.ProtocolVersion is the
	// version we EXPECT BACK from the child (checked in readFrame) — the two are
	// the same value today, and separating them keeps "what we speak" owned by
	// the shared contract rather than by a proxy-side config knob.
	if _, err := w.Write(pipewire.EncodeFrame(payload)); err != nil {
		return err
	}
	return w.Flush()
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
