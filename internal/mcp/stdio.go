package mcp

// stdio.go — P5 tasks 5.1 / 5.3 / 5.4 / 5.5. Hosting a LOCAL MCP server as a
// child process and exposing it over the gateway's HTTP surface.
//
// # What this buys, and why the extra hop is worth it
//
// Claude Code can already start a stdio MCP server itself. The reason to route
// it through AiKey is the four things the direct path structurally cannot do:
// the credential goes into the vault instead of the developer's `mcp.json`, the
// calls are audited, the tools are authorised, and manifest drift is caught.
// The cost is one loopback hop measured in microseconds. That is the whole
// trade (design §5.3).
//
// 🔴 And it is the one shape a cloud gateway cannot copy: nobody else can run a
// process on this developer's laptop.
//
// # Why this is a transport, not a special case
//
// It registers into the same registry as the two HTTP transports (upstream.go),
// so `tools/list`, drift detection, credential resolution, the isolation shell
// and the call path are shared verbatim. A `switch b.Transport` in the handler
// would have made stdio a second execution path that the security checks would
// have had to be re-applied to by hand — which is how one of them eventually
// gets missed.
//
// # The three things this file must never get wrong
//
//	credentials     go into the child's ENVIRONMENT only. Never argv (world-
//	                readable via ps), never a log line, never a temp file.
//	lifecycle       the child and every descendant die with the proxy. See
//	                aikeycompat.ProcessTree for why one Kill() is not enough.
//	stderr          is drained and surfaced. A child whose stderr nobody reads
//	                BLOCKS once the 64 KiB pipe buffer fills — the exact
//	                deadlock recorded in apphook's 2026-06-13 RCA.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/aikeycompat"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

func init() { RegisterTransport(NewStdioTransport(nil)) }

// EventProxyMCPChildStartFailedName re-exports the escalation's event name for
// the fence, so the test asserts on the SAME constant the code emits rather
// than on a copy of the string that can drift away from it.
const EventProxyMCPChildStartFailedName = observability.EventProxyMCPChildStartFailed

// stdioRequestTimeout bounds one JSON-RPC round trip to a child.
//
// Separate from the HTTP transport's 120s: a local process that has not
// answered in 60 seconds is wedged, not slow. There is no network in between to
// blame.
const stdioRequestTimeout = 60 * time.Second

// stdioStartTimeout bounds the initialize handshake.
//
// 🔴 Generous on purpose. The canonical invocation is `npx -y <pkg>`, and the
// FIRST run downloads the package — on a slow link that genuinely takes tens of
// seconds. A tight timeout here would make the first `aikey mcp add` of every
// backend fail, which is the worst possible first impression of the feature.
const stdioStartTimeout = 90 * time.Second

// stdio restart policy.
const (
	// stdioRestartBase is the first backoff step; it doubles up to the cap.
	stdioRestartBase = 500 * time.Millisecond
	// stdioRestartCap stops the backoff growing without bound.
	stdioRestartCap = 30 * time.Second
	// stdioRestartEscalateAfter is how many consecutive failed starts turn the
	// backend's health from "restarting" into a state an operator is expected
	// to act on.
	//
	// 🔴 There IS an escalation. The project rule is explicit that a self-check
	// must not sit at WARN forever: a backend that has failed to start five
	// times in a row is not "flapping", it is broken, and the log must stop
	// implying that patience will fix it.
	stdioRestartEscalateAfter = 5
)

// StdioTransport runs local MCP servers as child processes.
//
// One instance holds every child, keyed by backend id, because a transport is
// looked up by NAME and must therefore be a singleton — while a stdio backend
// needs a PERSISTENT process across calls, unlike the HTTP transports which are
// stateless per request.
type StdioTransport struct {
	logger *slog.Logger

	mu       sync.Mutex
	children map[string]*stdioChild
	// restarts tracks consecutive FAILED starts per backend, so a backend that
	// cannot come up is backed off instead of being retried at request rate.
	//
	// 🔴 Keyed by backend, not global: one broken backend must not slow down a
	// healthy one. That is the same fault-isolation rule the MCP plane as a
	// whole follows against the LLM plane.
	restarts map[string]*restartState
	// closed makes Shutdown final: a call that arrives during shutdown must not
	// start a fresh child that then outlives the proxy.
	closed bool
}

// restartState is one backend's consecutive-failure record.
type restartState struct {
	failures int
	// nextAttempt is when a start may next be tried. Before it, ensureChild
	// refuses immediately rather than spawning.
	nextAttempt time.Time
	// escalated latches once the failure count crosses the threshold, so the
	// louder message is emitted ONCE rather than on every subsequent call.
	escalated bool
}

// NewStdioTransport builds the transport.
func NewStdioTransport(logger *slog.Logger) *StdioTransport {
	if logger == nil {
		logger = slog.Default()
	}
	return &StdioTransport{
		logger:   logger,
		children: map[string]*stdioChild{},
		restarts: map[string]*restartState{},
	}
}

// Name implements UpstreamTransport.
func (t *StdioTransport) Name() string { return TransportStdio }

// ListTools implements UpstreamTransport.
func (t *StdioTransport) ListTools(ctx context.Context, b UpstreamBackend) ([]mcpwire.Tool, error) {
	env, err := t.rpc(ctx, b, mcpwire.MethodToolsList, nil)
	if err != nil {
		return nil, err
	}
	if env.Error != nil {
		return nil, &UpstreamError{Code: mcpwire.ErrUpstream5XX,
			Detail: "local backend refused tools/list: " + env.Error.Message}
	}
	var res mcpwire.ListToolsResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		return nil, &UpstreamError{Code: mcpwire.ErrUpstream5XX,
			Detail: "local backend tools/list result is not the documented shape"}
	}
	return res.Tools, nil
}

// CallTool implements UpstreamTransport.
func (t *StdioTransport) CallTool(ctx context.Context, b UpstreamBackend, name string, args json.RawMessage) (*mcpwire.CallToolResult, error) {
	params, err := json.Marshal(mcpwire.CallToolRequest{Name: name, Arguments: args})
	if err != nil {
		return nil, err
	}
	env, err := t.rpc(ctx, b, mcpwire.MethodToolsCall, params)
	if err != nil {
		return nil, err
	}
	if env.Error != nil {
		// Same rule as the HTTP transport: a JSON-RPC error is the backend's
		// ANSWER, surfaced in-band so the model can read it and self-correct,
		// not a protocol failure the client should treat as a broken link.
		return &mcpwire.CallToolResult{
			IsError: true,
			Content: []mcpwire.ContentBlock{{Type: "text", Text: env.Error.Message}},
		}, nil
	}
	var res mcpwire.CallToolResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		return nil, &UpstreamError{Code: mcpwire.ErrUpstream5XX,
			Detail: "local backend tools/call result is not the documented shape"}
	}
	return &res, nil
}

// Shutdown reaps every child. Called on proxy exit.
//
// 🔴 The proxy MUST call this. On Unix a process group is an id, not a handle,
// so nothing reaps it for us — see aikeycompat.ProcessTree.Close. Windows has
// KILL_ON_JOB_CLOSE as a backstop; Unix has only this function.
func (t *StdioTransport) Shutdown(ctx context.Context) {
	t.mu.Lock()
	t.closed = true
	children := make([]*stdioChild, 0, len(t.children))
	for _, c := range t.children {
		children = append(children, c)
	}
	t.children = map[string]*stdioChild{}
	t.mu.Unlock()

	var wg sync.WaitGroup
	for _, c := range children {
		wg.Add(1)
		go func(c *stdioChild) { defer wg.Done(); c.stop(ctx) }(c)
	}
	wg.Wait()
}

// Children reports how many backends are running, for /health/mcp.
func (t *StdioTransport) Children() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.children)
}

// rpc performs one round trip, starting the child if needed.
func (t *StdioTransport) rpc(ctx context.Context, b UpstreamBackend, method string, params json.RawMessage) (*mcpwire.Envelope, error) {
	if b.Command == "" {
		return nil, &UpstreamError{Code: mcpwire.ErrBackendUnavailable,
			Detail: "stdio backend has no command configured"}
	}
	// 🔴 Same refusal as the HTTP transport, for the same reason: a backend that
	// declares a credential the resolver could not produce must not be started
	// without it. It would come up, fail every call with the backend's own
	// authentication error, and read to the customer as "my token is wrong".
	if b.CredentialID != "" && b.Credential.Secret == "" {
		return nil, ErrCredentialMissing
	}

	child, err := t.ensureChild(ctx, b)
	if err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, stdioRequestTimeout)
	defer cancel()

	env, err := child.call(callCtx, method, params)
	if err == nil {
		return env, nil
	}
	// A dead child is worth exactly one transparent retry: the common cause is
	// that the backend exited between calls (its own idle timeout, an OOM), and
	// failing the user's first call after that is a worse answer than restarting
	// and serving it.
	//
	// 🔴 ONE retry, and only for a DEAD pipe — never for a timeout, and never
	// for an error the backend itself returned. Retrying a tool call that may
	// have already run is exactly what R4's non-idempotent rule forbids; a
	// broken pipe is the one case where we know it did not run.
	if !errors.Is(err, errStdioChildGone) {
		return nil, err
	}
	t.drop(b.ID, child)
	child, err = t.ensureChild(ctx, b)
	if err != nil {
		return nil, err
	}
	return child.call(callCtx, method, params)
}

func (t *StdioTransport) ensureChild(ctx context.Context, b UpstreamBackend) (*stdioChild, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, &UpstreamError{Code: mcpwire.ErrBackendUnavailable,
			Detail: "the gateway is shutting down"}
	}
	if c, ok := t.children[b.ID]; ok && c.live() {
		t.mu.Unlock()
		return c, nil
	}
	// 🔴 Backoff BEFORE spawning. Without it, a backend whose command does not
	// exist is re-spawned on every single tool call: a wedged Agent retrying in
	// a loop becomes a fork bomb against the developer's own machine, and every
	// attempt writes another line to the log that buries the first one.
	if st := t.restarts[b.ID]; st != nil && time.Now().Before(st.nextAttempt) {
		wait := time.Until(st.nextAttempt).Round(time.Millisecond)
		t.mu.Unlock()
		return nil, &UpstreamError{Code: mcpwire.ErrBackendUnavailable,
			Detail: fmt.Sprintf("local backend %q failed to start %d time(s) in a row; "+
				"the next attempt is in %s", b.Name, st.failures, wait)}
	}

	// Hold the lock across the start. Starting is slow (npx may download a
	// package), but two concurrent first-calls must not race into two children
	// for one backend — the loser would be an untracked process holding a
	// credential, which is the exact thing this phase exists to prevent.
	c, err := startStdioChild(ctx, b, t.logger)
	if err != nil {
		t.noteStartFailureLocked(b, err)
		t.mu.Unlock()
		return nil, err
	}
	// A successful start clears the record — the backoff measures CONSECUTIVE
	// failures, not lifetime ones. A backend that flaps once a week must not
	// eventually be treated as permanently broken.
	delete(t.restarts, b.ID)
	t.children[b.ID] = c
	t.mu.Unlock()
	return c, nil
}

// noteStartFailureLocked records a failed start and schedules the next attempt.
// Caller holds t.mu.
func (t *StdioTransport) noteStartFailureLocked(b UpstreamBackend, cause error) {
	st := t.restarts[b.ID]
	if st == nil {
		st = &restartState{}
		t.restarts[b.ID] = st
	}
	st.failures++

	backoff := stdioRestartBase << min(st.failures-1, 16)
	if backoff > stdioRestartCap || backoff <= 0 {
		backoff = stdioRestartCap
	}
	st.nextAttempt = time.Now().Add(backoff)

	// 🔴 The ESCALATION. The project rule is explicit that a self-check must not
	// sit at WARN forever: a backend that has failed to start five times running
	// is not flapping, it is broken, and a log that keeps saying "restarting"
	// implies patience will fix it. The louder line is emitted ONCE, on the
	// transition — repeating it every call would recreate the noise problem it
	// exists to solve.
	if st.failures >= stdioRestartEscalateAfter && !st.escalated {
		st.escalated = true
		t.logger.Error("MCP stdio backend has failed to start repeatedly and is not expected to recover on its own",
			"event.name", observability.EventProxyMCPChildStartFailed,
			"backend", b.Name, "backend_id", b.ID,
			"consecutive_failures", st.failures,
			"command", b.Command,
			// 🔴 The cause is included because this is the line an operator
			// will actually read, and "it failed" without the reason sends them
			// to the code instead of to their configuration.
			"error", cause.Error(),
			"next_step", "check that the command exists on this machine and can be run by the "+
				"account the proxy runs as; `aikey mcp test <name>` runs it in the foreground")
		return
	}
	t.logger.Warn("MCP stdio backend failed to start; backing off before the next attempt",
		"event.name", observability.EventProxyMCPChildRestarted,
		"backend", b.Name, "backend_id", b.ID,
		"consecutive_failures", st.failures,
		"retry_in", backoff.String(),
		"error", cause.Error())
}

func (t *StdioTransport) drop(backendID string, c *stdioChild) {
	t.mu.Lock()
	if cur, ok := t.children[backendID]; ok && cur == c {
		delete(t.children, backendID)
	}
	t.mu.Unlock()
	c.stop(context.Background())
}

// ---------------------------------------------------------------------------
// one child
// ---------------------------------------------------------------------------

// errStdioChildGone means the pipe is closed — the process exited.
var errStdioChildGone = errors.New("mcp: stdio backend process is gone")

// stdioChild is one running local MCP server.
type stdioChild struct {
	backendID string
	name      string
	logger    *slog.Logger

	cmd  *exec.Cmd
	tree aikeycompat.ProcessTree
	in   io.WriteCloser

	nextID atomic.Int64
	// pending maps a JSON-RPC id to the caller waiting for it. stdio is a
	// single duplex stream, so responses arrive interleaved and must be
	// demultiplexed by id — 🔴 NOT assumed to arrive in request order, which is
	// explicitly allowed by the spec and which a naive "read the next line"
	// implementation gets wrong only under concurrency.
	mu      sync.Mutex
	pending map[string]chan *mcpwire.Envelope
	dead    bool

	writeMu sync.Mutex
	stopped chan struct{}
}

func (c *stdioChild) live() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.dead
}

// startStdioChild spawns the process, performs the MCP handshake, and returns a
// child ready to serve.
func startStdioChild(ctx context.Context, b UpstreamBackend, logger *slog.Logger) (*stdioChild, error) {
	//nolint:gosec // command and args come from the org's MCP policy or the local
	// config an operator wrote; never from request input. The gateway refuses to
	// execute anything a tool CALL names.
	cmd := exec.Command(b.Command, b.Args...)
	aikeycompat.HideSpawnConsole(cmd)

	// 🔴 CREDENTIALS GO HERE AND NOWHERE ELSE.
	//
	// Not in b.Args — argv is world-readable through `ps` on every Unix, so a
	// credential passed as a flag is visible to every other user on the machine
	// and lands in any process listing an operator pastes into a ticket. The
	// environment of a running process is readable only by its owner (and root)
	// on Linux, and not at all through `ps` on macOS.
	//
	// Fence 5.F4 greps the process's command line and asserts the secret is not
	// there.
	env, err := stdioChildEnv(b)
	if err != nil {
		return nil, err
	}
	cmd.Env = env

	tree := aikeycompat.NewProcessTree()
	tree.Prepare(cmd) // 🔴 before Start

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, &UpstreamError{Code: mcpwire.ErrBackendUnavailable, Detail: "stdin pipe: " + err.Error()}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, &UpstreamError{Code: mcpwire.ErrBackendUnavailable, Detail: "stdout pipe: " + err.Error()}
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, &UpstreamError{Code: mcpwire.ErrBackendUnavailable, Detail: "stderr pipe: " + err.Error()}
	}

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		// 🔴 The error text is the OS's ("executable file not found in $PATH"),
		// which is the single most useful thing to show here — the overwhelming
		// majority of first-run failures are a missing `npx` or a typo'd command.
		return nil, &UpstreamError{Code: mcpwire.ErrBackendUnavailable,
			Detail: fmt.Sprintf("could not start %q: %v", b.Command, err)}
	}
	if err := tree.Adopt(cmd); err != nil { // 🔴 after Start
		// An unadoptable child is an UNTRACKED child. Kill it immediately rather
		// than serve from a process we cannot guarantee to reap.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, &UpstreamError{Code: mcpwire.ErrBackendUnavailable,
			Detail: "could not bind the backend process for reaping: " + err.Error()}
	}

	c := &stdioChild{
		backendID: b.ID,
		name:      b.Name,
		logger:    logger,
		cmd:       cmd,
		tree:      tree,
		in:        stdin,
		pending:   map[string]chan *mcpwire.Envelope{},
		stopped:   make(chan struct{}),
	}
	go c.readLoop(stdout)
	go c.drainStderr(stderr)

	if err := c.handshake(ctx); err != nil {
		c.stop(context.Background())
		return nil, err
	}
	logger.Info("MCP stdio backend started",
		"event.name", observability.EventProxyMCPChildStarted,
		"backend", b.Name, "backend_id", b.ID, "pid", cmd.Process.Pid,
		// 🔴 The COMMAND is logged; the env is not. The command is operator
		// configuration and is what an operator needs to see; the environment is
		// where the credential lives.
		"command", b.Command)
	return c, nil
}

// stdioChildEnv builds the child's environment.
//
// 🔴 It starts from the proxy's own environment because a local MCP server
// legitimately needs PATH, HOME and (on Windows) SYSTEMROOT to run at all — an
// empty environment makes `npx` fail in a way that reads as a broken gateway.
// The credential is APPENDED, so it wins over any same-named variable inherited
// from the proxy.
func stdioChildEnv(b UpstreamBackend) ([]string, error) {
	env := os.Environ()
	if b.Credential.Secret == "" {
		return env, nil
	}
	// For a stdio backend the credential's "kind" tells us the variable NAME:
	// `env` credentials carry it in HeaderName, reusing that field rather than
	// adding a column that means the same thing on a different transport.
	name := strings.TrimSpace(b.Credential.HeaderName)
	if b.Credential.Kind != CredentialKindEnv || name == "" {
		// 🔴 Refused rather than guessed. Injecting a bearer-shaped credential
		// into an arbitrary variable name would be a guess about the backend's
		// interface, and a wrong guess produces a server that starts fine and
		// fails every call — the hardest shape to diagnose.
		return nil, &UpstreamError{Code: mcpwire.ErrCredentialMissing,
			Detail: fmt.Sprintf("backend %q is bound to a credential of kind %q, but a stdio "+
				"backend needs kind \"env\" with the variable name set (for example "+
				"PGPASSWORD); rebind it or change the credential's kind",
				b.Name, b.Credential.Kind)}
	}
	if strings.ContainsAny(name, "=\x00") {
		return nil, &UpstreamError{Code: mcpwire.ErrCredentialMissing,
			Detail: "the credential's environment variable name contains an illegal character"}
	}
	return append(env, name+"="+b.Credential.Secret), nil
}

// handshake performs `initialize` then `notifications/initialized`.
func (c *stdioChild) handshake(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, stdioStartTimeout)
	defer cancel()

	params, err := json.Marshal(mcpwire.InitializeRequest{
		// 🔴 We offer OUR newest supported revision and accept whatever the
		// backend answers with. Same rule as the client-facing side (R1): the
		// version is negotiated, never compiled in as "the latest".
		ProtocolVersion: mcpwire.SupportedProtocolVersions[0],
		ClientInfo:      mcpwire.Implementation{Name: "aikey-gateway", Version: "1"},
	})
	if err != nil {
		return err
	}
	env, err := c.call(ctx, mcpwire.MethodInitialize, params)
	if err != nil {
		return &UpstreamError{Code: mcpwire.ErrBackendUnavailable,
			Detail: fmt.Sprintf("local backend %q did not complete the MCP handshake: %v", c.name, err)}
	}
	if env.Error != nil {
		return &UpstreamError{Code: mcpwire.ErrBackendUnavailable,
			Detail: fmt.Sprintf("local backend %q refused initialize: %s", c.name, env.Error.Message)}
	}
	// The spec requires the notification before any other request.
	return c.notify(mcpwire.MethodInitialized, nil)
}

// call sends a request and waits for the matching response.
func (c *stdioChild) call(ctx context.Context, method string, params json.RawMessage) (*mcpwire.Envelope, error) {
	id := fmt.Sprintf("%d", c.nextID.Add(1))
	ch := make(chan *mcpwire.Envelope, 1)

	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return nil, errStdioChildGone
	}
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	body, err := json.Marshal(mcpwire.Envelope{
		JSONRPC: mcpwire.JSONRPCVersion,
		ID:      json.RawMessage(`"` + id + `"`),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return nil, err
	}
	if err := c.write(body); err != nil {
		return nil, err
	}

	select {
	case env := <-ch:
		return env, nil
	case <-c.stopped:
		return nil, errStdioChildGone
	case <-ctx.Done():
		// 🔴 A timeout is NOT reported as errStdioChildGone. The retry above
		// keys on that sentinel, and retrying a tool call that may be running
		// right now would violate R4 for every non-idempotent tool.
		return nil, &UpstreamError{Code: mcpwire.ErrUpstreamTimeout,
			Detail: fmt.Sprintf("local backend %q did not answer in time", c.name)}
	}
}

func (c *stdioChild) notify(method string, params json.RawMessage) error {
	body, err := json.Marshal(mcpwire.Envelope{
		JSONRPC: mcpwire.JSONRPCVersion, Method: method, Params: params,
	})
	if err != nil {
		return err
	}
	return c.write(body)
}

// write sends one newline-delimited message.
//
// 🔴 MCP stdio framing is one JSON object per LINE — not LSP's Content-Length
// headers. The two are easy to confuse because both are "JSON-RPC over a pipe",
// and a mismatched framing produces a server that hangs on the first message
// with no error from either side.
func (c *stdioChild) write(body []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.in.Write(append(body, '\n')); err != nil {
		c.markDead()
		return errStdioChildGone
	}
	return nil
}

// readLoop demultiplexes responses by id.
func (c *stdioChild) readLoop(stdout io.ReadCloser) {
	defer c.markDead()
	scanner := bufio.NewScanner(stdout)
	// A tool result can be large (a query returning rows). The default 64 KiB
	// line cap would truncate it into invalid JSON, which would surface as
	// "backend speaks a broken protocol" rather than "the answer was big".
	scanner.Buffer(make([]byte, 0, 64*1024), maxUpstreamResponse)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var env mcpwire.Envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			// 🔴 Logged, not dropped silently. A backend that writes a banner to
			// STDOUT (rather than stderr) is a common packaging mistake, and this
			// line is the only thing that will ever say so.
			c.logger.Warn("MCP stdio backend wrote a non-JSON-RPC line to stdout; ignoring it",
				"event.name", observability.EventProxyMCPChildBadFrame,
				"backend", c.name, "backend_id", c.backendID,
				"bytes", len(line))
			continue
		}
		if env.IsNotification() {
			continue // we subscribe to nothing; notifications are not errors
		}
		key := strings.Trim(string(env.ID), `"`)
		c.mu.Lock()
		ch, ok := c.pending[key]
		c.mu.Unlock()
		if !ok {
			continue // a response to a request we already gave up on
		}
		e := env
		select {
		case ch <- &e:
		default:
		}
	}
}

// drainStderr surfaces the child's stderr.
//
// 🔴 Draining is not optional. An unread pipe fills at 64 KiB and the child then
// BLOCKS on its next write — it stops answering, every call times out, and
// nothing anywhere says why. That is not hypothetical: it is apphook's
// 2026-06-13 incident, and this loop is the same fix.
func (c *stdioChild) drainStderr(stderr io.ReadCloser) {
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 0, 8*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// For a local server this is the ONLY diagnostic channel that exists.
		c.logger.Warn("MCP stdio backend stderr",
			"event.name", observability.EventProxyMCPChildStderr,
			"backend", c.name, "backend_id", c.backendID, "line", line)
	}
}

func (c *stdioChild) markDead() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	close(c.stopped)
	c.mu.Unlock()
}

// stop reaps the child and everything it started.
func (c *stdioChild) stop(ctx context.Context) {
	c.markDead()
	_ = c.in.Close()

	// Graceful first: closing stdin is how an MCP server is told to exit, and a
	// server that shuts down cleanly gets to flush whatever it was doing.
	done := make(chan struct{})
	go func() { _ = c.cmd.Wait(); close(done) }()

	grace := 3 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < grace {
			grace = left
		}
	}
	select {
	case <-done:
		// The backend exited on its own. 🔴 That is NOT the end of the job.
	case <-time.After(grace):
		_ = c.tree.Terminate()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = c.tree.Kill()
			// 🔴 BOUNDED, not `<-done`. An unbounded wait here holds the whole
			// proxy shutdown hostage whenever the reap does not work — and
			// "does not work" is not hypothetical: it is what a wrong process
			// group looks like, which is exactly the mistake this file's
			// process-tree machinery exists to prevent and therefore exactly
			// the state in which this path runs. The proxy already carries a
			// bugfix for unbounded shutdown closes
			// (20260819-proxy-shutdown-unbounded-close); this is the same
			// hazard in a new place.
			//
			// Giving up here is safe: the process has been SIGKILLed, the
			// supervisor's own teardown watchdog is still above us, and the
			// alternative — never returning — turns one wedged backend into a
			// proxy that systemd has to SIGKILL at the 90-second mark.
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				c.logger.Error("MCP stdio backend did not exit after SIGKILL to its process group; "+
					"abandoning the wait so shutdown can finish",
					"event.name", observability.EventProxyMCPChildReapFailed,
					"backend", c.name, "backend_id", c.backendID, "pid", c.cmd.Process.Pid)
			}
		}
	}

	// 🔴 UNCONDITIONAL tree reap, on every path including the clean exit above.
	//
	// This line exists because the fence caught its absence
	// (TestStdio_ShutdownReapsTheChildAndItsDescendants, 2026-09-01). The
	// earlier version only killed the group when the child FAILED to exit in
	// time, which reads as correct and is not: `npx` exits the moment its stdin
	// closes, so the graceful branch was the one that always ran — and the
	// worker it had spawned, the process actually holding the database
	// password, was never signalled at all. A clean exit by the LAUNCHER says
	// nothing about its descendants.
	//
	// Killing an already-dead group is a no-op by construction
	// (aikeycompat.ProcessTree.Kill swallows ESRCH), so this is free on the
	// common path and is the whole protection on the path that matters.
	_ = c.tree.Kill()
	_ = c.tree.Close()
}
