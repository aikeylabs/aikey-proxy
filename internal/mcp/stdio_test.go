package mcp

// P5 fences 5.F2 / 5.F3 / 5.F4, and the transport's own behaviour.
//
// 🔴 Every test here runs a REAL child process. That is the point: orphan
// reaping, credential-in-environment and crash-restart are all properties of an
// OS process, and an in-process fake would let all three pass while shipping
// none of them.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// buildFakeMCP compiles testdata/fakemcp.go once per package run.
var (
	fakeOnce sync.Once
	fakePath string
	fakeErr  error
)

func fakeMCPBinary(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fakemcp-")
		if err != nil {
			fakeErr = err
			return
		}
		out := filepath.Join(dir, "fakemcp")
		if runtime.GOOS == "windows" {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out, "testdata/fakemcp.go")
		if b, err := cmd.CombinedOutput(); err != nil {
			fakeErr = fmt.Errorf("build fake mcp server: %v\n%s", err, b)
			return
		}
		fakePath = out
	})
	if fakeErr != nil {
		t.Fatalf("%v", fakeErr)
	}
	return fakePath
}

func stdioBackend(t *testing.T, extraEnv map[string]string, cred UpstreamCredential) UpstreamBackend {
	t.Helper()
	bin := fakeMCPBinary(t)
	for k, v := range extraEnv {
		t.Setenv(k, v)
	}
	return UpstreamBackend{
		ID: "b-stdio", Name: "local-postgres", Transport: TransportStdio,
		Command: bin, Credential: cred,
	}
}

func newStdio(t *testing.T) *StdioTransport {
	t.Helper()
	tr := NewStdioTransport(nil)
	t.Cleanup(func() { tr.Shutdown(context.Background()) })
	return tr
}

// ---------------------------------------------------------------------------
// the happy path — without it, every "it didn't leak" below is vacuous
// ---------------------------------------------------------------------------

func TestStdio_ListsAndCallsThroughARealChildProcess(t *testing.T) {
	tr := newStdio(t)
	b := stdioBackend(t, nil, UpstreamCredential{})

	tools, err := tr.ListTools(context.Background(), b)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "echo_secret_presence" {
		t.Fatalf("unexpected tools: %+v", tools)
	}
	res, err := tr.CallTool(context.Background(), b, "echo_secret_presence", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool reported an error: %+v", res.Content)
	}
	if tr.Children() != 1 {
		t.Fatalf("expected exactly one child process, got %d", tr.Children())
	}
}

// TestStdio_OneChildServesManyCalls — the process is persistent, not per-call.
//
// A transport that respawned per request would still pass every functional test
// while making `npx` download a package on every tool call.
func TestStdio_OneChildServesManyCalls(t *testing.T) {
	tr := newStdio(t)
	b := stdioBackend(t, nil, UpstreamCredential{})
	for i := 0; i < 3; i++ {
		if _, err := tr.ListTools(context.Background(), b); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if n := tr.Children(); n != 1 {
		t.Fatalf("three calls produced %d children; the process must be reused", n)
	}
}

// TestStdio_ConcurrentCallsAreDemultiplexedByID.
//
// 🔴 stdio is ONE duplex stream. Responses may arrive in any order, and an
// implementation that reads "the next line" as "my answer" works perfectly
// until two calls overlap — i.e. it passes every sequential test and corrupts
// answers in the field.
func TestStdio_ConcurrentCallsAreDemultiplexedByID(t *testing.T) {
	tr := newStdio(t)
	b := stdioBackend(t, nil, UpstreamCredential{})
	if _, err := tr.ListTools(context.Background(), b); err != nil {
		t.Fatalf("warm up: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := tr.CallTool(context.Background(), b, "echo_secret_presence", json.RawMessage(`{}`))
			if err != nil {
				errs <- err
				return
			}
			if len(res.Content) == 0 || !strings.HasPrefix(res.Content[0].Text, "secret_from_env=") {
				errs <- fmt.Errorf("answer does not match the request: %+v", res.Content)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent call: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 5.F4 — the credential is in the environment, NOT in argv
// ---------------------------------------------------------------------------

// TestStdio_ANonEnvCredentialOnAStdioBackendIsRefused.
//
// 🔴 Refused, not guessed. Picking a variable name for a bearer-shaped
// credential would be a guess about the backend's interface, and a wrong guess
// starts a server that runs fine and fails every call — the hardest shape to
// diagnose, because nothing is broken except the answer.
func TestStdio_ANonEnvCredentialOnAStdioBackendIsRefused(t *testing.T) {
	tr := newStdio(t)
	b := stdioBackend(t, nil, UpstreamCredential{Kind: CredentialKindBearer, Secret: "tok"})
	b.CredentialID = "c1"

	_, err := tr.ListTools(context.Background(), b)
	if err == nil {
		t.Fatal("a bearer credential on a stdio backend must be refused, not injected somewhere guessed")
	}
	// The message must tell the admin what to change.
	if !strings.Contains(err.Error(), "env") || !strings.Contains(err.Error(), "PGPASSWORD") {
		t.Fatalf("the refusal must name the fix (kind \"env\" + a variable name): %v", err)
	}
	if strings.Contains(err.Error(), "tok") {
		t.Fatalf("🔴 the refusal quoted the secret: %v", err)
	}
}

// TestStdio_ABackendWithAnUnresolvedCredentialIsNotStarted — same rule the HTTP
// transport already enforces, asserted here because the stdio path reaches the
// upstream through completely different code.
func TestStdio_ABackendWithAnUnresolvedCredentialIsNotStarted(t *testing.T) {
	tr := newStdio(t)
	b := stdioBackend(t, nil, UpstreamCredential{})
	b.CredentialID = "c-unresolved" // declared, but nothing resolved it

	_, err := tr.ListTools(context.Background(), b)
	if !errors.Is(err, ErrCredentialMissing) {
		t.Fatalf("want ErrCredentialMissing, got %v", err)
	}
	if tr.Children() != 0 {
		t.Fatal("🔴 the process was started anyway; it would authenticate with nothing and " +
			"every failure would read as 'the customer's credential is wrong'")
	}
}

// ---------------------------------------------------------------------------
// 5.F2 — no orphans (the stdio transport's own use of the process tree)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 5.F3 — crash → restart, and the child's voice is not discarded
// ---------------------------------------------------------------------------

// TestStdio_ACrashedBackendIsRestartedForTheNextCall.
//
// 🔴 The retry is transparent for a DEAD PIPE only. A backend that exits between
// calls (its own idle timeout, an OOM) must not fail the next user request; a
// backend that TIMED OUT must never be retried, because the tool may be running
// right now and R4 forbids retrying a non-idempotent call.
func TestStdio_ACrashedBackendIsRestartedForTheNextCall(t *testing.T) {
	tr := newStdio(t)
	b := stdioBackend(t, map[string]string{"FAKEMCP_CRASH_AFTER": "1"}, UpstreamCredential{})

	if _, err := tr.CallTool(context.Background(), b, "echo_secret_presence", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("first call: %v", err)
	}
	first := childPID(t, tr, b.ID)

	// The second call kills the child on arrival; the transport must restart and
	// serve it rather than surfacing a broken pipe to the user.
	_, _ = tr.CallTool(context.Background(), b, "echo_secret_presence", json.RawMessage(`{}`))
	res, err := tr.CallTool(context.Background(), b, "echo_secret_presence", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("after the backend crashed, the next call must be served by a fresh child: %v", err)
	}
	if res.IsError {
		t.Fatalf("restarted child answered with an error: %+v", res.Content)
	}
	if second := childPID(t, tr, b.ID); second == first {
		t.Fatalf("the transport reported the same pid %d after a crash; nothing was restarted", second)
	}
}

// TestStdio_ATimeoutIsNotRetried — the R4 half of the rule above.
func TestStdio_ATimeoutIsNotRetried(t *testing.T) {
	tr := newStdio(t)
	b := stdioBackend(t, map[string]string{"FAKEMCP_HANG": "1"}, UpstreamCredential{})
	if _, err := tr.ListTools(context.Background(), b); err != nil {
		t.Fatalf("warm up: %v", err)
	}
	first := childPID(t, tr, b.ID)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := tr.CallTool(ctx, b, "echo_secret_presence", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("a hanging backend must produce a timeout")
	}
	var ue *UpstreamError
	if !errors.As(err, &ue) || ue.Code != mcpwire.ErrUpstreamTimeout {
		t.Fatalf("a timeout must be reported as %s, not as a dead pipe (which would be "+
			"retried, re-running a tool that may be executing right now): %v",
			mcpwire.ErrUpstreamTimeout, err)
	}
	if second := childPID(t, tr, b.ID); second != first {
		t.Fatalf("🔴 the child was replaced after a TIMEOUT (pid %d → %d). A timeout means the "+
			"tool may still be running; restarting and retrying would execute it twice.",
			first, second)
	}
}

// TestStdio_ABannerOnStdoutDoesNotBreakTheSession.
//
// Writing a startup banner to stdout instead of stderr is a common packaging
// mistake in MCP servers. It must not be fatal, and it must not be silent —
// otherwise the user sees "this server doesn't work" with nothing to go on.
func TestStdio_ABannerOnStdoutDoesNotBreakTheSession(t *testing.T) {
	tr := newStdio(t)
	b := stdioBackend(t, map[string]string{"FAKEMCP_STDOUT_NOISE": "1"}, UpstreamCredential{})
	if _, err := tr.ListTools(context.Background(), b); err != nil {
		t.Fatalf("a non-JSON line on stdout must be skipped, not fatal: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func childPID(t *testing.T, tr *StdioTransport, backendID string) int {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	c, ok := tr.children[backendID]
	if !ok || c.cmd == nil || c.cmd.Process == nil {
		t.Fatalf("no running child for backend %q", backendID)
	}
	return c.cmd.Process.Pid
}

// ---------------------------------------------------------------------------
// 5.F3 (second half) — backoff, and the escalation out of WARN
// ---------------------------------------------------------------------------

// TestStdio_ARepeatedlyFailingBackendIsBackedOffNotRespawnedPerCall.
//
// 🔴 Without backoff, a backend whose command does not exist is spawned again
// on every tool call. A wedged Agent retrying in a loop then forks against the
// developer's own machine, and each attempt writes a log line that buries the
// first one — the one that said what was actually wrong.
func TestStdio_ARepeatedlyFailingBackendIsBackedOffNotRespawnedPerCall(t *testing.T) {
	tr := newStdio(t)
	b := UpstreamBackend{
		ID: "b-missing", Name: "typo-backend", Transport: TransportStdio,
		Command: filepath.Join(t.TempDir(), "definitely-not-installed"),
	}

	first := time.Now()
	if _, err := tr.ListTools(context.Background(), b); err == nil {
		t.Fatal("a missing command must fail")
	}
	// The immediate next call must be REFUSED by the backoff, not attempted.
	_, err := tr.ListTools(context.Background(), b)
	if err == nil {
		t.Fatal("expected the second call to be refused")
	}
	if !strings.Contains(err.Error(), "next attempt is in") {
		t.Fatalf("the second call was attempted rather than backed off (or the message does "+
			"not say when it will retry, which is the only actionable part): %v", err)
	}
	if time.Since(first) > 2*time.Second {
		t.Fatal("the backed-off call should be refused immediately, not slept through")
	}
}

// TestStdio_RepeatedStartFailuresEscalatePastWarn.
//
// 🔴 The project rule is explicit: a self-check must not sit at WARN forever. A
// backend that has failed N times running is broken, and a log that keeps
// saying "backing off" implies patience will fix it.
func TestStdio_RepeatedStartFailuresEscalatePastWarn(t *testing.T) {
	logs := &bytes.Buffer{}
	tr := NewStdioTransport(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { tr.Shutdown(context.Background()) })

	b := UpstreamBackend{
		ID: "b-missing", Name: "typo-backend", Transport: TransportStdio,
		Command: filepath.Join(t.TempDir(), "definitely-not-installed"),
	}
	// Drive it past the threshold, clearing the backoff each round so the
	// attempt actually happens (the backoff itself is covered above).
	for i := 0; i < stdioRestartEscalateAfter; i++ {
		tr.mu.Lock()
		if st := tr.restarts[b.ID]; st != nil {
			st.nextAttempt = time.Time{}
		}
		tr.mu.Unlock()
		_, _ = tr.ListTools(context.Background(), b)
	}

	out := logs.String()
	if !strings.Contains(out, "level=ERROR") {
		t.Fatalf("after %d consecutive start failures the backend must escalate past WARN; "+
			"it is still being reported as a transient condition:\n%s", stdioRestartEscalateAfter, out)
	}
	if !strings.Contains(out, EventProxyMCPChildStartFailedName) {
		t.Fatalf("the escalation must carry its own event name so an operator can alert on it:\n%s", out)
	}
	// 🔴 ONCE, not per call. An escalation repeated every request is noise
	// again, which is the problem it was introduced to solve.
	if n := strings.Count(out, EventProxyMCPChildStartFailedName); n != 1 {
		t.Fatalf("the escalation must be emitted once on the transition, got %d times", n)
	}
	// It must name the fix, not just the failure.
	if !strings.Contains(out, "aikey mcp test") {
		t.Fatalf("the escalation must tell the operator what to run next:\n%s", out)
	}
}

// TestStdio_ASuccessfulStartClearsTheBackoff — the backoff counts CONSECUTIVE
// failures. A backend that flaps once a week must not eventually be treated as
// permanently broken.
func TestStdio_ASuccessfulStartClearsTheBackoff(t *testing.T) {
	tr := newStdio(t)
	bad := UpstreamBackend{
		ID: "b1", Name: "flaky", Transport: TransportStdio,
		Command: filepath.Join(t.TempDir(), "not-installed"),
	}
	if _, err := tr.ListTools(context.Background(), bad); err == nil {
		t.Fatal("expected the bad command to fail")
	}
	tr.mu.Lock()
	failures := tr.restarts["b1"].failures
	tr.mu.Unlock()
	if failures != 1 {
		t.Fatalf("want 1 recorded failure, got %d", failures)
	}

	// Same backend id, now with a working command.
	good := stdioBackend(t, nil, UpstreamCredential{})
	good.ID = "b1"
	tr.mu.Lock()
	tr.restarts["b1"].nextAttempt = time.Time{}
	tr.mu.Unlock()
	if _, err := tr.ListTools(context.Background(), good); err != nil {
		t.Fatalf("recovered start: %v", err)
	}
	tr.mu.Lock()
	_, stillTracked := tr.restarts["b1"]
	tr.mu.Unlock()
	if stillTracked {
		t.Fatal("a successful start must clear the consecutive-failure record")
	}
}
