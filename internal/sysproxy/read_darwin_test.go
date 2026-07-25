//go:build darwin

package sysproxy

import (
	"strings"
	"testing"
	"time"
)

// Live exec smoke: `scutil --proxy` must run and parse on any macOS box —
// whatever it returns (proxy on/off) must not error. Guards the exec wiring
// the fixture tests can't cover.
func TestReadSystemProxy_ExecSmoke(t *testing.T) {
	snap, err := readSystemProxy()
	if err != nil {
		t.Fatalf("scutil exec path failed: %v", err)
	}
	t.Logf("live system proxy snapshot: %+v", snap)
}

// Regression guard for bugfix 20260725-proxy-startup-sysproxy-scutil-hang.
//
// The old readSystemProxy used exec.Command + cmd.WaitDelay, which does NOT bound
// a wedged child (WaitDelay only applies after the process exits or a context
// cancels — there was no context). A wedged `scutil` therefore blocked
// NewWatcher().prime() on the pre-serve startup path forever, stalling the proxy
// past the CLI's 5s health gate. This proves runProxyCmd now HARD-bounds a stuck
// child via a context deadline: a process that never exits returns an error
// quickly instead of hanging.
func TestRunProxyCmd_BoundsWedgedProcess(t *testing.T) {
	start := time.Now()
	// `sleep 10` stands in for a wedged scutil: it never returns on its own.
	out, err := runProxyCmd(300*time.Millisecond, "/bin/sleep", "10")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected a timeout error from a wedged child, got nil (out=%q)", out)
	}
	// Must return well before the child's own 10s — the whole point.
	if elapsed > 3*time.Second {
		t.Fatalf("runProxyCmd did not bound the wedged child: took %s (must be ~timeout, not the child's 10s)", elapsed)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error should name the timeout for operators, got: %v", err)
	}
}

// Happy path: a fast command returns output and no error, so the normal scutil
// read is unaffected by the timeout wrapper.
func TestRunProxyCmd_FastCommandSucceeds(t *testing.T) {
	out, err := runProxyCmd(scutilReadTimeout, "/bin/echo", "ok")
	if err != nil {
		t.Fatalf("fast command errored: %v", err)
	}
	if strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("output = %q, want \"ok\"", out)
	}
}

// A missing binary returns a non-timeout error (so operators can tell "not found"
// from "wedged"); it must not be misreported as a timeout.
func TestRunProxyCmd_MissingBinaryIsNotATimeout(t *testing.T) {
	_, err := runProxyCmd(scutilReadTimeout, "/usr/sbin/definitely-not-a-real-binary-xyz")
	if err == nil {
		t.Fatal("expected an error for a missing binary")
	}
	if strings.Contains(err.Error(), "timed out") {
		t.Fatalf("missing binary misreported as timeout: %v", err)
	}
}
