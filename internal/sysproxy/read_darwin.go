//go:build darwin

package sysproxy

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

const platformSupported = true

// scutilReadTimeout hard-bounds the `scutil --proxy` shell-out.
//
// Why this matters (bugfix 20260725-proxy-startup-sysproxy-scutil-hang): the
// FIRST read runs synchronously inside sysproxy.NewWatcher().prime(), which the
// proxy calls on its PRE-SERVE startup path (app.go: sysWatcher := NewWatcher(),
// before http.Serve). macOS's SCDynamicStore can briefly wedge `scutil` while
// another agent (e.g. Clash) toggles the system proxy on/off — and a wedged
// scutil must NOT pin startup: an unbounded read there stalls the whole proxy
// past the CLI's 5s health gate and the process is killed before it ever listens.
// 3s is ~300x the ~10ms happy path yet comfortably under the 5s gate. On timeout
// the read returns an error → the watcher treats it as "no system proxy"
// (fail-open to direct, its existing readFailing path), never a hang.
const scutilReadTimeout = 3 * time.Second

// readSystemProxy shells out to `scutil --proxy` — the canonical, cgo-free way
// to read the primary network service's proxy settings. It reflects Clash /
// System Settings changes immediately. Cost ~10ms, run every pollInterval.
func readSystemProxy() (Snapshot, error) {
	out, err := runProxyCmd(scutilReadTimeout, "/usr/sbin/scutil", "--proxy")
	if err != nil {
		return Snapshot{}, err
	}
	return parseScutilProxy(string(out)), nil
}

// runProxyCmd runs a proxy-reading command under a HARD context deadline.
//
// It uses exec.CommandContext (not bare exec.Command + WaitDelay): WaitDelay only
// bounds I/O cleanup AFTER the process exits or the context is canceled — with no
// context a wedged child blocks cmd.Output() forever, which is the exact bug this
// replaces (the old code set WaitDelay believing it capped the run; it did not).
// The context deadline is what actually kills a stuck child; WaitDelay is kept as
// a secondary guard so a child that ignores the kill can't keep the pipe (and this
// goroutine) open past a bounded grace.
func runProxyCmd(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("%s timed out after %s (wedged?): %w", name, timeout, ctx.Err())
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}
