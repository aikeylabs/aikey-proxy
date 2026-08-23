package supervisor

import (
	"errors"
	"log/slog"
	"os"
	"strconv"
	"syscall"
	"time"
)

// ParentWatchEnv names the PID this process must not outlive.
//
// 🔴 WHY THIS EXISTS (2026-08-22). aikey-test's harness starts the proxy through
// `aikey proxy start`, which DETACHES by design — that is right for a human
// (closing the terminal must not kill their proxy) and wrong for a test, which
// needs the opposite: the child must die with the run.
//
// Because the process detaches, the harness never owns it. It could only chase
// it afterwards through a PID file from `t.Cleanup` (harness/sandbox.go), and
// t.Cleanup does NOT run when the test binary is killed — `go test` timeout,
// Ctrl-C, CI cancel, panic-kill. A detached child is then re-parented to init
// and simply keeps running.
//
// That is not hypothetical: THREE leaked proxies were found on one developer
// machine, from three different tests, one alive for TEN DAYS. They kept polling
// a real control plane with deliberately-revoked test credentials, emitting 403s
// that were later mistaken for a production defect and cost a full investigation.
// The only symptom was a 466 MB log file nobody was watching.
//
// 🔴 WHY A PID TO WATCH AND NOT AN INHERITED PIPE. A pipe fd is the tidier
// orphan leash, but it cannot survive this path: the fd would have to be handed
// through the `aikey proxy start` CLI and across its detach. Watching a PID
// needs nothing from the intermediary — the value is just an env var, and the
// check is a signal-0 probe.
//
// 🔴 WHY THIS IS NOT A FEATURE FLAG. The project rule against env-var switches
// targets behavior toggles that fork the product's logic. This forks nothing:
// unset (every real install) means no goroutine and no behavior at all. It
// binds a LIFETIME, which has no other expression here.
const ParentWatchEnv = "AIKEY_PARENT_WATCH_PID"

// parentWatchInterval is short enough that a leak is measured in seconds rather
// than days, and long enough to be free: one signal-0 syscall per tick.
const parentWatchInterval = 2 * time.Second

// WatchParent exits this process once the PID in AIKEY_PARENT_WATCH_PID is gone.
// A missing or unparseable value disables it entirely — production never sets it.
//
// exit is injectable so the fence can prove the exit happens without killing the
// test binary that is asserting it.
func WatchParent(exit func(int)) {
	raw := os.Getenv(ParentWatchEnv)
	if raw == "" {
		return
	}
	pid, err := strconv.Atoi(raw)
	if err != nil || pid <= 1 {
		// Loud, not silent: a harness that set this expects a leash, and getting
		// none is exactly the state that produced ten-day orphans.
		slog.Warn("parent-liveness watch not armed — value is not a usable pid",
			"event.name", "proxy.parent_watch.invalid", ParentWatchEnv, raw)
		return
	}
	if exit == nil {
		exit = os.Exit
	}
	go func() {
		t := time.NewTicker(parentWatchInterval)
		defer t.Stop()
		for range t.C {
			if !pidAlive(pid) {
				slog.Warn("parent process is gone — exiting so this sandbox proxy cannot outlive its test run",
					"event.name", "proxy.parent_watch.parent_gone", "parent_pid", pid)
				exit(0)
				return
			}
		}
	}()
}

// pidAlive reports whether pid still exists. Signal 0 performs the existence and
// permission check without delivering anything — the portable POSIX idiom.
func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix FindProcess always succeeds, so the signal is the real probe.
	// ESRCH means gone; EPERM means alive but not ours (still alive).
	err = p.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// errors.Is, not ==: os.Process.Signal can return the errno WRAPPED (e.g.
	// *os.SyscallError), and a wrapped EPERM would fail the == comparison and be
	// read as "parent is gone" — the exact opposite of what EPERM means here
	// (the process exists, we just may not signal it). errorlint flags this.
	return errors.Is(err, syscall.EPERM)
}
