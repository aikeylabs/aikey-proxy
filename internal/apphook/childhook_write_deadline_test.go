package apphook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// wedgedChildFixture writes a child binary that signals ready and then stays
// ALIVE WITHOUT EVER READING STDIN. That is the exact failure mode of the real
// ai-compliance-detector when its serve loop is busy: it takes the worker
// semaphore INSIDE the read loop and AIKEY_COMPLIANCE_WORKERS defaults to 1, so
// one in-flight detection stops the child from draining stdin altogether.
//
// It must be a REAL process on a REAL OS pipe: the bug is OS-level write
// back-pressure (pipe buffer full → write(2) blocks). A mock Hook, an in-memory
// io.Writer or a child that merely replies slowly cannot reproduce it.
func wedgedChildFixture(t *testing.T) string {
	t.Helper()
	child := filepath.Join(t.TempDir(), "wedged-child.sh")
	// `exec sleep` (not a shell loop) so the process the proxy spawns is the one
	// that holds the pipe — no grandchild keeps the FDs alive past Kill.
	script := "#!/bin/sh\nprintf 'ready wedged-fixture\\n' >&2\nexec sleep 300\n"
	if err := os.WriteFile(child, []byte(script), 0o700); err != nil {
		t.Fatalf("write wedged child fixture: %v", err)
	}
	return child
}

// TestChildHook_WedgedChildDoesNotWedgeMainPath is the regression fence for the
// 2026-08-13 P0 recorded in
// workflow/CI/bugfix/20260813-childhook-write-before-deadline-wedges-main-path.md.
//
// Before the fix roundtrip() wrote the request frame BEFORE entering the
// select-on-ctx, and writeFrame held the hook-wide writeMu for the whole
// blocking write. Once the OS pipe buffer filled up:
//   - Detect never returned at all (the configured Timeout only guarded the
//     "wait for the reply" half, never the "get the request out" half),
//   - markDegraded never fired (a blocked write returns no error), so
//     lazyRecover could never take over the wedged child,
//   - Shutdown/restart blocked on the same writeMu, so the proxy could not even
//     be restarted — kill -9 was the only way out.
//
// Three assertions, one per symptom. All must hold at once.
func TestChildHook_WedgedChildDoesNotWedgeMainPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell child fixture is Unix-only")
	}

	const (
		detectTimeout = 150 * time.Millisecond
		// Must exceed what the OS pipe buffer can absorb, otherwise the writes
		// simply succeed and there is no back-pressure to test. 16 × 64 KiB = 1 MiB
		// against a 16–64 KiB pipe buffer.
		concurrency = 16
		payloadSize = 64 * 1024
		// Generous next to detectTimeout: -race plus a loaded CI box schedules
		// goroutines late. The bug under test is unbounded blocking (measured at
		// 4s+ and still climbing), so this stays far away from a false green.
		detectBudget = 2 * time.Second
	)

	h := NewChildHook(&ChildHookConfig{
		Name:         "wedged-child-write-deadline",
		BinaryPath:   wedgedChildFixture(t),
		Timeout:      detectTimeout,
		ReadyTimeout: 5 * time.Second,
	})
	startCtx, cancelStart := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStart()
	if err := h.Start(startCtx); err != nil {
		t.Fatalf("start wedged fixture: %v", err)
	}
	// Read the pid ONCE, before any concurrency, and reap it out-of-band. On the
	// regression path Shutdown itself is the thing that hangs, so it cannot be
	// relied on to stop the fixture; without this a failing run leaks a `sleep`
	// process. On the fixed path Shutdown already reaped it and this is a no-op.
	childPID := h.cmd.Process.Pid
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })

	// Hold the lazy self-heal off for this batch. WHY: lazyRecover respawns the
	// child and a successful respawn resets Status() to Healthy, which would race
	// the DegradedReason assertion below. Consuming the cooldown slot up front is
	// the production code's own guard (recoverCooldown = 2s), not a test-only
	// switch, and the batch below completes in well under 2s.
	h.lastRecoverAt.Store(time.Now().UnixNano())

	results := make(chan detectOutcome, concurrency)
	payload := bytes.Repeat([]byte("x"), payloadSize)
	// No WaitGroup on purpose: on the regression path these goroutines never
	// return, and joining them would turn a clear assertion failure into a
	// 10-minute package timeout. `results` is buffered to `concurrency`, so a late
	// straggler can always deliver without blocking, and the goroutine touches no
	// *testing.T after the test body ends.
	for i := 0; i < concurrency; i++ {
		go func() {
			start := time.Now()
			// context.Background(): the hook's own cfg.Timeout is what must bound
			// this call. Passing a test deadline would prove nothing.
			res := h.Detect(context.Background(), &Request{
				Direction: DirectionInbound,
				Payload:   payload,
			})
			results <- detectOutcome{res: res, elapsed: time.Since(start)}
		}()
	}

	// (1) Every Detect returns fail-open inside the budget.
	var (
		got            []detectOutcome
		sawWriteTimout bool
		slowest        time.Duration
	)
	deadline := time.After(detectBudget)
collect:
	for len(got) < concurrency {
		select {
		case o := <-results:
			got = append(got, o)
			if o.elapsed > slowest {
				slowest = o.elapsed
			}
			if strings.Contains(o.res.Reason, "write to child timed out") {
				sawWriteTimout = true
			}
		case <-deadline:
			break collect
		}
	}
	if len(got) < concurrency {
		t.Errorf("only %d/%d Detect calls returned within %s — the remaining %d are blocked "+
			"in writeFrame with no deadline (P0: user main path wedged by a stuck detector)",
			len(got), concurrency, detectBudget, concurrency-len(got))
	}
	for i, o := range got {
		if o.res.Action != ActionAllow || !o.res.Degraded {
			t.Errorf("Detect[%d]: got action=%v degraded=%v reason=%q; a wedged child must fail OPEN",
				i, o.res.Action, o.res.Degraded, o.res.Reason)
		}
	}
	t.Logf("returned %d/%d, slowest Detect %s (cfg.Timeout=%s)", len(got), concurrency, slowest, detectTimeout)

	// (2) The hook must be degraded WITH a reason that names the write deadline —
	// that flag is the only thing that lets lazyRecover replace the wedged child.
	st := h.Status()
	if st.Healthy {
		t.Errorf("Status().Healthy is still true after the write deadline expired — "+
			"lazyRecover can never take over, so the wedged child keeps being fed requests (reason=%q)",
			st.DegradedReason)
	}
	if !strings.Contains(st.DegradedReason, "write_timeout") {
		t.Errorf("Status().DegradedReason = %q, want it to name the write timeout", st.DegradedReason)
	}
	if !sawWriteTimout {
		t.Errorf("no Detect reported a write-timeout reason; reasons observed: %s", reasonsOf(got))
	}

	// (3) Shutdown must not be blocked by the stuck write. Measured out-of-band so
	// a regression reports instead of hanging the whole package for 10 minutes.
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancelShutdown()
	shutdownDone := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		_ = h.Shutdown(shutdownCtx)
		shutdownDone <- time.Since(start)
	}()
	select {
	case elapsed := <-shutdownDone:
		t.Logf("Shutdown returned in %s", elapsed)
		if elapsed > 1500*time.Millisecond {
			t.Errorf("Shutdown(1s) took %s — closing the pipe must not wait on the stuck write", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("Shutdown(1s) did not return within 3s — restart/reload is wedged behind the blocked " +
			"write's lock; operators are left with kill -9")
	}
}

// TestChildHook_WedgedChildIsReplacedByLazyRecover covers the OTHER half of the
// same P0's root cause: markDegraded was the only trigger for lazyRecover, and it
// fired exclusively when a write returned an ERROR. A write that blocks forever
// returns no error, so before the fix the wedged child was never marked degraded,
// never replaced, and kept receiving requests for the lifetime of the proxy — the
// documented self-heal was structurally unreachable in exactly the failure mode
// it exists for.
//
// Note this test deliberately does NOT pre-consume the recoverCooldown slot (the
// sibling test does): letting lazyRecover run is the entire point here.
func TestChildHook_WedgedChildIsReplacedByLazyRecover(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell child fixture is Unix-only")
	}

	h := NewChildHook(&ChildHookConfig{
		Name:         "wedged-child-lazy-recover",
		BinaryPath:   wedgedChildFixture(t),
		Timeout:      150 * time.Millisecond,
		ReadyTimeout: 5 * time.Second,
	})
	startCtx, cancelStart := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStart()
	if err := h.Start(startCtx); err != nil {
		t.Fatalf("start wedged fixture: %v", err)
	}
	childPID := h.cmd.Process.Pid
	t.Cleanup(func() {
		_ = syscall.Kill(childPID, syscall.SIGKILL)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.Shutdown(shutdownCtx)
	})

	payload := bytes.Repeat([]byte("x"), 64*1024)
	// Wedge the pipe.
	for i := 0; i < 16; i++ {
		go func() {
			_ = h.Detect(context.Background(), &Request{Direction: DirectionInbound, Payload: payload})
		}()
	}
	if !waitFor(3*time.Second, func() bool { return h.degraded.Load() }) {
		t.Fatalf("hook never went degraded despite a wedged pipe — lazyRecover has no trigger (status=%+v)", h.Status())
	}

	// lazyRecover is kicked off by the NEXT call that observes `degraded`, so one
	// more Detect is what a live proxy would supply. It must still fail open.
	if res := h.Detect(context.Background(), &Request{Direction: DirectionInbound, Payload: []byte("probe")}); !res.Degraded {
		t.Errorf("post-wedge Detect: want degraded fail-open, got %+v", res)
	}

	// RestartCount is read via Status() (atomic) rather than h.cmd, which the
	// background restart mutates concurrently.
	if !waitFor(8*time.Second, func() bool { return h.Status().RestartCount > 0 }) {
		t.Fatalf("wedged child was never replaced: RestartCount still 0 after the write timeout — "+
			"self-heal cannot reach this failure mode (status=%+v)", h.Status())
	}
	t.Logf("wedged child replaced; RestartCount=%d", h.Status().RestartCount)
}

func waitFor(budget time.Duration, cond func() bool) bool {
	for deadline := time.Now().Add(budget); time.Now().Before(deadline); {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// detectOutcome is one goroutine's Detect result plus how long it actually took.
type detectOutcome struct {
	res     *Response
	elapsed time.Duration
}

func reasonsOf(got []detectOutcome) string {
	seen := make(map[string]int, len(got))
	for _, o := range got {
		seen[o.res.Reason]++
	}
	var b strings.Builder
	for r, n := range seen {
		fmt.Fprintf(&b, "\n  %q ×%d", r, n)
	}
	return b.String()
}
