package supervisor

import (
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// The leash must fire when the watched process disappears.
//
// 🔴 WHY THIS FENCE EXISTS (2026-08-22). Three sandbox proxies were found alive
// on a developer machine — from three different tests, one running for TEN DAYS
// — because `aikey proxy start` detaches and the harness could only chase it
// from t.Cleanup, which does not run when the test binary is killed by timeout,
// Ctrl-C, CI cancel or panic. The orphans kept polling a real control plane with
// revoked test credentials and produced a 466 MB log that nobody read.
//
// The test watches a REAL process it kills, not a fabricated pid: the whole
// mechanism is "does signal-0 still find it", so a made-up number would prove
// nothing about the syscall behaviour this depends on.
func TestParentWatchExitsWhenTheWatchedProcessDies(t *testing.T) {
	victim := exec.Command("sleep", "30")
	if err := victim.Start(); err != nil {
		t.Fatalf("start victim: %v", err)
	}
	pid := victim.Process.Pid

	t.Setenv(ParentWatchEnv, strconv.Itoa(pid))
	var exited atomic.Int32
	exited.Store(-1)
	WatchParent(func(code int) { exited.Store(int32(code)) })

	// Alive: the leash must NOT fire. Without this half the test would pass on a
	// watcher that exits unconditionally.
	time.Sleep(parentWatchInterval + 500*time.Millisecond)
	if exited.Load() != -1 {
		t.Fatalf("leash fired while the watched process was still alive (code %d)", exited.Load())
	}

	_ = victim.Process.Kill()
	_, _ = victim.Process.Wait()

	deadline := time.Now().Add(4 * parentWatchInterval)
	for time.Now().Before(deadline) {
		if exited.Load() == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("watched process died but the proxy did not exit — a killed test run would leave this proxy orphaned, which is the ten-day leak this guards")
}

// An unset variable must arm nothing: every real install runs without it, and a
// production proxy that quietly acquired a lifetime leash would be a far worse
// bug than the leak this fixes.
func TestParentWatchIsInertWithoutTheEnvVar(t *testing.T) {
	t.Setenv(ParentWatchEnv, "")
	fired := make(chan int, 1)
	WatchParent(func(code int) { fired <- code })
	time.Sleep(parentWatchInterval + 300*time.Millisecond)
	select {
	case code := <-fired:
		t.Fatalf("leash fired with no %s set (code %d) — production must be untouched", ParentWatchEnv, code)
	default:
	}
	if os.Getenv(ParentWatchEnv) != "" {
		t.Fatal("test env not clean")
	}
}
