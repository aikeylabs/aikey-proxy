package apphook

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestChildHookShutdownClosesStdinForGracefulAuditFlush(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell child fixture is Unix-only")
	}
	tmp := t.TempDir()
	marker := filepath.Join(tmp, "flushed")
	child := filepath.Join(tmp, "child.sh")
	script := `#!/bin/sh
marker="$1"
trap 'exit 99' INT TERM
printf 'ready\n' >&2
while IFS= read -r _line; do :; done
printf 'flushed\n' > "$marker"
`
	if err := os.WriteFile(child, []byte(script), 0o700); err != nil {
		t.Fatalf("write child fixture: %v", err)
	}

	h := NewChildHook(&ChildHookConfig{
		Name:         "graceful-shutdown-test",
		BinaryPath:   child,
		BinaryArgs:   []string{marker},
		// Match the package's other child fixtures. Two seconds flakes when
		// release gates compile Rust and run Go race tests concurrently, before
		// this tiny shell process gets scheduled at all.
		ReadyTimeout: 5 * time.Second,
	})
	// The outer ctx must be LARGER than ReadyTimeout, not equal to it: it also
	// has to cover Shutdown and the marker read, so an equal budget means
	// ReadyTimeout can never actually be spent — the ctx expires first and the
	// 5s allowance above is dead code. That is how this failed a release round
	// on 2026-08-19 (`start fixture: context deadline exceeded` at exactly
	// 5.01s while the same test passes in ~0.7s on an idle machine). Sized like
	// the other fixture in this file, which pairs ReadyTimeout 5s with a 20s ctx.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	if err := h.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown fixture: %v", err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "flushed\n" {
		t.Fatalf("child did not observe stdin EOF and flush before exit: got=%q err=%v", got, err)
	}
}

// TestChildHook_ConcurrentDetect — Phase 1 (v3 request-id multiplexing): many
// goroutines fire Detect on ONE ChildHook at once. The async demux must match
// each response to its caller by request-id with no deadlock, no cross-talk, and
// no spurious degraded. Run under -race. (The echo child is still serial — this
// validates the proxy-side multiplex; Phase 2 makes the child concurrent.)
func TestChildHook_ConcurrentDetect(t *testing.T) {
	h := NewChildHook(&ChildHookConfig{
		Name: "concurrent-test", BinaryPath: requireDetectorBinary(t), BinaryArgs: detectorArgs(),
		Timeout: 2 * time.Second, ReadyTimeout: 5 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Skipf("child binary unavailable, skipping (build first): %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()

	const (
		goroutines = 32
		iterations = 20
	)
	var wg sync.WaitGroup
	var failures atomic.Int64
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				p := []byte(fmt.Sprintf("req-%d-%d", seed, i))
				res := h.Detect(ctx, &Request{Direction: DirectionInbound, Payload: p})
				if res.Degraded || res.Action != ActionAllow { // echo child always Allows
					failures.Add(1)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	if n := failures.Load(); n > 0 {
		t.Fatalf("%d/%d concurrent Detect calls failed — async demux broke under concurrency", n, goroutines*iterations)
	}
}

// requireDetectorBinary moved to detector_gate_test.go (BR-v1.0.5-26).
//
// It used to live here as `findDetectorBinary`: a path-only helper that never
// checked anything, on the reasoning that "the exec.Cmd reports a clearer error
// at run time". That error then landed in each caller's `t.Skipf` — and a
// skipping test passes, so an unbuilt sibling repo made this entire IPC suite
// disappear behind a green `ok`. The replacement classifies the failure and,
// under AIKEY_REQUIRE_NO_TEST_SKIPS=1, refuses to skip at all.

// detectorArgs returns the args to pass to the binary so it behaves like
// Stage A (echo-only) for apphook tests. Stage B+ binary has a real engine
// that requires rule paths; we don't need that for IPC contract tests.
// Empty slice means "no special args" — Stage A binary ignores them.
func detectorArgs() []string {
	return []string{"--echo-only"}
}

// TestChildHook_RestartRecovers — lazy self-heal core (2026-06-05): markDegraded
// used to be terminal (no respawn) → a degraded hook stayed down until the whole
// proxy restarted ("本机合规检测未运行"). restart() must kill the dead/desynced
// child, respawn a fresh one, and clear degraded.
func TestChildHook_RestartRecovers(t *testing.T) {
	h := NewChildHook(&ChildHookConfig{
		Name: "recover-test", BinaryPath: requireDetectorBinary(t), BinaryArgs: detectorArgs(),
		Timeout: 1 * time.Second, ReadyTimeout: 5 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Skipf("child binary unavailable, skipping (build first): %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()

	oldPid := h.cmd.Process.Pid
	h.markDegraded("simulated degrade")
	if !h.degraded.Load() {
		t.Fatal("expected degraded after markDegraded")
	}
	if err := h.restart(ctx); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if h.degraded.Load() {
		t.Fatal("expected recovered (degraded cleared) after restart")
	}
	if h.cmd.Process.Pid == oldPid {
		t.Errorf("expected a NEW child pid after restart, got same pid %d", oldPid)
	}
	if res := h.Detect(ctx, &Request{Direction: DirectionInbound, Payload: []byte("hi")}); res.Degraded {
		t.Fatalf("Detect still degraded after restart: %s", res.Reason)
	}
}

// TestChildHook_LazyRecoverOnDetect — a degraded Detect FAILS OPEN immediately
// (never blocks the hot path on the restart) and kicks the bounded restart off in
// the background; a subsequent Detect, once the async restart clears `degraded`,
// serves recovered. This is the fail-open invariant: synchronous lazyRecover used
// context.Background()+2s and stalled the first post-degrade Detect up to 2s.
func TestChildHook_LazyRecoverOnDetect(t *testing.T) {
	h := NewChildHook(&ChildHookConfig{
		Name: "lazy-test", BinaryPath: requireDetectorBinary(t), BinaryArgs: detectorArgs(),
		Timeout: 1 * time.Second, ReadyTimeout: 5 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Skipf("child binary unavailable, skipping (build first): %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()

	h.markDegraded("simulated")

	// The first degraded Detect must fail open IMMEDIATELY — not block on the
	// background restart (the whole point of the fix).
	start := time.Now()
	res := h.Detect(ctx, &Request{Direction: DirectionInbound, Payload: []byte("hi")})
	if !res.Degraded {
		t.Fatalf("expected the first degraded Detect to fail open (degraded), got non-degraded")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("degraded Detect blocked %v — must fail open immediately, not wait on the restart", elapsed)
	}

	// The background lazyRecover then restarts the child; once it clears `degraded`
	// a subsequent Detect serves recovered. Poll past the restart bound + margin.
	recovered := false
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
		if !h.degraded.Load() {
			recovered = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !recovered {
		t.Fatal("expected the background lazy restart to clear degraded")
	}
	if res := h.Detect(ctx, &Request{Direction: DirectionInbound, Payload: []byte("hi")}); res.Degraded {
		t.Fatalf("Detect still degraded after background recovery: %s", res.Reason)
	}
}

func TestChildHookEchoRoundtrip(t *testing.T) {
	binary := requireDetectorBinary(t)

	h := NewChildHook(&ChildHookConfig{
		Name:         "ai-compliance-detector-test",
		BinaryPath:   binary,
		BinaryArgs:   detectorArgs(),  // --echo-only: skip rule load, deterministic for IPC test
		Timeout:      1 * time.Second, // generous for first-call test
		ReadyTimeout: 5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := h.Start(ctx); err != nil {
		t.Skipf("child binary unavailable, skipping E2E (build first): %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()

	// Send Detect — child Stage A always returns Allow.
	res := h.Detect(ctx, &Request{
		Direction: DirectionInbound,
		Payload:   []byte("hello compliance"),
	})

	if res.Degraded {
		t.Fatalf("unexpected degraded: reason=%s", res.Reason)
	}
	if res.Action != ActionAllow {
		t.Errorf("action: got %v want Allow", res.Action)
	}
	if res.LatencyObserved == 0 {
		t.Errorf("LatencyObserved should be > 0")
	}
	if res.LatencyObserved > 100*time.Millisecond {
		t.Logf("warning: roundtrip slow (%s) — may indicate platform issue (Stage A spike showed p99 < 70µs)", res.LatencyObserved)
	}

	// Status should now show healthy.
	st := h.Status()
	if !st.Healthy {
		t.Errorf("expected Healthy=true after successful Detect, got reason=%s", st.DegradedReason)
	}
	if st.LastDetectAt.IsZero() {
		t.Errorf("LastDetectAt should be set after Detect")
	}
}

func TestChildHookDegradedOnMissingBinary(t *testing.T) {
	h := NewChildHook(&ChildHookConfig{
		Name:       "ai-compliance-detector-test-missing",
		BinaryPath: "/nonexistent/path/detector",
		Timeout:    1 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := h.Start(ctx)
	if err == nil {
		t.Fatal("expected Start to fail on missing binary, got nil")
	}

	// Detect should NOT block, should return degraded immediately.
	res := h.Detect(ctx, &Request{Payload: []byte("test")})
	if !res.Degraded {
		t.Errorf("expected degraded=true, got %+v", res)
	}
	if res.Action != ActionAllow {
		t.Errorf("expected ActionAllow (main path unblocked), got %v", res.Action)
	}

	st := h.Status()
	if st.Healthy {
		t.Errorf("expected Healthy=false")
	}
}

func TestDisabledHook(t *testing.T) {
	d := NewDisabled("test-app")
	if d.Name() != "test-app" {
		t.Errorf("name: got %q want test-app", d.Name())
	}
	res := d.Detect(context.Background(), &Request{Payload: []byte("x")})
	if res.Action != ActionAllow || res.Degraded {
		t.Errorf("disabled hook should return Allow, not degraded: %+v", res)
	}
	st := d.Status()
	if !st.Healthy {
		t.Errorf("disabled hook reports Healthy=true (vacuously)")
	}
}
