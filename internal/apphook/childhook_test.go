package apphook

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// findDetectorBinary returns path to the ai-compliance-detector binary built
// by `cd ai-compliance-detector && make build`. Test is skipped if binary
// is missing — CI builds it explicitly.
func findDetectorBinary(t *testing.T) string {
	t.Helper()

	// Walk up from internal/apphook → aikey-proxy → aikeylabs/ → ai-compliance-detector/bin/detector
	_, file, _, _ := runtime.Caller(0)
	apphookDir := filepath.Dir(file)                          // .../aikey-proxy/internal/apphook
	proxyDir := filepath.Dir(filepath.Dir(apphookDir))        // .../aikey-proxy
	aikeylabsDir := filepath.Dir(proxyDir)                    // .../aikeylabs
	binary := filepath.Join(aikeylabsDir, "ai-compliance-detector", "bin", "detector")

	// Note: not stat-probing here — if the detector isn't built, the actual
	// exec.Cmd reports a clearer error at run time. Keeping this function
	// path-only avoids a useless extra stat call.
	return binary
}

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
	h := NewChildHook(ChildHookConfig{
		Name: "recover-test", BinaryPath: findDetectorBinary(t), BinaryArgs: detectorArgs(),
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

// TestChildHook_LazyRecoverOnDetect — the trigger: a degraded Detect lazily
// restarts the child and serves recovered, instead of failing open forever.
func TestChildHook_LazyRecoverOnDetect(t *testing.T) {
	h := NewChildHook(ChildHookConfig{
		Name: "lazy-test", BinaryPath: findDetectorBinary(t), BinaryArgs: detectorArgs(),
		Timeout: 1 * time.Second, ReadyTimeout: 5 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Skipf("child binary unavailable, skipping (build first): %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()

	h.markDegraded("simulated")
	res := h.Detect(ctx, &Request{Direction: DirectionInbound, Payload: []byte("hi")})
	if res.Degraded {
		t.Fatalf("expected lazy recovery on Detect, still degraded: %s", res.Reason)
	}
	if h.degraded.Load() {
		t.Fatal("expected degraded cleared after lazy recover on Detect")
	}
}

func TestChildHookEchoRoundtrip(t *testing.T) {
	binary := findDetectorBinary(t)

	h := NewChildHook(ChildHookConfig{
		Name:         "ai-compliance-detector-test",
		BinaryPath:   binary,
		BinaryArgs:   detectorArgs(), // --echo-only: skip rule load, deterministic for IPC test
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
	h := NewChildHook(ChildHookConfig{
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
