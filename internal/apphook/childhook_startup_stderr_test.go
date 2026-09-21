package apphook

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer safe to read while the stderr-drain goroutine
// is still writing to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestChildHook_SurfacesStderrWrittenBeforeReady — every line the child writes
// to stderr must reach the log, INCLUDING the ones it writes before the ready
// sentinel.
//
// WHY THIS FENCE EXISTS
// (bugfix 2026-09-20-cluster-node-home-subtree-owned-by-root-disables-pack-pull.md)
//
// The drain goroutine used to log only lines seen AFTER the ready sentinel;
// everything before it was read and thrown away. That window is precisely where
// a child reports what it could not initialize — it has not finished booting
// yet, so of course its startup complaints come first.
//
// On every Cluster worker the detector wrote two lines there:
//
//	warn: pack cache dir init failed (...permission denied); puller disabled
//	warn: pack health file init failed (...); puller disabled
//
// and then came up healthy with `packs=off` in its ready banner. Both lines were
// discarded. A full-journal grep for them returned zero hits, so the operator's
// only evidence was the word `off` with no reason attached, and the actual cause
// (a root-owned directory) took a live权限 walk on the node to find. The child's
// voice is the cheapest diagnosis in the system and this dropped half of it —
// not just for this bug, but for ANY detector startup failure.
//
// The assertion is deliberately about the WINDOW, not about pack pulling: any
// pre-ready line must survive. A fix that special-cases "lines mentioning
// puller" would pass a test written the other way and still lose the next one.
func TestChildHook_SurfacesStderrWrittenBeforeReady(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell child fixture is Unix-only")
	}

	tmp := t.TempDir()
	child := filepath.Join(tmp, "child.sh")
	// The shape of the real detector: complain about a subsystem it could not
	// start, THEN announce itself ready and serve normally.
	script := `#!/bin/sh
printf 'warn: pack cache dir init failed (mkdir /home/svc/.aikey/apps: permission denied); puller disabled\n' >&2
printf 'warn: pack health file init failed (permission denied); puller disabled\n' >&2
printf 'ai-compliance-detector ready (version=fence, packs=off)\n' >&2
while IFS= read -r _line; do :; done
`
	if err := os.WriteFile(child, []byte(script), 0o700); err != nil {
		t.Fatalf("write child fixture: %v", err)
	}

	var logs syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	h := NewChildHook(&ChildHookConfig{
		Name:       "startup-stderr-fence",
		BinaryPath: child,
		// Sized like the other child fixtures in this package: a three-line shell
		// script only needs to be scheduled, but package-level parallelism during a
		// full `go test ./internal/...` can delay that by seconds.
		ReadyTimeout: 15 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	defer func() { _ = h.Shutdown(ctx) }()

	// The drain goroutine races the Start() return; give it a bounded moment.
	var got string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got = logs.String()
		if strings.Contains(got, "pack cache dir init failed") &&
			strings.Contains(got, "pack health file init failed") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, want := range []string{
		"pack cache dir init failed",
		"pack health file init failed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("child stderr written BEFORE the ready sentinel was discarded: %q never reached the log.\n"+
				"That window is where a child says what it could not initialize; dropping it is how a\n"+
				"Cluster-wide compliance outage presented as the single word `packs=off`.\nlog was:\n%s",
				want, got)
		}
	}
	// The sentinel itself is consumed as the ready signal, not re-logged as a
	// child-stderr warning — it is already reported as the hook's Version.
	if strings.Count(got, "ai-compliance-detector ready") > 0 {
		t.Errorf("the ready sentinel should be consumed as the ready signal, not echoed as a stderr warning; log was:\n%s", got)
	}
}
