package observability

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGoSafe_IsolatedPanicRecovered confirms that a panic in an Isolated
// goroutine is caught, logged, and the parent process survives. This is the
// primary invariant that would have prevented the 2026-04-22 stream_drainer
// crash.
func TestGoSafe_IsolatedPanicRecovered(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	SetCrashDumpDir(tmpDir)

	// Redirect slog to an in-memory buffer so the test can assert on the
	// ERROR record without polluting stderr.
	var logBuf bytes.Buffer
	var mu sync.Mutex
	h := slog.NewJSONHandler(&syncWriter{w: &logBuf, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelError})
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	done := make(chan struct{})
	GoSafe("test.isolated", Isolated, func() {
		defer close(done)
		panic("boom-isolated")
	})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("GoSafe goroutine did not finish — panic not recovered?")
	}

	// Give the deferred recover time to run after done is closed.
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	logs := logBuf.String()
	mu.Unlock()
	if !strings.Contains(logs, "boom-isolated") {
		t.Fatalf("expected panic value logged, got: %s", logs)
	}
	if !strings.Contains(logs, "test.isolated") {
		t.Fatalf("expected goroutine name logged, got: %s", logs)
	}

	// Crash dump should have been written.
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("read dump dir: %v", err)
	}
	var dumpFound bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "crash-") && strings.Contains(e.Name(), "test.isolated") {
			dumpFound = true
			body, err := os.ReadFile(filepath.Join(tmpDir, e.Name()))
			if err != nil {
				t.Fatalf("read dump file: %v", err)
			}
			if !bytes.Contains(body, []byte("boom-isolated")) {
				t.Fatalf("dump missing panic value: %s", body)
			}
			if !bytes.Contains(body, []byte("goroutine=test.isolated")) {
				t.Fatalf("dump missing goroutine name: %s", body)
			}
			// The all-goroutine traceback section must be present: it is
			// what turns a single-goroutine panic dump into a
			// deadlock-diagnosable artifact without risking key material
			// leakage (pointer args only, no heap contents).
			if !bytes.Contains(body, []byte("all_goroutines:")) {
				t.Fatalf("dump missing all_goroutines section: %s", body)
			}
			break
		}
	}
	if !dumpFound {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("no crash dump file found in %s; got: %v", tmpDir, names)
	}
}

// TestGoSafe_FatalInvokesFlushHook confirms that Fatal severity triggers the
// flush hook before the process would exit. We cannot actually call os.Exit
// in a test, so the test verifies the hook is invoked by pre-empting exit
// via an injected panic in the hook itself (caught by our own recover).
func TestGoSafe_FatalInvokesFlushHook(t *testing.T) {
	// Can't run parallel: mutates package-level flushHook.
	tmpDir := t.TempDir()
	SetCrashDumpDir(tmpDir)

	var logBuf bytes.Buffer
	var mu sync.Mutex
	h := slog.NewJSONHandler(&syncWriter{w: &logBuf, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelError})
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	var hookCalled atomic.Bool
	// The hook panics to short-circuit os.Exit — we recover here in the test
	// after running the Fatal path synchronously (not via GoSafe so exit path
	// runs on THIS stack, where we can recover from the hook's re-panic).
	SetFatalFlushHook(func() {
		hookCalled.Store(true)
		panic("skip-exit")
	})
	t.Cleanup(func() { SetFatalFlushHook(nil) })

	func() {
		defer func() {
			if r := recover(); r != nil && r != "skip-exit" {
				t.Fatalf("unexpected re-panic: %v", r)
			}
		}()
		defer recoverPanic("test.fatal", Fatal)
		panic("boom-fatal")
	}()

	if !hookCalled.Load() {
		t.Fatal("Fatal severity did not invoke flush hook")
	}

	mu.Lock()
	logs := logBuf.String()
	mu.Unlock()
	if !strings.Contains(logs, "boom-fatal") {
		t.Fatalf("expected panic value logged, got: %s", logs)
	}
}

// TestSanitiseName_NeverEmpty guards against a filename-crafted panic name
// slipping through and producing crash-<ts>-.log (no name segment).
func TestSanitiseName_NeverEmpty(t *testing.T) {
	t.Parallel()
	if got := sanitiseName(""); got != "unnamed" {
		t.Fatalf("empty name should become 'unnamed', got %q", got)
	}
	if got := sanitiseName("foo/bar:baz"); got != "foo_bar_baz" {
		t.Fatalf("unsafe chars not replaced: %q", got)
	}
	if got := sanitiseName("a.b-c_d.1"); got != "a.b-c_d.1" {
		t.Fatalf("safe chars mangled: %q", got)
	}
}

// syncWriter is a minimal mutex-guarded writer for buffering slog output in
// parallel tests without a data race.
type syncWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
