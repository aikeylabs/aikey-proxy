package observability

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/pkg/aikeycompat"
)

// Severity selects what happens when a GoSafe-wrapped goroutine panics.
//
// Isolated: per-request / per-stream goroutines. A panic in one must not
//
//	bring down the whole proxy — it is logged, a crash dump is
//	written, and the goroutine exits. The parent process keeps
//	serving other requests.
//
// Fatal:    long-running service loops (log writer, supervisor, collector,
//
//	reporter, canary, server Serve). If one of these dies the
//	proxy is in an unrecoverable state, so we log + dump + exit(2)
//	to let the OS supervisor (systemd / launchd / nssm / sandbox
//	runner) restart the process cleanly. Exit(2) is used rather
//	than panic() to ensure the log writer Flush() runs and the
//	crash dump actually lands on disk before we go.
type Severity int

const (
	Isolated Severity = iota
	Fatal
)

func (s Severity) String() string {
	switch s {
	case Fatal:
		return "fatal"
	case Isolated:
		return "isolated"
	default:
		return "unknown"
	}
}

// crashDumpDir is the directory where panic stack traces are persisted.
// It is set once by SetCrashDumpDir (called from main after log setup) and
// read concurrently by panicking goroutines. atomic.Value keeps the read
// path lock-free and safe under racing goroutine panics.
var (
	crashDumpDir atomic.Value // stored type: string

	// flushHook, if set, is invoked just before exit(2) in Fatal mode so the
	// async log writer can drain its queue. Kept as a plain function to avoid
	// an import cycle back to the caller.
	flushHook   func()
	flushHookMu sync.Mutex
)

// SetCrashDumpDir configures where GoSafe writes panic dumps. Pass the same
// directory as the structured log dir — dumps live alongside current.jsonl
// so an operator looking at logs finds crashes without hunting elsewhere.
func SetCrashDumpDir(dir string) {
	crashDumpDir.Store(dir)
}

// SetFatalFlushHook registers a hook to run right before exit(2) in Fatal
// mode. Typically wired to AsyncWriter.Flush so ERROR records about the
// panic actually make it to disk.
func SetFatalFlushHook(fn func()) {
	flushHookMu.Lock()
	defer flushHookMu.Unlock()
	flushHook = fn
}

// GoSafe spawns fn as a goroutine wrapped with panic recovery, structured
// logging, and a crash-dump writer. Every production goroutine should use
// this helper instead of a bare `go func(){}()` so mystery exits become
// diagnosable.
//
// name is a short stable label (e.g. "stream_drainer.watcher",
// "supervisor.managed_key_sync") embedded in logs and crash-dump filenames.
func GoSafe(name string, sev Severity, fn func()) {
	go func() {
		defer recoverPanic(name, sev)
		fn()
	}()
}

// recoverPanic is the shared panic-handling path for GoSafe and the HTTP
// recover middleware. It is exported-ish (lowercase) because both callers
// live in this package.
func recoverPanic(name string, sev Severity) {
	r := recover()
	if r == nil {
		return
	}
	stack := debug.Stack()            // current goroutine only → slog field
	allStacks := allGoroutineStacks() // every goroutine → crash dump file
	dumpPath := writeCrashDump(name, r, stack, allStacks)

	slog.Error("goroutine panic",
		"event.name", "proxy.goroutine.panic",
		"goroutine", name,
		"severity", sev.String(),
		"panic", fmt.Sprintf("%v", r),
		"crash_dump", dumpPath,
		"stack", string(stack),
	)

	if sev == Fatal {
		// Give the async log writer a chance to drain so the ERROR record
		// above lands on disk before the process goes away.
		flushHookMu.Lock()
		hook := flushHook
		flushHookMu.Unlock()
		if hook != nil {
			hook()
		}
		// exit(2) rather than re-panic: lets the OS supervisor restart us
		// with exit-code semantics ("crashed") instead of an abort-with-
		// stack that some supervisors treat differently.
		os.Exit(2)
	}
}

// writeCrashDump persists a full panic record (timestamp, pid, goroutine
// name, panic value, panicking-goroutine stack, and the stacks of every
// other goroutine) to <crashDumpDir>/crash-<ts>-<name>.log. Returns the
// path written (or "" if no dump dir is configured / write failed). All
// errors are swallowed intentionally: a crash dump failure must not mask
// the original panic.
//
// allStacks is intentionally NOT inlined into the slog record — one crash
// can easily produce 50KB+ of goroutine traces, which would drown the
// structured log. The compact `stack` in slog plus a file pointer via
// `crash_dump` is the right split.
//
// Privacy note: these stacks contain Go runtime state only (function
// names, line numbers, args shown as hex pointers). They intentionally do
// NOT dump the process heap — vault keys and plaintext API keys stay out
// of the crash file. A full OS core dump would be unsafe here because the
// proxy holds decrypted key material in memory; see
// workflow/CI/bugfix/2026-04-22-connectivity-probe-through-proxy.md.
func writeCrashDump(name string, panicVal any, stack, allStacks []byte) string {
	dirAny := crashDumpDir.Load()
	dir, _ := dirAny.(string)
	if dir == "" {
		return ""
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return ""
	}
	// Stage 2.5 windows-compat: harden NTFS ACL — crash dumps include
	// stack traces with potentially-sensitive variable names. No-op on Unix.
	_ = aikeycompat.EnforceOwnerOnly(dir)
	ts := time.Now().UTC().Format("20060102T150405.000Z")
	safe := sanitiseName(name)
	path := filepath.Join(dir, fmt.Sprintf("crash-%s-%s.log", ts, safe))

	var buf []byte
	buf = append(buf, fmt.Sprintf("time=%s\n", time.Now().UTC().Format(time.RFC3339Nano))...)
	buf = append(buf, fmt.Sprintf("pid=%d\n", os.Getpid())...)
	buf = append(buf, fmt.Sprintf("goroutine=%s\n", name)...)
	buf = append(buf, fmt.Sprintf("panic=%v\n", panicVal)...)
	buf = append(buf, "stack:\n"...)
	buf = append(buf, stack...)
	if len(allStacks) > 0 {
		buf = append(buf, "\nall_goroutines:\n"...)
		buf = append(buf, allStacks...)
	}

	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return ""
	}
	return path
}

// allGoroutineStacks returns a traceback of every goroutine in the
// process. Used to capture deadlock / cross-goroutine corruption state
// that the panicking goroutine's own stack cannot show. Grows the buffer
// until runtime.Stack fits the whole picture, capped at 8 MB so a
// pathological goroutine explosion cannot eat unbounded memory during a
// crash.
func allGoroutineStacks() []byte {
	const cap8MB = 8 * 1024 * 1024
	buf := make([]byte, 64*1024)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return buf[:n]
		}
		if len(buf) >= cap8MB {
			// Truncated: better some info than none.
			return buf
		}
		buf = make([]byte, len(buf)*2)
	}
}

// sanitiseName makes name safe to use inside a filename. Only keep letters,
// digits, '.', '_', '-'; everything else becomes '_'.
func sanitiseName(s string) string {
	if s == "" {
		return "unnamed"
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// RecoverHTTP is an http middleware helper. Call as:
//
//	defer observability.RecoverHTTP(w, r, "handler.name")
//
// It catches panics from HTTP handlers, writes a crash dump and ERROR log,
// and emits a 500 response if headers have not yet been flushed. An HTTP
// panic is always treated as Isolated — one bad request must not kill the
// proxy for every other caller.
func RecoverHTTP(w httpResponder, route string) {
	r := recover()
	if r == nil {
		return
	}
	// ReverseProxy deliberately panics with http.ErrAbortHandler after a
	// downstream disconnect or an unrecoverable streaming error. The outer
	// net/http server recognizes this sentinel and suppresses the usual panic
	// traceback. Treating it as an application panic creates a large, noisy
	// crash dump for normal connection aborts (74 false reports in the month
	// ending 2026-07-20). Re-panic so net/http can apply its documented
	// handling; no 500 can be written reliably on an already-aborted stream.
	if r == http.ErrAbortHandler {
		panic(r)
	}
	stack := debug.Stack()
	allStacks := allGoroutineStacks()
	name := "http." + route
	dumpPath := writeCrashDump(name, r, stack, allStacks)

	slog.Error("http handler panic",
		"event.name", "proxy.http.panic",
		"route", route,
		"panic", fmt.Sprintf("%v", r),
		"crash_dump", dumpPath,
		"stack", string(stack),
	)

	if w != nil {
		w.TryWrite500()
	}
}

// httpResponder is the minimal interface RecoverHTTP needs from the wrapper
// around http.ResponseWriter. Keeping it abstract avoids importing net/http
// here (which would pull proxy.go's concrete middleware into this file).
type httpResponder interface {
	TryWrite500()
}
