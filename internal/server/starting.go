package server

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/pkg/buildinfo"
)

// The pre-Serve silence this file removes (2026-09-01, customer machine 方波
// + winpc2, bugfix 2026-09-01-proxy-slow-start-killed-by-5s-deadline.md):
//
// app.Run binds the TCP listener EARLY (so the port is owned for the whole
// process lifetime) but only calls Serve at the END of init — vault Argon2
// derive, egress engine, OAuth broker, observers. During that window the
// kernel accepts connections into the listen backlog and nobody ever answers
// them. From the outside, a proxy that is 80% through a slow start and a
// proxy that is dead look IDENTICAL: TCP connects, HTTP hangs. The CLI's
// health wait read that as "crashed silently" and killed a child that was
// seconds from ready; the tray showed a scary red "unresponsive"; a human
// with curl learned nothing.
//
// The fix: ONE http.Server whose handler is swappable. It starts serving the
// moment the port is bound, answering everything with an honest "starting"
// (503 + phase), and is promoted to the real mux when init completes. The
// listener is never re-bound, graceful shutdown is unchanged — only the
// handler pointer moves.

// Switchboard is an http.Handler whose target can be swapped atomically.
type Switchboard struct {
	h atomic.Value // http.Handler
}

// NewSwitchboard returns a Switchboard initially routing to h.
func NewSwitchboard(h http.Handler) *Switchboard {
	s := &Switchboard{}
	s.h.Store(h)
	return s
}

// Swap atomically replaces the target handler.
func (s *Switchboard) Swap(h http.Handler) { s.h.Store(h) }

// ServeHTTP delegates to the current target.
func (s *Switchboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 🔴 Comma-ok, and it still panics — deliberately identical to the bare
	// assertion this replaces. Nothing but NewSwitchboard and Swap ever stores
	// here and both take an http.Handler, so !ok is unreachable; if it ever
	// happens it is a programming error, and swallowing it would leave the port
	// answering with an empty 200, which is the failure this whole file exists
	// to make impossible. errcheck (check-type-assertions) wants the assertion
	// written out; it does not want the failure hidden.
	h, ok := s.h.Load().(http.Handler)
	if !ok {
		panic("switchboard: no http.Handler stored")
	}
	h.ServeHTTP(w, r)
}

// StartupPhase is a tiny thread-safe label of how far init has come. app.Run
// sets it at each milestone; the starting handler reports it, so "stuck" is
// diagnosable ("phase":"egress" for two minutes says exactly where to look).
type StartupPhase struct {
	v atomic.Value // string
}

// NewStartupPhase starts at the given label.
func NewStartupPhase(initial string) *StartupPhase {
	p := &StartupPhase{}
	p.v.Store(initial)
	return p
}

// Set moves the label to the next milestone.
func (p *StartupPhase) Set(label string) { p.v.Store(label) }

// Get returns the current label.
//
// 🔴 Comma-ok for errcheck, and the empty string is the right fallback rather
// than a panic: this value only ever reaches a diagnostic field ("phase") in the
// starting response. A health probe must not be turned into a crash by a
// diagnostic. NewStartupPhase always stores a string, so !ok is unreachable.
func (p *StartupPhase) Get() string {
	label, _ := p.v.Load().(string)
	return label
}

// startingHandler answers for the whole surface while init runs.
//
//   - GET /health  → 503 {"status":"starting","phase":…,"uptime_ms":…}
//     503 keeps every existing consumer's semantics: the CLI's health wait,
//     the cluster node probes and the installer all require a 200 — "starting"
//     stays "not ready" for all of them, it just stops being indistinguishable
//     from "dead".
//   - GET /version → normal build info (static, safe, useful in a bug report).
//   - everything else → 503 {"error":"proxy_starting"} — a data-plane request
//     that arrives mid-start gets an immediate honest refusal instead of
//     hanging in the accept backlog until init finishes.
func startingHandler(phase func() string, since time.Time) http.Handler {
	mux := http.NewServeMux()
	writeStarting := func(w http.ResponseWriter, body map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(body)
	}
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buildinfo.Get().JSON())
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeStarting(w, map[string]any{
			"status":    "starting",
			"phase":     phase(),
			"uptime_ms": time.Since(since).Milliseconds(),
		})
	})
	mux.HandleFunc("/{path...}", func(w http.ResponseWriter, _ *http.Request) {
		writeStarting(w, map[string]any{
			"error": "proxy_starting",
			"phase": phase(),
		})
	})
	return mux
}
