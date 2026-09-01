package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/admin"
	"github.com/AiKeyLabs/pkg/buildinfo"
)

// Server manages the HTTP server lifecycle.
// It accepts a pre-created net.Listener so the TCP port is never released
// during graceful reloads — only the request handler is swapped.
type Server struct {
	ln         net.Listener
	httpServer *http.Server
	// sb is non-nil only for NewStarting servers: the switchboard Promote
	// swaps the real mux into.
	sb *Switchboard
}

// New creates a new Server.
//
//   - ln is the already-bound TCP listener (held by the caller across reloads).
//   - dataHandler is the http.Handler for the AI proxy endpoints; the Supervisor
//     returns a stable wrapper that atomically delegates to the active generation.
//   - adminHandler serves /health, /status, /metrics, and /admin/reload.
//
// RouteRegistrar can register HTTP routes on a ServeMux.
// Used by the broker handler to register /oauth/* routes without tight coupling.
type RouteRegistrar interface {
	RegisterRoutes(mux *http.ServeMux)
}

func New(ln net.Listener, dataHandler http.Handler, adminHandler *admin.Handler, gate AdminGate, extraHandlers ...RouteRegistrar) *Server {
	return newServer(ln, recoverMiddleware(buildMux(dataHandler, adminHandler, gate, extraHandlers...)), nil)
}

// NewStarting binds the full server SHELL to the listener before init has
// anything real to serve: every request is answered with an honest "starting"
// (see starting.go) until Promote swaps in the real mux. This is what makes a
// slow start distinguishable from a dead process from the very first second
// the port is owned (2026-09-01).
func NewStarting(ln net.Listener, phase func() string) *Server {
	sb := NewSwitchboard(startingHandler(phase, time.Now()))
	return newServer(ln, recoverMiddleware(sb), sb)
}

// Promote swaps the starting surface for the real handler set. Only servers
// built with NewStarting can be promoted; calling it on a classic New server
// is a wiring bug and panics loudly rather than silently doing nothing — a
// proxy that LOOKS promoted but still answers "starting" forever would be the
// exact silence this file exists to remove.
func (s *Server) Promote(dataHandler http.Handler, adminHandler *admin.Handler, gate AdminGate, extraHandlers ...RouteRegistrar) {
	if s.sb == nil {
		panic("server.Promote called on a server without a starting switchboard")
	}
	s.sb.Swap(buildMux(dataHandler, adminHandler, gate, extraHandlers...))
}

func buildMux(dataHandler http.Handler, adminHandler *admin.Handler, gate AdminGate, extraHandlers ...RouteRegistrar) *http.ServeMux {
	mux := http.NewServeMux()

	// Data plane: catch-all — forwards every request not claimed by the admin routes
	// above to the proxy handler. Proxy.Handle internally decides between:
	//   - path-prefix routing  (/anthropic/v1/..., /openai/v1/..., etc.)
	//   - token-based routing  (/v1/messages, /v1/chat/completions, etc.)
	// Using a wildcard here means no server.go change is needed when new provider
	// prefixes are added. Go 1.22+ ServeMux gives more-specific patterns priority,
	// so the admin routes above always win.
	mux.Handle("/{path...}", dataHandler)

	// Build info: unauthenticated, returns build metadata only.
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buildinfo.Get().JSON())
	})

	// Control plane: admin endpoints.
	mux.HandleFunc("GET /health", adminHandler.Health)
	mux.HandleFunc("GET /health/provider-targets", adminHandler.HealthProviderTargets)
	mux.HandleFunc("GET /health/providers", adminHandler.HealthProviders)
	mux.HandleFunc("GET /health/keys", adminHandler.HealthKeys)
	mux.HandleFunc("GET /status", adminHandler.Status)
	mux.HandleFunc("GET /metrics", adminHandler.Metrics)
	mux.HandleFunc("POST /admin/reload", gate.guard(adminHandler.Reload))
	// Effective compliance packs (built-in + pulled) of the live filter child.
	mux.HandleFunc("GET /admin/compliance/packs", gate.guard(adminHandler.CompliancePacks))
	// Replay dead-letter usage events. Re-uses current reporter config
	// (post-login JWT, current route URLs) so brief upstream errors
	// (transient 401 / 5xx) don't permanently lose data. Operator
	// triggers via `aikey proxy replay-dead-letter`. Idempotent: re-
	// running is safe (entries that re-deliver are removed; entries
	// still failing stay in the file for the next try).
	mux.HandleFunc("POST /admin/replay-dead-letter", gate.guard(adminHandler.ReplayDeadLetter))
	// Connectivity probe endpoint — used by `aikey test` / `aikey doctor` /
	// `aikey add` to measure reachability + latency from the proxy's network
	// context to upstream providers. Respects config.upstream_proxy.url and
	// standard HTTPS_PROXY / HTTP_PROXY / ALL_PROXY env vars — essential for
	// the China-network deployment where direct TCP to upstream is blocked.
	mux.HandleFunc("POST /admin/probe/ping", gate.guard(adminHandler.ProbePing))

	// Debug toggle for outbound upstream headers. 3-layer resolution
	// (API > env AIKEY_PROXY_DEBUG_UPSTREAM_HEADERS > compile-time ldflags);
	// see internal/proxy/debug_upstream.go for full semantics.
	mux.HandleFunc("GET /admin/debug/upstream-headers", gate.guard(adminHandler.DebugUpstreamHeadersGet))
	mux.HandleFunc("POST /admin/debug/upstream-headers", gate.guard(adminHandler.DebugUpstreamHeadersSet))
	mux.HandleFunc("DELETE /admin/debug/upstream-headers", gate.guard(adminHandler.DebugUpstreamHeadersClear))

	// In-memory "most recent call per app_slug" snapshot — drives the Web
	// "Connected Apps" list Health column. Volatile (process memory only);
	// see internal/proxy/apppipe/health.go for the rationale.
	mux.HandleFunc("GET /admin/apps/health", gate.guard(adminHandler.AppHealth))

	// Delivery-integrity audit (D2.5 / D3): local client state + client-confirmed
	// reconciliation (re-send WAL-present gaps, confirm WAL-absent gaps lost).
	mux.HandleFunc("GET /admin/audit/status", gate.guard(adminHandler.AuditStatus))
	mux.HandleFunc("POST /admin/audit/reconcile", gate.guard(adminHandler.AuditReconcile))

	// Egress (upstream) proxy config — read + hot-swap. Relayed by the local web
	// "Settings → Upstream proxy" card (R25 出口收敛: egress lives on the proxy node).
	mux.HandleFunc("GET /admin/upstream-proxy", gate.guard(adminHandler.UpstreamProxyGet))
	mux.HandleFunc("PUT /admin/upstream-proxy", gate.guard(adminHandler.UpstreamProxySet))
	// Escape hatch (2026-07-19): opt-in override that routes OAuth per-account
	// egress traffic through the node upstream chain (Settings checkbox).
	mux.HandleFunc("GET /admin/oauth-egress-override", gate.guard(adminHandler.OAuthEgressOverrideGet))
	mux.HandleFunc("PUT /admin/oauth-egress-override", gate.guard(adminHandler.OAuthEgressOverrideSet))
	mux.HandleFunc("POST /admin/upstream-proxy/probe", gate.guard(adminHandler.UpstreamProxyProbe))
	// Exit-IP identity probe for a candidate/current upstream spec (节点管理
	// Nodes page test button, update 20260718). Distinct from probe above:
	// probe asks "can this URL reach the provider", this asks "WHICH exit IP
	// does a spec leave from" (TestDial through the same engine registry the
	// forwarding transport uses). Public face never sees it — worker nginx
	// denies /admin/* (P3 方案C); the master console calls it over the
	// cluster-internal network.
	mux.HandleFunc("POST /admin/egress-test", gate.guard(adminHandler.EgressTest))

	// Per-account egress connectivity self-check (§5.4): `aikey test` (presence)
	// / `aikey doctor` (?dial=1) read this to verify each pool account's egress.
	mux.HandleFunc("GET /admin/egress/selfcheck", gate.guard(adminHandler.EgressSelfCheck))

	// Extra route registrars (e.g., OAuth broker handler)
	for _, h := range extraHandlers {
		h.RegisterRoutes(mux)
	}

	return mux
}

func newServer(ln net.Listener, handler http.Handler, sb *Switchboard) *Server {
	return &Server{
		ln: ln,
		sb: sb,
		httpServer: &http.Server{
			// The handler arrives already wrapped in recoverMiddleware so one
			// bad handler cannot take down the whole proxy. net/http's default
			// recover silently swallows panics without logging or crash-dump —
			// that made the 2026-04-22 stream-drainer nil-collector crash
			// undiagnosable from logs alone.
			Handler:           handler,
			ReadHeaderTimeout: 30 * time.Second,
			// Bound idle keep-alive connections so slow/abandoned clients cannot
			// pin sockets/file descriptors indefinitely. NOT Read/WriteTimeout:
			// those would sever long-lived SSE streams (the LLM main path), so
			// they are intentionally left unset.
			IdleTimeout: 120 * time.Second,
		},
	}
}

// Serve starts accepting connections on the pre-bound listener. It blocks
// until the server is stopped.
func (s *Server) Serve() error {
	slog.Info("starting server", "addr", s.ln.Addr())
	return s.httpServer.Serve(s.ln)
}

// Shutdown gracefully shuts down the server with a timeout.
func (s *Server) Shutdown(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	slog.Info("shutting down server", "timeout", timeout)
	return s.httpServer.Shutdown(ctx)
}
