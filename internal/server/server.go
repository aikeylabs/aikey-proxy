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
}

// New creates a new Server.
//
//   - ln is the already-bound TCP listener (held by the caller across reloads).
//   - dataHandler is the http.Handler for the AI proxy endpoints; the Supervisor
//     returns a stable wrapper that atomically delegates to the active generation.
//   - adminHandler serves /health, /status, /metrics, and /admin/reload.
// RouteRegistrar can register HTTP routes on a ServeMux.
// Used by the broker handler to register /oauth/* routes without tight coupling.
type RouteRegistrar interface {
	RegisterRoutes(mux *http.ServeMux)
}

func New(ln net.Listener, dataHandler http.Handler, adminHandler *admin.Handler, extraHandlers ...RouteRegistrar) *Server {
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
		w.Write(buildinfo.Get().JSON())
	})

	// Control plane: admin endpoints.
	mux.HandleFunc("GET /health", adminHandler.Health)
	mux.HandleFunc("GET /health/provider-targets", adminHandler.HealthProviderTargets)
	mux.HandleFunc("GET /health/providers", adminHandler.HealthProviders)
	mux.HandleFunc("GET /health/keys", adminHandler.HealthKeys)
	mux.HandleFunc("GET /status", adminHandler.Status)
	mux.HandleFunc("GET /metrics", adminHandler.Metrics)
	mux.HandleFunc("POST /admin/reload", adminHandler.Reload)
	// Effective compliance packs (built-in + pulled) of the live filter child.
	mux.HandleFunc("GET /admin/compliance/packs", adminHandler.CompliancePacks)
	// Replay dead-letter usage events. Re-uses current reporter config
	// (post-login JWT, current route URLs) so brief upstream errors
	// (transient 401 / 5xx) don't permanently lose data. Operator
	// triggers via `aikey proxy replay-dead-letter`. Idempotent: re-
	// running is safe (entries that re-deliver are removed; entries
	// still failing stay in the file for the next try).
	mux.HandleFunc("POST /admin/replay-dead-letter", adminHandler.ReplayDeadLetter)
	// Connectivity probe endpoint — used by `aikey test` / `aikey doctor` /
	// `aikey add` to measure reachability + latency from the proxy's network
	// context to upstream providers. Respects config.upstream_proxy.url and
	// standard HTTPS_PROXY / HTTP_PROXY / ALL_PROXY env vars — essential for
	// the China-network deployment where direct TCP to upstream is blocked.
	mux.HandleFunc("POST /admin/probe/ping", adminHandler.ProbePing)

	// Debug toggle for outbound upstream headers. 3-layer resolution
	// (API > env AIKEY_PROXY_DEBUG_UPSTREAM_HEADERS > compile-time ldflags);
	// see internal/proxy/debug_upstream.go for full semantics.
	mux.HandleFunc("GET /admin/debug/upstream-headers", adminHandler.DebugUpstreamHeadersGet)
	mux.HandleFunc("POST /admin/debug/upstream-headers", adminHandler.DebugUpstreamHeadersSet)
	mux.HandleFunc("DELETE /admin/debug/upstream-headers", adminHandler.DebugUpstreamHeadersClear)

	// In-memory "most recent call per app_slug" snapshot — drives the Web
	// "Connected Apps" list Health column. Volatile (process memory only);
	// see internal/proxy/apppipe/health.go for the rationale.
	mux.HandleFunc("GET /admin/apps/health", adminHandler.AppHealth)

	// Delivery-integrity audit (D2.5 / D3): local client state + client-confirmed
	// reconciliation (re-send WAL-present gaps, confirm WAL-absent gaps lost).
	mux.HandleFunc("GET /admin/audit/status", adminHandler.AuditStatus)
	mux.HandleFunc("POST /admin/audit/reconcile", adminHandler.AuditReconcile)

	// Extra route registrars (e.g., OAuth broker handler)
	for _, h := range extraHandlers {
		h.RegisterRoutes(mux)
	}

	return &Server{
		ln: ln,
		httpServer: &http.Server{
			// Wrap the mux with a panic-recover middleware so one bad handler
			// cannot take down the whole proxy. net/http's default recover
			// silently swallows panics without logging or crash-dump — that
			// made the 2026-04-22 stream-drainer nil-collector crash
			// undiagnosable from logs alone.
			Handler:           recoverMiddleware(mux),
			ReadHeaderTimeout: 30 * time.Second,
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
