package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/admin"
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
func New(ln net.Listener, dataHandler http.Handler, adminHandler *admin.Handler) *Server {
	mux := http.NewServeMux()

	// Data plane: catch-all — forwards every request not claimed by the admin routes
	// above to the proxy handler. Proxy.Handle internally decides between:
	//   - path-prefix routing  (/anthropic/v1/..., /openai/v1/..., etc.)
	//   - token-based routing  (/v1/messages, /v1/chat/completions, etc.)
	// Using a wildcard here means no server.go change is needed when new provider
	// prefixes are added. Go 1.22+ ServeMux gives more-specific patterns priority,
	// so the admin routes above always win.
	mux.Handle("/{path...}", dataHandler)

	// Control plane: admin endpoints.
	mux.HandleFunc("GET /health", adminHandler.Health)
	mux.HandleFunc("GET /health/provider-targets", adminHandler.HealthProviderTargets)
	mux.HandleFunc("GET /health/providers", adminHandler.HealthProviders)
	mux.HandleFunc("GET /health/keys", adminHandler.HealthKeys)
	mux.HandleFunc("GET /status", adminHandler.Status)
	mux.HandleFunc("GET /metrics", adminHandler.Metrics)
	mux.HandleFunc("POST /admin/reload", adminHandler.Reload)

	return &Server{
		ln: ln,
		httpServer: &http.Server{
			Handler:           mux,
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
