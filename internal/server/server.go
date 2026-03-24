package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/admin"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// Server manages the HTTP server lifecycle.
type Server struct {
	httpServer *http.Server
}

// New creates a new Server with the given address, proxy, and admin handler.
func New(addr string, p *proxy.Proxy, adminHandler *admin.Handler) *Server {
	mux := http.NewServeMux()

	// Data plane: proxy endpoints.
	mux.HandleFunc("POST /v1/chat/completions", p.Handle)
	mux.HandleFunc("POST /v1/messages", p.Handle)

	// Also handle without explicit method for broader compatibility.
	// Some clients may send OPTIONS or other methods.

	// Control plane: admin endpoints.
	mux.HandleFunc("GET /health", adminHandler.Health)
	mux.HandleFunc("GET /status", adminHandler.Status)
	mux.HandleFunc("GET /metrics", adminHandler.Metrics)

	return &Server{
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 30 * time.Second,
		},
	}
}

// ListenAndServe starts the HTTP server. It blocks until the server is stopped.
func (s *Server) ListenAndServe() error {
	slog.Info("starting server", "addr", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server with a timeout.
func (s *Server) Shutdown(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	slog.Info("shutting down server", "timeout", timeout)
	return s.httpServer.Shutdown(ctx)
}
