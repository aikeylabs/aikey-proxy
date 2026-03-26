package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

const Version = "0.1.0"

// Handler serves admin/control API endpoints.
type Handler struct {
	cfg       *config.Config
	registry  *vkeys.Registry
	store     *events.Store
	startedAt time.Time

	// Injected from proxy for live metrics.
	TotalRequestsFn func() int64
	TotalErrorsFn   func() int64

	// ReloadFn triggers a graceful reload of the active runtime generation.
	// Set by main.go after wiring the Supervisor.
	ReloadFn func(ctx context.Context) error
}

// NewHandler creates admin handlers.
func NewHandler(cfg *config.Config, reg *vkeys.Registry, store *events.Store) *Handler {
	return &Handler{
		cfg:       cfg,
		registry:  reg,
		store:     store,
		startedAt: time.Now(),
	}
}

type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// Health returns basic health status.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	tc := observability.ExtractOrCreate(r)
	slog.Debug("admin: health check",
		"trace_id", tc.TraceID,
		"request_id", tc.RequestID,
	)
	writeJSON(w, http.StatusOK, healthResponse{
		Status:  "ok",
		Version: Version,
	})
}

type statusResponse struct {
	Status      string `json:"status"`
	Version     string `json:"version"`
	Uptime      string `json:"uptime"`
	ListenAddr  string `json:"listen_addr"`
	VirtualKeys int    `json:"virtual_keys_loaded"`
	VaultPath   string `json:"vault_path"`
	StartedAt   string `json:"started_at"`
	TotalReqs   int64  `json:"total_requests"`
	TotalErrs   int64  `json:"total_errors"`
}

// Status returns detailed proxy status.
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	tc := observability.ExtractOrCreate(r)
	slog.Debug("admin: status requested",
		"trace_id", tc.TraceID,
		"request_id", tc.RequestID,
	)

	var totalReqs, totalErrs int64
	if h.TotalRequestsFn != nil {
		totalReqs = h.TotalRequestsFn()
	}
	if h.TotalErrorsFn != nil {
		totalErrs = h.TotalErrorsFn()
	}

	writeJSON(w, http.StatusOK, statusResponse{
		Status:      "ok",
		Version:     Version,
		Uptime:      time.Since(h.startedAt).Round(time.Second).String(),
		ListenAddr:  h.cfg.Listen.Addr(),
		VirtualKeys: h.registry.Count(),
		VaultPath:   h.cfg.Vault.Path,
		StartedAt:   h.startedAt.Format(time.RFC3339),
		TotalReqs:   totalReqs,
		TotalErrs:   totalErrs,
	})
}

type metricsResponse struct {
	TotalRequests      int64            `json:"total_requests"`
	TotalErrors        int64            `json:"total_errors"`
	RequestsByVKey     map[string]int64 `json:"requests_by_vkey"`
	RequestsByProvider map[string]int64 `json:"requests_by_provider"`
}

// Metrics returns aggregated usage metrics.
func (h *Handler) Metrics(w http.ResponseWriter, r *http.Request) {
	var totalReqs, totalErrs int64
	if h.TotalRequestsFn != nil {
		totalReqs = h.TotalRequestsFn()
	}
	if h.TotalErrorsFn != nil {
		totalErrs = h.TotalErrorsFn()
	}

	byVKey, byProvider, err := h.store.QueryStats()
	if err != nil {
		byVKey = make(map[string]int64)
		byProvider = make(map[string]int64)
	}

	writeJSON(w, http.StatusOK, metricsResponse{
		TotalRequests:      totalReqs,
		TotalErrors:        totalErrs,
		RequestsByVKey:     byVKey,
		RequestsByProvider: byProvider,
	})
}

// Reload triggers a graceful runtime reload without closing the TCP listener.
// The new generation opens a fresh vault snapshot; once it passes the readiness
// gate, all new requests are routed to it and the old generation is drained.
//
// Returns 200 OK when the new generation is active, 503 if ReloadFn is not
// wired, or 500 on reload failure.
func (h *Handler) Reload(w http.ResponseWriter, r *http.Request) {
	tc := observability.ExtractOrCreate(r)
	logger := slog.With(
		"trace_id", tc.TraceID,
		"request_id", tc.RequestID,
	)

	if h.ReloadFn == nil {
		logger.Warn("admin: reload not supported")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "reload not supported",
		})
		return
	}

	logger.Info("admin: reload requested")

	// Give the reload up to 30 s to build the new generation.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := h.ReloadFn(ctx); err != nil {
		logger.Error("admin: reload failed",
			"error.message", err.Error(),
		)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
		return
	}

	logger.Info("admin: reload completed successfully")
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
