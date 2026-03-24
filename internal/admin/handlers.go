package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
