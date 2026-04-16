package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
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

	// KeyChecksFn resolves the active key's decrypted credentials for each provider.
	// Injected by the Supervisor. Used by GET /health/keys.
	KeyChecksFn func() ([]KeyCheckTarget, error)

	// ReporterMetricsFn returns usage reporter counters (nil = reporter disabled).
	ReporterMetricsFn func() *events.ReporterMetrics
	// CanaryResultFn returns the latest canary probe result (nil = canary disabled).
	CanaryResultFn func() *events.CanaryResult
}

// KeyCheckTarget holds decrypted credentials for one provider, used by GET /health/keys.
type KeyCheckTarget struct {
	Provider string // e.g. "anthropic"
	Protocol string // "anthropic" | "openai" | "google" — drives auth header selection
	BaseURL  string // upstream base URL; empty → handler uses built-in default
	APIKey   string // decrypted real key
	KeyRef   string // alias / vk_id for display
}

// knownProviders lists the upstream base URLs checked by GET /health/providers.
var knownProviders = []struct {
	code    string
	baseURL string
}{
	{"anthropic", "https://api.anthropic.com"},
	{"openai", "https://api.openai.com/v1"},
	{"deepseek", "https://api.deepseek.com/v1"},
	{"kimi", "https://api.kimi.com/coding"},
	{"google", "https://generativelanguage.googleapis.com"},
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
	TotalRequests      int64                  `json:"total_requests"`
	TotalErrors        int64                  `json:"total_errors"`
	RequestsByVKey     map[string]int64       `json:"requests_by_vkey"`
	RequestsByProvider map[string]int64       `json:"requests_by_provider"`
	Reporter           *events.ReporterMetrics `json:"reporter,omitempty"`
	Canary             *events.CanaryResult    `json:"canary,omitempty"`
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

	var reporterMetrics *events.ReporterMetrics
	if h.ReporterMetricsFn != nil {
		reporterMetrics = h.ReporterMetricsFn()
	}
	var canaryResult *events.CanaryResult
	if h.CanaryResultFn != nil {
		canaryResult = h.CanaryResultFn()
	}

	writeJSON(w, http.StatusOK, metricsResponse{
		TotalRequests:      totalReqs,
		TotalErrors:        totalErrs,
		RequestsByVKey:     byVKey,
		RequestsByProvider: byProvider,
		Reporter:           reporterMetrics,
		Canary:             canaryResult,
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

// HealthProviderTargets returns the provider list for the currently active key without
// probing them. Used by the CLI's doctor command to drive its own concurrent connectivity
// checks, so the CLI — not the proxy — controls parallelism and streaming terminal output.
// GET /health/provider-targets
func (h *Handler) HealthProviderTargets(w http.ResponseWriter, r *http.Request) {
	type target struct {
		Provider string `json:"provider"`
		BaseURL  string `json:"base_url"`
	}

	if h.KeyChecksFn == nil {
		writeJSON(w, http.StatusOK, map[string]any{"targets": []target{}})
		return
	}
	checks, err := h.KeyChecksFn()
	if err != nil || len(checks) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"targets": []target{}})
		return
	}

	// Deduplicate by base_url: a personal key on a custom gateway serves all protocols from
	// one URL — no point probing the same host multiple times for connectivity.
	seen := make(map[string]bool)
	targets := make([]target, 0, len(checks))
	for _, c := range checks {
		baseURL := c.BaseURL
		if baseURL == "" {
			baseURL = providerDefaultBaseURL(c.Provider)
		}
		if seen[baseURL] {
			continue
		}
		seen[baseURL] = true
		targets = append(targets, target{Provider: c.Provider, BaseURL: baseURL})
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": targets})
}

// HealthProviders tests network reachability + latency for each known provider's upstream URL.
// GET /health/providers — no authentication required.
func (h *Handler) HealthProviders(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		// Don't follow redirects — connectivity check only.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type result struct {
		Provider  string `json:"provider"`
		BaseURL   string `json:"base_url"`
		Reachable bool   `json:"reachable"`
		LatencyMs int64  `json:"latency_ms,omitempty"`
		Error     string `json:"error,omitempty"`
	}

	results := make([]result, 0, len(knownProviders))
	for _, p := range knownProviders {
		start := time.Now()
		resp, err := client.Get(p.baseURL)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			results = append(results, result{
				Provider: p.code, BaseURL: p.baseURL,
				Reachable: false, Error: classifyNetError(err),
			})
			continue
		}
		resp.Body.Close()
		results = append(results, result{
			Provider: p.code, BaseURL: p.baseURL,
			Reachable: true, LatencyMs: latency,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": results})
}

// HealthKeys tests whether the active key can authenticate to its provider(s)
// using a lightweight GET /v1/models call (free endpoint, no inference cost).
// GET /health/keys
func (h *Handler) HealthKeys(w http.ResponseWriter, r *http.Request) {
	if h.KeyChecksFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "key checks not wired"})
		return
	}
	targets, err := h.KeyChecksFn()
	if err != nil || len(targets) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}, "message": "no active key configured"})
		return
	}

	type result struct {
		Provider   string `json:"provider"`
		KeyRef     string `json:"key_ref"`
		Ok         bool   `json:"ok"`
		LatencyMs  int64  `json:"latency_ms,omitempty"`
		StatusCode int    `json:"status_code,omitempty"`
		Error      string `json:"error,omitempty"`
	}

	client := &http.Client{Timeout: 15 * time.Second}
	results := make([]result, 0, len(targets))
	for _, t := range targets {
		start := time.Now()
		code, callErr := probeKey(client, t)
		latency := time.Since(start).Milliseconds()

		// 200        → key confirmed valid (inference succeeded).
		// 401 / 403  → key rejected by the provider.
		// other 4xx  → request was authenticated; failure is model/format, not the key.
		// 5xx        → provider-side server error (treat as failure).
		ok := callErr == nil && code != http.StatusUnauthorized && code != http.StatusForbidden && code < 500
		var errMsg string
		if callErr != nil {
			ok = false
			errMsg = classifyNetError(callErr)
		} else if code == http.StatusUnauthorized || code == http.StatusForbidden {
			ok = false
			errMsg = fmt.Sprintf("HTTP %d — key may be invalid or expired", code)
		} else if code >= 500 {
			ok = false
			errMsg = fmt.Sprintf("HTTP %d — provider service error", code)
		}
		results = append(results, result{
			Provider: t.Provider, KeyRef: t.KeyRef,
			Ok: ok, LatencyMs: latency, StatusCode: code, Error: errMsg,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": results})
}

// probeKey verifies a key by sending a minimal real inference request (max_tokens=1).
// This confirms the key is accepted end-to-end by the actual provider or gateway,
// rather than relying on a metadata endpoint (/v1/models) that many gateways don't implement.
//
// Response semantics:
//   - 200        → key confirmed valid
//   - 401 / 403  → key rejected (invalid or expired)
//   - other 4xx  → authenticated (auth passed), request/model issue — still treated as ok
//   - 5xx        → provider-side server error
func probeKey(client *http.Client, t KeyCheckTarget) (int, error) {
	baseURL := strings.TrimRight(t.BaseURL, "/")
	if baseURL == "" {
		baseURL = providerDefaultBaseURL(t.Provider)
	}
	// Strip /v1 suffix: probe functions append their own versioned paths
	// (e.g. /v1/chat/completions). Without this, base_urls like
	// "https://api.openai.com/v1" would produce double /v1/v1/... paths.
	baseURL = strings.TrimSuffix(baseURL, "/v1")

	switch t.Protocol {
	case "anthropic":
		return probeAnthropic(client, baseURL, t.APIKey)
	case "google", "gemini":
		return probeGoogle(client, baseURL, t.APIKey)
	default: // openai, deepseek, kimi, moonshot, etc.
		return probeOpenAICompat(client, baseURL, t.APIKey, probeModelForProtocol(t.Protocol))
	}
}

// probeAnthropic sends a minimal POST /v1/messages (max_tokens=1) to verify the key.
func probeAnthropic(client *http.Client, baseURL, apiKey string) (int, error) {
	body := `{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequest("POST", baseURL+"/v1/messages", strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// probeOpenAICompat sends a minimal POST /v1/chat/completions (max_tokens=1) to verify the key.
func probeOpenAICompat(client *http.Client, baseURL, apiKey, model string) (int, error) {
	body := fmt.Sprintf(`{"model":%q,"max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`, model)
	req, err := http.NewRequest("POST", baseURL+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// probeGoogle sends a minimal POST to the Gemini generateContent endpoint to verify the key.
func probeGoogle(client *http.Client, baseURL, apiKey string) (int, error) {
	body := `{"contents":[{"parts":[{"text":"hi"}]}]}`
	url := fmt.Sprintf("%s/v1beta/models/gemini-1.5-flash:generateContent?key=%s", baseURL, apiKey)
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// probeModelForProtocol returns a lightweight well-known model name for each protocol,
// used as the inference target in the key validity probe.
func probeModelForProtocol(protocol string) string {
	switch strings.ToLower(protocol) {
	case "deepseek":
		return "deepseek-chat"
	case "kimi", "moonshot":
		return "moonshot-v1-8k"
	default: // openai and any other OpenAI-compatible gateway
		return "gpt-4o-mini"
	}
}

// providerDefaultBaseURL returns the default upstream base URL for a known provider.
func providerDefaultBaseURL(code string) string {
	switch strings.ToLower(code) {
	case "anthropic", "claude":
		return "https://api.anthropic.com"
	case "openai":
		return "https://api.openai.com/v1"
	case "google", "gemini":
		return "https://generativelanguage.googleapis.com"
	case "kimi", "moonshot":
		return "https://api.kimi.com/coding"
	case "deepseek":
		return "https://api.deepseek.com/v1"
	default:
		return ""
	}
}

// classifyNetError converts a Go net error into a short human-readable message.
func classifyNetError(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "context deadline"):
		return "timeout"
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	case strings.Contains(s, "no such host"):
		return "DNS lookup failed"
	default:
		return s
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
