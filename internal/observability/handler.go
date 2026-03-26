package observability

import (
	"context"
	"log/slog"
	"os"
)

// ---- Event name constants ----

// Proxy process lifecycle events.
const (
	EventProxyProcessStarted = "proxy.process.started"
	EventProxyProcessStopped = "proxy.process.stopped"
	EventProxyConfigLoaded   = "proxy.config.loaded"
	EventProxyListenerBound  = "proxy.listener.bound"
)

// Reload and generation lifecycle events.
const (
	EventProxyReloadStarted          = "proxy.reload.started"
	EventProxyReloadCompleted        = "proxy.reload.completed"
	EventProxyReloadFailed           = "proxy.reload.failed"
	EventProxyGenerationDraining     = "proxy.generation.draining"
	EventProxyGenerationDrained      = "proxy.generation.drained"
	EventProxyGenerationDrainTimeout = "proxy.generation.drain_timeout"
)

// Health events.
const (
	EventProxyHealthOk        = "proxy.health.ok"
	EventProxyHealthDegraded  = "proxy.health.degraded"
	EventProxyHealthRecovered = "proxy.health.recovered"
	EventProxyVaultStale      = "proxy.vault.stale_detected"
)

// Request events.
const (
	EventProxyRequestAuthFailed    = "proxy.request.auth_failed"
	EventProxyRequestPolicyDenied  = "proxy.request.policy_denied"
	EventProxyRequestVaultFailed   = "proxy.request.vault_lookup_failed"
	EventProxyRequestUpstreamError = "proxy.request.upstream_error"
	EventProxyRequestSlow          = "proxy.request.slow"
	EventProxyRequestCompleted     = "proxy.request.completed"
)

// ---- Error code constants ----

const (
	ErrCodeTokenMissing         = "TOKEN_MISSING"
	ErrCodeTokenInvalid         = "TOKEN_INVALID"
	ErrCodePolicyModelForbidden = "POLICY_MODEL_FORBIDDEN"
	ErrCodeSecretNotConfigured  = "SECRET_NOT_CONFIGURED"
	ErrCodeUpstreamError        = "UPSTREAM_ERROR"
	ErrCodeProviderError        = "PROVIDER_ERROR"
)

// ---- HealthSnapshot ----

// HealthSnapshot captures a point-in-time view of proxy health for log records.
type HealthSnapshot struct {
	Status           string  `json:"status"`
	GenerationID     int     `json:"generation_id,omitempty"`
	InflightRequests int64   `json:"inflight_requests"`
	TotalRequests    int64   `json:"total_requests"`
	TotalErrors      int64   `json:"total_errors"`
	LatencyP95Ms     float64 `json:"latency_p95_ms,omitempty"`
	VaultChangeSeq   uint64  `json:"vault_change_seq,omitempty"`
	ProxyLoadedSeq   uint64  `json:"proxy_loaded_seq,omitempty"`
	UptimeSeconds    float64 `json:"uptime_seconds,omitempty"`
}

// ---- MultiHandler ----

// MultiHandler is a slog.Handler that forwards every record to all registered
// child handlers. It enables writing structured JSON to a log file while
// simultaneously printing human-readable text to stderr.
type MultiHandler struct {
	handlers []slog.Handler
}

// NewMultiHandler returns a MultiHandler that forwards to all given handlers.
func NewMultiHandler(handlers ...slog.Handler) *MultiHandler {
	return &MultiHandler{handlers: handlers}
}

// Enabled reports whether any child handler is enabled for level.
func (h *MultiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, hh := range h.handlers {
		if hh.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle forwards rec to all child handlers that are enabled for its level.
func (h *MultiHandler) Handle(ctx context.Context, rec slog.Record) error {
	for _, hh := range h.handlers {
		if hh.Enabled(ctx, rec.Level) {
			// Clone the record so each handler gets an independent copy.
			_ = hh.Handle(ctx, rec.Clone())
		}
	}
	return nil
}

// WithAttrs returns a new MultiHandler with attrs pre-applied to all children.
func (h *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, hh := range h.handlers {
		handlers[i] = hh.WithAttrs(attrs)
	}
	return &MultiHandler{handlers: handlers}
}

// WithGroup returns a new MultiHandler with the group applied to all children.
func (h *MultiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, hh := range h.handlers {
		handlers[i] = hh.WithGroup(name)
	}
	return &MultiHandler{handlers: handlers}
}

// ---- Logger setup ----

// SetupLogger initialises the global slog logger to write:
//   - human-readable text to stderr (for local development visibility)
//   - structured JSON Lines to logDir/current.jsonl (for machine parsing)
//
// It returns the AsyncWriter so the caller can Flush/Close it on shutdown.
// serviceName and serviceVersion are embedded in every log record.
func SetupLogger(logDir, serviceName, serviceVersion string, level slog.Level) (*AsyncWriter, error) {
	hostname, _ := os.Hostname()

	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Rename built-in slog keys to match the spec field names.
			switch a.Key {
			case slog.TimeKey:
				return slog.Attr{Key: "ts", Value: a.Value}
			case slog.MessageKey:
				return slog.Attr{Key: "message", Value: a.Value}
			}
			return a
		},
	}

	// Text handler for stderr (developer-facing).
	textHandler := slog.NewTextHandler(os.Stderr, opts)

	// Async JSONL handler for the log file.
	asyncW, err := NewAsyncWriter(logDir)
	if err != nil {
		return nil, err
	}
	jsonHandler := slog.NewJSONHandler(asyncW, opts)

	// Attach common fields to both handlers.
	commonAttrs := []slog.Attr{
		slog.String("service.name", serviceName),
		slog.String("service.version", serviceVersion),
		slog.String("host.name", hostname),
		slog.Int("process.pid", os.Getpid()),
	}
	text := textHandler.WithAttrs(commonAttrs)
	json := jsonHandler.WithAttrs(commonAttrs)

	slog.SetDefault(slog.New(NewMultiHandler(text, json)))
	return asyncW, nil
}
