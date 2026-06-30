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
	EventProxyRequestQuotaExceeded = "proxy.request.quota_exceeded"
	// EventProxyQuotaModelUnpriced: a completed request's model has no entry in
	// the edge price summary (D-U8/P7), so its usd was NOT counted locally — the
	// token quota floor backstops it and the server baseline catches up on
	// re-sync. Recurring hits signal a stale summary needing a price re-sync.
	EventProxyQuotaModelUnpriced = "proxy.quota.model_unpriced"
	// Oauth-group routing (N8). EventProxyGroupRouteResolved: a group VK request
	// picked + injected a candidate account. EventProxyGroupRouteDegraded: no
	// usable candidate (no material / all expired-exhausted / key unavailable) →
	// the request is failed rather than silently routed wrong.
	EventProxyGroupRouteResolved = "proxy.group.route_resolved"
	EventProxyGroupRouteDegraded = "proxy.group.route_degraded"
	// EventProxyGroupAccountCooldown (N8c): a pool account's upstream returned a
	// fallback-worthy failure (401 broken / exhaustion-429), so it was cooled down
	// and subsequent requests route around it.
	EventProxyGroupAccountCooldown = "proxy.group.account_cooldown"
	// EventProxyGroupAccountSwitched (N9 #8): the seat's rank-0 (primary) account
	// was unusable (cooled / exhausted / expired / no material) so the request
	// fell back to a different candidate — an auditable account switch.
	EventProxyGroupAccountSwitched = "proxy.group.account_switched"
	// EventProxyGroupLoginRequired (RW2/D2): the HRW-routed account has no token
	// for this member (they haven't logged into it). The proxy returns a structured
	// login prompt naming the account (strict HRW — it does NOT skip to a later
	// logged-in account) so the member logs into THAT account on their local node.
	EventProxyGroupLoginRequired = "proxy.group.login_required"
	// EventProxyGroupWindowPrecut (N10): an account's upstream utilization crossed
	// its randomized window cap (window_max_util_pct), so it was pre-cut for that
	// window (cooled until reset) — staying under 100% which looks like abuse.
	EventProxyGroupWindowPrecut = "proxy.group.window_precut"
	// EventProxyGroupSeatBlocked (§5.5): the engine left this seat UNBOUND because
	// every account in its pool/segment is at the ≤3-人/号 cap, so the proxy 429s it
	// (never WRH-falls-back, which would route a 4th user onto a full account).
	EventProxyGroupSeatBlocked = "proxy.group.seat_blocked"
)

// Usage extraction events.
//
// EventProxyExtractionMismatch fires when an extractor falls back to defaults
// because the response body doesn't match expected wire format (json error,
// missing usage field, unknown field names like Responses API's
// input_tokens/output_tokens vs Chat Completions' prompt_tokens/completion_tokens).
//
// EventProxyExtractionEmpty is the caller-side double-defense: HTTP 200 with
// non-empty body but extractor returned (0, 0). Catches the case where a new
// wire format ships and the extractor wasn't updated to log Mismatch for it.
const (
	EventProxyExtractionMismatch = "proxy.extraction.shape_mismatch"
	EventProxyExtractionEmpty    = "proxy.extraction.empty"
)

// ---- Error code constants ----

const (
	ErrCodeTokenMissing          = "TOKEN_MISSING"
	ErrCodeTokenInvalid          = "TOKEN_INVALID"
	ErrCodePolicyModelForbidden  = "POLICY_MODEL_FORBIDDEN"
	ErrCodeSecretNotConfigured   = "SECRET_NOT_CONFIGURED"
	ErrCodeUpstreamError         = "UPSTREAM_ERROR"
	ErrCodeProviderError         = "PROVIDER_ERROR"
	ErrCodeUsageExtractionFailed = "USAGE_EXTRACTION_FAILED"
	// Enterprise quota (Phase 2, design §5.5). Stage 3 wires the token code;
	// USD + degraded-block are reserved for later stages ($ enforcement / §8).
	ErrCodeQuotaExceededToken = "QUOTA_EXCEEDED_TOKEN"
	ErrCodeQuotaExceededUSD   = "QUOTA_EXCEEDED_USD"
	ErrCodeQuotaDegradedBlock = "QUOTA_DEGRADED_BLOCK"
	// Oauth-group routing degrade codes (N8). The resolver's typed reasons
	// (GROUP_NO_CANDIDATES / GROUP_NO_MATERIAL / GROUP_ALL_UNUSABLE) are surfaced
	// verbatim; GROUP_KEY_UNAVAILABLE is the proxy-local "can't decrypt" case.
	ErrCodeGroupKeyUnavailable = "GROUP_KEY_UNAVAILABLE"
	// ErrCodeGroupPoolFull (§5.5): 429 when the seat is blocked — every pool account
	// is at the per-account user cap; the user waits or the admin adds accounts.
	ErrCodeGroupPoolFull = "GROUP_POOL_FULL"
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
func (h *MultiHandler) Handle(ctx context.Context, rec slog.Record) error { //nolint:gocritic // rec type is fixed by the slog.Handler interface; cannot be a pointer
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

// SetupLogger initializes the global slog logger to write:
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
