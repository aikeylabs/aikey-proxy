package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/apppipe"
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
	// CollectorMetricsFn returns async collector counters — notably usage
	// events dropped under buffer backpressure (nil = collector disabled).
	CollectorMetricsFn func() *events.CollectorMetrics
	// ReplayDeadLetterFn re-delivers entries from dead_letter.jsonl using
	// the *current* reporter config (post-login JWT, fresh route URLs,
	// etc). Nil = reporter / dead-letter writer disabled. Wired by main.go
	// after the supervisor builds its first generation. See
	// events.Reporter.ReplayDeadLetter for the contract.
	ReplayDeadLetterFn func(ctx context.Context) (events.ReplayDeadLetterResult, error)
	// CanaryResultFn returns the latest canary probe result (nil = canary disabled).
	CanaryResultFn func() *events.CanaryResult

	// DebugUpstreamHeadersStateFn / DebugUpstreamHeadersSetFn drive the
	// /admin/debug/upstream-headers endpoints. State returns the resolved
	// (enabled, source) tuple — source is "api" / "env" / "compile" /
	// "default". Set takes a tri-state: 1 = force ON, 0 = clear API
	// override (inherit env / compile), -1 = force OFF. Wired by main.go
	// to proxy.UpstreamHeadersDebugState / SetUpstreamHeadersDebugAPIOverride.
	DebugUpstreamHeadersStateFn func() (enabled bool, source string)
	DebugUpstreamHeadersSetFn   func(state int)

	// AppHealthFn returns the in-memory record of "the most recent app
	// pipeline call, per app_slug" for the GET /admin/apps/health endpoint.
	// Wired by main.go to *proxy.Proxy.AppHealthSnapshot — see
	// internal/proxy/apppipe/health.go for the cache rationale (volatile
	// observability surface, NOT a CQRS read projection).
	//
	// nil means the proxy did not wire the cache (older build, or test
	// harness that didn't construct one) — the handler responds 503 in
	// that case so consumers can distinguish "no data yet" (empty array)
	// from "feature disabled" (503).
	AppHealthFn func() []apppipe.AppHealth

	// PoolHealthFn returns oauth-group routing health for /status (N9). nil → the
	// pool_routing field is omitted (non-pool deployments unchanged).
	PoolHealthFn func() *PoolRoutingHealth
	// SyncHealthFn supplies the SyncRail per-rail health map for /status. Nil or
	// an empty map → the control_plane_sync field is omitted.
	SyncHealthFn func() map[string]SyncRailStatus

	// EffectivePacksFn returns the raw JSON report of compliance packs currently
	// effective in the live filter child (built-in + pulled). Returns an error
	// (apphook.ErrPacksUnavailable) when no filter child is active / can't report;
	// the handler maps that to `{available:false}`, never a 5xx. Drives the Web
	// "effective packs" drawer on the self-view compliance page.
	EffectivePacksFn func(ctx context.Context) ([]byte, error)

	// AuditStatusFn / ReconcileGapsFn drive `aikey audit` (D2.5 / D3): the local
	// client delivery state, and the client-confirmed reconciliation pass
	// (re-send WAL-present gaps, confirm WAL-absent gaps lost now). nil → 503.
	AuditStatusFn   func() *events.AuditStatus
	ReconcileGapsFn func(ctx context.Context) (events.ReconcileResult, error)

	// GetUpstreamProxyFn / SetUpstreamProxyFn back the GET/PUT /admin/upstream-proxy
	// endpoints that the local web "Settings → Upstream proxy" card relays to. Get
	// returns the live egress proxy URL ("" = direct); Set persists it to
	// aikey-user.yaml and HOT-SWAPS the running transport + impersonate client (no
	// restart). nil → 503 (endpoint disabled — e.g. cluster node). See
	// config.PersistUpstreamProxyURL + the main.go wiring.
	GetUpstreamProxyFn func() string
	SetUpstreamProxyFn func(url string) error

	// EgressStateFn backs the layered "egress" block in GET /admin/upstream-proxy
	// (2026-07-08, `aikey env` 逐级显示需求): the daemon-truth view of the egress
	// decision — explicit URL > daemon process env > OS system proxy — plus the
	// effective result computed through the SAME resolution path the forwarding
	// transport uses (display must never diverge from behavior). nil → the GET
	// response stays the legacy {"url"} shape (older wiring / cluster nodes).
	EgressStateFn func() EgressState

	// ProbeUpstreamProxyFn tests whether a CANDIDATE egress URL can actually carry
	// traffic to an AI provider (built with the same buildTransport the live path
	// uses), WITHOUT persisting it — so the web "Test connectivity" button can verify
	// before Save. Returns (httpStatus, elapsedMs, err); err = the request never got
	// a response (proxy unreachable / DNS / timeout). Any HTTP status = reachable.
	// nil → 503.
	ProbeUpstreamProxyFn func(url string) (status int, elapsedMs int64, err error)

	// EgressSelfCheckFn backs GET /admin/egress/selfcheck — the per-account egress
	// connectivity self-check for `aikey test` (presence) / `aikey doctor` (dial).
	// Enumerates the registry's per-account egress specs and, when dial=true,
	// probes each via the shared egress.TestDial. nil → empty list. See
	// egress_selfcheck.go + the app.Run wiring.
	EgressSelfCheckFn func(ctx context.Context, dial bool) []EgressCheckResult
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
	// 2026-05-08 Kimi 双平台拆分: 'kimi' 拆为 'kimi_code' (api.kimi.com) +
	// 'moonshot' (api.moonshot.cn);两条都进 admin probe 列表。
	{"kimi_code", "https://api.kimi.com/coding"},
	{"moonshot", "https://api.moonshot.cn"},
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
	// UsagePipeline is the BYPASS usage/billing pipeline verdict (缺口3). It is
	// deliberately SEPARATE from the top-level Status (which stays a pure liveness
	// signal for the MAIN LLM-forwarding path): a degraded bypass pipeline must
	// not make /health report the process down, or a false restart could take out
	// healthy main-link forwarding (architecture: 主链路/旁路 isolation). Omitted
	// when neither reporter nor canary is wired (offline Personal).
	UsagePipeline *pipelineHealth `json:"usage_pipeline,omitempty"`
	Status        string          `json:"status"`
	Version       string          `json:"version"`
}

// pipelineHealth is a single readable verdict an external monitor / the release
// E2E can assert on, derived from already-exposed reporter + canary signals.
type pipelineHealth struct {
	State   string   `json:"state"`             // "ok" | "degraded"
	Reasons []string `json:"reasons,omitempty"` // populated when degraded
}

const (
	// uploadDegradedThreshold: consecutive upload failures before the usage
	// pipeline is reported degraded. >1 so a single transient blip (now retried
	// from the WAL, B' 缺口2) doesn't flap the verdict.
	uploadDegradedThreshold = 3
	// canaryDegradedThreshold: consecutive canary pipeline-failures before
	// degraded. The canary runs every 5min, so 2 ≈ a sustained ~10min fault.
	canaryDegradedThreshold = 2
)

// usagePipelineHealth derives the bypass-pipeline verdict from the reporter
// metrics + latest canary result. Returns nil when neither is wired, so the
// field is omitted rather than falsely reporting "ok".
//
// Why these inputs: the readable counters already exist on /metrics (health-
// signal-surface), but the principle also requires the health ENDPOINT to carry
// a derived verdict that escalates — not just raw counters a dashboard might
// aggregate stale. This computes that verdict from self-healing signals (upload
// + canary consecutive failures reset on recovery) plus the serious cumulative
// WAL-append-failure counter.
func usagePipelineHealth(rm *events.ReporterMetrics, cr *events.CanaryResult) *pipelineHealth {
	if rm == nil && cr == nil {
		return nil
	}
	var reasons []string
	if rm != nil {
		// A WAL append failure means a usage event was lost locally (disk full /
		// IO). Cumulative + serious: surface degraded until restart so it can't be
		// missed (reserve-ahead turns it into an auditable gap, but local
		// integrity is already compromised).
		if rm.WALAppendFail > 0 {
			reasons = append(reasons, "wal_append_failed")
		}
		// Sustained upload failure → collector unreachable. Self-healing: resets
		// to 0 on a successful upload, so it clears once delivery resumes.
		if rm.ConsecutiveFailures >= uploadDegradedThreshold {
			reasons = append(reasons, "upload_failing")
		}
	}
	if cr != nil {
		// Canary is the pipeline self-test; a sustained failed streak means the
		// end-to-end path can't be confirmed.
		if cr.Status == "failed" && cr.ConsecutiveFailures >= canaryDegradedThreshold {
			reasons = append(reasons, "canary_pipeline_failed")
		}
	}
	state := "ok"
	if len(reasons) > 0 {
		state = "degraded"
	}
	return &pipelineHealth{State: state, Reasons: reasons}
}

// Health returns process liveness (Status) plus the bypass usage-pipeline
// verdict (UsagePipeline). Always HTTP 200 with Status "ok" while serving — see
// healthResponse / usagePipelineHealth for the liveness-vs-pipeline split.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	tc := observability.ExtractOrCreate(r)
	slog.Debug("admin: health check",
		"trace_id", tc.TraceID,
		"request_id", tc.RequestID,
	)

	var rm *events.ReporterMetrics
	if h.ReporterMetricsFn != nil {
		rm = h.ReporterMetricsFn()
	}
	var cr *events.CanaryResult
	if h.CanaryResultFn != nil {
		cr = h.CanaryResultFn()
	}

	writeJSON(w, http.StatusOK, healthResponse{
		Status:        "ok", // liveness only — NOT flipped by bypass-pipeline degradation
		Version:       Version,
		UsagePipeline: usagePipelineHealth(rm, cr),
	})
}

type statusResponse struct {
	Status      string `json:"status"`
	Version     string `json:"version"`
	Uptime      string `json:"uptime"`
	ListenAddr  string `json:"listen_addr"`
	VaultPath   string `json:"vault_path"`
	StartedAt   string `json:"started_at"`
	VirtualKeys int    `json:"virtual_keys_loaded"`
	TotalReqs   int64  `json:"total_requests"`
	TotalErrs   int64  `json:"total_errors"`
	// PoolRouting is the oauth-group routing health (N9). Omitted unless the
	// feature is on, so non-pool deployments' /status is unchanged. Lets the
	// operator monitoring the first pool batch see which accounts are cooled.
	PoolRouting *PoolRoutingHealth `json:"pool_routing,omitempty"`
	// ControlPlaneSync is the SyncRail health surface (2026-07-03): per-rail
	// ok/stale/offline state with failure counts and last error. Omitted when no
	// rail has ever attempted a cycle (personal installs — /status unchanged).
	// Release-checklist E2E and `aikey statusline` read this to assert the
	// master-sync pipeline is alive (health-signal-surface rule).
	ControlPlaneSync map[string]SyncRailStatus `json:"control_plane_sync,omitempty"`
}

// SyncRailStatus mirrors supervisor.RailSyncStatus for the /status wire (built
// by the cmd layer — admin does not import supervisor).
type SyncRailStatus struct {
	State               string `json:"state"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	LastSuccessAt       int64  `json:"last_success_at,omitempty"`
	LastError           string `json:"last_error,omitempty"`
}

// PoolRoutingHealth is the oauth-group account-routing health surface (N9). Built
// by the cmd layer from the proxy's reactive cooldown state.
type PoolRoutingHealth struct {
	Enabled        bool            `json:"enabled"`
	CooledAccounts []CooledAccount `json:"cooled_accounts,omitempty"`
}

// CooledAccount is one pool account currently routed around (401 / exhaustion).
type CooledAccount struct {
	AccountID       string `json:"account_id"`
	CooldownSeconds int    `json:"cooldown_seconds"`
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

	var poolRouting *PoolRoutingHealth
	if h.PoolHealthFn != nil {
		poolRouting = h.PoolHealthFn()
	}
	var syncHealth map[string]SyncRailStatus
	if h.SyncHealthFn != nil {
		syncHealth = h.SyncHealthFn()
	}

	writeJSON(w, http.StatusOK, statusResponse{
		Status:           "ok",
		Version:          Version,
		Uptime:           time.Since(h.startedAt).Round(time.Second).String(),
		ListenAddr:       h.cfg.Listen.Addr(),
		VirtualKeys:      h.registry.Count(),
		VaultPath:        h.cfg.Vault.Path,
		StartedAt:        h.startedAt.Format(time.RFC3339),
		TotalReqs:        totalReqs,
		TotalErrs:        totalErrs,
		PoolRouting:      poolRouting,
		ControlPlaneSync: syncHealth,
	})
}

type metricsResponse struct {
	RequestsByVKey     map[string]int64 `json:"requests_by_vkey"`
	RequestsByProvider map[string]int64 `json:"requests_by_provider"`
	// RequestsByAccount: per real serving account (oauth_group attribution).
	// Counts follow pool fallback (A→B counts toward B). Empty when no group
	// routing has happened. Lets local audit see "which account served" without
	// the collector/ODS.
	RequestsByAccount map[string]int64         `json:"requests_by_account"`
	Reporter          *events.ReporterMetrics  `json:"reporter,omitempty"`
	Collector         *events.CollectorMetrics `json:"collector,omitempty"`
	Canary            *events.CanaryResult     `json:"canary,omitempty"`
	TotalRequests     int64                    `json:"total_requests"`
	TotalErrors       int64                    `json:"total_errors"`
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
	byAccount, err := h.store.QueryByAccount()
	if err != nil {
		byAccount = make(map[string]int64)
	}

	var reporterMetrics *events.ReporterMetrics
	if h.ReporterMetricsFn != nil {
		reporterMetrics = h.ReporterMetricsFn()
	}
	var collectorMetrics *events.CollectorMetrics
	if h.CollectorMetricsFn != nil {
		collectorMetrics = h.CollectorMetricsFn()
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
		RequestsByAccount:  byAccount,
		Reporter:           reporterMetrics,
		Collector:          collectorMetrics,
		Canary:             canaryResult,
	})
}

// AuditStatus serves GET /admin/audit/status (D2.5): the local client-side
// delivery state (allocator high-water, WAL backlog, dead-letter pile, upload
// health) that the collector's completeness endpoint cannot see.
func (h *Handler) AuditStatus(w http.ResponseWriter, r *http.Request) {
	if h.AuditStatusFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "usage reporter not configured"})
		return
	}
	st := h.AuditStatusFn()
	if st == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "usage reporter not configured"})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// AuditReconcile serves POST /admin/audit/reconcile (D3): force a client-confirmed
// reconciliation — re-send gaps still in the WAL, confirm WAL-absent gaps as lost
// now. Returns how many were re-sent vs confirmed-lost.
func (h *Handler) AuditReconcile(w http.ResponseWriter, r *http.Request) {
	if h.ReconcileGapsFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "usage reporter not configured"})
		return
	}
	res, err := h.ReconcileGapsFn(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
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

// ReplayDeadLetter handles POST /admin/replay-dead-letter.
//
// Triggers reporter.ReplayDeadLetter() — see that method's docstring
// for full semantics. Synchronous: the response carries the count
// summary so operators see exactly how many entries were re-delivered.
//
// Returns:
//   - 200 OK + ReplayDeadLetterResult JSON on success (including "0
//     entries scanned" — that's still a successful no-op)
//   - 503 Service Unavailable when ReplayDeadLetterFn isn't wired
//     (reporter disabled at startup, e.g. no collector_url configured)
//   - 500 Internal Server Error when replay itself errors (file
//     read/write fail). Partial-success counts still come back in
//     the result body so the operator can see what was already
//     delivered before the error.
//
// Added 2026-05-11 per B-phase follow-up: dead_letter.jsonl used to be
// permanent state — terminal failures (JWT expired briefly, collector
// down for a few seconds) silently lost data forever. With replay an
// operator runs `aikey proxy replay-dead-letter` after fixing the
// upstream cause and recovers all dead-lettered events.
func (h *Handler) ReplayDeadLetter(w http.ResponseWriter, r *http.Request) {
	tc := observability.ExtractOrCreate(r)
	logger := slog.With(
		"trace_id", tc.TraceID,
		"request_id", tc.RequestID,
	)

	if h.ReplayDeadLetterFn == nil {
		logger.Warn("admin: replay-dead-letter not supported (reporter disabled)")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "reporter / dead-letter writer not configured",
		})
		return
	}

	// Give the replay up to 60 s. Each individual upload uses the
	// reporter's HTTP client timeout (10 s), so a worst-case 6 entries
	// of stuck upload still complete within budget.
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	logger.Info("admin: replay-dead-letter requested")
	result, err := h.ReplayDeadLetterFn(ctx)
	if err != nil {
		logger.Error("admin: replay-dead-letter failed",
			"error.message", err.Error(),
			"entries_scanned", result.EntriesScanned,
			"entries_replayed_ok", result.EntriesReplayedOK,
		)
		// Still return the partial result so operators see what was
		// recovered before the file I/O error hit.
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":  err.Error(),
			"result": result,
		})
		return
	}

	logger.Info("admin: replay-dead-letter completed",
		"entries_scanned", result.EntriesScanned,
		"entries_replayed_ok", result.EntriesReplayedOK,
		"entries_still_failing", result.EntriesStillFailing,
	)
	writeJSON(w, http.StatusOK, result)
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
		Error     string `json:"error,omitempty"`
		LatencyMs int64  `json:"latency_ms,omitempty"`
		Reachable bool   `json:"reachable"`
	}

	results := make([]result, 0, len(knownProviders))
	for _, p := range knownProviders {
		start := time.Now()
		req, reqErr := http.NewRequestWithContext(r.Context(), "GET", p.baseURL, http.NoBody)
		if reqErr != nil {
			results = append(results, result{
				Provider: p.code, BaseURL: p.baseURL,
				Reachable: false, Error: "request_build_failed",
			})
			continue
		}
		resp, err := client.Do(req)
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

// AppHealthResponse is the JSON envelope GET /admin/apps/health emits.
// `apps` is sorted by app_slug for deterministic snapshots.
type AppHealthResponse struct {
	Apps []apppipe.AppHealth `json:"apps"`
}

// AppHealth returns the in-process record of "most recent app pipeline call
// per slug". Drives the Web "Connected Apps" list's Health column.
//
// GET /admin/apps/health
//
// Why a separate endpoint vs piggy-backing on /metrics: /metrics is a
// system-wide counter dashboard (request totals, error totals, reporter
// stats). Per-app health is a different consumer surface — the Web list
// page reads it once per page load, not periodic scrape — so a focused
// endpoint with a stable schema is easier to evolve than burying app data
// inside metricsResponse.
//
// Cache lifetime: process-memory only; proxy restart returns an empty
// list and the UI shows "No recent calls" until traffic resumes. The
// query-service / DWD path remains the durable source of truth for
// historic auditing (this endpoint is intentionally NOT that).
func (h *Handler) AppHealth(w http.ResponseWriter, r *http.Request) {
	if h.AppHealthFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "app health cache not wired",
		})
		return
	}
	apps := h.AppHealthFn()
	if apps == nil {
		apps = []apppipe.AppHealth{}
	}
	writeJSON(w, http.StatusOK, AppHealthResponse{Apps: apps})
}

// CompliancePacksEnvelope wraps the detector's raw effective-packs report so the
// Web can distinguish "no compliance filter active" (available:false) from a
// real report. report is the detector's {built_in,pulled,cursor} JSON verbatim.
type CompliancePacksEnvelope struct {
	Report    json.RawMessage `json:"report,omitempty"`
	Available bool            `json:"available"`
}

// CompliancePacks returns the compliance packs currently effective in the LIVE
// filter detector child (built-in baseline + pulled from master), queried over
// the IPC (op=ListPacks). Same process that serves Detect → same source.
//
// GET /admin/compliance/packs
//
// A missing/idle filter child (compliance off, offline, or an older detector) is
// a NORMAL state, not an error — returns {available:false} with 200 so the data
// plane and the Web both treat it gracefully.
func (h *Handler) CompliancePacks(w http.ResponseWriter, r *http.Request) {
	if h.EffectivePacksFn == nil {
		writeJSON(w, http.StatusOK, CompliancePacksEnvelope{Available: false})
		return
	}
	report, err := h.EffectivePacksFn(r.Context())
	if err != nil || len(report) == 0 {
		writeJSON(w, http.StatusOK, CompliancePacksEnvelope{Available: false})
		return
	}
	writeJSON(w, http.StatusOK, CompliancePacksEnvelope{Available: true, Report: report})
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
	// WHY: previously `err != nil || len(targets) == 0` collapsed into the same
	// "no active key configured" message, so a credential that exists but fails
	// to resolve/decrypt was misreported as "no key configured" and the only
	// signal lived in logs. Split the error case into a DISTINCT message so the
	// decrypt/resolve failure is externally readable (health-signal-surface +
	// "异常需区分原因"). HTTP 200 is preserved to keep the response contract; the
	// message is terse and does not leak internal install/bundle names.
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}, "message": fmt.Sprintf("key resolution failed: %s", err)})
		return
	}
	if len(targets) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}, "message": "no active key configured"})
		return
	}

	type result struct {
		Provider   string `json:"provider"`
		KeyRef     string `json:"key_ref"`
		Error      string `json:"error,omitempty"`
		LatencyMs  int64  `json:"latency_ms,omitempty"`
		StatusCode int    `json:"status_code,omitempty"`
		Ok         bool   `json:"ok"`
	}

	client := &http.Client{Timeout: 15 * time.Second}
	results := make([]result, 0, len(targets))
	for i := range targets {
		t := &targets[i]
		start := time.Now()
		code, callErr := probeKey(r.Context(), client, t)
		latency := time.Since(start).Milliseconds()

		// 200        → key confirmed valid (inference succeeded).
		// 401 / 403  → key rejected by the provider.
		// other 4xx  → request was authenticated; failure is model/format, not the key.
		// 5xx        → provider-side server error (treat as failure).
		ok := callErr == nil && code != http.StatusUnauthorized && code != http.StatusForbidden && code < 500
		var errMsg string
		switch {
		case callErr != nil:
			ok = false
			errMsg = classifyNetError(callErr)
		case code == http.StatusUnauthorized || code == http.StatusForbidden:
			ok = false
			errMsg = fmt.Sprintf("HTTP %d — key may be invalid or expired", code)
		case code >= 500:
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
func probeKey(ctx context.Context, client *http.Client, t *KeyCheckTarget) (int, error) {
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
		return probeAnthropic(ctx, client, baseURL, t.APIKey)
	case "google", "gemini":
		return probeGoogle(ctx, client, baseURL, t.APIKey)
	default: // openai, deepseek, kimi_code, moonshot, etc.
		// 2026-05-08 Kimi 双平台拆分 review feedback (medium):
		// probeModelForProtocol 名字误导,实际接收 provider code 而非 protocol。
		// supervisor.go::providerProtocol 把 kimi_code/moonshot 都归到 "openai"
		// protocol,如果传 t.Protocol 则永远命中默认 gpt-4o-mini,api.kimi.com
		// 会 reject。改传 t.Provider (provider_code: kimi_code / moonshot / ...) ,
		// probeModelForProtocol 内的 kimi_code → kimi-k2.5、moonshot → moonshot-v1-8k
		// case 才能真正生效。
		return probeOpenAICompat(ctx, client, baseURL, t.APIKey, probeModelForProtocol(t.Provider))
	}
}

// probeAnthropic sends a minimal POST /v1/messages (max_tokens=1) to verify the key.
func probeAnthropic(ctx context.Context, client *http.Client, baseURL, apiKey string) (int, error) {
	body := `{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/v1/messages", strings.NewReader(body))
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
func probeOpenAICompat(ctx context.Context, client *http.Client, baseURL, apiKey, model string) (int, error) {
	body := fmt.Sprintf(`{"model":%q,"max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`, model)
	req, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/v1/chat/completions", strings.NewReader(body))
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
func probeGoogle(ctx context.Context, client *http.Client, baseURL, apiKey string) (int, error) {
	body := `{"contents":[{"parts":[{"text":"hi"}]}]}`
	url := fmt.Sprintf("%s/v1beta/models/gemini-1.5-flash:generateContent?key=%s", baseURL, apiKey)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
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
	// 2026-05-08 Kimi 双平台拆分: 两个平台用不同 model 名 (kimi-cli upstream 自带规范)
	case "kimi_code", "kimi":
		return "kimi-k2.5" // Kimi Code (api.kimi.com),'kimi' 是 deprecated alias
	case "moonshot":
		return "moonshot-v1-8k" // Moonshot (api.moonshot.cn)
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
	// 2026-05-08 Kimi 双平台拆分: 拆 case,'kimi' 为 deprecated alias 与 kimi_code
	// 同 endpoint;moonshot 是独立的 api.moonshot.cn upstream。
	case "kimi_code", "kimi":
		return "https://api.kimi.com/coding"
	case "moonshot":
		return "https://api.moonshot.cn"
	case "deepseek":
		return "https://api.deepseek.com/v1"
	default:
		return ""
	}
}

// ----------------------------------------------------------------------------
// Probe endpoints — connectivity test primitives used by `aikey test` / doctor.
//
// Why "probe" vs the existing /health/* surface: /health/* reports health for
// the active config. The probe endpoints exist for per-target pre-flight
// checks (e.g. `aikey test <alias>` testing a specific key that may or may
// not be active) and for fast standalone latency measurement from the
// proxy's network viewpoint.
//
// POST /admin/probe/ping body: { "provider": "anthropic" }
//   → TCP connect from proxy to the provider's upstream host:443
//
// API and Chat probes reuse the existing data plane — CLI sends them to
// /<provider>/v1/... with the bearer it already uses at runtime. The
// `X-Aikey-Probe: 1` header (see reportable.go / middleware) suppresses
// usage-event recording for that traffic so pre-flight tests don't pollute
// reporter counters or bill the user twice.
// ----------------------------------------------------------------------------

// ProbePingRequest is the POST body for /admin/probe/ping.
type ProbePingRequest struct {
	Provider string `json:"provider"`           // canonical code: "anthropic", "openai", "kimi", ...
	BaseURL  string `json:"base_url,omitempty"` // optional override; empty → default for provider
}

// ProbePingResponse is what the CLI reads back. `OK` is true iff the TCP
// handshake completed within the timeout — no HTTP call, no authentication.
type ProbePingResponse struct {
	Host      string `json:"host,omitempty"` // echoed back for debugging
	Error     string `json:"error,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	OK        bool   `json:"ok"`
}

// ProbePing handles POST /admin/probe/ping.
//
// Measures reachability + latency from the proxy's network context to the
// upstream provider. Two modes:
//
//  1. No upstream proxy configured (neither config.upstream_proxy.url nor
//     HTTPS_PROXY / HTTP_PROXY / ALL_PROXY env var): raw TCP connect to
//     `host:port`. Fastest; measures pure network RTT.
//
//  2. Upstream proxy configured: TCP connect to the provider host will be
//     blocked in restricted networks. Fall through to an HTTP HEAD that
//     rides the same proxy the data plane uses at runtime — otherwise the
//     ping fails even though the real proxied requests succeed (the bug
//     the user's China-network deployment was reporting).
//
// Always returns 200 OK so the CLI can read the structured result even on
// network failure. Transport errors go into the Error field.
func (h *Handler) ProbePing(w http.ResponseWriter, r *http.Request) {
	tc := observability.ExtractOrCreate(r)
	logger := slog.With(
		"trace_id", tc.TraceID,
		"request_id", tc.RequestID,
	)

	var req ProbePingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body: " + err.Error(),
		})
		return
	}
	if req.Provider == "" && req.BaseURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "provider or base_url required",
		})
		return
	}

	// Resolve target host:port. Override wins; otherwise fall back to the
	// well-known default URL for the provider code.
	baseURL := req.BaseURL
	if baseURL == "" {
		baseURL = providerDefaultBaseURL(req.Provider)
	}
	if baseURL == "" {
		writeJSON(w, http.StatusOK, ProbePingResponse{
			OK:    false,
			Error: fmt.Sprintf("unknown provider %q and no base_url supplied", req.Provider),
		})
		return
	}

	host, port := extractHostPort(baseURL)
	if host == "" {
		writeJSON(w, http.StatusOK, ProbePingResponse{
			OK:    false,
			Error: "could not extract host from base_url",
		})
		return
	}

	// 3s is enough for a functional check. Longer would punish the user on a
	// bad network more than the signal is worth.
	const probeTimeout = 3 * time.Second

	// Resolve upstream proxy for THIS specific target. Precedence:
	//   1. config.upstream_proxy.url — explicit config wins.
	//   2. HTTPS_PROXY / HTTP_PROXY env via Go's ProxyFromEnvironment —
	//      honors NO_PROXY automatically, so targets like 127.0.0.1 or
	//      localhost correctly bypass the HTTP proxy even when the shell
	//      has `https_proxy=...` set (the 2026-04-21 test-flake scenario
	//      from the user's Clash-configured shell).
	//   3. Neither → direct TCP.
	proxyURL := ""
	if h.cfg != nil && h.cfg.UpstreamProxy.URL != "" {
		proxyURL = h.cfg.UpstreamProxy.URL
	} else {
		// Build a synthetic request so ProxyFromEnvironment can apply
		// NO_PROXY matching against the actual target URL.
		if probeReq, perr := http.NewRequestWithContext(context.Background(), http.MethodHead, baseURL, http.NoBody); perr == nil {
			if p, _ := http.ProxyFromEnvironment(probeReq); p != nil {
				proxyURL = p.String()
			}
		}
	}

	start := time.Now()
	var err error
	if proxyURL == "" {
		// Direct TCP connect — fastest path, accurate RTT measurement.
		var conn net.Conn
		conn, err = net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), probeTimeout)
		if conn != nil {
			conn.Close()
		}
	} else {
		// Proxied path: HTTP HEAD through the configured proxy. TCP-level
		// ping can't traverse HTTP proxies, so this is the only option.
		// Any non-5xx response (200/301/401/403/404/etc.) counts as "reached
		// upstream" — we're testing reachability, not authentication.
		err = httpHeadViaProxy(baseURL, proxyURL, probeTimeout)
	}
	latency := time.Since(start).Milliseconds()

	if err != nil {
		logger.Debug("probe ping failed",
			"provider", req.Provider,
			"host", host,
			"via_proxy", proxyURL != "",
			"error.message", err.Error(),
		)
		writeJSON(w, http.StatusOK, ProbePingResponse{
			OK:        false,
			LatencyMs: latency,
			Host:      host,
			Error:     classifyNetError(err),
		})
		return
	}

	writeJSON(w, http.StatusOK, ProbePingResponse{
		OK:        true,
		LatencyMs: latency,
		Host:      host,
	})
}

// httpHeadViaProxy sends an HTTP HEAD to `targetURL` through the given
// proxy URL (supports http/https/socks5 schemes via net/http's default
// Proxy hook). Returns nil on any HTTP response (including 4xx/5xx — we
// only care about "reachable vs not"); a non-nil error means the request
// never got a response.
func httpHeadViaProxy(targetURL, proxyURL string, timeout time.Duration) error {
	pURL, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(pURL),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Don't follow redirects — we only care about "did we talk to upstream".
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// Some upstreams 405 on HEAD /; that still proves reachability. A
	// transport-level failure is what we want to detect, not HTTP status.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, targetURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// extractHostPort parses a URL-ish string "https://host:port/..." into
// (host, port). Defaults to 443 (https) / 80 (http) when port is absent.
// Returns ("", 0) on malformed input.
func extractHostPort(rawURL string) (host string, port int) {
	trimmed := strings.TrimPrefix(rawURL, "https://")
	isHTTP := false
	if trimmed == rawURL {
		trimmed = strings.TrimPrefix(rawURL, "http://")
		isHTTP = trimmed != rawURL
	}
	if trimmed == rawURL {
		// No scheme — assume https.
		trimmed = rawURL
	}
	// Strip path.
	if i := strings.Index(trimmed, "/"); i >= 0 {
		trimmed = trimmed[:i]
	}
	if trimmed == "" {
		return "", 0
	}
	// Parse optional :port.
	if i := strings.LastIndex(trimmed, ":"); i >= 0 {
		host = trimmed[:i]
		portStr := trimmed[i+1:]
		port = 0
		for _, c := range portStr {
			if c < '0' || c > '9' {
				port = 0
				break
			}
			port = port*10 + int(c-'0')
		}
		if port == 0 {
			port = 443
		}
		return host, port
	}
	if isHTTP {
		return trimmed, 80
	}
	return trimmed, 443
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
	_ = json.NewEncoder(w).Encode(v)
}

// DebugUpstreamHeadersGet returns the current state of the upstream-headers
// debug toggle plus the layer that produced it.
//
//	GET /admin/debug/upstream-headers
//	→ 200 {"enabled": true|false, "source": "api"|"env"|"compile"|"default"}
//	→ 503 {"error": "not wired"}        when the proxy didn't inject the hook
func (h *Handler) DebugUpstreamHeadersGet(w http.ResponseWriter, r *http.Request) {
	if h.DebugUpstreamHeadersStateFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "not wired"})
		return
	}
	enabled, source := h.DebugUpstreamHeadersStateFn()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": enabled,
		"source":  source,
	})
}

// DebugUpstreamHeadersSet flips the API runtime override.
//
//	POST /admin/debug/upstream-headers   body: {"enabled": true | false}
//	→ 200 {"enabled": true|false, "source": "api"}
//
// Why JSON body (not query param): keeps the verb idempotent (re-POSTing
// the same body is a no-op) and matches the established pattern of
// /admin/probe/ping. Future fields (level / verbosity / TTL) extend
// without breaking the URL.
func (h *Handler) DebugUpstreamHeadersSet(w http.ResponseWriter, r *http.Request) {
	if h.DebugUpstreamHeadersSetFn == nil || h.DebugUpstreamHeadersStateFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "not wired"})
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "body must be JSON object with bool field 'enabled'",
		})
		return
	}
	if *req.Enabled {
		h.DebugUpstreamHeadersSetFn(1)
	} else {
		h.DebugUpstreamHeadersSetFn(-1)
	}
	enabled, source := h.DebugUpstreamHeadersStateFn()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": enabled,
		"source":  source,
	})
}

// DebugUpstreamHeadersClear removes the API override so the toggle inherits
// from env / compile / default.
//
//	DELETE /admin/debug/upstream-headers
//	→ 200 {"enabled": <resolved-from-lower-layers>, "source": "env"|"compile"|"default"}
func (h *Handler) DebugUpstreamHeadersClear(w http.ResponseWriter, r *http.Request) {
	if h.DebugUpstreamHeadersSetFn == nil || h.DebugUpstreamHeadersStateFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "not wired"})
		return
	}
	h.DebugUpstreamHeadersSetFn(0)
	enabled, source := h.DebugUpstreamHeadersStateFn()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": enabled,
		"source":  source,
	})
}
