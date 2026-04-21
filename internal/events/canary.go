package events

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// CanaryConfig configures the synthetic canary probe.
type CanaryConfig struct {
	// DiagnosticsURL is the collector-service base URL used to check if an
	// event reached ODS and was acked by the projector. In trial mode this
	// collapses with the control URL on a single port; in production it
	// points to the collector-service container.
	//   e.g. "http://127.0.0.1:8090" (trial)
	//        "http://collector.aikey.internal:27300" (production)
	DiagnosticsURL string
	// QueryURL, if set, enables a third-stage query-side check by calling
	// GET {QueryURL}/internal/canary-check on query-service. Empty means
	// "skip query stage" — which is the correct choice for trial where
	// collector and query are the same process; production should set it
	// to the query-service URL for full end-to-end coverage.
	QueryURL string
	// Interval between canary probes. Default: 5 minutes.
	Interval time.Duration
	// CheckDelay is how long to wait after sending before checking arrival. Default: 15s.
	CheckDelay time.Duration
}

// CanaryResult holds the outcome of the most recent canary probe.
type CanaryResult struct {
	EventID       string    `json:"event_id"`
	SentAt        time.Time `json:"sent_at"`
	ODSReceived   bool      `json:"ods_received"`
	DWDProjected  bool      `json:"dwd_projected"`
	QueryReadable bool      `json:"query_readable"`
	Status        string    `json:"status"`       // "ok" | "partial" | "failed" | "unavailable"
	FailedStage   string    `json:"failed_stage"` // "" | "ingest" | "projection" | "query" | "diagnostics_unreachable"
	RoundTripMs   int64     `json:"round_trip_ms"`
}

// CanaryProbe sends periodic synthetic events through the pipeline and verifies arrival.
type CanaryProbe struct {
	reporter *Reporter
	cfg      CanaryConfig
	client   *http.Client
	done     chan struct{}
	wg       sync.WaitGroup

	mu                  sync.RWMutex
	lastResult          CanaryResult
	consecutiveFailures int
}

// NewCanaryProbe creates and starts a canary probe. Pass nil reporter to disable.
func NewCanaryProbe(reporter *Reporter, cfg CanaryConfig) *CanaryProbe {
	if reporter == nil || cfg.DiagnosticsURL == "" {
		return nil
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.CheckDelay <= 0 {
		cfg.CheckDelay = 15 * time.Second
	}

	p := &CanaryProbe{
		reporter: reporter,
		cfg:      cfg,
		client:   &http.Client{Timeout: 10 * time.Second},
		done:     make(chan struct{}),
	}

	p.wg.Add(1)
	// Fatal: canary probe is the pipeline's self-test. A silent death here
	// means "everything looks fine" while nothing is actually checked.
	observability.GoSafe("events.canary.loop", observability.Fatal, p.loop)
	slog.Info("canary probe started", "interval", cfg.Interval, "diagnostics_url", cfg.DiagnosticsURL)
	return p
}

// LastResult returns the most recent canary probe result.
func (p *CanaryProbe) LastResult() CanaryResult {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastResult
}

// ConsecutiveFailures returns the number of consecutive canary failures.
func (p *CanaryProbe) ConsecutiveFailures() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.consecutiveFailures
}

// Close stops the canary probe.
func (p *CanaryProbe) Close() {
	close(p.done)
	p.wg.Wait()
}

func (p *CanaryProbe) loop() {
	defer p.wg.Done()

	// Run first probe after a short initial delay (let services start up).
	initialDelay := 30 * time.Second
	select {
	case <-time.After(initialDelay):
	case <-p.done:
		return
	}

	p.probe()

	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.probe()
		case <-p.done:
			return
		}
	}
}

func (p *CanaryProbe) probe() {
	eventID := fmt.Sprintf("canary-%d", time.Now().Unix())
	sentAt := time.Now()

	// Send canary event through the normal Reporter channel.
	ev := ReportableEvent{
		EventID:       eventID,
		SchemaVersion: 1,
		EventTime:     sentAt,
		OccurredAt:    sentAt,
		OrgID:         "__canary__",
		VirtualKeyID:  "__canary__",
		RequestCount:  1,
		RequestStatus: "success",
		RouteSource:   "canary",
	}
	// Set total_tokens to 1 to minimize data pollution.
	one := int64(1)
	ev.TotalTokens = &one

	p.reporter.Report(ev)

	// Wait for the event to traverse the pipeline.
	select {
	case <-time.After(p.cfg.CheckDelay):
	case <-p.done:
		return
	}

	// Check arrival at each stage via the diagnostics endpoint.
	result := p.checkArrival(eventID, sentAt)

	p.mu.Lock()
	p.lastResult = result
	if result.Status == "ok" {
		if p.consecutiveFailures > 0 {
			slog.Info("canary probe recovered",
				"event_id", eventID,
				"round_trip_ms", result.RoundTripMs,
				"previous_failures", p.consecutiveFailures)
		}
		p.consecutiveFailures = 0
	} else if result.Status == "unavailable" {
		// Diagnostics endpoint not available (server-mode without endpoints).
		// Don't count as failure — log once then suppress.
		if p.consecutiveFailures == 0 {
			slog.Info("canary probe: diagnostics endpoint not available, probe results limited to reporter metrics",
				"diagnostics_url", p.cfg.DiagnosticsURL)
		}
		// Keep consecutiveFailures at 0 — "unavailable" is not a pipeline fault.
	} else {
		p.consecutiveFailures++
		slog.Warn("canary probe failed",
			"event_id", eventID,
			"status", result.Status,
			"failed_stage", result.FailedStage,
			"consecutive", p.consecutiveFailures)
	}
	p.mu.Unlock()
}

func (p *CanaryProbe) checkArrival(eventID string, sentAt time.Time) CanaryResult {
	result := CanaryResult{
		EventID: eventID,
		SentAt:  sentAt,
	}

	url := fmt.Sprintf("%s/internal/canary-check?event_id=%s", p.cfg.DiagnosticsURL, eventID)
	resp, err := p.client.Get(url)
	if err != nil {
		// Diagnostics endpoint unreachable — deployment/network issue rather
		// than a pipeline fault. Mark as "unavailable" (not "failed") so the
		// probe doesn't count this toward consecutiveFailures.
		result.Status = "unavailable"
		result.FailedStage = "diagnostics_unreachable"
		slog.Debug("canary check: diagnostics unreachable", "url", url, "error", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Endpoint not registered. As of 2026-04-17 this is no longer the
		// "feature not implemented" case — /internal/canary-check lives in
		// collector-service. 404 here means DiagnosticsURL is pointing at the
		// wrong service (misconfiguration) or an older binary without the
		// endpoint.
		result.Status = "unavailable"
		result.FailedStage = "diagnostics_unreachable"
		return result
	}
	if resp.StatusCode != http.StatusOK {
		result.Status = "failed"
		result.FailedStage = "ingest"
		return result
	}

	var check struct {
		ODSReceived  bool `json:"ods_received"`
		DWDProjected bool `json:"dwd_projected"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&check); err != nil {
		result.Status = "failed"
		result.FailedStage = "ingest"
		return result
	}

	result.ODSReceived = check.ODSReceived
	result.DWDProjected = check.DWDProjected
	result.RoundTripMs = time.Since(sentAt).Milliseconds()

	// Short-circuit on failures before attempting the query-stage probe:
	// there's no point verifying "can query-service see the canary" if the
	// projector hasn't even acked it.
	switch {
	case !check.ODSReceived:
		result.Status = "failed"
		result.FailedStage = "ingest"
		return result
	case !check.DWDProjected:
		result.Status = "partial"
		result.FailedStage = "projection"
		return result
	}

	// Optional query-stage probe (P2/P3 → landed 2026-04-17). Skipped when
	// QueryURL is empty (trial single-port deployments) because collector
	// and query share a DB — a positive DWD ack already implies the query
	// side can read it. Production should set QueryURL to cover the case
	// where query-service is a separate container with its own DB connection.
	if p.cfg.QueryURL != "" {
		queryURL := fmt.Sprintf("%s/internal/canary-check?event_id=%s", p.cfg.QueryURL, eventID)
		qResp, qErr := p.client.Get(queryURL)
		if qErr != nil || qResp.StatusCode != http.StatusOK {
			// Query-service unreachable or error. Don't demote the overall
			// status to "failed" — collector side is fine. Report "partial"
			// with query as the failed stage so operators know where to look.
			if qResp != nil {
				qResp.Body.Close()
			}
			result.Status = "partial"
			result.FailedStage = "query"
			slog.Debug("canary query-stage probe failed", "url", queryURL, "error", qErr)
			return result
		}
		defer qResp.Body.Close()
		var qCheck struct {
			QueryReadable bool `json:"query_readable"`
		}
		if err := json.NewDecoder(qResp.Body).Decode(&qCheck); err != nil {
			result.Status = "partial"
			result.FailedStage = "query"
			return result
		}
		result.QueryReadable = qCheck.QueryReadable
		if !qCheck.QueryReadable {
			result.Status = "partial"
			result.FailedStage = "query"
			return result
		}
	}

	result.Status = "ok"
	return result
}
