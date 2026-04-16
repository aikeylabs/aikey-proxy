package events

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// CanaryConfig configures the synthetic canary probe.
type CanaryConfig struct {
	// DiagnosticsURL is the control/trial server base URL for canary-check queries.
	// e.g. "http://127.0.0.1:8090"
	DiagnosticsURL string
	// Interval between canary probes. Default: 5 minutes.
	Interval time.Duration
	// CheckDelay is how long to wait after sending before checking arrival. Default: 15s.
	CheckDelay time.Duration
}

// CanaryResult holds the outcome of the most recent canary probe.
type CanaryResult struct {
	EventID      string    `json:"event_id"`
	SentAt       time.Time `json:"sent_at"`
	ODSReceived  bool      `json:"ods_received"`
	DWDProjected bool      `json:"dwd_projected"`
	Status       string    `json:"status"`       // "ok" | "partial" | "failed" | "unavailable"
	FailedStage  string    `json:"failed_stage"` // "" | "ingest" | "projection" | "diagnostics_unreachable"
	RoundTripMs  int64     `json:"round_trip_ms"`
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
	go p.loop()
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
		// Diagnostics endpoint unreachable — this is expected in server-mode where
		// control-service doesn't have /internal/canary-check yet (P2/P3).
		// Mark as "unavailable" (not "failed") to avoid false alarms.
		result.Status = "unavailable"
		result.FailedStage = "diagnostics_unreachable"
		slog.Debug("canary check: diagnostics unreachable", "url", url, "error", err)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Endpoint not registered on this server (server-mode without diagnostics).
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

	// Canary only checks ODS and DWD — no "query" stage.
	// Why: query-service doesn't have /internal/canary-check yet (P2/P3).
	// Claiming "query ok" when we only checked DWD would be a false positive.
	switch {
	case !check.ODSReceived:
		result.Status = "failed"
		result.FailedStage = "ingest"
	case !check.DWDProjected:
		result.Status = "partial"
		result.FailedStage = "projection"
	default:
		result.Status = "ok"
	}

	return result
}
