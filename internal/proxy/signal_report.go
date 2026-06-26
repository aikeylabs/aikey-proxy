package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// signal_report.go — I5 proxy emit. The proxy parses the upstream's unified-*
// 5h-utilization off the response headers and ships it best-effort to master's
// POST /accounts/me/signals, where it lands in the account's engine_meta sample
// ring for the allocation engine to read.
//
// MAIN-LINK SAFETY (架构第一优先级 = 主链路健壮): this never touches the forward
// path's latency or success. enqueue() is a NON-BLOCKING channel send (a full
// buffer drops the sample — utilization is a trend signal, a lost reading is
// harmless); the upload runs in a background goroutine whose failures are only
// logged, never surfaced to the request. A nil reporter = feature off.

// signalSample is one parsed util reading queued for delivery.
type signalSample struct {
	CredentialID string  `json:"credential_id"`
	TS           int64   `json:"ts"`
	Util5h       float64 `json:"util_5h"`
}

type signalReporter struct {
	url    string
	bearer func(ctx context.Context) (string, error) // account-JWT (reuses the group-runtime poll credential)
	client *http.Client
	in     chan signalSample
	logger *slog.Logger
}

// newSignalReporter returns nil (feature off) unless both a control URL and an
// auth bearer are configured. On success it starts the background upload loop.
func newSignalReporter(controlURL string, bearer func(context.Context) (string, error), logger *slog.Logger) *signalReporter {
	if controlURL == "" || bearer == nil {
		return nil
	}
	r := &signalReporter{
		url:    strings.TrimRight(controlURL, "/") + "/accounts/me/signals",
		bearer: bearer,
		client: &http.Client{Timeout: 10 * time.Second},
		in:     make(chan signalSample, 256),
		logger: logger,
	}
	go r.loop()
	return r
}

// enqueue is a non-blocking best-effort hand-off from the forward path.
func (r *signalReporter) enqueue(credentialID string, ts int64, util float64) {
	if r == nil || credentialID == "" {
		return
	}
	select {
	case r.in <- signalSample{CredentialID: credentialID, TS: ts, Util5h: util}:
	default: // buffer full → drop (trend signal; never block forwarding)
	}
}

func (r *signalReporter) loop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var batch []signalSample
	flush := func() {
		if len(batch) == 0 {
			return
		}
		r.post(batch)
		batch = batch[:0]
	}
	for {
		select {
		case s := <-r.in:
			if batch = append(batch, s); len(batch) >= 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (r *signalReporter) post(samples []signalSample) {
	body, err := json.Marshal(map[string]any{"samples": samples})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok, err := r.bearer(ctx)
	if err != nil {
		r.logger.Warn("signal report bearer unavailable",
			"event.name", "proxy.signal.bearer_failed", "error", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := r.client.Do(req)
	if err != nil {
		r.logger.Warn("signal report upload failed",
			"event.name", "proxy.signal.upload_failed", "error", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		r.logger.Warn("signal report rejected",
			"event.name", "proxy.signal.upload_rejected", "status", resp.StatusCode)
	}
}

// parseUnifiedUtil5h reads the anthropic-ratelimit-unified-5h-utilization header
// (a float 0..1) off a response, returning (value, true) only on a clean parse —
// a missing / malformed header yields (0, false) so the caller simply skips it.
func parseUnifiedUtil5h(h http.Header) (float64, bool) {
	raw := h.Get("anthropic-ratelimit-unified-5h-utilization")
	if raw == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || v < 0 || v > 1 {
		return 0, false
	}
	return v, true
}
