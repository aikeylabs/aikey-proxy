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

// revokedSample flags a credential whose OAuth token the upstream hard-revoked
// (401 "OAuth token has been revoked") — master quarantines the account so the
// allocation engine stops picking it. Same best-effort, fault-isolated delivery
// as signalSample (see file header); a dropped flag just delays quarantine until
// the next 401 re-emits it, so loss is self-healing.
type revokedSample struct {
	CredentialID string `json:"credential_id"`
	Reason       string `json:"reason"`
}

type signalReporter struct {
	url       string
	bearer    func(ctx context.Context) (string, error) // account-JWT (reuses the group-runtime poll credential)
	client    *http.Client
	in        chan signalSample
	revokedIn chan revokedSample
	logger    *slog.Logger
}

// newSignalReporter returns nil (feature off) unless both a control URL and an
// auth bearer are configured. On success it starts the background upload loop.
func newSignalReporter(controlURL string, bearer func(context.Context) (string, error), logger *slog.Logger) *signalReporter {
	if controlURL == "" || bearer == nil {
		return nil
	}
	r := &signalReporter{
		url:       strings.TrimRight(controlURL, "/") + "/accounts/me/signals",
		bearer:    bearer,
		client:    &http.Client{Timeout: 10 * time.Second},
		in:        make(chan signalSample, 256),
		revokedIn: make(chan revokedSample, 64),
		logger:    logger,
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

// enqueueRevoked is the revoked-feed sibling of enqueue: a non-blocking,
// best-effort hand-off from the forward path's 401 detection. Same MAIN-LINK
// safety contract — nil receiver / empty id are dropped silently and a full
// buffer drops rather than blocks (a hard-ban 401s many in-flight requests at
// once, so the queue can fill; a dropped flag self-heals on the next 401).
func (r *signalReporter) enqueueRevoked(credentialID, reason string) {
	if r == nil || credentialID == "" {
		return
	}
	if reason == "" {
		reason = "revoked"
	}
	select {
	case r.revokedIn <- revokedSample{CredentialID: credentialID, Reason: reason}:
	default: // buffer full → drop (best-effort; never block forwarding)
	}
}

func (r *signalReporter) loop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var batch []signalSample
	var revoked []revokedSample
	flush := func() {
		if len(batch) == 0 && len(revoked) == 0 {
			return
		}
		r.post(batch, revoked)
		batch = batch[:0]
		revoked = revoked[:0]
	}
	for {
		select {
		case s := <-r.in:
			if batch = append(batch, s); len(batch) >= 64 {
				flush()
			}
		case rv := <-r.revokedIn:
			// Revoked rides the SAME 30s batch flush rather than an immediate
			// per-event POST: a hard-ban 401s many concurrent in-flight requests
			// at once, so per-event posting would be a POST storm; batching reuses
			// one flush path (simplicity + main-link isolation) and the engine
			// tolerating ≤30s quarantine latency is an acceptable best-effort
			// trade. The >=64 cap bounds a burst so it doesn't wait the full tick.
			if revoked = append(revoked, rv); len(revoked) >= 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (r *signalReporter) post(samples []signalSample, revoked []revokedSample) {
	// Both arrays are optional: marshal only the non-empty ones so an all-samples
	// or all-revoked flush still posts a valid body the master can decode.
	payload := make(map[string]any, 2)
	if len(samples) > 0 {
		payload["samples"] = samples
	}
	if len(revoked) > 0 {
		payload["revoked"] = revoked
	}
	if len(payload) == 0 {
		return
	}
	body, err := json.Marshal(payload)
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

// isHardRevoked reports whether a 401 upstream response means the credential's
// OAuth token was HARD-revoked (gone for good) vs a routine expiry the refresh
// path recovers from. Anthropic returns 401 with an "OAuth token has been
// revoked" message in the hard case. We gate on status==401 AND the "revoked"
// keyword in the parsed error type/message so a plain token-expiry 401 does NOT
// quarantine an otherwise-healthy account.
//
// ponytail: keyword match on the documented "revoked" string only — narrow on
// purpose to avoid false-positive quarantines; widen the term list here if other
// hard-ban phrasings show up.
func isHardRevoked(statusCode int, errType, errMsg string) bool {
	if statusCode != http.StatusUnauthorized {
		return false
	}
	return strings.Contains(strings.ToLower(errType+" "+errMsg), "revoked")
}
