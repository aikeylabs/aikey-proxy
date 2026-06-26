package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ponytail: flush cadence doubles as the rate-limit count window — one constant
// so loop()'s ticker and the reported window_secs can never drift apart.
const signalFlushInterval = 30 * time.Second

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

// rateLimitSample reports how many 429/403 responses a credential drew in the
// last flush window. Master normalizes count/window into the allocation engine's
// §5.1 w5 "Recent429FreqNorm" risk signal (near-window 429/403 rhythm). Unlike
// util/revoked these are a per-credential COUNTER (a map+mutex, not a channel):
// 429s are frequent — a rate-limited account can draw a burst per second — so a
// per-event channel send would be a POST storm. The integer is reset every flush,
// which bounds the map to the credentials seen in one window. WindowSecs = the
// flush cadence so master can divide count by it without assuming the interval.
type rateLimitSample struct {
	CredentialID string `json:"credential_id"`
	Count        int    `json:"count"`
	WindowSecs   int    `json:"window_secs"`
}

type signalReporter struct {
	url       string
	bearer    func(ctx context.Context) (string, error) // account-JWT (reuses the group-runtime poll credential)
	client    *http.Client
	in        chan signalSample
	revokedIn chan revokedSample
	rlMu      sync.Mutex     // guards rlCounts
	rlCounts  map[string]int // per-credential 429/403 tally, reset each flush
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
		rlCounts:  make(map[string]int),
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

// incrRateLimit tallies one upstream 429/403 for a credential. Same MAIN-LINK
// safety contract as enqueue (see file header): nil receiver / empty id are
// dropped, and the bump is a short-held map lock that never blocks forwarding.
// A counter (not a channel) collapses a 429 burst to O(1) memory per credential;
// the map is reset every flush (see snapshotRateLimits), so it stays bounded by
// the live credential set. Lazy-inits the map so a directly-constructed reporter
// (tests, future call sites) can't nil-panic.
func (r *signalReporter) incrRateLimit(credentialID string) {
	if r == nil || credentialID == "" {
		return
	}
	r.rlMu.Lock()
	if r.rlCounts == nil {
		r.rlCounts = make(map[string]int)
	}
	r.rlCounts[credentialID]++
	r.rlMu.Unlock()
}

// snapshotRateLimits atomically reads + clears the 429/403 counters into wire
// samples. Reset-on-read is what bounds the map: each window only retains the
// credentials seen since the previous flush. Returns nil when nothing was seen
// (so an empty window omits the rate_limits array entirely).
func (r *signalReporter) snapshotRateLimits() []rateLimitSample {
	r.rlMu.Lock()
	defer r.rlMu.Unlock()
	if len(r.rlCounts) == 0 {
		return nil
	}
	out := make([]rateLimitSample, 0, len(r.rlCounts))
	for id, n := range r.rlCounts {
		out = append(out, rateLimitSample{
			CredentialID: id,
			Count:        n,
			WindowSecs:   int(signalFlushInterval / time.Second),
		})
	}
	r.rlCounts = make(map[string]int) // reset the window
	return out
}

func (r *signalReporter) loop() {
	ticker := time.NewTicker(signalFlushInterval)
	defer ticker.Stop()
	var batch []signalSample
	var revoked []revokedSample
	// flush takes the rate-limit snapshot as an arg rather than reading the
	// counter itself: the size-triggered early flushes below pass nil so they
	// DON'T disturb the 429/403 window, keeping its span exactly one ticker
	// period — only the ticker case snapshots, so the reported window_secs stays
	// accurate even when a util/revoked burst forces an early flush.
	flush := func(rl []rateLimitSample) {
		if len(batch) == 0 && len(revoked) == 0 && len(rl) == 0 {
			return
		}
		r.post(batch, revoked, rl)
		batch = batch[:0]
		revoked = revoked[:0]
	}
	for {
		select {
		case s := <-r.in:
			if batch = append(batch, s); len(batch) >= 64 {
				flush(nil)
			}
		case rv := <-r.revokedIn:
			// Revoked rides the SAME 30s batch flush rather than an immediate
			// per-event POST: a hard-ban 401s many concurrent in-flight requests
			// at once, so per-event posting would be a POST storm; batching reuses
			// one flush path (simplicity + main-link isolation) and the engine
			// tolerating ≤30s quarantine latency is an acceptable best-effort
			// trade. The >=64 cap bounds a burst so it doesn't wait the full tick.
			if revoked = append(revoked, rv); len(revoked) >= 64 {
				flush(nil)
			}
		case <-ticker.C:
			flush(r.snapshotRateLimits())
		}
	}
}

func (r *signalReporter) post(samples []signalSample, revoked []revokedSample, rateLimits []rateLimitSample) {
	// All arrays are optional: marshal only the non-empty ones so an all-samples,
	// all-revoked, or all-rate_limits flush still posts a valid body the master
	// can decode.
	payload := make(map[string]any, 3)
	if len(samples) > 0 {
		payload["samples"] = samples
	}
	if len(revoked) > 0 {
		payload["revoked"] = revoked
	}
	if len(rateLimits) > 0 {
		payload["rate_limits"] = rateLimits
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
