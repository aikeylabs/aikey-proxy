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

// signalSample is one parsed util reading queued for delivery. Util7d is the
// 7-day-window sibling of Util5h (master reads it into engine_meta.util_7d for
// the weekly-squeeze target). It's `omitempty` so a 5h-only reading stays
// byte-identical to the pre-7d wire — ponytail: a genuine util_7d==0.0 is
// indistinguishable from "no 7d header" on the wire, which is fine for a trend
// signal (other samples in the window carry the non-zero reading); switch to
// *float64 only if master ever needs to tell zero-util from no-data.
type signalSample struct {
	CredentialID string  `json:"credential_id"`
	TS           int64   `json:"ts"`
	Util5h       float64 `json:"util_5h"`
	Util7d       float64 `json:"util_7d,omitempty"`
}

// concurrencySample reports the PEAK number of concurrent in-flight forwarded
// requests a credential drew within one flush window. The allocation engine's
// DeriveFanout (§8.1) treats a high-concurrency account as several humans, so a
// raw peak (not an average) is what it wants. Like rateLimitSample this is a
// per-credential aggregate reset every flush, not a per-event channel.
type concurrencySample struct {
	CredentialID string `json:"credential_id"`
	Peak         int    `json:"peak"`
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
	// in-flight concurrency tracking. inflCur is the LIVE count (inc on forward
	// start, dec on completion — persists across windows so a request spanning a
	// flush keeps being counted); inflPeak is the max inflCur seen this window,
	// reset each flush. Both guarded by inflMu.
	// ponytail: one global mutex for both maps — the critical section is two map
	// ops; split to per-credential locks only if this lock ever shows up hot.
	inflMu   sync.Mutex
	inflCur  map[string]int
	inflPeak map[string]int
	logger   *slog.Logger
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
		inflCur:   make(map[string]int),
		inflPeak:  make(map[string]int),
		logger:    logger,
	}
	go r.loop()
	return r
}

// enqueue is a non-blocking best-effort hand-off from the forward path. util7d
// is the optional 7-day reading (pass 0 when the upstream sent no 7d header —
// signalSample.Util7d is omitempty so a 0 drops off the wire and util_5h stays
// byte-identical to the pre-7d format).
func (r *signalReporter) enqueue(credentialID string, ts int64, util5h, util7d float64) {
	if r == nil || credentialID == "" {
		return
	}
	select {
	case r.in <- signalSample{CredentialID: credentialID, TS: ts, Util5h: util5h, Util7d: util7d}:
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

// trackInflight marks one in-flight forwarded request for credentialID and
// returns a release func to call (via `defer …()`) on completion. It bumps the
// live count and updates this window's peak under a short map lock. Same
// MAIN-LINK safety contract as the other hooks: a nil receiver / empty id yield
// a no-op closure so the caller can `defer trackInflight(id)()` unconditionally
// without a nil check, and the lock is held only for two map ops.
//
// The returned func MUST run (use defer) — it decrements the live count, so a
// missed call would leak a credential as permanently "in flight" and pin its
// peak high forever. defer at the forward call site guarantees it fires even on
// panic. Lazy-inits both maps so a directly-constructed reporter (tests) can't
// nil-panic.
func (r *signalReporter) trackInflight(credentialID string) func() {
	if r == nil || credentialID == "" {
		return func() {} // no-op: safe to `defer …()`
	}
	r.inflMu.Lock()
	if r.inflCur == nil {
		r.inflCur = make(map[string]int)
		r.inflPeak = make(map[string]int)
	}
	r.inflCur[credentialID]++
	if r.inflCur[credentialID] > r.inflPeak[credentialID] {
		r.inflPeak[credentialID] = r.inflCur[credentialID]
	}
	r.inflMu.Unlock()
	return func() {
		r.inflMu.Lock()
		if r.inflCur[credentialID] > 0 {
			r.inflCur[credentialID]--
		}
		r.inflMu.Unlock()
	}
}

// snapshotConcurrency atomically reads + clears this window's per-credential
// peak into wire samples. Reset-on-read bounds the map to credentials seen this
// window — exactly like snapshotRateLimits. inflCur is deliberately NOT reset:
// requests still forwarding at the window boundary stay counted, so the next
// inc keeps computing a truthful peak (a cross-window burst still registers
// because inflPeak starts from 0 but inflCur already carries the live count).
// Returns nil for an idle window so post() omits the concurrency array.
//
// ponytail: a single long-lived stream sitting in a window with no NEW arrivals
// won't re-bump its peak, so a quiet steady-state-1 window can report nothing
// for that credential — harmless for a "several humans?" signal where the peak
// is what matters; revisit only if steady-state concurrency becomes a target.
func (r *signalReporter) snapshotConcurrency() []concurrencySample {
	r.inflMu.Lock()
	defer r.inflMu.Unlock()
	if len(r.inflPeak) == 0 {
		return nil
	}
	out := make([]concurrencySample, 0, len(r.inflPeak))
	for id, peak := range r.inflPeak {
		out = append(out, concurrencySample{CredentialID: id, Peak: peak})
	}
	r.inflPeak = make(map[string]int) // reset the window (inflCur persists)
	return out
}

func (r *signalReporter) loop() {
	ticker := time.NewTicker(signalFlushInterval)
	defer ticker.Stop()
	var batch []signalSample
	var revoked []revokedSample
	// flush takes the rate-limit + concurrency snapshots as args rather than
	// reading the per-window aggregates itself: the size-triggered early flushes
	// below pass nil so they DON'T disturb those windows, keeping each span
	// exactly one ticker period — only the ticker case snapshots, so the reported
	// window_secs / peak stay accurate even when a util/revoked burst forces an
	// early flush.
	flush := func(rl []rateLimitSample, conc []concurrencySample) {
		if len(batch) == 0 && len(revoked) == 0 && len(rl) == 0 && len(conc) == 0 {
			return
		}
		r.post(batch, revoked, rl, conc)
		batch = batch[:0]
		revoked = revoked[:0]
	}
	for {
		select {
		case s := <-r.in:
			if batch = append(batch, s); len(batch) >= 64 {
				flush(nil, nil)
			}
		case rv := <-r.revokedIn:
			// Revoked rides the SAME 30s batch flush rather than an immediate
			// per-event POST: a hard-ban 401s many concurrent in-flight requests
			// at once, so per-event posting would be a POST storm; batching reuses
			// one flush path (simplicity + main-link isolation) and the engine
			// tolerating ≤30s quarantine latency is an acceptable best-effort
			// trade. The >=64 cap bounds a burst so it doesn't wait the full tick.
			if revoked = append(revoked, rv); len(revoked) >= 64 {
				flush(nil, nil)
			}
		case <-ticker.C:
			flush(r.snapshotRateLimits(), r.snapshotConcurrency())
		}
	}
}

func (r *signalReporter) post(samples []signalSample, revoked []revokedSample, rateLimits []rateLimitSample, concurrency []concurrencySample) {
	// All arrays are optional: marshal only the non-empty ones so an all-samples,
	// all-revoked, all-rate_limits, or all-concurrency flush still posts a valid
	// body the master can decode.
	payload := make(map[string]any, 4)
	if len(samples) > 0 {
		payload["samples"] = samples
	}
	if len(revoked) > 0 {
		payload["revoked"] = revoked
	}
	if len(rateLimits) > 0 {
		payload["rate_limits"] = rateLimits
	}
	if len(concurrency) > 0 {
		payload["concurrency"] = concurrency
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

// parseUnifiedUtil7d is the 7-day-window sibling of parseUnifiedUtil5h: it reads
// the anthropic-ratelimit-unified-7d-utilization header (a float 0..1) the
// upstream sends alongside the 5h one, with identical (value, true)-only-on-
// clean-parse semantics. ponytail: a near-mirror of the 5h reader (3 lines of
// shared parse logic, below the extract-a-helper threshold) — kept separate so
// the master-facing names map 1:1 to the two header names.
func parseUnifiedUtil7d(h http.Header) (float64, bool) {
	raw := h.Get("anthropic-ratelimit-unified-7d-utilization")
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
