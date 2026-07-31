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

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
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

// signalSample is one parsed util reading queued for delivery. Util7d is a
// pointer so the wire preserves "provider reported 0%" vs "provider omitted the
// 7d window". The vault quota display must never turn unknown into a fake 0%.
type signalSample struct {
	CredentialID string   `json:"credential_id"`
	TS           int64    `json:"ts"`
	Util5h       float64  `json:"util_5h"`
	Util7d       *float64 `json:"util_7d,omitempty"`
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
	// FallbackCount is how many of Count arrived while this credential was being
	// tried as a FALLBACK hop rather than as the primary (F-12b = C, task 3.12).
	//
	// 🔴 Why marked rather than dropped, and why not silently merged. Upstream
	// fallback makes one client request touch several credentials, so a single
	// user request can now raise the risk score of two or three of them at once.
	// Those refusals are real — the vendors did reject us — so suppressing them
	// would hide genuine evidence. But they are also CORRELATED in a way the
	// allocation engine's model does not assume: they all came from one request,
	// not from independent traffic. Marking lets the engine decide; merging them
	// in unmarked silently changes what its risk numbers mean.
	//
	// 🚫 This is not an implementation detail to slide past — it feeds account-pool
	// scheduling, and a scheduler acting on a distribution that quietly changed
	// shape is very hard to debug from the outside.
	FallbackCount int `json:"fallback_count,omitempty"`
}

type signalReporter struct {
	url       string
	bearer    func(ctx context.Context) (string, error) // account-JWT (reuses the group-runtime poll credential)
	client    *httpx.SwappableClient                    // control-plane: rebuilt on host network change (self-heal registry)
	in        chan signalSample
	revokedIn chan revokedSample
	rlMu      sync.Mutex     // guards rlCounts and rlFallback
	rlCounts  map[string]int // per-credential 429/403 tally, reset each flush
	// rlFallback is the subset of rlCounts that arrived on a FALLBACK hop
	// (F-12b). Reset on the same flush, so the two always describe one window.
	rlFallback map[string]int
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

	// stop terminates loop() on Close so the goroutine + ticker don't leak. A
	// fresh signalReporter is built per generation (buildGeneration); without
	// this, every reload (aikey use, filter/quota/audit toggle, /admin/reload)
	// leaked one loop() + 30s ticker holding a live bearer closure over the old
	// vault reader. Close is idempotent (stopOnce) — generation.close() may run
	// once but defensive against double-close.
	stop     chan struct{}
	stopOnce sync.Once
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
		client:    httpx.NewSwappableDirect(10 * time.Second),
		in:        make(chan signalSample, 256),
		revokedIn: make(chan revokedSample, 64),
		rlCounts:  make(map[string]int),
		inflCur:   make(map[string]int),
		inflPeak:  make(map[string]int),
		logger:    logger,
		stop:      make(chan struct{}),
	}
	go r.loop()
	return r
}

// Close stops the upload loop (idempotent, nil-safe). Called from
// generation.close() on every reload so the loop() goroutine + ticker don't
// leak. It does NOT close r.in / r.revokedIn — the forward path may still send
// there (non-blocking, default-drop), and closing them would panic that send.
func (r *signalReporter) Close() error {
	if r == nil {
		return nil
	}
	r.stopOnce.Do(func() { close(r.stop) })
	return nil
}

// enqueue is a non-blocking best-effort hand-off from the forward path. util7d
// is nil when the upstream sent no 7d window and non-nil even for a genuine 0%.
func (r *signalReporter) enqueue(credentialID string, ts int64, util5h float64, util7d *float64) {
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
	r.incrRateLimitHop(credentialID, false)
}

// incrRateLimitHop is incrRateLimit with the fallback marking (F-12b = C).
func (r *signalReporter) incrRateLimitHop(credentialID string, duringFallback bool) {
	if r == nil || credentialID == "" {
		return
	}
	r.rlMu.Lock()
	if r.rlCounts == nil {
		r.rlCounts = make(map[string]int)
	}
	r.rlCounts[credentialID]++
	if duringFallback {
		if r.rlFallback == nil {
			r.rlFallback = make(map[string]int)
		}
		r.rlFallback[credentialID]++
	}
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
			CredentialID:  id,
			Count:         n,
			FallbackCount: r.rlFallback[id],
			WindowSecs:    int(signalFlushInterval / time.Second),
		})
	}
	r.rlCounts = make(map[string]int) // reset the window
	r.rlFallback = nil                // 🔴 reset TOGETHER — a fallback tally that
	// outlived its window would attribute this window's refusals to the last one
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
		case <-r.stop:
			// Final flush on shutdown so a reload doesn't drop the in-flight
			// batch, then return — ends the goroutine + ticker (no leak).
			flush(r.snapshotRateLimits(), r.snapshotConcurrency())
			return
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
	resp, err := r.client.Get().Do(req)
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

// codex5hThresholdMinutes: a window shorter than this is the "5h" (short/head)
// window, longer is the "7d" (weekly) window. 360 = 6h, mirroring sub2api's
// single-window disambiguation. Live Plus windows are 300 (5h) and 10080 (7d).
const codex5hThresholdMinutes = 360

// parseCodexUtil reads Codex's per-window utilization off an upstream response
// (the X-Codex-* headers ride on every chatgpt.com /responses 200 — verified
// live 2026-07-06, see research/oauth-codex-ratelimit/2026-07-06-codex-ratelimit-
// taxonomy.md) and NORMALIZES it to the SAME (util_5h, util_7d) fraction shape
// the allocation engine consumes for Anthropic, so master stays provider-neutral
// (design §4B/§5.1). Two gotchas baked in:
//   - percent is 0..100 → ÷100 (Anthropic util is already 0..1).
//   - Codex ships TWO windows named primary/secondary whose durations are NOT
//     fixed to 5h/7d (a Plus account's primary is 5h, but sub2api's own comment
//     had it backwards). We classify by X-Codex-*-Window-Minutes — smaller = 5h,
//     larger = 7d — NEVER by the primary/secondary name.
//
// Returns (0,0,false) when no X-Codex-*-used-percent header is present (i.e. the
// response is not Codex traffic), so the caller simply skips the sample — the
// same "clean-parse-only" contract as parseUnifiedUtil5h. util_7d is 0 when its
// window is absent (matches the Anthropic path's omitempty-0 behavior).
func parseCodexUtil(h http.Header) (util5h float64, util7d *float64, ok bool) {
	pUsed, pOK := parseCodexPercent(h.Get("X-Codex-Primary-Used-Percent"))
	sUsed, sOK := parseCodexPercent(h.Get("X-Codex-Secondary-Used-Percent"))
	if !pOK && !sOK {
		return 0, nil, false // not Codex traffic (or no util headers) → skip
	}
	// Shared with pre-cut/reset reporting so all three consumers classify the
	// provider's primary/secondary names by duration identically.
	primaryIs5h := codexPrimaryIs5h(h)

	if primaryIs5h {
		util5h = pUsed / 100
		if sOK {
			v := sUsed / 100
			util7d = &v
		}
	} else {
		util5h = sUsed / 100
		if pOK {
			v := pUsed / 100
			util7d = &v
		}
	}
	return util5h, util7d, true
}

// parseCodexPercent parses an X-Codex-*-used-percent header (float 0..100+). Codex
// can report >100 briefly; we clamp the upper bound to 100 so the normalized
// fraction stays in [0,1] for the engine, but treat a missing/negative/garbage
// value as "absent" (ok=false).
func parseCodexPercent(raw string) (float64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v < 0 {
		return 0, false
	}
	if v > 100 {
		v = 100
	}
	return v, true
}

// parseCodexInt parses an X-Codex-*-window-minutes / -reset-after-seconds header;
// 0 on missing/garbage (treated as "unknown" by callers).
func parseCodexInt(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if i, err := strconv.Atoi(raw); err == nil && i > 0 {
		return i
	}
	return 0
}

// isHardRevoked reports whether a 401 upstream response means the credential's
// OAuth token was HARD-revoked (gone for good) vs a routine expiry the refresh
// path recovers from. We gate on status==401 AND a documented hard-revocation
// marker in the parsed error type/message (errMsg is the raw body), so a plain
// token-expiry 401 does NOT quarantine an otherwise-healthy account:
//   - anthropic: "OAuth token has been revoked" (contains "revoked").
//   - codex/openai (sub2api-derived, see research/oauth-codex-ratelimit): the
//     error code "token_revoked" (contains "revoked") or "token_invalidated",
//     or the non-standard body {"detail":"Unauthorized"} = permanently invalid.
//
// ponytail: narrow keyword/shape match on purpose to avoid false-positive
// quarantines; widen the term list here if other hard-ban phrasings show up.
func isHardRevoked(statusCode int, errType, errMsg string) bool {
	if statusCode != http.StatusUnauthorized {
		return false
	}
	blob := strings.ToLower(errType + " " + errMsg)
	return strings.Contains(blob, "revoked") ||
		strings.Contains(blob, "token_invalidated") ||
		strings.Contains(blob, `"detail":"unauthorized"`)
}
