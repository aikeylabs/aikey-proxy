package proxy

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
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
// path's latency or success. enqueue() is a NON-BLOCKING channel send; the
// background loop retains failed trend uploads in a bounded accumulator and
// exposes retry/degraded/drop state through /status. A nil reporter = feature off.

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

// revokedSample is retained only for wire compatibility tests and rolling
// upgrades. Current request handling never emits this credential-global shape:
// Master cannot safely map it to one member token and therefore ignores it.
type revokedSample struct {
	CredentialID string `json:"credential_id"`
	Reason       string `json:"reason"`
}

// authFailureSample identifies the exact member-token route that the upstream
// rejected as permanently revoked. Unlike revokedSample, this is NOT a global
// provider-credential ban: credential_id may have healthy tokens for other
// seats. Master resolves Agent seats to their parent seat before demoting only
// oauth_member_token(credential_id, seat_id).
type authFailureSample struct {
	CredentialID     string `json:"credential_id"`
	OAuthGroupID     string `json:"oauth_group_id"`
	SeatID           string `json:"seat_id"`
	TokenFingerprint string `json:"token_fingerprint"`
	Reason           string `json:"reason"`
}

// schedulingEventSample is one scheduling STATE-CHANGE event shipped to the
// master's unified scheduling log (scheduling_event_log — design:
// update/20260817-账号池调度日志统一视图与导出-方案.md). Only change-gated /
// low-frequency events ride this rail (switch, cooldown, pre-cut, login
// required, failover, degrade); per-request route resolutions are deliberately
// NOT reported (拍板 2026-08-17 #3 — usage attribution already answers "which
// account served this request").
//
// EventID is proxy-generated and TIME-PREFIXED so the master rows sort within
// one second, and doubles as the idempotency key (master inserts with
// conflict-ignore, so a retried batch never duplicates). CredentialID is the
// real credential_id of the subject account — the master's ownership gate
// authorizes on it; AccountID is the oauth_group_account id (display id space,
// same as the drawer). The two id spaces are deliberately both carried:
// account_decision_log.account_id holds credential ids, so credential_id is
// the JOIN key to decisions while account_id matches the admin UI.
type schedulingEventSample struct {
	EventID      string         `json:"event_id"`
	TSMs         int64          `json:"ts_ms"`
	EventName    string         `json:"event_name"`
	Severity     string         `json:"severity,omitempty"`
	ErrorCode    string         `json:"error_code,omitempty"`
	OauthGroupID string         `json:"oauth_group_id,omitempty"`
	CredentialID string         `json:"credential_id,omitempty"`
	AccountID    string         `json:"account_id,omitempty"`
	SeatID       string         `json:"seat_id,omitempty"`
	TraceID      string         `json:"trace_id,omitempty"`
	// Origin says who produced the SIGNAL behind this row (拍板 2026-08-18):
	// "provider" = a concrete upstream response triggered it (429/5xx/401/4xx
	// passthrough); "aikey" = aikey's own scheduling/protection produced it
	// (settle, switch, pre-cut, login prompt, degrade). Pre-cut is "aikey" by
	// decision: the upstream reported nothing wrong — we proactively moved.
	Origin string         `json:"origin,omitempty"`
	Detail map[string]any `json:"detail,omitempty"`
	// dedupeKey extends the per-window suppression key WITHOUT going on the
	// wire: logically distinct transitions that share an event name (e.g.
	// route_resolved reason=first_settle vs =recovered arriving in one window)
	// must each keep their row.
	dedupeKey string
}

// rateLimitSample reports how many 429/403 responses a credential drew in the
// last flush window. Master normalizes Risk429Count/window into the allocation
// engine's §5.1 w5 "Recent429FreqNorm" risk signal. Unlike
// util/revoked these are a per-credential COUNTER (a map+mutex, not a channel):
// 429s are frequent — a rate-limited account can draw a burst per second — so a
// per-event channel send would be a POST storm. The integer is reset every flush,
// which bounds the map to the credentials seen in one window. WindowSecs = the
// flush cadence so master can divide count by it without assuming the interval.
type rateLimitSample struct {
	CredentialID string `json:"credential_id"`
	Count        int    `json:"count"`
	WindowSecs   int    `json:"window_secs"`
	// ForbiddenCount is the 403 share of Count (2026-08-15 方案 c, ban-visibility).
	// 429 and 403 are different evidence: a 429 is quota rhythm (normal pool
	// life), a structured 403 is a suspension/permission signal that the drawer
	// must surface as "upstream rejected" — folding them together would light
	// the ban indicator on every ordinary rate-limit wave. Additive optional
	// field: an old master ignores it; an old proxy omits it (reads as 0).
	ForbiddenCount int `json:"forbidden_count,omitempty"`
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
	// Risk429Count is the only count the allocation risk model may consume:
	// primary-hop 429 responses. 403 is visibility-only; fallback refusals are
	// correlated repeats from the same client request and are excluded as well.
	Risk429Count int `json:"risk_429_count"`
}

type signalReporter struct {
	configMu  sync.RWMutex
	url       string
	sourceID  string                                    // stable vault/Worker identity; optional during rolling upgrade
	bearer    func(ctx context.Context) (string, error) // account-JWT (reuses the group-runtime poll credential)
	client    *httpx.SwappableClient                    // control-plane: rebuilt on host network change (self-heal registry)
	in        chan signalSample
	revokedIn chan revokedSample
	authMu    sync.Mutex
	// authFailures is a durable, deduplicated outbox. A hard revocation is not a
	// trend sample: if its first upload fails, local token blocking prevents
	// another upstream 401, so dropping it would leave Master falsely logged_in.
	authFailures map[string]authFailureSample
	authWake     chan struct{}
	rlMu         sync.Mutex     // guards all rl* maps
	rlCounts     map[string]int // per-credential 429/403 tally, reset each flush
	// rlFallback is the subset of rlCounts that arrived on a FALLBACK hop
	// (F-12b). Reset on the same flush, so the two always describe one window.
	rlFallback map[string]int
	// rlForbidden is the 403 subset of rlCounts (2026-08-15 方案 c ban
	// visibility). Reset on the same flush for the same one-window reason.
	rlForbidden map[string]int
	rlRisk      map[string]int
	// rlPrevious makes an empty next window explicit once. Without that zero,
	// Master's last non-zero 403 window stayed red forever when traffic went quiet.
	rlPrevious map[string]struct{}
	// in-flight concurrency tracking. inflCur is the LIVE count (inc on forward
	// start, dec on completion — persists across windows so a request spanning a
	// flush keeps being counted); inflPeak is the max inflCur seen this window,
	// reset each flush. Both guarded by inflMu.
	// ponytail: one global mutex for both maps — the critical section is two map
	// ops; split to per-credential locks only if this lock ever shows up hot.
	inflMu       sync.Mutex
	inflCur      map[string]int
	inflPeak     map[string]int
	inflPrevious map[string]struct{}
	// evIn queues scheduling events for the unified master log. evSuppress
	// dedupes identical (event, group, credential, account, seat) keys within one
	// flush window: a fault burst (429 storm, blocked login) re-emits the same
	// condition on every request, and the LOG needs the transition, not the storm.
	// Reset every ticker flush, so a condition persisting across windows re-logs
	// at most once per 30s — bounded, and still visibly "ongoing" on the page.
	evIn       chan schedulingEventSample
	evSupMu    sync.Mutex
	evSuppress map[string]struct{}
	logger     *slog.Logger
	healthMu     sync.Mutex
	health       SignalReportingHealth
	dropSinceOK  bool

	// stop terminates loop() on Close so the goroutine + ticker don't leak. The
	// Supervisor owns one reporter for the full process lifetime; hot-reload
	// generations only reconfigure it and publish into it. Close is idempotent.
	stop     chan struct{}
	stopOnce sync.Once
}

// SignalReportingHealth is the developer-facing /status projection for the
// Proxy→Master allocation-signal pipe. It contains no credential/provider data.
type SignalReportingHealth struct {
	Status              string `json:"status"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	LastAttemptAt       int64  `json:"last_attempt_at,omitempty"`
	LastSuccessAt       int64  `json:"last_success_at,omitempty"`
	LastError           string `json:"last_error,omitempty"`
	PendingSignals      int    `json:"pending_signals"`
	DroppedSignals      int64  `json:"dropped_signals"`
}

// newSignalReporter returns nil (feature off) unless both a control URL and an
// auth bearer are configured. On success it starts the background upload loop.
//
// No sourceID parameter: this helper builds the MEMBER endpoint
// (/accounts/me/signals), where the caller's identity comes from the bearer
// token and a source id would be ignored. Org-scoped reporting, which does
// carry one, goes through newSignalReporterEndpoint directly — see
// proxy.go's use of p.sourceID. The parameter existed and every caller passed
// "", which is what unparam reported.
func newSignalReporter(controlURL string, bearer func(context.Context) (string, error), logger *slog.Logger) *signalReporter {
	if controlURL == "" {
		return nil
	}
	return newSignalReporterEndpoint(strings.TrimRight(controlURL, "/")+"/accounts/me/signals", "", bearer, logger)
}

func newSignalReporterEndpoint(endpoint, sourceID string, bearer func(context.Context) (string, error), logger *slog.Logger) *signalReporter {
	if endpoint == "" || bearer == nil {
		return nil
	}
	r := newDormantSignalReporter(logger)
	r.configure(endpoint, sourceID, bearer)
	return r
}

func newDormantSignalReporter(logger *slog.Logger) *signalReporter {
	if logger == nil {
		logger = slog.Default()
	}
	r := &signalReporter{
		client: httpx.NewSwappableDirect(10 * time.Second),
		// A 300-person team can complete more than 256 requests at once. The loop
		// collapses these by credential immediately; this buffer absorbs the burst
		// without making the user request wait for Control.
		in:           make(chan signalSample, maxPendingSignalCredentials),
		revokedIn:    make(chan revokedSample, 64),
		authFailures: make(map[string]authFailureSample),
		authWake:     make(chan struct{}, 1),
		rlCounts:     make(map[string]int),
		rlRisk:       make(map[string]int),
		rlPrevious:   make(map[string]struct{}),
		inflCur:      make(map[string]int),
		inflPeak:     make(map[string]int),
		inflPrevious: make(map[string]struct{}),
		evIn:         make(chan schedulingEventSample, 256),
		evSuppress:   make(map[string]struct{}),
		logger:       logger,
		health:       SignalReportingHealth{Status: "disabled"},
		stop:         make(chan struct{}),
	}
	r.hydrateAuthFailures()
	go r.loop()
	return r
}

// configure atomically moves the process-owned reporter to the control-plane
// identity of a newly activated generation. In-flight uploads keep a complete
// old snapshot; later uploads use the complete new snapshot, so endpoint and
// bearer can never be mixed across control servers.
func (r *signalReporter) configure(endpoint, sourceID string, bearer func(context.Context) (string, error)) {
	if r == nil {
		return
	}
	r.configMu.Lock()
	wasEnabled := r.url != "" && r.bearer != nil
	endpointChanged := r.url != endpoint || r.sourceID != sourceID
	r.url = endpoint
	r.sourceID = sourceID
	r.bearer = bearer
	enabled := endpoint != "" && bearer != nil
	r.configMu.Unlock()

	r.healthMu.Lock()
	if !enabled {
		r.health.Status = "disabled"
		r.health.LastError = ""
	} else if !wasEnabled || endpointChanged {
		r.health.Status = "starting"
		r.health.ConsecutiveFailures = 0
		r.health.LastError = ""
	}
	r.healthMu.Unlock()

	if enabled {
		select {
		case r.authWake <- struct{}{}:
		default:
		}
	}
}

func (r *signalReporter) configured() bool {
	if r == nil {
		return false
	}
	r.configMu.RLock()
	defer r.configMu.RUnlock()
	return r.url != "" && r.bearer != nil
}

// Close stops the upload loop (idempotent, nil-safe). A Supervisor calls this
// once during process shutdown; a standalone Proxy calls it from
// StopSignalReporting. It does NOT close r.in / r.revokedIn because closing a
// channel while a final request publishes would panic that send.
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
		r.recordSignalDrop(1)
	}
}

// enqueueRevoked exists only for rolling-wire compatibility tests. Production
// hard-revocation detection uses enqueueAuthFailure with route and token version.
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
		r.recordSignalDrop(1)
	}
}

// maxPendingSchedulingEvents bounds both the per-window suppression map and the
// retry accumulator: a master outage keeps at most this many events in memory
// and drops (counted, /status-visible) beyond it — the log is an observability
// bypass and must never grow with request rate.
const maxPendingSchedulingEvents = 512

// newSchedulingEventID mints a time-prefixed sortable id ("sev_<13-digit
// ms>_<4-byte hex>"). The decimal millisecond prefix keeps lexicographic order
// aligned with time order (13 digits covers past year 2280); the random suffix
// disambiguates same-millisecond events from one proxy.
func newSchedulingEventID(tsMs int64) string {
	var b [4]byte
	_, _ = cryptorand.Read(b[:])
	return fmt.Sprintf("sev_%013d_%s", tsMs, hex.EncodeToString(b[:]))
}

// enqueueSchedulingEvent is the non-blocking hand-off from the serving path.
// Same MAIN-LINK safety contract as enqueue: nil receiver / missing name are
// dropped silently, a full buffer drops with a counted signal-drop, and the
// per-window suppression bounds fault-burst re-emission (see evSuppress).
func (r *signalReporter) enqueueSchedulingEvent(s schedulingEventSample) {
	if r == nil || s.EventName == "" {
		return
	}
	if s.TSMs <= 0 {
		s.TSMs = time.Now().UnixMilli()
	}
	// ErrorCode joins the key so distinct conditions on one subject (e.g. a 400
	// vs 403 passthrough in the same window) each keep one row.
	key := s.EventName + "|" + s.ErrorCode + "|" + s.dedupeKey + "|" + s.OauthGroupID + "|" + s.CredentialID + "|" + s.AccountID + "|" + s.SeatID
	r.evSupMu.Lock()
	if r.evSuppress == nil {
		r.evSuppress = make(map[string]struct{})
	}
	if _, dup := r.evSuppress[key]; dup {
		r.evSupMu.Unlock()
		return // same condition already logged this window — transition, not storm
	}
	if len(r.evSuppress) >= maxPendingSchedulingEvents {
		r.evSupMu.Unlock()
		r.recordSignalDrop(1)
		return
	}
	r.evSuppress[key] = struct{}{}
	r.evSupMu.Unlock()
	if s.EventID == "" {
		s.EventID = newSchedulingEventID(s.TSMs)
	}
	select {
	case r.evIn <- s:
	default:
		r.recordSignalDrop(1)
	}
}

// clearSchedulingEventSuppression opens a fresh emission window (called from
// every ticker flush, success or not — suppression bounds emission RATE; the
// accumulator owns delivery reliability).
func (r *signalReporter) clearSchedulingEventSuppression() {
	r.evSupMu.Lock()
	r.evSuppress = make(map[string]struct{})
	r.evSupMu.Unlock()
}

const signalAuthFailureFilename = "signal-auth-failures.json"

func authFailureKey(s authFailureSample) string {
	return s.CredentialID + "|" + s.OAuthGroupID + "|" + s.SeatID
}

func signalAuthFailurePath() (string, error) {
	cooldownPath, err := poolCooldownPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cooldownPath), signalAuthFailureFilename), nil
}

// enqueueAuthFailure performs no network work on the request path. It makes one
// rare, bounded local state-file write so a Proxy crash cannot lose the only
// hard-revocation observation; network delivery always happens in loop().
func (r *signalReporter) enqueueAuthFailure(credentialID, oauthGroupID, seatID, tokenFingerprint string) {
	if r == nil || credentialID == "" || oauthGroupID == "" || seatID == "" || tokenFingerprint == "" {
		return
	}
	sample := authFailureSample{
		CredentialID: credentialID, OAuthGroupID: oauthGroupID, SeatID: seatID,
		TokenFingerprint: tokenFingerprint, Reason: "token_revoked",
	}
	r.authMu.Lock()
	if r.authFailures == nil {
		r.authFailures = make(map[string]authFailureSample)
	}
	r.authFailures[authFailureKey(sample)] = sample
	r.persistAuthFailuresLocked()
	r.authMu.Unlock()
	if r.authWake != nil {
		select {
		case r.authWake <- struct{}{}:
		default:
		}
	}
}

func (r *signalReporter) snapshotAuthFailures() []authFailureSample {
	if r == nil {
		return nil
	}
	r.authMu.Lock()
	defer r.authMu.Unlock()
	out := make([]authFailureSample, 0, len(r.authFailures))
	for _, sample := range r.authFailures {
		out = append(out, sample)
	}
	return out
}

func (r *signalReporter) acknowledgeAuthFailures(sent []authFailureSample) {
	if len(sent) == 0 {
		return
	}
	r.authMu.Lock()
	for _, sample := range sent {
		key := authFailureKey(sample)
		if r.authFailures[key] == sample {
			delete(r.authFailures, key)
		}
	}
	r.persistAuthFailuresLocked()
	r.authMu.Unlock()
}

func (r *signalReporter) hydrateAuthFailures() {
	path, err := signalAuthFailurePath()
	if err != nil {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var body struct {
		Failures []authFailureSample `json:"auth_failures"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		r.logger.Warn("auth-failure signal outbox is unreadable; starting empty",
			"event.name", observability.EventProxySignalAuthFailureStateInvalid, "error", err)
		return
	}
	for _, sample := range body.Failures {
		if sample.CredentialID != "" && sample.OAuthGroupID != "" && sample.SeatID != "" && sample.TokenFingerprint != "" {
			r.authFailures[authFailureKey(sample)] = sample
		}
	}
}

func (r *signalReporter) persistAuthFailuresLocked() {
	path, err := signalAuthFailurePath()
	if err != nil {
		return
	}
	if len(r.authFailures) == 0 {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			r.logger.Warn("auth-failure signal outbox remove failed",
				"event.name", observability.EventProxySignalAuthFailureStateWriteFailed, "error", removeErr)
		}
		return
	}
	failures := make([]authFailureSample, 0, len(r.authFailures))
	for _, sample := range r.authFailures {
		failures = append(failures, sample)
	}
	data, err := json.Marshal(map[string]any{"auth_failures": failures})
	if err == nil {
		err = os.MkdirAll(filepath.Dir(path), 0o700)
	}
	if err == nil {
		tmp := path + ".tmp"
		if err = os.WriteFile(tmp, data, 0o600); err == nil {
			err = os.Rename(tmp, path)
		}
	}
	if err != nil {
		r.logger.Warn("auth-failure signal outbox write failed",
			"event.name", observability.EventProxySignalAuthFailureStateWriteFailed, "error", err)
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
	r.incrRateLimitHop(credentialID, false, false)
}

// incrRateLimitHop is incrRateLimit with the fallback marking (F-12b = C) and
// the 403 marking (2026-08-15 方案 c: forbidden responses are tallied separately
// so the drawer can distinguish "suspension evidence" from quota rhythm).
func (r *signalReporter) incrRateLimitHop(credentialID string, duringFallback, forbidden bool) {
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
	if forbidden {
		if r.rlForbidden == nil {
			r.rlForbidden = make(map[string]int)
		}
		r.rlForbidden[credentialID]++
	}
	if !duringFallback && !forbidden {
		if r.rlRisk == nil {
			r.rlRisk = make(map[string]int)
		}
		r.rlRisk[credentialID]++
	}
	r.rlMu.Unlock()
}

// snapshotRateLimits atomically reads + clears the 429/403 counters into wire
// samples. Reset-on-read is what bounds the map: each window only retains the
// credentials seen since the previous flush. One explicit zero window follows
// activity so Master can clear that source; later idle windows are omitted.
func (r *signalReporter) snapshotRateLimits() []rateLimitSample {
	r.rlMu.Lock()
	defer r.rlMu.Unlock()
	if len(r.rlCounts) == 0 && len(r.rlPrevious) == 0 {
		return nil
	}
	ids := make(map[string]struct{}, len(r.rlCounts)+len(r.rlPrevious))
	for id := range r.rlCounts {
		ids[id] = struct{}{}
	}
	for id := range r.rlPrevious {
		ids[id] = struct{}{}
	}
	out := make([]rateLimitSample, 0, len(ids))
	for id := range ids {
		out = append(out, rateLimitSample{
			CredentialID:   id,
			Count:          r.rlCounts[id],
			FallbackCount:  r.rlFallback[id],
			ForbiddenCount: r.rlForbidden[id],
			Risk429Count:   r.rlRisk[id],
			WindowSecs:     int(signalFlushInterval / time.Second),
		})
	}
	nextPrevious := make(map[string]struct{}, len(r.rlCounts))
	for id := range r.rlCounts {
		nextPrevious[id] = struct{}{}
	}
	r.rlPrevious = nextPrevious
	r.rlCounts = make(map[string]int) // reset the window
	r.rlFallback = nil                // 🔴 reset TOGETHER — a fallback tally that
	// outlived its window would attribute this window's refusals to the last one
	r.rlForbidden = nil // same one-window contract as rlFallback
	r.rlRisk = nil
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
		if r.inflCur[credentialID] == 0 {
			delete(r.inflCur, credentialID)
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
// A long-lived request is re-published every window from inflCur. One explicit
// zero follows the final completion so Master does not retain a stale peak.
func (r *signalReporter) snapshotConcurrency() []concurrencySample {
	r.inflMu.Lock()
	defer r.inflMu.Unlock()
	for id, current := range r.inflCur {
		if current > r.inflPeak[id] {
			r.inflPeak[id] = current
		}
	}
	if len(r.inflPeak) == 0 && len(r.inflPrevious) == 0 {
		return nil
	}
	ids := make(map[string]struct{}, len(r.inflPeak)+len(r.inflPrevious))
	for id := range r.inflPeak {
		ids[id] = struct{}{}
	}
	for id := range r.inflPrevious {
		ids[id] = struct{}{}
	}
	out := make([]concurrencySample, 0, len(ids))
	for id := range ids {
		out = append(out, concurrencySample{CredentialID: id, Peak: r.inflPeak[id]})
	}
	r.inflPrevious = make(map[string]struct{}, len(r.inflPeak))
	for id := range r.inflPeak {
		r.inflPrevious[id] = struct{}{}
	}
	r.inflPeak = make(map[string]int) // reset the window (inflCur persists)
	return out
}

const maxPendingSignalCredentials = 2048

// signalTrendAccumulator is a bounded, idempotent retry buffer. Utilization
// keeps the newest reading per credential; failed rate windows are combined
// into one longer window; concurrency keeps the maximum peak. This prevents a
// Control outage from either silently discarding the batch or growing memory
// with request rate.
type signalTrendAccumulator struct {
	credentials map[string]struct{}
	util        map[string]signalSample
	revoked     map[string]revokedSample
	rate        map[string]rateLimitSample
	conc        map[string]concurrencySample
	// events is append-only within a delivery attempt and idempotent across
	// retries (master conflict-ignores on event_id), so unlike the trend maps it
	// needs no merge logic — just its own bound (maxPendingSchedulingEvents).
	events []schedulingEventSample
}

func newSignalTrendAccumulator() *signalTrendAccumulator {
	return &signalTrendAccumulator{
		credentials: make(map[string]struct{}),
		util:        make(map[string]signalSample), revoked: make(map[string]revokedSample),
		rate: make(map[string]rateLimitSample), conc: make(map[string]concurrencySample),
	}
}

func (a *signalTrendAccumulator) acceptCredential(id string) bool {
	if _, exists := a.credentials[id]; exists {
		return true
	}
	if len(a.credentials) >= maxPendingSignalCredentials {
		return false
	}
	a.credentials[id] = struct{}{}
	return true
}

func (a *signalTrendAccumulator) addUtil(s signalSample) bool {
	if current, ok := a.util[s.CredentialID]; ok {
		if s.TS >= current.TS {
			a.util[s.CredentialID] = s
		}
		return true
	}
	if !a.acceptCredential(s.CredentialID) {
		return false
	}
	a.util[s.CredentialID] = s
	return true
}

func (a *signalTrendAccumulator) addRevoked(s revokedSample) bool {
	if _, ok := a.revoked[s.CredentialID]; !ok && !a.acceptCredential(s.CredentialID) {
		return false
	}
	a.revoked[s.CredentialID] = s
	return true
}

func (a *signalTrendAccumulator) mergeRate(samples []rateLimitSample) int64 {
	var dropped int64
	for _, sample := range samples {
		current, ok := a.rate[sample.CredentialID]
		if !ok && !a.acceptCredential(sample.CredentialID) {
			dropped++
			continue
		}
		current.CredentialID = sample.CredentialID
		current.Count += sample.Count
		current.WindowSecs += sample.WindowSecs
		current.ForbiddenCount += sample.ForbiddenCount
		current.FallbackCount += sample.FallbackCount
		current.Risk429Count += sample.Risk429Count
		a.rate[sample.CredentialID] = current
	}
	return dropped
}

func (a *signalTrendAccumulator) addEvent(s schedulingEventSample) bool {
	if len(a.events) >= maxPendingSchedulingEvents {
		return false
	}
	a.events = append(a.events, s)
	return true
}

func (a *signalTrendAccumulator) mergeConcurrency(samples []concurrencySample) int64 {
	var dropped int64
	for _, sample := range samples {
		current, ok := a.conc[sample.CredentialID]
		if !ok && !a.acceptCredential(sample.CredentialID) {
			dropped++
			continue
		}
		if !ok || sample.Peak > current.Peak {
			a.conc[sample.CredentialID] = sample
		}
	}
	return dropped
}

func (a *signalTrendAccumulator) slices() ([]signalSample, []revokedSample, []rateLimitSample, []concurrencySample, []schedulingEventSample) {
	util := make([]signalSample, 0, len(a.util))
	for _, sample := range a.util {
		util = append(util, sample)
	}
	revoked := make([]revokedSample, 0, len(a.revoked))
	for _, sample := range a.revoked {
		revoked = append(revoked, sample)
	}
	rate := make([]rateLimitSample, 0, len(a.rate))
	for _, sample := range a.rate {
		rate = append(rate, sample)
	}
	conc := make([]concurrencySample, 0, len(a.conc))
	for _, sample := range a.conc {
		conc = append(conc, sample)
	}
	return util, revoked, rate, conc, a.events
}

func (a *signalTrendAccumulator) count() int {
	return len(a.util) + len(a.revoked) + len(a.rate) + len(a.conc) + len(a.events)
}

func (r *signalReporter) loop() {
	ticker := time.NewTicker(signalFlushInterval)
	defer ticker.Stop()
	pending := newSignalTrendAccumulator()
	flush := func(rate []rateLimitSample, conc []concurrencySample) {
		r.recordSignalDrop(pending.mergeRate(rate) + pending.mergeConcurrency(conc))
		authFailures := r.snapshotAuthFailures()
		r.setPendingSignals(pending.count() + len(authFailures))
		if pending.count() == 0 && len(authFailures) == 0 {
			return
		}
		// A disabled reporter retains its bounded trend accumulator and durable
		// auth outbox without pretending an upload failed. Activation calls
		// configure and wakes this same loop, so recovery needs no polling or
		// replay of the rejected Token.
		if !r.configured() {
			return
		}
		attempted := false
		allOK := true
		detail := ""
		if pending.count() > 0 {
			util, revoked, rates, concurrency, events := pending.slices()
			ok, uploadDetail := r.uploadAll(util, revoked, nil, rates, concurrency, events)
			attempted = true
			if ok {
				pending = newSignalTrendAccumulator()
			} else {
				allOK = false
				detail = uploadDetail
			}
		}
		// Durable auth failures are intentionally isolated one by one. The master
		// rejects an unauthorized route with HTTP 409; batching it with trend data
		// or another route would otherwise poison unrelated signals indefinitely.
		for _, failure := range authFailures {
			ok, uploadDetail := r.uploadAll(nil, nil, []authFailureSample{failure}, nil, nil, nil)
			attempted = true
			if ok {
				r.acknowledgeAuthFailures([]authFailureSample{failure})
				continue
			}
			allOK = false
			if detail == "" {
				detail = uploadDetail
			}
		}
		if attempted {
			r.recordSignalUpload(allOK, detail)
		}
		r.setPendingSignals(pending.count() + len(r.snapshotAuthFailures()))
	}
	for {
		select {
		case sample := <-r.in:
			if !pending.addUtil(sample) {
				r.recordSignalDrop(1)
			}
		case sample := <-r.revokedIn:
			if !pending.addRevoked(sample) {
				r.recordSignalDrop(1)
			}
		case ev := <-r.evIn:
			if !pending.addEvent(ev) {
				r.recordSignalDrop(1)
			}
		case <-r.authWake:
			flush(nil, nil)
		case <-ticker.C:
			r.clearSchedulingEventSuppression()
			flush(r.snapshotRateLimits(), r.snapshotConcurrency())
		case <-r.stop:
			flush(r.snapshotRateLimits(), r.snapshotConcurrency())
			return
		}
	}
}

func (r *signalReporter) post(samples []signalSample, revoked []revokedSample, rateLimits []rateLimitSample, concurrency []concurrencySample) {
	r.postAll(samples, revoked, r.snapshotAuthFailures(), rateLimits, concurrency)
}

func (r *signalReporter) postAll(samples []signalSample, revoked []revokedSample, authFailures []authFailureSample, rateLimits []rateLimitSample, concurrency []concurrencySample) bool {
	ok, detail := r.uploadAll(samples, revoked, authFailures, rateLimits, concurrency, nil)
	r.recordSignalUpload(ok, detail)
	return ok
}

func (r *signalReporter) uploadAll(samples []signalSample, revoked []revokedSample, authFailures []authFailureSample, rateLimits []rateLimitSample, concurrency []concurrencySample, events []schedulingEventSample) (ok bool, detail string) {
	r.configMu.RLock()
	endpoint := r.url
	sourceID := r.sourceID
	bearer := r.bearer
	r.configMu.RUnlock()
	if endpoint == "" || bearer == nil {
		return false, "signal reporting disabled"
	}
	// All arrays are optional: marshal only the non-empty ones so an all-samples,
	// all-revoked, all-rate_limits, or all-concurrency flush still posts a valid
	// body the master can decode.
	payload := make(map[string]any, 6)
	if sourceID != "" {
		payload["source_id"] = sourceID
	}
	if len(samples) > 0 {
		payload["samples"] = samples
	}
	if len(revoked) > 0 {
		payload["revoked"] = revoked
	}
	if len(authFailures) > 0 {
		payload["auth_failures"] = authFailures
	}
	if len(rateLimits) > 0 {
		payload["rate_limits"] = rateLimits
	}
	if len(concurrency) > 0 {
		payload["concurrency"] = concurrency
	}
	if len(events) > 0 {
		payload["events"] = events
	}
	if len(payload) == 0 || (len(payload) == 1 && sourceID != "") {
		return true, ""
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, "signal payload encoding failed"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok, err := bearer(ctx)
	if err != nil {
		r.logger.Warn("signal report bearer unavailable",
			"event.name", observability.EventProxySignalBearerFailed, "error", err)
		return false, "signal bearer unavailable"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, "signal request construction failed"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := r.client.Get().Do(req)
	if err != nil {
		r.logger.Warn("signal report upload failed",
			"event.name", observability.EventProxySignalUploadFailed, "error", err)
		return false, "signal upload failed"
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		r.logger.Warn("signal report rejected",
			"event.name", observability.EventProxySignalUploadRejected, "status", resp.StatusCode)
		return false, "signal report rejected with HTTP " + strconv.Itoa(resp.StatusCode)
	}
	return true, ""
}

func (r *signalReporter) recordSignalUpload(ok bool, detail string) {
	if r == nil {
		return
	}
	now := time.Now().Unix()
	r.healthMu.Lock()
	r.health.LastAttemptAt = now
	if ok {
		r.health.Status = "healthy"
		r.health.ConsecutiveFailures = 0
		r.health.LastSuccessAt = now
		r.health.LastError = ""
		r.dropSinceOK = false
	} else {
		r.health.ConsecutiveFailures++
		r.health.Status = "retrying"
		if r.health.ConsecutiveFailures >= 3 || r.dropSinceOK {
			r.health.Status = "degraded"
		}
		r.health.LastError = detail
	}
	r.healthMu.Unlock()
}

func (r *signalReporter) setPendingSignals(count int) {
	if r == nil {
		return
	}
	r.healthMu.Lock()
	r.health.PendingSignals = count
	r.healthMu.Unlock()
}

func (r *signalReporter) recordSignalDrop(count int64) {
	if r == nil || count <= 0 {
		return
	}
	r.healthMu.Lock()
	r.health.DroppedSignals += count
	r.dropSinceOK = true
	r.health.Status = "degraded"
	r.health.LastError = "signal buffer capacity exceeded"
	r.healthMu.Unlock()
}

func (r *signalReporter) healthSnapshot() SignalReportingHealth {
	if r == nil {
		return SignalReportingHealth{Status: "disabled"}
	}
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	return r.health
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
	if !hardRevocationStatus(statusCode) {
		return false
	}
	blob := strings.ToLower(errType + " " + errMsg)
	return strings.Contains(blob, "revoked") ||
		strings.Contains(blob, "token_invalidated") ||
		strings.Contains(blob, `"detail":"unauthorized"`)
}

// hardRevocationStatus reports whether a status code can CARRY a hard-revocation
// marker. It does not decide anything on its own — the marker list above still
// has to match.
//
// # 🔴 O23: why 403 was added, and what this deliberately does NOT claim
//
// The gate used to be `statusCode != 401 → false`, which made 403 structurally
// unreachable: an operator who KNEW the exact phrasing of a ban still had no way
// to express it, because the status check ran first. That is a different problem
// from "we picked the wrong keywords", and it is the half that can be fixed
// without evidence we do not have.
//
// 🚫 No keyword was added. The three markers are unchanged and were each paid for
// with an observed body. Extending them to 403 does not widen what counts as a
// hard revocation — it only stops the status code from vetoing a marker that is
// unambiguous wherever it appears. A 403 whose body says "OAuth token has been
// revoked" is a revocation by any reading; a 403 from a content filter, a region
// block or an org policy says none of those things and still does not match.
//
// 🔴 This does NOT close the plan-expiry case, and must not be reported as
// closing it. The premise that an expired plan or a ban surfaces as 403 comes
// from a 阶段7 requirements note with no captured artifact behind it. Sampling on
// 2026-08-01 across three real vendors produced SIX failures and ZERO 403s
// (Anthropic bad key → 401; Anthropic no-access model → 404; Anthropic admin
// endpoint → 401; GLM bad key → 401; GLM unknown model → 400; DeepSeek bad key →
// 401). Until a real 403 body exists to read, writing a rule for its wording
// would be inventing the evidence.
//
// `expired` / 402 are deliberately absent: an expiry is recoverable, and
// quarantining a recoverable account removes a working upstream from the pool —
// worse than the retry loop this is meant to stop.
func hardRevocationStatus(statusCode int) bool {
	return statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden
}
