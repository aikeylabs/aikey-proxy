// device_routing_status.go — the worker half of the device-routing token
// contract: the internal header it reads, the four refusals it writes, and the
// three counters that make those refusals visible from outside the process.
//
// # Why counters at all
//
// Every refusal in this file is invisible to the control plane: it spends no
// upstream quota, produces no usage event, and the client that gets the 503 is a
// relay that will simply retry. Two of the three causes are VERSION SKEW —
// an ingress or a cluster daemon that is older than this worker — which means
// nobody is watching for them and the symptom (intermittent 503) looks like a
// network problem. So the two skew cases are counted and published on
// `GET /status` under pool_routing.device_routing_token, and the cluster
// heartbeat forwards the same two numbers to the hub (4.8's stats source), where
// the control plane's `nodes_unsupported` CRIT reads them.
//
// # Why these three shapes
//
//	decision_missing_24h    — SLIDING 24h window. A lifetime total can only grow,
//	                          so the WARN would never clear after one old-ingress
//	                          request and an operator would learn to ignore it.
//	route_kind_missing_active — a SET of tokens, not a counter: it self-heals the
//	                          moment the route is repaired or the token is gone,
//	                          so the CRIT clears with no proxy restart. Alerting
//	                          reads ONLY this.
//	route_kind_missing_total  — lifetime, diagnosis only, never alerting.
//
// Field names are the health-signal contract's dotted names verbatim
// (design §4b.5). None of them is omitempty: a degradation signal that vanishes
// at zero is indistinguishable from a build that cannot report it at all, and a
// release check asserting "zero" would then pass on an absent field.
//
// # No timers
//
// The active set is cleared on the two paths a fix must pass through anyway —
// the next request for that token that gets through the strict branch, and the
// next route reload (ReconcileDeviceRoutingRouteKind). A background sweeper
// would add a goroutine whose death is itself a silent failure.
//
// spec: R-device-routing-token-dispatch-7 worker 严格分支：按头指定的账号服务或按原因拒绝
// spec: R-device-routing-token-dispatch-20 类别缺失 → 拒绝 + 计数，两条必经之路清除
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/device-routing-token-dispatch/spec.md
package proxy

import (
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

const (
	// headerRouteAccount carries the control plane's account decision from the
	// cluster ingress to this worker. The value is the ACCOUNT id
	// (oauth_group_account.account_id), NOT the credential id — the credential id
	// travels a different path (node pick + usage attribution) and deliberately
	// never enters this header (design §4b.3).
	//
	// 🔴 It is in the X-Aikey-* namespace, so stripAikeyRequestHeaders removes it
	// before any upstream request. That strip is indiscriminate and has no
	// carve-out; see workflow/CI/IDE/claude/principles/no-aikey-headers-to-llm-upstream.md.
	headerRouteAccount = "X-Aikey-Route-Account"

	// routeKindDeviceRoutingToken is the ResolvedRoute.RouteKind value that marks
	// a device-routing token. Empty means "not a device-routing route" — which is
	// ALSO what a rolled-back cluster daemon leaves in the vault column, and the
	// two are indistinguishable from here on purpose: both mean this worker must
	// not treat the header as authoritative (design §4b.8).
	routeKindDeviceRoutingToken = "device_routing_token"

	// deviceRoutingReasonRouteKindMissing is the `reason` on a NODE_UNSUPPORTED
	// refusal produced by the worker's own self-check, as opposed to the control
	// plane's capability gate which returns the same code without it.
	deviceRoutingReasonRouteKindMissing = "route_kind_missing"

	// deviceRoutingRetryAfterNoDecision / …NotReady / …NodeUnsupported are the
	// documented Retry-After values (design §4b.2). All three situations are
	// expected to resolve on their own (an upgrade finishing, a material sync
	// landing), so the client is told to come back rather than to give up.
	deviceRoutingRetryAfterNoDecision      = 1
	deviceRoutingRetryAfterNotReady        = 2
	deviceRoutingRetryAfterNodeUnsupported = 5
)

// deviceRoutingWindowBuckets is the sliding window's resolution: 24 one-hour
// buckets indexed by epoch hour mod 24. Bounded memory (a slice of timestamps
// would grow with traffic during an incident, which is the worst moment to
// allocate) and exact enough for a signal whose only question is "> 0 or not".
const deviceRoutingWindowBuckets = 24

// deviceRoutingCounters is the process-wide state behind the three numbers.
// Process-wide rather than per-Proxy for the same reason identityKeyFallback is
// (group_resolve.go): a generation reload builds a new Proxy, and a signal that
// reset itself on every reload would under-report exactly while an operator is
// restarting things to make it stop.
type deviceRoutingCounters struct {
	// now is the injectable clock (design §4b.5 requires it so the 24h window is
	// testable without sleeping).
	now                    func() time.Time
	routeKindMissingActive map[string]struct{}
	routeKindMissingTotal  int64
	// decisionMissingCount[i] counts occurrences in epoch hour
	// decisionMissingHour[i]; a bucket whose hour is more than 23 hours old is
	// simply ignored (and overwritten when its slot comes round again), so
	// nothing has to expire anything.
	decisionMissingCount [deviceRoutingWindowBuckets]int64
	decisionMissingHour  [deviceRoutingWindowBuckets]int64
	mu                   sync.Mutex
}

var deviceRoutingStatus = &deviceRoutingCounters{
	now:                    time.Now,
	routeKindMissingActive: map[string]struct{}{},
	// Hour 0 is a real epoch hour (1970-01-01), so the zero value of
	// decisionMissingHour would look like a populated bucket. Counts are zero
	// there, so the sum is still 0 — the stamp is only consulted to decide
	// whether a non-zero count is still in range.
}

// resetDeviceRoutingStatusForTest is the test seam for the process-wide state:
// it isolates one test from another's counts and installs a controllable clock.
// Exported names are avoided on purpose — only same-package fences use it.
func resetDeviceRoutingStatusForTest(now func() time.Time) {
	deviceRoutingStatus.mu.Lock()
	defer deviceRoutingStatus.mu.Unlock()
	deviceRoutingStatus.now = now
	deviceRoutingStatus.routeKindMissingActive = map[string]struct{}{}
	deviceRoutingStatus.routeKindMissingTotal = 0
	deviceRoutingStatus.decisionMissingCount = [deviceRoutingWindowBuckets]int64{}
	deviceRoutingStatus.decisionMissingHour = [deviceRoutingWindowBuckets]int64{}
}

// DeviceRoutingTokenHealth is the externally readable device-routing signal,
// published under /status pool_routing.device_routing_token and forwarded to the
// hub inside the cluster heartbeat.
type DeviceRoutingTokenHealth struct {
	// DecisionMissing24h > 0 → WARN: requests for a device-routing token arrived
	// without the control plane's account decision in the last 24 hours.
	DecisionMissing24h int64 `json:"decision_missing_24h"`
	// RouteKindMissingActive > 0 → CRIT: tokens that STILL do not line up right
	// now. Self-healing; alerting reads only this one.
	RouteKindMissingActive int64 `json:"route_kind_missing_active"`
	// RouteKindMissingTotal is lifetime, for diagnosis. Never alerting.
	RouteKindMissingTotal int64 `json:"route_kind_missing_total"`
}

// DeviceRoutingTokenSnapshot reads the three counters for the health surfaces.
func DeviceRoutingTokenSnapshot() DeviceRoutingTokenHealth {
	c := deviceRoutingStatus
	c.mu.Lock()
	defer c.mu.Unlock()
	hour := c.now().Unix() / 3600
	var within int64
	for i := range c.decisionMissingCount {
		if hour-c.decisionMissingHour[i] < deviceRoutingWindowBuckets {
			within += c.decisionMissingCount[i]
		}
	}
	return DeviceRoutingTokenHealth{
		DecisionMissing24h:     within,
		RouteKindMissingActive: int64(len(c.routeKindMissingActive)),
		RouteKindMissingTotal:  c.routeKindMissingTotal,
	}
}

func noteDeviceRoutingDecisionMissing() {
	c := deviceRoutingStatus
	c.mu.Lock()
	defer c.mu.Unlock()
	hour := c.now().Unix() / 3600
	i := ((hour % deviceRoutingWindowBuckets) + deviceRoutingWindowBuckets) % deviceRoutingWindowBuckets
	if c.decisionMissingHour[i] != hour {
		c.decisionMissingHour[i] = hour
		c.decisionMissingCount[i] = 0
	}
	c.decisionMissingCount[i]++
}

func noteDeviceRoutingRouteKindMissing(virtualKeyID string) {
	c := deviceRoutingStatus
	c.mu.Lock()
	defer c.mu.Unlock()
	c.routeKindMissingTotal++
	if virtualKeyID != "" {
		c.routeKindMissingActive[virtualKeyID] = struct{}{}
	}
}

// clearDeviceRoutingRouteKindMissing is necessary-path #1: a request for this
// token got through the strict branch, which can only happen once its route
// carries the kind.
func clearDeviceRoutingRouteKindMissing(virtualKeyID string) {
	if virtualKeyID == "" {
		return
	}
	c := deviceRoutingStatus
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.routeKindMissingActive, virtualKeyID)
}

// ReconcileDeviceRoutingRouteKind is necessary-path #2: the route reload. A
// token drops out of the active set when the reloaded registry shows its route
// now carries the kind, or when the token is gone from the registry entirely
// (deleted / rotated / revoked).
//
// This is an idempotent reconcile over the authoritative view rather than an
// event the reload has to remember to emit: a reload that forgets to call it
// leaves a stale CRIT, whereas a reload that calls it twice changes nothing.
// See workflow/CI/IDE/claude/principles/event-write-reconcile-read.md.
func ReconcileDeviceRoutingRouteKind(routes map[string]*vkeys.ResolvedRoute) {
	stillMissing := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if route == nil || route.VirtualKeyID == "" {
			continue
		}
		if route.RouteKind != routeKindDeviceRoutingToken {
			stillMissing[route.VirtualKeyID] = struct{}{}
		}
	}
	c := deviceRoutingStatus
	c.mu.Lock()
	defer c.mu.Unlock()
	for vkID := range c.routeKindMissingActive {
		if _, present := stillMissing[vkID]; !present {
			delete(c.routeKindMissingActive, vkID)
		}
	}
}

// ── the four refusals ───────────────────────────────────────────────────────

// refuseDeviceRoutingNoDecision answers a device-routing request that carried no
// account decision. Fail closed: the alternative — picking an account locally —
// puts this device on a second account and re-creates the linkage the feature
// exists to cut, silently and only during an upgrade window, which is the
// hardest possible thing to notice afterwards.
//
// spec: R-device-routing-token-dispatch-7.S3 决定缺失（老入口）→ 503 + WARN + 计数
func (p *Proxy) refuseDeviceRoutingNoDecision(w http.ResponseWriter, logger *slog.Logger, route *vkeys.ResolvedRoute) {
	p.errors.Add(1)
	noteDeviceRoutingDecisionMissing()
	logger.Warn("device-routing token arrived without the control plane's account decision",
		"event.name", observability.EventProxyDeviceRoutingDecisionMissing,
		"error.code", observability.ErrCodeDeviceRoutingTokenNoDecision,
		"oauth_group_id", route.OauthGroupID,
		"virtual_key_id", route.VirtualKeyID,
		"seat_id", route.SeatID,
	)
	w.Header().Set("Retry-After", strconv.Itoa(deviceRoutingRetryAfterNoDecision))
	writeJSONError(w, http.StatusServiceUnavailable, "server_error",
		observability.ErrCodeDeviceRoutingTokenNoDecision,
		"This request's account assignment did not reach the node. Retry shortly; if it persists, the cluster ingress needs an upgrade.")
}

// refuseDeviceRoutingRouteKindMissing answers a request that carries the
// internal header while this worker's route does not say it is a device-routing
// route — a cluster daemon rolled back to a version that stopped writing
// route_kind, or an inbound forgery (the cluster port is unauthenticated inside
// the cluster network).
//
// 🔴 It must NOT fall back to serving the request on the seat path. That path
// picks an account locally, which is precisely what a device-routing token
// forbids; and because the request would then succeed, nothing would ever
// report the skew.
//
// spec: R-device-routing-token-dispatch-20.S2 —— 拒绝，而不是当普通令牌服务
func (p *Proxy) refuseDeviceRoutingRouteKindMissing(w http.ResponseWriter, logger *slog.Logger, route *vkeys.ResolvedRoute) {
	p.errors.Add(1)
	noteDeviceRoutingRouteKindMissing(route.VirtualKeyID)
	// ERROR, not WARN: /status grades route_kind_missing_active > 0 as CRIT, and
	// every request for this token fails until a daemon is upgraded.
	logger.Error("device-routing decision received for a route with no device-routing kind — refusing instead of serving it on the seat path",
		"event.name", observability.EventProxyDeviceRoutingRouteKindMissing,
		"error.code", observability.ErrCodeDeviceRoutingTokenNodeUnsupported,
		"reason", deviceRoutingReasonRouteKindMissing,
		"oauth_group_id", route.OauthGroupID,
		"virtual_key_id", route.VirtualKeyID,
		"seat_id", route.SeatID,
	)
	w.Header().Set("Retry-After", strconv.Itoa(deviceRoutingRetryAfterNodeUnsupported))
	writeJSONErrorDetails(w, http.StatusServiceUnavailable, "server_error",
		observability.ErrCodeDeviceRoutingTokenNodeUnsupported,
		"This node cannot carry device-routing traffic yet. Upgrade the node's aikey daemon; GET /cluster/health lists the affected nodes.",
		map[string]any{"reason": deviceRoutingReasonRouteKindMissing})
}

// refuseDeviceRoutingAccount answers with the PINNED account's own state.
//
// The split is the whole point of R-…-7.S4: only a closed window is a 429. A
// worker that reported every unavailable account as ACCOUNT_EXHAUSTED would send
// the operator to look at provider quota while the real fact is a material sync
// lag or a revoked token — and, because an external relay treats 429 as
// retryable and 503 as not, it would also change whether the customer's
// third-party fallback engages.
//
// spec: R-device-routing-token-dispatch-7.S1 额度 / 冷却 / 窗口 → 429，零上游
// spec: R-device-routing-token-dispatch-7.S4 材料未到 / 凭证失效 → 503，不报成额度用完
func (p *Proxy) refuseDeviceRoutingAccount(
	w http.ResponseWriter, logger *slog.Logger, route *vkeys.ResolvedRoute,
	pinned string, state vkeys.OverrideState,
) {
	p.errors.Add(1)
	identity := groupAccountIdentity(route.GroupRuntime, pinned)
	logger.Warn("device-routing token's bound account cannot serve this request",
		"event.name", observability.EventProxyDeviceRoutingAccountUnavail,
		"error.code", deviceRoutingAccountCode(state),
		"reason", string(state),
		"oauth_group_id", route.OauthGroupID,
		"virtual_key_id", route.VirtualKeyID,
		"account_id", pinned,
		"account_identity", identity,
	)
	p.reportSchedEvent(observability.EventProxyDeviceRoutingAccountUnavail, schedSeverityWarn, schedOriginAikey,
		deviceRoutingAccountCode(state), route.OauthGroupID, "", pinned, route.SeatID, "",
		map[string]any{"reason": string(state)})

	if state != vkeys.OverrideQuotaExhausted {
		// Not a quota problem: no retry_at exists to promise, only "come back".
		w.Header().Set("Retry-After", strconv.Itoa(deviceRoutingRetryAfterNotReady))
		writeJSONErrorDetails(w, http.StatusServiceUnavailable, "server_error",
			observability.ErrCodeDeviceRoutingTokenAccountNotReady,
			"The account bound to this device is not ready on this node yet. Retrying is safe; if it persists, check node sync and the account's sign-in state.",
			map[string]any{"reason": string(state)})
		return
	}

	// Quota class: the body shape mirrors the existing pre-check 429
	// (degradeGroupWithRetry — retry_after_seconds / retry_at / retry_reason) so a
	// client that already parses pool 429s needs no second shape. The deadline is
	// the LOCAL routing deadline, which is what actually governs re-entry — never
	// an estimate from a window snapshot.
	seconds, retryAt, reason := p.deviceRoutingRetryHorizon(route, pinned)
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeJSONErrorDetails(w, http.StatusTooManyRequests, "rate_limit_error",
		observability.ErrCodeDeviceRoutingTokenAccountExhausted,
		"The account bound to this device has no quota left in its current window. It will recover on its own; this request was not served by another account.",
		map[string]any{
			"retry_after_seconds": seconds,
			"retry_at":            retryAt,
			"retry_reason":        reason,
		})
}

// deviceRoutingAccountCode maps the classified state to its client-facing code.
// One place, so the log line and the body can never disagree about which fact
// this refusal is reporting.
func deviceRoutingAccountCode(state vkeys.OverrideState) string {
	if state == vkeys.OverrideQuotaExhausted {
		return observability.ErrCodeDeviceRoutingTokenAccountExhausted
	}
	return observability.ErrCodeDeviceRoutingTokenAccountNotReady
}

// deviceRoutingRetryHorizon returns the authoritative recovery horizon for the
// pinned account: its own cooldown deadline when the cooldown store holds one,
// else the provider's own window reset from the delivered material. Falls back
// to one second rather than omitting the header — a 429 with no horizon makes
// every relay guess, and guessing is what the pre-check exists to avoid.
func (p *Proxy) deviceRoutingRetryHorizon(route *vkeys.ResolvedRoute, pinned string) (seconds int, retryAt int64, reason string) {
	only := map[string]bool{pinned: true}
	// nil material and no seat: this horizon reads the delivered window itself,
	// below, and a dead pinned credential never gets here (ClassifyOverride
	// answers credential_unusable first), so the store is asked for the local
	// cooldown alone.
	if s, at, why, ok := p.poolCooldown.earliestRetryAdvice(only, nil, "", ""); ok {
		if why == "" {
			why = poolRouteRateLimited
		}
		return s, at, why
	}
	if reset, ok := groupWindowResetAt(route.GroupRuntime, pinned); ok {
		now := time.Now().Unix()
		if secs := reset - now; secs > 0 {
			return int(secs), reset, poolRouteWindowExhausted
		}
	}
	return 1, time.Now().Unix() + 1, string(vkeys.OverrideQuotaExhausted)
}

// refuseDeviceRoutingOverrideMismatch fails a request whose pick did not land on
// the account the control plane named.
//
// This is unreachable by construction — the classifier said the pinned account
// is usable, and PickRoutedAccount honors a usable override — so reaching it
// means the two disagree, i.e. a defect in this worker. The choice is then
// between serving a DIFFERENT account (breaking the one guarantee a
// device-routing token makes, silently) and failing loudly. It fails loudly.
//
// spec: R-device-routing-token-dispatch-11.S1 —— 严格分支消费未改动的
// PickRoutedAccount，结果必须等于头值
func (p *Proxy) refuseDeviceRoutingOverrideMismatch(
	w http.ResponseWriter, logger *slog.Logger, route *vkeys.ResolvedRoute, pinned, served string,
) {
	p.errors.Add(1)
	logger.Error("device-routing pick did not land on the account the control plane named — refusing rather than serving another account",
		"event.name", observability.EventProxyDeviceRoutingOverrideMismatch,
		"error.code", observability.ErrCodeDeviceRoutingTokenAccountNotReady,
		"oauth_group_id", route.OauthGroupID,
		"virtual_key_id", route.VirtualKeyID,
		"requested_account_id", pinned,
		"picked_account_id", served,
	)
	w.Header().Set("Retry-After", strconv.Itoa(deviceRoutingRetryAfterNotReady))
	writeJSONErrorDetails(w, http.StatusServiceUnavailable, "server_error",
		observability.ErrCodeDeviceRoutingTokenAccountNotReady,
		"The account bound to this device could not be selected on this node. Retrying is safe; if it persists, report the node's logs.",
		map[string]any{"reason": string(vkeys.OverrideMaterialNotReady)})
}
