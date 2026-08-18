package proxy

import (
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// sched_event_report.go — serving-path hooks that ship scheduling STATE-CHANGE
// events to the master's unified scheduling log (design:
// update/20260817-账号池调度日志统一视图与导出-方案.md). Every hook is a bypass:
// nil reporter / missing ids degrade to no-op, and the reporter's enqueue is
// non-blocking, so the forward path's latency and success are untouched.

const (
	schedSeverityInfo = "info"
	schedSeverityWarn = "warn"

	// Origin values (拍板 2026-08-18): who produced the signal behind the row.
	schedOriginProvider = "provider" // a concrete upstream response triggered it
	schedOriginAikey    = "aikey"    // aikey's own scheduling/protection produced it

	// route_resolved reasons (detail.reason — 拍板 2026-08-18 触发语义扩展):
	schedResolveFirstSettle = "first_settle" // first resolution this process knows of
	schedResolveDaily       = "daily"        // first request of a new LOCAL day (本地时区拍板)
	schedResolveRecovered   = "recovered"    // first success after this account's cooldown lapsed
)

// schedDay returns the LOCAL calendar day used for the daily-first-call marker.
// Local timezone by decision (拍板 a): "每天第一次" should match the operator's
// wall clock, not UTC. Overridable in tests.
var schedDay = func() string { return time.Now().Format("2006-01-02") }

// schedRouteState is one (group|seat)'s last settle observation.
type schedRouteState struct {
	account string
	day     string
}

// reportSchedEvent enqueues one event for the master log. origin is one of the
// schedOrigin* constants; errorCode may be empty. credentialID is the subject
// account's real credential_id (the master's ownership gate authorizes on it —
// pass "" only for group-level events with no single subject account, e.g. a
// pool-wide degrade).
func (p *Proxy) reportSchedEvent(eventName, severity, origin, errorCode, groupID, credentialID, accountID, seatID, traceID string, detail map[string]any) { //nolint:unparam // severity is warn-only through THIS helper today, but schedSeverityInfo is live on the sibling path (reportRouteResolved builds the sample directly). Dropping the parameter would fork one event API into two.
	r := p.signalReporter
	if r == nil || eventName == "" {
		return
	}
	r.enqueueSchedulingEvent(schedulingEventSample{
		TSMs:         time.Now().UnixMilli(),
		EventName:    eventName,
		Severity:     severity,
		Origin:       origin,
		ErrorCode:    errorCode,
		OauthGroupID: groupID,
		CredentialID: credentialID,
		AccountID:    accountID,
		SeatID:       seatID,
		TraceID:      traceID,
		Detail:       detail,
	})
}

// noteSchedRouteSettled implements the route_resolved trigger semantics
// (拍板 2026-08-17 #3, expanded 2026-08-18 覆盖度审计): a row is emitted when —
//   - the seat settles for the first time this process           → first_settle
//   - the routed account CHANGES                                 → account_switched (from→to)
//   - the SAME account resumes after its cooldown lapsed         → recovered
//   - the first request of a new local day arrives               → daily
//
// Steady sticky traffic within one day reports nothing. A change that is ALSO
// a recovery (回迁: switching back to a lapsed account) stays ONE row —
// account_switched with detail.recovered=true.
func (p *Proxy) noteSchedRouteSettled(groupID, seatID, accountID, credentialID, traceID string) {
	if p.signalReporter == nil || groupID == "" || accountID == "" {
		return
	}
	key := groupID + "|" + seatID
	day := schedDay()
	recovered := p.poolCooldown != nil && p.poolCooldown.consumeLapsed(accountID)
	prevAny, hadPrev := p.schedRouted.Load(key)
	prev, _ := prevAny.(schedRouteState)

	reason := ""
	switch {
	case !hadPrev:
		reason = schedResolveFirstSettle
	case prev.account != accountID:
		p.schedRouted.Store(key, schedRouteState{account: accountID, day: day})
		detail := map[string]any{"from_account_id": prev.account, "to_account_id": accountID}
		if recovered {
			detail["recovered"] = true
		}
		p.reportSchedEvent(observability.EventProxyGroupAccountSwitched, schedSeverityWarn, schedOriginAikey, "",
			groupID, credentialID, accountID, seatID, traceID, detail)
		return
	case recovered:
		reason = schedResolveRecovered
	case prev.day != day:
		reason = schedResolveDaily
	default:
		return // sticky, same day, no recovery — no row
	}
	p.schedRouted.Store(key, schedRouteState{account: accountID, day: day})
	r := p.signalReporter
	r.enqueueSchedulingEvent(schedulingEventSample{
		TSMs:      time.Now().UnixMilli(),
		EventName: observability.EventProxyGroupRouteResolved,
		Severity:  schedSeverityInfo, Origin: schedOriginAikey,
		OauthGroupID: groupID, CredentialID: credentialID, AccountID: accountID,
		SeatID: seatID, TraceID: traceID,
		Detail:    map[string]any{"reason": reason},
		dedupeKey: reason,
	})
}
