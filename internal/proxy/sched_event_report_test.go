package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// looplessSignalReporter builds a reporter WITHOUT the background loop() so
// tests can assert on evIn contents deterministically (the dormant constructor
// starts a goroutine that would race these length checks).
func looplessSignalReporter() *signalReporter {
	return &signalReporter{
		client:     httpx.NewSwappableDirect(2 * time.Second),
		in:         make(chan signalSample, 8),
		revokedIn:  make(chan revokedSample, 1),
		evIn:       make(chan schedulingEventSample, 256),
		evSuppress: make(map[string]struct{}),
		logger:     slog.Default(),
		stop:       make(chan struct{}),
	}
}

// sched_event_report_test.go — unit fences for the unified scheduling-log rail
// (update/20260817-账号池调度日志统一视图与导出-方案.md P1/T1.5):
//  1. events ride the existing signal flush payload as an optional `events` array;
//  2. the per-window suppression collapses a fault burst to one row;
//  3. route settling is CHANGE-gated (拍板 #3): sticky traffic emits nothing,
//     the first settle emits route_resolved, a change emits account_switched.

// flushEvents drains the reporter's event channel into the accumulator and
// posts, mimicking one ticker flush without waiting 30s.
func flushSchedEvents(t *testing.T, r *signalReporter) {
	t.Helper()
	pending := newSignalTrendAccumulator()
	for {
		select {
		case ev := <-r.evIn:
			if !pending.addEvent(ev) {
				t.Fatal("accumulator refused event below its bound")
			}
			continue
		default:
		}
		break
	}
	_, _, _, _, events := pending.slices()
	if len(events) == 0 {
		return
	}
	ok, detail := r.uploadAll(nil, nil, nil, nil, nil, events)
	if !ok {
		t.Fatalf("uploadAll failed: %s", detail)
	}
}

func TestSchedulingEventRidesSignalPayload(t *testing.T) {
	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got <- b
	}))
	defer srv.Close()

	r := looplessSignalReporter()
	r.configure(srv.URL, "src-1", func(context.Context) (string, error) { return "tok", nil })

	r.enqueueSchedulingEvent(schedulingEventSample{
		EventName:    observability.EventProxyGroupAccountSwitched,
		Severity:     "warn",
		OauthGroupID: "g1",
		CredentialID: "cred1",
		AccountID:    "acct1",
		SeatID:       "seat1",
		Detail:       map[string]any{"from_account_id": "acct0", "to_account_id": "acct1"},
	})
	flushSchedEvents(t, r)

	var decoded struct {
		Events []schedulingEventSample `json:"events"`
	}
	if err := json.Unmarshal(<-got, &decoded); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if len(decoded.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(decoded.Events))
	}
	ev := decoded.Events[0]
	if ev.EventName != observability.EventProxyGroupAccountSwitched || ev.CredentialID != "cred1" ||
		ev.OauthGroupID != "g1" || ev.SeatID != "seat1" {
		t.Fatalf("event fields wrong: %+v", ev)
	}
	if ev.EventID == "" || !strings.HasPrefix(ev.EventID, "sev_") {
		t.Fatalf("event_id missing/unsortable prefix: %q", ev.EventID)
	}
	if ev.TSMs <= 0 {
		t.Fatalf("ts_ms not stamped: %d", ev.TSMs)
	}
}

// TestSchedulingEventIDsSortWithinOneSecond pins the reason the id is
// time-prefixed at millisecond precision: account_decision_log's second-level
// created_at made same-second ordering impossible — the event log must not
// inherit that gap.
func TestSchedulingEventIDsSortWithinOneSecond(t *testing.T) {
	a := newSchedulingEventID(1755400000123)
	b := newSchedulingEventID(1755400000124)
	if !(a < b) {
		t.Fatalf("ids do not sort by time: %q !< %q", a, b)
	}
}

func TestSchedulingEventBurstIsSuppressedWithinWindow(t *testing.T) {
	r := looplessSignalReporter()

	same := schedulingEventSample{
		EventName:    observability.EventProxyGroupAccountCooldown,
		OauthGroupID: "g1", CredentialID: "cred1", AccountID: "acct1", SeatID: "seat1",
	}
	for i := 0; i < 50; i++ {
		r.enqueueSchedulingEvent(same)
	}
	if n := len(r.evIn); n != 1 {
		t.Fatalf("burst enqueued %d events, suppression wants exactly 1", n)
	}

	// A NEW window re-admits the same condition once (ongoing conditions stay
	// visible at flush cadence, bounded).
	r.clearSchedulingEventSuppression()
	r.enqueueSchedulingEvent(same)
	if n := len(r.evIn); n != 2 {
		t.Fatalf("after window clear got %d events, want 2", n)
	}

	// A DIFFERENT subject in the same window is not suppressed.
	other := same
	other.AccountID = "acct2"
	r.enqueueSchedulingEvent(other)
	if n := len(r.evIn); n != 3 {
		t.Fatalf("distinct subject suppressed: %d events, want 3", n)
	}
}

func TestNoteSchedRouteSettledIsChangeGated(t *testing.T) {
	r := looplessSignalReporter()
	p := &Proxy{signalReporter: r, poolCooldown: newPoolCooldownStore()}

	drain := func() []schedulingEventSample {
		var out []schedulingEventSample
		for {
			select {
			case ev := <-r.evIn:
				out = append(out, ev)
				continue
			default:
			}
			return out
		}
	}

	// First settle → exactly one route_resolved(reason=first_settle, origin=aikey).
	p.noteSchedRouteSettled("g1", "seat1", "acctA", "credA", "tr-1")
	// Sticky repeats (same day) → nothing.
	p.noteSchedRouteSettled("g1", "seat1", "acctA", "credA", "tr-2")
	p.noteSchedRouteSettled("g1", "seat1", "acctA", "credA", "tr-3")
	events := drain()
	if len(events) != 1 || events[0].EventName != observability.EventProxyGroupRouteResolved {
		t.Fatalf("first settle: got %+v, want one route_resolved", events)
	}
	if events[0].Detail["reason"] != schedResolveFirstSettle || events[0].Origin != schedOriginAikey {
		t.Fatalf("first settle reason/origin wrong: %+v", events[0])
	}

	// Change → exactly one account_switched carrying from→to.
	p.noteSchedRouteSettled("g1", "seat1", "acctB", "credB", "tr-4")
	events = drain()
	if len(events) != 1 || events[0].EventName != observability.EventProxyGroupAccountSwitched {
		t.Fatalf("switch: got %+v, want one account_switched", events)
	}
	if events[0].Detail["from_account_id"] != "acctA" || events[0].Detail["to_account_id"] != "acctB" {
		t.Fatalf("switch detail wrong: %+v", events[0].Detail)
	}

	// Another seat settling on the same account is its own first settle.
	p.noteSchedRouteSettled("g1", "seat2", "acctB", "credB", "tr-5")
	events = drain()
	if len(events) != 1 || events[0].EventName != observability.EventProxyGroupRouteResolved {
		t.Fatalf("second seat: got %+v, want one route_resolved", events)
	}
}

// TestNoteSchedRouteSettled_DailyFirstCall pins 拍板 a (2026-08-18): the first
// request of a NEW LOCAL DAY re-emits route_resolved(reason=daily) even though
// the account never changed — "每天第一次调用" is visible in the log.
func TestNoteSchedRouteSettled_DailyFirstCall(t *testing.T) {
	r := looplessSignalReporter()
	p := &Proxy{signalReporter: r, poolCooldown: newPoolCooldownStore()}
	origDay := schedDay
	defer func() { schedDay = origDay }()

	schedDay = func() string { return "2026-08-18" }
	p.noteSchedRouteSettled("g1", "seat1", "acctA", "credA", "")
	<-r.evIn // consume first_settle
	p.noteSchedRouteSettled("g1", "seat1", "acctA", "credA", "")
	if len(r.evIn) != 0 {
		t.Fatal("same-day sticky must stay silent")
	}

	schedDay = func() string { return "2026-08-19" }
	p.noteSchedRouteSettled("g1", "seat1", "acctA", "credA", "")
	if len(r.evIn) != 1 {
		t.Fatalf("day rollover must emit exactly one row, got %d", len(r.evIn))
	}
	ev := <-r.evIn
	if ev.EventName != observability.EventProxyGroupRouteResolved || ev.Detail["reason"] != schedResolveDaily {
		t.Fatalf("daily row wrong: %+v", ev)
	}
	// And only once per day.
	p.noteSchedRouteSettled("g1", "seat1", "acctA", "credA", "")
	if len(r.evIn) != 0 {
		t.Fatal("second call of the new day must stay silent")
	}
}

// TestNoteSchedRouteSettled_RecoveredSameAccount pins the recovery gap fix
// (覆盖度审计 2026-08-18 问题1/2): when the SAME account resumes after its
// cooldown lapsed (single-account pool — no switch ever happened), the first
// success re-emits route_resolved(reason=recovered).
func TestNoteSchedRouteSettled_RecoveredSameAccount(t *testing.T) {
	r := looplessSignalReporter()
	store := newPoolCooldownStore()
	p := &Proxy{signalReporter: r, poolCooldown: store}

	p.noteSchedRouteSettled("g1", "seat1", "acctA", "credA", "")
	<-r.evIn // first_settle

	// Cool the account, then advance the injected clock past the deadline; the
	// next skipSet() observation prunes it and records the lapse (the
	// lazy-recovery flow — expiry is only ever noticed by traffic).
	store.mark("acctA", time.Now().Add(30*time.Second))
	store.now = func() time.Time { return time.Now().Add(time.Minute) }
	_ = store.skipSet()

	p.noteSchedRouteSettled("g1", "seat1", "acctA", "credA", "")
	if len(r.evIn) != 1 {
		t.Fatalf("recovery must emit exactly one row, got %d", len(r.evIn))
	}
	ev := <-r.evIn
	if ev.EventName != observability.EventProxyGroupRouteResolved || ev.Detail["reason"] != schedResolveRecovered {
		t.Fatalf("recovered row wrong: %+v", ev)
	}
	// Consumed — the next sticky request is silent again.
	p.noteSchedRouteSettled("g1", "seat1", "acctA", "credA", "")
	if len(r.evIn) != 0 {
		t.Fatal("recovery marker must be one-shot")
	}
}

// TestSchedulingEventAccumulatorBound pins the memory ceiling: a master outage
// keeps at most maxPendingSchedulingEvents queued and drops (counted) beyond it.
func TestSchedulingEventAccumulatorBound(t *testing.T) {
	a := newSignalTrendAccumulator()
	for i := 0; i < maxPendingSchedulingEvents; i++ {
		if !a.addEvent(schedulingEventSample{EventName: "e", TSMs: int64(i + 1)}) {
			t.Fatalf("event %d refused below bound", i)
		}
	}
	if a.addEvent(schedulingEventSample{EventName: "e", TSMs: time.Now().UnixMilli()}) {
		t.Fatal("accumulator accepted an event beyond its bound")
	}
	if a.count() < maxPendingSchedulingEvents {
		t.Fatalf("count() = %d does not include events", a.count())
	}
}

// TestSchedEventHooksAreNilReporterSafe pins the Personal-edition contract
// (update/20260817 P5 版型矩阵): a proxy with NO signal reporter (Personal has
// no master to report to) must treat every scheduling-log hook as a no-op —
// no panic, no state.
func TestSchedEventHooksAreNilReporterSafe(t *testing.T) {
	p := &Proxy{} // signalReporter nil — the Personal shape
	p.reportSchedEvent(observability.EventProxyGroupAccountCooldown, schedSeverityWarn, schedOriginProvider, "",
		"g1", "cred1", "acct1", "seat1", "tr", map[string]any{"status": 429})
	p.noteSchedRouteSettled("g1", "seat1", "acct1", "cred1", "tr")
	if _, loaded := p.schedRouted.Load("g1|seat1"); loaded {
		t.Fatal("nil-reporter settle must not record state (Personal stays untouched)")
	}
}
