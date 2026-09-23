package proxy

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// sched_event_report_device_routing_test.go — the settle-key fence for
// DEVICE-ROUTING TOKEN traffic (task 4.11).
//
// # What was wrong
//
// A device-routing token is ONE token — therefore ONE seat — shared by many
// devices, and the control plane pins each device to its OWN pool account
// (4.5's strict branch serves exactly that account or refuses). The scheduling
// log's settle key was `group|seat`, which assumes one seat ↔ one account.
// Under that assumption two devices alternating on one token are
// indistinguishable from one seat flapping between accounts: 100 alternating
// requests emitted 99 `proxy.group.account_switched` rows, every one of them
// false.
//
// That is not cosmetic. `account_switched` is a WARN the operator reads to hunt
// REAL pool instability; 99 fabricated rows per 100 requests bury the real one.
//
// # What the fix is, and what it deliberately is NOT
//
// The account joins the key for this route kind only — the seat path keeps
// `group|seat` verbatim, where a changed account still IS a switch (拍板
// 2026-08-17 #3). Both halves are fenced here on purpose: a fix that silenced
// switch rows globally would pass a device-only fence.
//
// spec: R-device-routing-token-dispatch-19.S5 worker 不因设备交替误报切号
// roadmap20260320/技术实现/阶段9-商业化版本/codex-pool-anti-linkage/openspec/specs/device-routing-token-dispatch/spec.md

const (
	drtFenceGroupID = "grp-pool-1"
	// ONE token = ONE seat. Both devices below share it; that sharing is the
	// whole reason the seat key was not enough.
	drtFenceSeatID  = "seat-drt-1"
	drtFenceAcctX   = "acct-X"
	drtFenceAcctY   = "acct-Y"
	drtFenceCredX   = "cred-X"
	drtFenceCredY   = "cred-Y"
	drtFenceRequest = 100
)

// alternateTwoDevices drives `rounds` settles that alternate between two
// devices pinned to acct-X and acct-Y, and returns every scheduling event they
// produced plus the Proxy that produced them (so the key shape itself can be
// asserted).
//
// pickX / pickY are the provenance labels the RESOLVER hands in — this function
// only ever READS them (Ruling-24: pick_source is written once, at its source in
// resolveGroupCredential). That the source really writes device_ledger for this
// route kind is proved by TestSchedRouteSettled_DeviceRoutingPickSourceIsSingleSourced,
// which drives the real chain; here the labels are inputs, so passing anything
// else would be fencing an input the serving path cannot produce.
//
// The emission window is cleared before every call ON PURPOSE. The reporter's
// 30s burst suppressor would collapse repeated switch rows by itself, so a
// fence that let it run could not tell "the key stopped producing switches"
// from "the suppressor hid them". Clearing it makes every count below a
// statement about the KEY.
func alternateTwoDevices(t *testing.T, routeKind string, rounds int, pickX, pickY string) ([]schedulingEventSample, *Proxy) {
	t.Helper()
	r := looplessSignalReporter()
	p := &Proxy{signalReporter: r, poolCooldown: newPoolCooldownStore()}
	var out []schedulingEventSample
	for i := 0; i < rounds; i++ {
		account, credential, pickSource := drtFenceAcctX, drtFenceCredX, pickX
		if i%2 == 1 {
			account, credential, pickSource = drtFenceAcctY, drtFenceCredY, pickY
		}
		r.clearSchedulingEventSuppression()
		p.noteSchedRouteSettled(drtFenceGroupID, drtFenceSeatID, account, credential, "tr", pickSource, routeKind)
		for {
			select {
			case ev := <-r.evIn:
				out = append(out, ev)
				continue
			default:
			}
			break
		}
	}
	return out, p
}

func countByEventName(events []schedulingEventSample, name string) int {
	n := 0
	for _, ev := range events {
		if ev.EventName == name {
			n++
		}
	}
	return n
}

// TestSchedRouteSettled_DeviceRoutingKeyedByAccount is 4.A23.
//
// GIVEN two devices on ONE device-routing token, pinned to accounts X and Y
// WHEN they alternate 100 requests
// THEN zero account_switched rows, exactly one first_settle per account, and
// every row's pick_source says the DEVICE LEDGER decided
// BUT NOT on the seat path, where the same alternation still reports switches.
func TestSchedRouteSettled_DeviceRoutingKeyedByAccount(t *testing.T) {
	t.Run("device_routing_token: alternation is two settle lanes, not 99 switches", func(t *testing.T) {
		events, p := alternateTwoDevices(t, routeKindDeviceRoutingToken, drtFenceRequest,
			pickSourceDeviceLedger, pickSourceDeviceLedger)

		if got := countByEventName(events, observability.EventProxyGroupAccountSwitched); got != 0 {
			t.Errorf("account_switched = %d, want 0 — two devices alternating is not a switch", got)
		}
		if len(events) != 2 {
			t.Errorf("total rows = %d, want 2 (one first_settle per account); rows: %s", len(events), summarizeRows(events))
		}

		firstSettleByAccount := map[string]int{}
		for _, ev := range events {
			if ev.EventName != observability.EventProxyGroupRouteResolved {
				continue
			}
			if ev.Detail["reason"] == schedResolveFirstSettle {
				firstSettleByAccount[ev.AccountID]++
			}
		}
		for _, account := range []string{drtFenceAcctX, drtFenceAcctY} {
			if firstSettleByAccount[account] != 1 {
				t.Errorf("first_settle for %s = %d, want exactly 1", account, firstSettleByAccount[account])
			}
		}

		// Provenance rides through unchanged: this layer reads it, and the value
		// it reads is the one the source wrote.
		assertEveryRowPickSource(t, events, pickSourceDeviceLedger)

		// The key shape itself: one lane per (group, seat, account), and nothing
		// parked on the seat-shaped key. Asserted directly because the row counts
		// above would also be satisfied by a reporter that simply stopped
		// emitting for this route kind.
		for _, account := range []string{drtFenceAcctX, drtFenceAcctY} {
			if _, ok := p.schedRouted.Load(drtFenceGroupID + "|" + drtFenceSeatID + "|" + account); !ok {
				t.Errorf("no settle lane for account %s — key is not group|seat|account", account)
			}
		}
		if _, ok := p.schedRouted.Load(drtFenceGroupID + "|" + drtFenceSeatID); ok {
			t.Error("device-routing traffic still occupies the seat-shaped key group|seat")
		}
	})

	t.Run("seat path: the same alternation still reports every switch", func(t *testing.T) {
		// routeKind "" is an ordinary seat pool route (and also what a route
		// written by a pre-4.10 cluster daemon carries).
		events, p := alternateTwoDevices(t, "", drtFenceRequest,
			pickSourceLocalHRW, pickSourceLocalHRW)

		if got, want := countByEventName(events, observability.EventProxyGroupAccountSwitched), drtFenceRequest-1; got != want {
			t.Errorf("seat path account_switched = %d, want %d — 拍板 2026-08-17 #3: 席位路径账号变化即报", got, want)
		}
		if got := countByEventName(events, observability.EventProxyGroupRouteResolved); got != 1 {
			t.Errorf("seat path route_resolved = %d, want 1 (the first settle only)", got)
		}
		// The provenance rewrite must NOT leak onto this path.
		assertEveryRowPickSource(t, events, pickSourceLocalHRW)
		if _, ok := p.schedRouted.Load(drtFenceGroupID + "|" + drtFenceSeatID); !ok {
			t.Error("seat path lost its group|seat key")
		}
		if _, ok := p.schedRouted.Load(drtFenceGroupID + "|" + drtFenceSeatID + "|" + drtFenceAcctX); ok {
			t.Error("seat path gained an account dimension it must not have")
		}
	})
}

// ── Ruling-24: pick_source has ONE source ───────────────────────────────────
//
// The value is written once, where the ledger-pinned account becomes the served
// account (resolveGroupCredential), and every consumer downstream only READS
// res.PickSource. The two fences below are what makes "one source" checkable
// rather than aspirational: the first pins that the two consumers agree inside
// ONE request, the second pins the audit line that reads the same field.

// TestSchedRouteSettled_DeviceRoutingPickSourceIsSingleSourced drives one real
// request through the handler chain and compares the value the slog line printed
// with the value the scheduling event carried.
//
// Why this needs the real chain: a unit test on noteSchedRouteSettled can only
// see what it was handed. The failure mode being fenced — the same field name
// carrying two different values for one request — is only visible where both
// consumers exist.
func TestSchedRouteSettled_DeviceRoutingPickSourceIsSingleSourced(t *testing.T) {
	drtResetStatus(t)
	pool := newDRTPool(t, routeKindDeviceRoutingToken)
	reporter := looplessSignalReporter()
	pool.p.signalReporter = reporter
	logs := drtLogs(t)

	pinned, _ := drtAccounts(t)
	if w := pool.serve(t, pinned); w.Code != http.StatusOK {
		t.Fatalf("serve = %d (%s), want 200", w.Code, w.Body.String())
	}

	fromLog := logFieldOnce(t, logs.String(), "group route resolved", "pick_source")
	fromEvent := pickSourceOfNextEvent(t, reporter)

	if fromLog != fromEvent {
		t.Errorf("one request, two values for pick_source: slog=%q, scheduling event=%q — "+
			"whoever reads them cannot tell which one names the real decider", fromLog, fromEvent)
	}
	if fromEvent != pickSourceDeviceLedger {
		t.Errorf("pick_source = %q, want %q — the control plane's device ledger named this account",
			fromEvent, pickSourceDeviceLedger)
	}
}

// TestSchedRouteSettled_DeviceRoutingSuppressesOffRank0Audit pins the second
// false-alarm channel of the same family as the settle key.
//
// "Served off the local rank-0" is an ANOMALY on the seat path — it means the
// floor's first choice was unusable or the engine redirected. For a
// device-routing token it is the NORMAL state: the control plane's choice has
// nothing to do with where that account lands in this seat's hash order, so the
// audit line fires on essentially every request and says nothing.
func TestSchedRouteSettled_DeviceRoutingSuppressesOffRank0Audit(t *testing.T) {
	const offRank0AuditMsg = "oauth-group account switched off rank-0"

	t.Run("device_routing_token: 100 requests, zero off-rank-0 audit rows", func(t *testing.T) {
		drtResetStatus(t)
		pool := newDRTPool(t, routeKindDeviceRoutingToken)
		pool.p.signalReporter = looplessSignalReporter()
		logs := drtLogs(t)

		// The pinned account is deliberately the one local ranking would NOT
		// choose — i.e. every one of these requests is "off rank-0" by the old
		// condition, which is exactly why the old condition was wrong here.
		pinned, _ := drtAccounts(t)
		for i := 0; i < drtFenceRequest; i++ {
			if w := pool.serve(t, pinned); w.Code != http.StatusOK {
				t.Fatalf("request %d = %d (%s), want 200", i, w.Code, w.Body.String())
			}
		}
		if got := countLogMessage(logs.String(), offRank0AuditMsg); got != 0 {
			t.Errorf("%q logged %d times in %d requests, want 0 — for this token type the pick is "+
				"ALWAYS off rank-0, so the line is noise that buries the seat path's real ones",
				offRank0AuditMsg, got, drtFenceRequest)
		}
	})

	t.Run("seat path: a pick that really left rank-0 still audits", func(t *testing.T) {
		drtResetStatus(t)
		rank0 := rankOrder(drtSeatID, drtAccountA, drtAccountB)[0]
		// Make rank-0 unusable so the ranked walk genuinely advances past it —
		// the real anomaly this audit line exists to report.
		pool := newDRTPool(t, "", func(live map[string]*vkeys.GroupRuntimeAccount) {
			live[rank0].ExpiresAt = 1
		})
		pool.p.signalReporter = looplessSignalReporter()
		logs := drtLogs(t)

		if w := pool.serve(t, ""); w.Code != http.StatusOK {
			t.Fatalf("seat serve = %d (%s), want 200", w.Code, w.Body.String())
		}
		if got := countLogMessage(logs.String(), offRank0AuditMsg); got == 0 {
			t.Errorf("%q was not logged — the suppression must be scoped to the device-routing "+
				"pick_source, not silence the audit line altogether", offRank0AuditMsg)
		}
	})
}

// logFieldOnce returns one field of the single slog record whose msg matches.
// It fails when the record is missing or duplicated, so an assertion can never
// silently pass on "there was no such line".
func logFieldOnce(t *testing.T, buf, msg, field string) string {
	t.Helper()
	found := make([]string, 0, 1) // the contract is exactly one matching record
	for _, line := range strings.Split(strings.TrimSpace(buf), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue // not a JSON record from this handler
		}
		if rec["msg"] != msg {
			continue
		}
		value, _ := rec[field].(string)
		found = append(found, value)
	}
	if len(found) != 1 {
		t.Fatalf("slog records with msg %q = %d, want exactly 1 (field %q unreadable otherwise)",
			msg, len(found), field)
	}
	return found[0]
}

func countLogMessage(buf, msg string) int {
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(buf), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec["msg"] == msg {
			n++
		}
	}
	return n
}

// pickSourceOfNextEvent takes the one scheduling event the request produced.
func pickSourceOfNextEvent(t *testing.T, r *signalReporter) string {
	t.Helper()
	select {
	case ev := <-r.evIn:
		source, _ := ev.Detail["pick_source"].(string)
		return source
	default:
		t.Fatal("the request produced no scheduling event — nothing to compare the slog line with")
		return ""
	}
}

// assertEveryRowPickSource reports ONE aggregated failure instead of one per
// row: the broken state here is "all 100 rows carry the wrong label", and 100
// identical lines hide the two counts above them.
func assertEveryRowPickSource(t *testing.T, events []schedulingEventSample, want string) {
	t.Helper()
	wrong := map[string]int{}
	for _, ev := range events {
		if got, _ := ev.Detail["pick_source"].(string); got != want {
			wrong[got]++
		}
	}
	if len(wrong) == 0 {
		return
	}
	t.Errorf("pick_source: %d of %d rows are not %q (got %v)", sumCounts(wrong), len(events), want, wrong)
}

func sumCounts(counts map[string]int) int {
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
}

// summarizeRows renders the rows a failing count actually produced, so a red
// run names WHICH rows are unexpected instead of only how many. Capped: the
// first few rows already identify the pattern.
func summarizeRows(events []schedulingEventSample) string {
	const maxRows = 6
	out := ""
	for i, ev := range events {
		if i == maxRows {
			out += ", … (" + strconv.Itoa(len(events)-maxRows) + " more)"
			break
		}
		if out != "" {
			out += ", "
		}
		out += ev.EventName + "{account=" + ev.AccountID
		if reason, ok := ev.Detail["reason"].(string); ok {
			out += " reason=" + reason
		}
		if src, ok := ev.Detail["pick_source"].(string); ok {
			out += " pick_source=" + src
		}
		out += "}"
	}
	if out == "" {
		return "(none)"
	}
	return out
}
