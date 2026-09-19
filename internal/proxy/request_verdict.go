package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// scenarioRequestVerdict marks a compliance event as a REQUEST-level verdict
// rather than a content hit.
//
// It must stay byte-identical to storage.ScenarioRequestVerdict in
// aikey-control-master — the audit page keys the two kinds of rows apart on this
// value, and getting it wrong does not fail loudly: the verdict simply shows up
// as an ordinary hit and inflates the violation count.
//
// spec: R-compliance-grading-18 (请求级处置另开事件记账，内容行保持各自处置)
const scenarioRequestVerdict = "request_verdict"

// escalationWire is the typed `escalation` payload on the compliance intake
// wire. The field set is FIXED by DEC-compliance-grading-14 (user decision
// 2026-09-10): the rejected alternative was an open, client-writable `metadata`
// object, which would have put an arbitrary-content hole on a straight-to-column
// JSON blob and made this capability's rule 「不得有内容派生值进 wire 或落库」
// structurally unenforceable. A fixed set behind master's DisallowUnknownFields
// is the actual gate — one extra key is a 400.
//
// 🔴 UnitIDs carry compliance event ids and NOTHING ELSE: no hash, no
// fingerprint, no digest, no snippet. They are primary keys of audit rows that
// already exist, which is exactly why carrying them is not a content-derived
// value crossing the wire (DC5).
//
// Mirror of aikey-control-master's intakeEscalationWire /
// storage.Escalation. Adding a sub-field is a WIRE CHANGE: declare it on master
// and ship master FIRST (release order §1 → §4 → §2 → §3), or every batch this
// proxy sends — the ordinary content events riding along included — comes back
// 400 from any master that has not been upgraded yet.
type escalationWire struct {
	Rule    string   `json:"rule"`
	Counted int      `json:"counted"`
	UnitIDs []string `json:"unit_ids"`
	// CountedIsLowerBound — DEC-compliance-grading-27 (TODO-171, user decision
	// 2026-09-18; declared on master first). true ⇔ a piece was cut at
	// pipeInputCap, so Counted is only a lower bound. Same word as the
	// proxy.filter.escalated log field. omitempty: only `true` ever travels —
	// absent must never be read as 「计数完整」.
	// spec: R-compliance-grading-17.S2
	CountedIsLowerBound bool `json:"counted_is_lower_bound,omitempty"`
}

// routePolicyWire is the typed `route_policy` verdict payload — BESIDE
// escalation on the same verdict row (DEC-compliance-grading-27). Mirror of
// master intakeRoutePolicyWire / storage.RoutePolicy; same wire-change rules as
// escalationWire above (declared on master first, which is why this proxy may
// send it).
//
// 🔴 NOT the grading document's route_policy[] (RoutePolicyRule list): this is
// the ONE rule the request violated plus the request's target.
//
// DC5: MinLevel is the administrator's number, TargetProvider the route's own
// provider code, UnitIDs primary keys of existing audit rows. Nothing derived
// from the prompt.
// spec: R-compliance-grading-8.S1
type routePolicyWire struct {
	MinLevel       int      `json:"min_level"`
	TargetProvider string   `json:"target_provider,omitempty"`
	UnitIDs        []string `json:"unit_ids"`
}

// maxRoutePolicyVerdictUnitIDs mirrors master's bound (intake_level.go
// maxRoutePolicyUnitIDs): master STRIPS a route_policy with more ids than
// this, so the sender truncates first rather than lose the whole verdict.
const maxRoutePolicyVerdictUnitIDs = 256

// requestVerdict is everything the escalation conclusion needs in order to be
// recorded. All of it is already resolved on the filter's request path; nothing
// here is read back out of the detector.
//
// Now is passed in rather than read from the clock so the builder stays a pure
// function (the same reason the inject* family takes its values as arguments).
type requestVerdict struct {
	// TraceID is THIS TURN's W3C trace id — the identity the event id derives
	// from. Empty means no verdict event is emitted at all; see
	// requestVerdictEventID.
	TraceID string
	// TenantID is the VK's resolved org, stamped by the proxy exactly as it is on
	// content events (never client-reported).
	TenantID     string
	VirtualKeyID string
	SeatID       string
	SessionID    string
	// Action is the ESCALATED action — what actually happened to the request
	// (e.g. "block"). It is the verdict row's own action_taken and has nothing to
	// do with any content row's, which keep whatever the ladder gave them.
	Action string
	// Rule / Counted / UnitIDs are the escalation evidence; see escalationWire.
	// Rule == "" means the cumulative rule did NOT fire on this request, and the
	// payload then carries no `escalation` key at all (a verdict that only
	// violated a route policy must not read as 「触发了空规则、数了 0 条」).
	Rule    string
	Counted int
	UnitIDs []string
	// CountedIsLowerBound: see escalationWire. Only meaningful with Rule != "".
	CountedIsLowerBound bool
	// RoutePolicy is the route-policy conclusion; nil ⇔ no route_policy rule
	// was violated. DEC-compliance-grading-27 (TODO-171).
	RoutePolicy *routePolicyVerdict
	Now         time.Time
}

// routePolicyVerdict is the route-policy conclusion for one request: the
// violated rule's floor, the request's target provider code ("" ⇔ unknown),
// and the ids of the content rows whose confirmed hit reached the floor.
type routePolicyVerdict struct {
	MinLevel       int
	TargetProvider string
	UnitIDs        []string
}

// requestVerdictEventID derives the verdict row's event id from the turn's trace
// id.
//
// WHY derived rather than random: the compliance upload lane conserves a failed
// batch in dead_letter.jsonl and replays it on recovery, so the same verdict can
// legitimately arrive at master twice. A CSPRNG id would land as two audit rows
// claiming the same request was blocked once each. A trace-derived id lets
// master's ON CONFLICT (event_id) DO NOTHING absorb the replay with no new dedup
// machinery — the same argument auditUnitID makes for content rows, with the
// REQUEST's identity (its trace) standing in for the content's.
//
// WHY NOT content-derived like auditUnitID: a request-level conclusion is not
// about any single piece of content, and one turn must produce at most one
// verdict row however many pieces it flagged.
//
// 🔴 Empty trace → empty id, and the caller emits NOTHING. Hashing "" would give
// every trace-less request on every machine in the fleet the same id: one shared
// row silently absorbing all of them, an audit gap wearing idempotence as a
// disguise. (A turn with no trace has no conversation record to link to anyway —
// see injectTraceID.)
//
// 🔴 CROSS-REPO TWIN — aikey-control-master's storage.RequestVerdictEventID must
// produce the same bytes; it is how master looks this row up. The two are
// deliberately NOT shared through a common module (a new shared module is a
// one-way door for a 3-line function; same call as compliance.GradingByteSize).
// Both sides are pinned by the same golden vector instead, so drift on either
// side goes red: see TestRequestVerdictEventID_GoldenVector in BOTH repos.
func requestVerdictEventID(traceID string) string {
	if traceID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("aikey-request-verdict\x00" + traceID))
	return "rv_" + hex.EncodeToString(sum[:16])
}

// buildRequestVerdictEvent mints the request-level verdict event for one turn,
// in the same JSON shape the detector's content events travel in, ready to be
// appended to the batch the filter uploads on exit.
//
// 🔴 THIS IS THE ONE COMPLIANCE EVENT THE PROXY AUTHORS FROM SCRATCH. Every
// other one is the detector's bytes with attribution stamped on (the inject*
// family). That means the detector-side redaction this codebase relies on does
// not apply here — whatever this function puts in the payload is what leaves the
// machine. Hence the deliberately small, whitelisted field set, and the fence
// that asserts it (TestBuildRequestVerdictEvent_CarriesNoContent).
//
// 🔴 IT DOES NOT — AND MUST NOT — TOUCH THE CONTENT EVENTS. The escalation
// conclusion is recorded as a SEPARATE row precisely so the content rows stay as
// they are (R-compliance-grading-18):
//
//   - technically: a content row's event_id is content-derived and master
//     ingests with ON CONFLICT (event_id) DO NOTHING. Rewriting one would require
//     DO UPDATE, and from that moment any re-scan could overwrite an audit
//     record.
//   - semantically: piece 1 was not blocked. The REQUEST was. Writing "block"
//     onto piece 1's row is a false statement in an audit log.
//
// Returns (nil, nil) when there is no trace to derive an id from — a normal
// state, not a failure; see requestVerdictEventID.
func buildRequestVerdictEvent(v requestVerdict) ([]byte, error) {
	eventID := requestVerdictEventID(v.TraceID)
	if eventID == "" {
		return nil, nil
	}
	// Declared inline rather than as a package type: this is the only place a
	// verdict event is shaped, and keeping the shape at the single write site is
	// what makes the whitelist fence above meaningful — a second constructor
	// elsewhere would be a second answer to "what does this event carry".
	//
	// Every key here is declared on master's intakeEventWire. `findings` is sent
	// as an empty array rather than omitted so the row reads as "a verdict, with
	// no findings of its own" instead of "findings unknown" — the hits live on
	// the content rows named in escalation.unit_ids.
	payload := struct {
		EventID      string           `json:"event_id"`
		CreatedAt    time.Time        `json:"created_at"`
		TenantID     string           `json:"tenant_id"`
		Scenario     string           `json:"scenario"`
		PromptLength int              `json:"prompt_length"`
		ActionTaken  string           `json:"action_taken"`
		VirtualKeyID string           `json:"virtual_key_id,omitempty"`
		SeatID       string           `json:"seat_id,omitempty"`
		SessionID    string           `json:"session_id,omitempty"`
		TraceID      string           `json:"trace_id"`
		Escalation   *escalationWire  `json:"escalation,omitempty"`
		RoutePolicy  *routePolicyWire `json:"route_policy,omitempty"`
		Findings     []struct{}       `json:"findings"`
	}{
		EventID:      eventID,
		CreatedAt:    v.Now.UTC(),
		TenantID:     v.TenantID,
		Scenario:     scenarioRequestVerdict,
		ActionTaken:  v.Action,
		VirtualKeyID: v.VirtualKeyID,
		SeatID:       v.SeatID,
		SessionID:    v.SessionID,
		TraceID:      v.TraceID,
		Findings:     []struct{}{},
	}
	// Each conclusion travels only when it was reached (DEC-compliance-grading-27):
	// one trace ⇒ one verdict row, carrying escalation, route_policy, or both.
	if v.Rule != "" {
		payload.Escalation = &escalationWire{
			Rule:                v.Rule,
			Counted:             v.Counted,
			UnitIDs:             v.UnitIDs,
			CountedIsLowerBound: v.CountedIsLowerBound,
		}
	}
	if v.RoutePolicy != nil {
		ids := v.RoutePolicy.UnitIDs
		if ids == nil {
			ids = []string{}
		}
		if len(ids) > maxRoutePolicyVerdictUnitIDs {
			ids = ids[:maxRoutePolicyVerdictUnitIDs]
		}
		payload.RoutePolicy = &routePolicyWire{
			MinLevel:       v.RoutePolicy.MinLevel,
			TargetProvider: v.RoutePolicy.TargetProvider,
			UnitIDs:        ids,
		}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("build request verdict event: %w", err)
	}
	return raw, nil
}

// strongerVerdictAction folds the route-policy conclusion into the verdict
// row's action_taken. Each conclusion is ALREADY post-ceiling (MAX_ACTION), so
// this only decides what one row says when both fired: `block` wins if either
// concluded block; otherwise the conclusion already on the row stands (the
// escalation's own action, exactly as the row said before TODO-171), and a
// row with none yet takes the new one.
//
// Deliberately NOT a general action-strength order — none exists in this
// package, and inventing one for a single call site would be a second answer
// to a question the ladder already owns.
func strongerVerdictAction(current, next apphook.Action) apphook.Action {
	switch {
	case current == apphook.ActionBlock || next == apphook.ActionBlock:
		return apphook.ActionBlock
	case current == apphook.ActionAllow:
		return next
	default:
		return current
	}
}

// buildVerdictRowOrWarn builds the request-verdict row and turns both
// no-row outcomes into a loud WARN (fail-loud, never fail the request: the
// refusal still happens, the audit row is what is missing).
func (p *Proxy) buildVerdictRowOrWarn(logger *slog.Logger, v requestVerdict) []byte {
	ev, err := buildRequestVerdictEvent(v)
	switch {
	case err != nil:
		logger.Warn("filter: request verdict event could not be built; the request-level verdict was "+
			"enforced but not recorded",
			"event.name", observability.EventProxyFilterEscalationEventDropped,
			"error", err.Error(), "rule", v.Rule, "route_policy", v.RoutePolicy != nil)
		return nil
	case len(ev) == 0:
		// No trace id → no derivable event id. buildRequestVerdictEvent documents
		// why minting one anyway would be worse than emitting nothing (every
		// trace-less request in the fleet would collapse onto one shared row).
		logger.Warn("filter: request-level verdict reached but no trace id to derive a verdict event id "+
			"from; it is enforced but has no audit row",
			"event.name", observability.EventProxyFilterEscalationEventDropped,
			"rule", v.Rule, "route_policy", v.RoutePolicy != nil)
		return nil
	}
	return ev
}
