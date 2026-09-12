package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
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
}

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
	Rule    string
	Counted int
	UnitIDs []string
	Now     time.Time
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
		EventID      string         `json:"event_id"`
		CreatedAt    time.Time      `json:"created_at"`
		TenantID     string         `json:"tenant_id"`
		Scenario     string         `json:"scenario"`
		PromptLength int            `json:"prompt_length"`
		ActionTaken  string         `json:"action_taken"`
		VirtualKeyID string         `json:"virtual_key_id,omitempty"`
		SeatID       string         `json:"seat_id,omitempty"`
		SessionID    string         `json:"session_id,omitempty"`
		TraceID      string         `json:"trace_id"`
		Escalation   escalationWire `json:"escalation"`
		Findings     []struct{}     `json:"findings"`
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
		Escalation: escalationWire{
			Rule:    v.Rule,
			Counted: v.Counted,
			UnitIDs: v.UnitIDs,
		},
		Findings: []struct{}{},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("build request verdict event: %w", err)
	}
	return raw, nil
}
