package events

// LaneOfOrg maps an event's org to its delivery lane — the SINGLE place that
// mapping exists.
//
// The lane is what the client allocates sequence numbers on, and it must equal
// what the SERVER keys its integrity watermark on, which is org_id. Any other
// key (route_source was the obvious candidate) re-splits the stream the moment
// personal events are routed to a team collector or a machine belongs to two
// orgs — with the same silent failure mode that wrote 768 real events off as
// lost on 2026-08-20.
//
// 🔴 The empty→"personal" fallback MUST stay identical to BuildReportableEvent's
// (reportable.go: `if orgID == "" { orgID = "personal" }`). If the two ever
// disagree, an event is allocated on one lane and accounted on another — which
// is exactly the bug, just relocated. LaneMatchesEventOrg fences that.
//
// Operators are told about "local" and "team" lanes because that is the useful
// mental model; internally the key is the org so the invariant holds by
// construction rather than by coincidence.
func LaneOfOrg(orgID string) string {
	// 🔴 Canary events have NO lane (2026-08-21, found live on winpc2).
	// They are synthetic liveness probes and are already excluded from
	// sequence allocation at the stamping site — but the exclusion was only
	// half done: the reporter derived a lane from every event regardless, so
	// the probe grew its own seq state file, reported an allocated_seq for a
	// stream that never allocates, and triggered a stream-switch declaration
	// for a lane that has nothing to declare.
	//
	// An empty lane is the honest answer, and every caller already treats
	// `batchLane == ""` as "no lane bookkeeping for this batch".
	if orgID == CanaryOrgSentinel {
		return ""
	}
	if orgID == "" {
		return PersonalOrgSentinel
	}
	return orgID
}

// PersonalOrgSentinel is the org_id stamped on events that have no org at all
// (personal keys and personal OAuth carry no managed virtual key, so there is
// nothing to take an org from). It is a SENTINEL, not a tenant: it means "no
// org", and treating it as a tenant is what makes a mixed machine look like two
// tenants sharing one sequence stream.
const PersonalOrgSentinel = "personal"

// CanaryOrgSentinel marks the synthetic liveness probe. It is NOT a tenant and
// NOT a lane: canary traffic must leave no trace in the delivery-integrity
// ledger, or the probe starts reporting on itself.
const CanaryOrgSentinel = "__canary__"

// LaneOfEvent is LaneOfOrg for a built event.
func LaneOfEvent(ev *ReportableEvent) string {
	if ev == nil {
		return PersonalOrgSentinel
	}
	return LaneOfOrg(ev.OrgID)
}
