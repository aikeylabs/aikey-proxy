package events

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// The lane key and the org stamped on the event must be the SAME value. If they
// drift, an event is allocated a seq on one lane and accounted against another
// — the original defect, just moved. This fences the two fallbacks against each
// other rather than restating either.
func TestLaneMatchesEventOrg(t *testing.T) {
	// The drift that matters is between the TWO fallbacks: LaneOfOrg("") and
	// whatever BuildReportableEvent stamps when the route carries no org. An
	// earlier version of this test fed "" through BuildReportableEvent first,
	// which applies the sentinel itself — so LaneOfOrg's fallback was never
	// reached and breaking it kept the test green. Compare them head-on.
	ev := BuildReportableEvent(&ReportOpts{EventID: "e1", Route: &vkeys.ResolvedRoute{OrgID: ""}})
	if got, want := LaneOfOrg(""), ev.OrgID; got != want {
		t.Fatalf("no-org fallback disagrees: LaneOfOrg(\"\")=%q but the event is stamped org=%q — "+
			"the event would be allocated on one lane and accounted on another", got, want)
	}

	// And for a real org the lane must be the org verbatim, with no mapping.
	for _, org := range []string{"personal", "624a2488-a8c1-4951-9730-3181f1d2c337"} {
		e := BuildReportableEvent(&ReportOpts{EventID: "e2", Route: &vkeys.ResolvedRoute{OrgID: org}})
		if got := LaneOfEvent(&e); got != e.OrgID {
			t.Fatalf("org %q: lane=%q, event org=%q", org, got, e.OrgID)
		}
	}
}

// Canary events are synthetic liveness probes. They are already excluded from
// sequence allocation at the stamping site, but that exclusion was only HALF
// done: the reporter derived a lane from every event regardless, so on winpc2
// the probe grew its own seq state file, reported an allocated_seq for a stream
// that never allocates, and fired a stream-switch declaration for a lane with
// nothing to declare — six failing WARNs in 0.7 seconds.
//
// A probe that reports on itself is worse than no probe.
// 能红: make LaneOfOrg return the org for the canary sentinel.
func TestCanaryHasNoLane(t *testing.T) {
	if got := LaneOfOrg(CanaryOrgSentinel); got != "" {
		t.Fatalf("canary got lane %q, want none — it would then own a seq state file, "+
			"an allocated_seq and a stream-switch obligation, none of which it can honor", got)
	}
	ev := BuildReportableEvent(&ReportOpts{EventID: "c1", Route: &vkeys.ResolvedRoute{OrgID: CanaryOrgSentinel}})
	if got := LaneOfEvent(&ev); got != "" {
		t.Fatalf("canary event got lane %q, want none", got)
	}
	// And a real org is unaffected by the carve-out.
	if got := LaneOfOrg("org-real"); got != "org-real" {
		t.Fatalf("real org lane = %q", got)
	}
}
