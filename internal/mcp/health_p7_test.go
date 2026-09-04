package mcp

// health_p7_test.go — P7 tasks 7.7 / 7.7b and fence 7.F4.
//
// 🔴 What this endpoint is FOR, restated because it is the thing that keeps
// getting confused: the release checklist's E2E section asserts against it, and
// the console dashboard cannot substitute. The dashboard reads a historical
// aggregate, so a reporting pipeline that broke five minutes ago still LOOKS
// fine there. This endpoint reports the CURRENT world.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func healthDoc(t *testing.T, mux *http.ServeMux) HealthDocument {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/mcp", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/health/mcp answered %d", rec.Code)
	}
	var doc HealthDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode health: %v (%s)", err, rec.Body.String())
	}
	return doc
}

// planeWithPolicy builds a plane whose policy holds one tool in the given state.
func planeWithPolicy(t *testing.T, toolState string, calls CallSink) (*http.ServeMux, *PolicyStore) {
	t.Helper()
	tool := publishedTool()
	tool.State = toolState
	store := NewPolicyStore()
	store.Store(&Policy{
		OrgID: testOrg, Version: 1,
		Backends: []PolicyBackend{{ID: "b1", Name: "gh", Transport: TransportStreamableHTTP,
			EndpointURL: "http://127.0.0.1:1", Status: "active"}},
		Toolsets: []PolicyToolset{{ID: "ts1", Slug: testToolset, Status: "active",
			Tools: []PolicyTool{tool}}},
		Grants: []PolicyGrant{{SubjectKind: SubjectSeat, SubjectID: testSeat, VirtualServerID: "ts1"}},
	})
	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{testToken: {OrgID: testOrg, SeatID: testSeat}},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
		Logger:          discardLogger(),
		PolicyStore:     store,
		Calls:           calls,
		CallStats:       NewCallStats(),
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, store
}

// TestFence_7F4_HealthReportsAStalePolicyRail.
//
// 🔴 "The control plane has been unreachable for 40 minutes" is the single most
// useful sentence this endpoint ever says, and it is invisible everywhere else:
// the gateway keeps serving its last-known policy perfectly, so an administrator
// who just revoked a grant sees the console confirm it while the fleet keeps
// honouring the old one.
func TestFence_7F4_HealthReportsAStalePolicyRail(t *testing.T) {
	mux, store := planeWithPolicy(t, ToolStatePublished, nil)

	// Fresh: healthy.
	if doc := healthDoc(t, mux); doc.PolicyAgeSeconds == nil || *doc.PolicyAgeSeconds > 5 {
		t.Fatalf("precondition: a just-synced rail reported age %v", doc.PolicyAgeSeconds)
	}

	// Wind the clock back past the staleness window.
	store.now = func() time.Time { return time.Now().Add(time.Duration(policyStaleAfterSeconds+600) * time.Second) }
	doc := healthDoc(t, mux)
	if doc.Status != PlaneDegraded {
		t.Errorf("status = %q with a rail %d seconds stale, want degraded",
			doc.Status, *doc.PolicyAgeSeconds)
	}
	if !strings.Contains(doc.Reason, "minutes") {
		t.Errorf("the reason does not say how long: %q. 'Stale' without a number sends an "+
			"operator to guess whether it is a blip or an outage.", doc.Reason)
	}
	// 🔴 The AGE must be readable as a number too, not only inferable from prose:
	// a release gate asserts on a field, not on a sentence.
	if doc.PolicyAgeSeconds == nil || *doc.PolicyAgeSeconds <= policyStaleAfterSeconds {
		t.Errorf("policy_age_seconds = %v; a gate cannot assert on the prose", doc.PolicyAgeSeconds)
	}
}

// TestHealthDistinguishesNeverPolledFromStale — two facts that send an operator
// to two different places.
func TestHealthDistinguishesNeverPolledFromStale(t *testing.T) {
	mux, store := planeWithPolicy(t, ToolStatePublished, nil)
	store.MarkNeverPolled()
	doc := healthDoc(t, mux)
	if doc.Status != PlaneDegraded {
		t.Fatalf("a node that has never reached the control plane reported %q", doc.Status)
	}
	if !strings.Contains(doc.Reason, "never") {
		t.Errorf("the reason does not distinguish 'never reached' from 'stale': %q. The first "+
			"means check the URL and the credentials; the second means check the network.", doc.Reason)
	}
}

// TestHealthReportsTheReviewBacklogAndEscalatesIt is task 7.7b.
//
// 🔴 A signal that sits at the same level forever is a signal nobody acts on.
func TestHealthReportsTheReviewBacklogAndEscalatesIt(t *testing.T) {
	mux, store := planeWithPolicy(t, ToolStateNeedsReview, nil)
	doc := healthDoc(t, mux)
	if doc.ToolsNeedingReview == nil {
		t.Fatal("tools_needing_review is absent on a node that HAS a policy. Absent means 'not " +
			"tracked', which a release gate asserting on zero would read as success.")
	}
	if *doc.ToolsNeedingReview != 1 {
		t.Errorf("tools_needing_review = %d, want 1", *doc.ToolsNeedingReview)
	}
	if doc.ReviewBacklogState != ReviewBacklogPending {
		t.Errorf("review_backlog_state = %q, want %q", doc.ReviewBacklogState, ReviewBacklogPending)
	}

	// Age the backlog past the escalation window, and 🔴 deliver ANOTHER policy
	// while it is still non-empty — which is what actually happens: the rail
	// polls every 60 seconds, so a backlog that lasts a day is re-delivered
	// ~1400 times. If each delivery restarted the clock, the escalation could
	// never fire, and the fence would be measuring a code path no deployment
	// ever takes.
	store.now = func() time.Time {
		return time.Now().Add(time.Duration(reviewBacklogEscalatesAfterSeconds+60) * time.Second)
	}
	stillPending := publishedTool()
	stillPending.State = ToolStateNeedsReview
	store.Store(&Policy{
		OrgID: testOrg, Version: 2,
		Toolsets: []PolicyToolset{{ID: "ts1", Slug: testToolset, Status: "active",
			Tools: []PolicyTool{stillPending}}},
		Grants: []PolicyGrant{{SubjectKind: SubjectSeat, SubjectID: testSeat, VirtualServerID: "ts1"}},
	})
	if got := healthDoc(t, mux).ReviewBacklogState; got != ReviewBacklogOverdue {
		t.Errorf("review_backlog_state = %q after the escalation window, want %q. A backlog that "+
			"never escalates is one nobody acts on — and re-delivering the same backlog on the "+
			"60s poll must NOT reset its age.", got, ReviewBacklogOverdue)
	}

	// A cleared backlog goes back to clear — and stops the clock, so the NEXT
	// backlog is timed from its own start rather than inheriting this one's age.
	mux2, _ := planeWithPolicy(t, ToolStatePublished, nil)
	doc2 := healthDoc(t, mux2)
	if doc2.ReviewBacklogState != ReviewBacklogClear {
		t.Errorf("an empty backlog reported %q, want %q", doc2.ReviewBacklogState, ReviewBacklogClear)
	}
	if doc2.ToolsNeedingReview == nil || *doc2.ToolsNeedingReview != 0 {
		t.Errorf("tools_needing_review = %v on a clean policy, want 0 (present, not absent)",
			doc2.ToolsNeedingReview)
	}
}

// TestHealthSaysWhetherCallsAreBeingRecordedAtAll.
//
// 🔴 Without this field, "the call log is empty" and "nothing was called" are
// the same observation, and an operator goes looking for traffic that was never
// recorded rather than for the wiring that never recorded it.
func TestHealthSaysWhetherCallsAreBeingRecordedAtAll(t *testing.T) {
	muxOff, _ := planeWithPolicy(t, ToolStatePublished, nil)
	if got := healthDoc(t, muxOff).CallRecording; got != "off" {
		t.Errorf("call_recording = %q on a node with no sink, want \"off\"", got)
	}
	muxOn, _ := planeWithPolicy(t, ToolStatePublished, &captureSink{})
	if got := healthDoc(t, muxOn).CallRecording; got != "on" {
		t.Errorf("call_recording = %q on a node with a sink, want \"on\"", got)
	}
}

// TestHealthOmitsTheReviewCountBeforeTheFirstPoll.
//
// 🔴 Absent and zero are opposite claims. "Zero tools await review" is a
// finding; "we have not learned what awaits review" is not. A release gate that
// asserts on the first while receiving the second is asserting on nothing —
// which is exactly how a node that never reached the control plane would pass a
// gate about that control plane's data.
func TestHealthOmitsTheReviewCountBeforeTheFirstPoll(t *testing.T) {
	store := NewPolicyStore() // never Store()d: no poll has succeeded
	h := NewHandler(Config{
		Catalog:         NewPolicyCatalog(store, nil),
		Resolver:        stubResolver{},
		Isolation:       NewIsolation(DefaultPlaneConcurrency, nil, discardLogger()),
		ExternalBaseURL: "http://127.0.0.1:8787",
		Logger:          discardLogger(),
		PolicyStore:     store,
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/mcp", nil))
	if strings.Contains(rec.Body.String(), `"tools_needing_review"`) {
		t.Errorf("a node that has never polled reported tools_needing_review anyway: %s\n"+
			"That renders 'we do not know' as 'there are none'.", rec.Body.String())
	}
	if doc := healthDoc(t, mux); doc.ReviewBacklogState != "" {
		t.Errorf("review_backlog_state = %q before any poll; an unknown backlog has no state",
			doc.ReviewBacklogState)
	}
}

// TestHealthOmitsTheBacklogRatherThanReportingZero — an absent number and a
// zero are opposite claims, and only one of them means "everything is
// delivered".
func TestHealthOmitsTheBacklogRatherThanReportingZero(t *testing.T) {
	mux, _ := planeWithPolicy(t, ToolStatePublished, &captureSink{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/mcp", nil))
	if strings.Contains(rec.Body.String(), `"call_backlog"`) {
		t.Errorf("a sink that cannot report a backlog produced a call_backlog field anyway: %s. "+
			"Zero would read as 'everything is delivered' on a node that has no idea.", rec.Body.String())
	}
}
