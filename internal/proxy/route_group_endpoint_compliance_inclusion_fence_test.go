package proxy

import (
	"net/http/httptest"
	"testing"
)

// route_group_endpoint_compliance_inclusion_fence_test.go — invariant I5
// (openspec change `aliyun-aigw-route-group-endpoint`, task 4.9, requirement
// R-rge-9): route-group SERVICE ENDPOINT traffic traverses the same outbound
// compliance filter chain as every other data-plane request.
//
// # 🔴 The finding this fence encodes: there is no "endpoint pipeline"
//
// It is tempting to look for one, and its absence is the whole point. An
// endpoint request reaches a node as `aikey_team_<vk_id>` — the cluster ingress
// rewrites the Bearer to exactly that wire form — so the node dispatches it
// Tier1Team and the registry resolves it with RouteSource "team", the SAME
// classification an employee's managed key carries. The endpoint is a KEY, not a
// pipeline.
//
// That is good news for coverage and bad news for assurance: coverage is
// inherited, and inherited coverage is what R-rge-9 explicitly refuses to accept
// on trust —
//
//	"this inclusion MUST be asserted by a fence rather than assumed from
//	 co-location"
//
// …because "it runs in the same process" is exactly the reasoning that left the
// App pipeline recorded as exempt for ten weeks while it was being scanned, and
// would have left it unscanned had anyone "fixed the code to match the spec"
// (see app_pipeline_compliance_inclusion_fence_test.go for that history).
//
// # What is asserted
//
// The ENTRY-POINT property — the compliance chain was entered for this traffic —
// plus the verdict reaching the body. 🚫 Not "a compliance event was produced":
// that depends on whether today's shipped rule packs happen to match today's
// prompt, so a rule-set change would turn such an assertion green while the
// traffic silently stopped being scanned.
//
// 能红: add `if routeSource == "team" { return true }` beside the existing
// isProbePipelineRoute guard in filter_dispatch.go.

// endpointPrompt is the shape of content a CI job or a backend service sends
// through a route-group endpoint. Its literal text does not matter to the
// assertions (the spy masks unconditionally); it is written this way so a reader
// sees WHAT is crossing to an external LLM on this path — content that belongs
// to the company and was never typed by the employee whose seat owns the key.
const endpointPrompt = "Draft the renewal email for account 13812345678, contract ends next month."

func TestRouteGroupEndpointTraffic_AlwaysEntersComplianceFilter(t *testing.T) {
	const body = `{"model":"m","messages":[{"role":"user","content":"` + endpointPrompt + `"}]}`

	t.Run("team route source enters the chain", func(t *testing.T) {
		// 🔴 "team" is the endpoint's route source. The cluster ingress rewrites an
		// endpoint key's Bearer to `aikey_team_<vk_id>`, the node dispatches that
		// Tier1Team, and the registry classifies it "team". If that ever stops
		// being true, this fence is measuring the wrong traffic — see
		// vkeys.ResolvedRoute.RouteSource for the authoritative list.
		spy := &spyFilterHook{}
		p := &Proxy{filterHook: spy}
		r := newReq(body)
		p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "", "", "", "", "", discardLogger())
		if spy.calls() == 0 {
			t.Error("the compliance chain was NOT entered for RouteSource=team.\n" +
				"Route-group service endpoints arrive on exactly this route source, so an exemption " +
				"here silently removes DLP from every request a CI job, backend service or partner " +
				"integration sends through a published endpoint — traffic that leaves the company " +
				"without any employee in the loop to notice.\n" +
				"See R-rge-9 in openspec/changes/aliyun-aigw-route-group-endpoint/specs/" +
				"route-group-endpoint/spec.md")
		}
		if got := readReqBody(t, r); got == body {
			t.Error("the endpoint body was forwarded unchanged although the spy always masks — " +
				"the filter's verdict is consulted but not applied on this route source, so the " +
				"chain is entered and the raw content still reaches the upstream")
		}
	})

	// Discriminating control, exactly as the App fence has one: without it, "the
	// chain was entered for team" could pass because the guard is inert rather
	// than because it distinguishes correctly.
	t.Run("probe is still the only exemption", func(t *testing.T) {
		spy := &spyFilterHook{}
		p := &Proxy{filterHook: spy}
		r := newReq(body)
		p.applyInboundFilter(httptest.NewRecorder(), r, "m", "probe", "", "", "", "", "", discardLogger())
		if n := spy.calls(); n != 0 {
			t.Fatalf("Detect called %d time(s) for RouteSource=probe; the probe exemption regressed, "+
				"so the assertion above no longer discriminates", n)
		}
	})

	// 🔴 The inclusion set stated POSITIVELY, over every classification the
	// registry can produce. A fence that only named "team" would go green if a
	// future route source were added and quietly exempted — and the endpoint
	// feature is exactly the kind of change that adds one.
	t.Run("every non-probe route source is scanned", func(t *testing.T) {
		for _, src := range []string{"team", "app", "oauth", "personal", "personal_byok", ""} {
			spy := &spyFilterHook{}
			p := &Proxy{filterHook: spy}
			r := newReq(body)
			p.applyInboundFilter(httptest.NewRecorder(), r, "m", src, "", "", "", "", "", discardLogger())
			if spy.calls() == 0 {
				t.Errorf("RouteSource=%q is exempt from the compliance chain; the only exemption "+
					"that was ever adjudicated is probe (masking destroys the fixed-prompt "+
					"fingerprint). Any other exemption must be argued in the spec first.", src)
			}
		}
	})
}
