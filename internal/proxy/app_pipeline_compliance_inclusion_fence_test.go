package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// app_pipeline_compliance_inclusion_fence_test.go — machine enforcement for the
// rule "the App pipeline (/apps/<slug>/v1/...) IS scanned by the compliance
// filter, i.e. it is NOT exempt".
//
// This is the deliberate MIRROR IMAGE of
// probe_pipeline_compliance_exclusion_fence_test.go. Same funnel, opposite
// verdict, so read them together:
//
//	probe pipeline → EXEMPT   → fence asserts Detect is called ZERO times
//	app   pipeline → SCANNED  → fence asserts Detect IS called (this file)
//
// WHY THIS FILE EXISTS (root cause, 2026-08-11).
// `workflow/CI/requirements/2026-06-04-compliance-filter-direction-and-scope.md`
// recorded — for ten weeks, as settled fact — that BOTH the App and the probe
// pipeline were exempt from compliance, on the reasoning that applyInboundFilter
// is only ever called from serveRoute. That reasoning was wrong for both: serveRoute
// is the SHARED DOWNSTREAM FUNNEL that handleAppPipeline and handleProbePipeline
// each delegate to on their last line. "The filter is only called in serveRoute"
// never meant "only serveRoute-shaped traffic is filtered".
//
// When that was discovered, the two pipelines were adjudicated in OPPOSITE
// directions, and neither answer is a typo to be tidied up later:
//
//   - Probe: MUST be exempt. Masking rewrites the fixed degrade-detection prompt
//     (its whole discriminative power is that not one byte changes) and turns
//     aikey's own synthetic corpus into a compliance event attributed to the
//     employee. Correctness constraint, not preference.
//   - App (this file): MUST STAY SCANNED. 🔴 USER DECISION, 2026-08-11 — the code
//     behaviour was right and the SPEC was wrong, so the SPEC was corrected to
//     match the code and the code was left alone. An /apps/ request carries real
//     user content on its way to an external LLM, which is precisely what DLP
//     exists to inspect; exempting it would widen the DLP gap by exactly the
//     amount of traffic third-party and first-party apps carry. There is no
//     probe-style correctness argument on this side to trade against it.
//
// WHY A FENCE AT ALL — the App rule survives today only as code behaviour with
// nothing pinning it. The spec's own closing rule ("any claim that some traffic
// is NOT filtered must name a fence test") is written for exemptions, but the
// failure mode is symmetric: the 2026-06-04 text says the App pipeline should be
// exempt, so anyone who finds that older wording and "fixes the code to match"
// re-opens a DLP hole, and nothing goes red. This fence is what makes the
// decision machine-enforced in the direction it was actually decided.
//
// 能红 (how to see it fail): add an App-pipeline exemption to applyInboundFilter,
// e.g.
//
//	if routeSource == "app" { return true }
//
// next to the existing isProbePipelineRoute guard in filter_dispatch.go. Both
// tests below fail: Detect is never called and the upstream receives the raw
// prompt.
//
// NOTE ON WHAT IS ASSERTED. The assertion is the ENTRY-POINT property — "the
// compliance chain was entered for this traffic" — and the mutation the spy hook
// deterministically returns. It deliberately does NOT assert "a compliance event
// was produced", because that depends on whether today's shipped rule packs
// happen to match today's prompt; a rule-set change would turn such an assertion
// green while the pipeline silently stopped being scanned. Same reasoning as the
// probe fence, applied to the opposite verdict. Reuses spyFilterHook from
// probe_pipeline_compliance_exclusion_fence_test.go on purpose: one spy, two
// mirrored fences, so the pair cannot drift apart.

// appSensitivePrompt is prompt-shaped user content of the kind an integrated app
// forwards on the user's behalf. Its literal text does not matter to the
// assertions (the spy masks unconditionally); it is written this way so a reader
// sees what class of content the App pipeline is carrying to an external LLM,
// which is the whole reason the decision went the way it did.
const appSensitivePrompt = "Summarise this customer record: contact 13812345678, follow up tomorrow."

func TestAppPipeline_AlwaysEntersComplianceFilter(t *testing.T) {
	cases := []struct {
		name             string
		slug             string
		upstreamProvider string
		requestPath      string
		requestBody      string
		upstreamResponse string
	}{
		{
			name:             "openai wire app",
			slug:             "fence-openai-app",
			upstreamProvider: "openai",
			requestPath:      "/apps/fence-openai-app/v1/chat/completions",
			requestBody: `{"model":"gpt-4o","messages":[{"role":"user","content":"` +
				appSensitivePrompt + `"}]}`,
			upstreamResponse: `{"id":"chatcmpl_fence","choices":[{"message":{"content":"ok"}}],` +
				`"usage":{"prompt_tokens":1,"completion_tokens":1}}`,
		},
		{
			name:             "anthropic wire app",
			slug:             "fence-anthropic-app",
			upstreamProvider: "anthropic",
			requestPath:      "/apps/fence-anthropic-app/v1/messages",
			requestBody: `{"model":"claude-3-5-sonnet-20241022","max_tokens":600,` +
				`"messages":[{"role":"user","content":"` + appSensitivePrompt + `"}]}`,
			upstreamResponse: `{"id":"msg_fence","type":"message","content":[{"type":"text","text":"ok"}],` +
				`"usage":{"input_tokens":1,"output_tokens":1}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamBody string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				upstreamBody = string(b)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.upstreamResponse))
			}))
			defer upstream.Close()

			av := newAppPipelineTestVault(tc.slug, []string{tc.upstreamProvider},
				"sk-upstream-real", upstream.URL)
			p := setupTestProxyWithActive(t, av)
			seedAppRouteInProxy(p, tc.slug)
			spy := &spyFilterHook{}
			p.SetFilterHook(spy)

			req := httptest.NewRequest(http.MethodPost, tc.requestPath, strings.NewReader(tc.requestBody))
			req.Header.Set("Authorization", "Bearer "+testAppBearer)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			p.Handle(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("app request status=%d, want 200; body=%s", w.Code, w.Body.String())
			}
			if spy.calls() == 0 {
				t.Errorf("compliance filter was NOT invoked for App-pipeline traffic; want it invoked.\n" +
					"The App pipeline (/apps/<slug>/v1/...) is NOT exempt from compliance — user decision " +
					"2026-08-11, which overrode the 2026-06-04 spec text claiming it should be exempt. " +
					"App traffic carries real user content to an external LLM, so exempting it widens the " +
					"DLP gap with no offsetting correctness argument (unlike the probe pipeline, whose " +
					"exemption exists because masking destroys the fixed-prompt fingerprint).\n" +
					"If you just added an App exemption to applyInboundFilter, that is the regression this " +
					"fence exists to catch — take it back to the spec before changing it.\n" +
					"See workflow/CI/requirements/2026-06-04-compliance-filter-direction-and-scope.md")
			}
			// Second leg: the verdict must actually reach the wire. "Hook consulted"
			// without "verdict applied" would still leak the raw prompt upstream, so
			// entry alone is not enough to call the pipeline covered.
			if strings.Contains(upstreamBody, appSensitivePrompt) {
				t.Errorf("upstream received the App-pipeline prompt VERBATIM — the filter's verdict was "+
					"consulted but not applied to the forwarded body, so DLP does not actually cover "+
					"this pipeline.\ngot: %s", upstreamBody)
			}
		})
	}
}

// TestApplyInboundFilter_DoesNotSkipAppRouteSource pins the rule at the unit
// level: applyInboundFilter must enter the chain for RouteSource "app",
// regardless of which funnel delivered it. This matters because the App pipeline
// reaches serveRoute by TWO routes — directly (handleAppPipeline's last line) and
// through serveManagedChain when the app's binding has a route group (chain hops
// keep RouteSource "app", see chain_app.go). Pinning the predicate rather than
// one call site covers both, and covers any funnel added later.
//
// The probe sub-case is the discriminating control: without it, "Detect was
// called for app" could pass simply because the guard is inert, rather than
// because it correctly distinguishes the two pipelines.
func TestApplyInboundFilter_DoesNotSkipAppRouteSource(t *testing.T) {
	const body = `{"model":"m","messages":[{"role":"user","content":"` + appSensitivePrompt + `"}]}`

	t.Run("app route source enters the chain", func(t *testing.T) {
		spy := &spyFilterHook{}
		p := &Proxy{filterHook: spy}
		r := newReq(body)
		p.applyInboundFilter(httptest.NewRecorder(), r, "m", "app", "", "", "", "", "", discardLogger())
		if n := spy.calls(); n == 0 {
			t.Error("Detect was NOT called for RouteSource=app; want the App pipeline scanned. " +
				"An App-pipeline compliance exemption was rejected by the user on 2026-08-11 — " +
				"see workflow/CI/requirements/2026-06-04-compliance-filter-direction-and-scope.md")
		}
		if got := readReqBody(t, r); got == body {
			t.Error("app body was forwarded unchanged although the spy always masks — " +
				"the verdict is not being applied on this route source")
		}
	})

	// Discriminating control: the guard must skip probe and ONLY probe. If this
	// sub-test also entered the chain, the assertion above would prove nothing
	// about the guard, only that a hook was installed.
	t.Run("probe route source is still the only skip", func(t *testing.T) {
		spy := &spyFilterHook{}
		p := &Proxy{filterHook: spy}
		r := newReq(body)
		p.applyInboundFilter(httptest.NewRecorder(), r, "m", "probe", "", "", "", "", "", discardLogger())
		if n := spy.calls(); n != 0 {
			t.Fatalf("Detect called %d time(s) for RouteSource=probe; want 0 — the probe exemption "+
				"regressed, so the app assertion above no longer discriminates", n)
		}
	})
}
