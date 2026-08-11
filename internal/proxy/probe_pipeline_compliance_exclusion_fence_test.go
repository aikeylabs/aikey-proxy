package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// probe_pipeline_compliance_exclusion_fence_test.go — machine enforcement for the
// rule "the Probe pipeline is NEVER touched by the compliance filter".
//
// WHY THIS FILE EXISTS (root cause, 2026-08-11).
// `workflow/CI/requirements/2026-06-04-compliance-filter-direction-and-scope.md`
// states the rule as fact ("App/probe 管线 handleAppPipeline/handleProbePipeline …
// 不过滤"). It was never true for the probe pipeline: the compliance dispatcher was
// added to serveRoute on 2026-06-01 (ef816e0) and serveRoute is the single funnel
// handleProbePipeline delegates to (added 2026-05-23, cd8c844). The spec was
// written three days AFTER the behaviour it denies, and nothing machine-checkable
// stood behind it, so it read as a guarantee for 10 weeks while probes were in
// fact scanned, masked and turned into compliance events.
//
// WHY IT MATTERS (two distinct harms, both real):
//  1. Detection correctness. The degrade detector (trust-local) judges a model by
//     the response fingerprint of a FIXED prompt (CANONICAL_L3_PROBE et al). If
//     compliance rewrites one character of that prompt, the model answers a
//     different question and every rhythm/ITT baseline is invalid — silently.
//  2. Content attribution. A masked probe emits a compliance event. On
//     Personal/Trial the detector runs in LocalIntake mode, which carries the
//     UN-REDACTED context_snippet unconditionally — so aikey's own probe text is
//     stored and rendered on the member self-view as "the content YOU sent that
//     tripped a rule". On Production/Cluster the same event is uploaded by the
//     detector to control-master and shows up in the administrator's audit log.
//     Neither is employee content; both are noise in an audit trail whose whole
//     value is that every row is real.
//
// The fence asserts the ENTRY-POINT property (the filter is never invoked for
// probe-pipeline traffic), not a downstream symptom, because "no event was
// written" can pass for the wrong reason (no rule matched today's prompt).
//
// 能红 (how to see it fail): delete the `isProbePipelineRoute` guard in
// applyInboundFilter (filter_dispatch.go) and both subtests fail — Detect gets
// called and the upstream receives the masked body.

// spyFilterHook is a minimal apphook.Hook that records every Detect call and
// always masks, so "was the compliance chain entered?" and "was the payload
// rewritten?" are both observable without the real detector binary.
type spyFilterHook struct {
	mu       sync.Mutex
	payloads [][]byte
}

func (h *spyFilterHook) Name() string { return "spy-filter-hook" }

func (h *spyFilterHook) Detect(_ context.Context, req *apphook.Request) *apphook.Response {
	h.mu.Lock()
	h.payloads = append(h.payloads, append([]byte(nil), req.Payload...))
	h.mu.Unlock()
	return &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte("***MASKED-BY-SPY***"),
		Reason:         "spy always masks",
	}
}

func (h *spyFilterHook) Status() *apphook.Status {
	return &apphook.Status{Healthy: true, BinaryPath: "spy"}
}

func (h *spyFilterHook) calls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.payloads)
}

// canonicalProbePrompt mirrors ai-degrade-detector shared/algorithms/rhythm.py
// CANONICAL_L3_PROBE["prompt"]. Kept verbatim so a reader sees exactly what the
// compliance filter would have been rewriting.
const canonicalProbePrompt = "List 25 interesting facts about Mars exploration history, " +
	"each fact one sentence, numbered 1 to 25."

func TestProbePipeline_IsNeverTouchedByComplianceFilter(t *testing.T) {
	// The probe question bank is aikey-authored, but a rule can fire on ANY text
	// (the shipped intl-PII packs match bare digit runs — verified live
	// 2026-08-11: a Mars-facts prompt carrying a phone number produced seven
	// findings). Use a prompt that is certain to be rewritten if the filter runs
	// at all, so the assertion cannot pass because "no rule matched today".
	const probePrompt = canonicalProbePrompt + " Contact 13812345678 for details."

	cases := []struct {
		name             string
		alias            string
		protocolType     string
		requestPath      string
		requestBody      string
		runtimePrefix    string
		upstreamResponse string
	}{
		{
			name:          "anthropic wire probe",
			alias:         "mock-anthropic",
			protocolType:  "anthropic",
			requestPath:   "/probe/mock-anthropic/v1/messages",
			requestBody:   `{"model":"claude-3-5-sonnet-20241022","max_tokens":600,"messages":[{"role":"user","content":"` + probePrompt + `"}]}`,
			runtimePrefix: "/anthropic",
			upstreamResponse: `{"id":"msg_probe","type":"message","content":[{"type":"text","text":"ok"}],` +
				`"usage":{"input_tokens":1,"output_tokens":1}}`,
		},
		{
			name:          "openai wire probe",
			alias:         "mock-openai",
			protocolType:  "openai_compatible",
			requestPath:   "/probe/mock-openai/v1/chat/completions",
			requestBody:   `{"model":"gpt-4o","max_tokens":600,"messages":[{"role":"user","content":"` + probePrompt + `"}]}`,
			runtimePrefix: "/openai",
			upstreamResponse: `{"id":"chatcmpl_probe","choices":[{"message":{"content":"ok"}}],` +
				`"usage":{"prompt_tokens":1,"completion_tokens":1}}`,
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

			binding := &vault.ProviderBinding{
				ProviderCode:  "mock",
				ProtocolType:  tc.protocolType,
				KeySourceType: "personal",
				KeySourceRef:  tc.alias,
			}
			av := &mockActiveVault{
				aliasCreds: map[string]*vault.AliasCredential{
					tc.alias: {Binding: binding, Status: "active", AliasKind: "personal"},
				},
				personalAlias:   tc.alias,
				personalText:    "mock-secret",
				personalProv:    "mock",
				personalBaseURL: upstream.URL + tc.runtimePrefix,
			}
			p := setupTestProxyWithActive(t, av)
			spy := &spyFilterHook{}
			p.SetFilterHook(spy)

			req := httptest.NewRequest(http.MethodPost, tc.requestPath, strings.NewReader(tc.requestBody))
			req.Header.Set("Authorization", "Bearer aikey_app_internal_degrade_detector_v1")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			p.Handle(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("probe status=%d, want 200; body=%s", w.Code, w.Body.String())
			}
			if n := spy.calls(); n != 0 {
				t.Errorf("compliance filter was invoked %d time(s) for probe-pipeline traffic; want 0.\n"+
					"The Probe pipeline must be excluded at the compliance entry point "+
					"(applyInboundFilter), not downstream. Masking a probe changes the fixed "+
					"prompt the degrade detector fingerprints, and emits a compliance event that "+
					"attributes aikey's own probe text to the employee.\n"+
					"See workflow/CI/requirements/2026-06-04-compliance-filter-direction-and-scope.md", n)
			}
			if !strings.Contains(upstreamBody, probePrompt) {
				t.Errorf("upstream did not receive the probe prompt verbatim — the compliance "+
					"filter rewrote it, which invalidates the degrade-detection fingerprint.\ngot: %s", upstreamBody)
			}
		})
	}
}

// TestApplyInboundFilter_SkipsProbeRouteSource pins the guard at the unit level:
// applyInboundFilter itself must refuse to enter the chain for RouteSource
// "probe", independent of how it was reached. A future caller that forwards
// probe traffic through some other funnel inherits the exclusion.
func TestApplyInboundFilter_SkipsProbeRouteSource(t *testing.T) {
	const body = `{"model":"m","messages":[{"role":"user","content":"Contact 13812345678 for details."}]}`

	t.Run("probe route source is skipped", func(t *testing.T) {
		spy := &spyFilterHook{}
		p := &Proxy{filterHook: spy}
		r := newReq(body)
		if !p.applyInboundFilter(httptest.NewRecorder(), r, "m", "probe", "", "", "", "", "", discardLogger()) {
			t.Fatal("probe request was blocked by the compliance filter; probes must never be blocked")
		}
		if n := spy.calls(); n != 0 {
			t.Errorf("Detect called %d time(s) for RouteSource=probe; want 0", n)
		}
		if got := readReqBody(t, r); got != body {
			t.Errorf("probe body was rewritten.\n got: %s\nwant: %s", got, body)
		}
	})

	// Negative control — without this the test above could pass because the spy
	// is wired wrong rather than because the guard works.
	t.Run("non-probe route source still enters the chain", func(t *testing.T) {
		spy := &spyFilterHook{}
		p := &Proxy{filterHook: spy}
		r := newReq(body)
		p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", "", discardLogger())
		if n := spy.calls(); n == 0 {
			t.Fatal("Detect was NOT called for RouteSource=personal — the spy hook is not wired, " +
				"so the probe-skip assertion above proves nothing")
		}
	})
}
