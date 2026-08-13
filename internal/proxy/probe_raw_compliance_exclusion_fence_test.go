package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// probe_raw_compliance_exclusion_fence_test.go — machine enforcement for the
// rule "pre-save probe traffic (`aikey_probe_raw_*`, handleProbeRaw) is NEVER
// touched by the compliance filter".
//
// This is the THIRD member of a deliberately symmetric set. Read all three
// together; they share one spy hook on purpose so they cannot drift apart:
//
//	probe pipeline  (/probe/<alias>/...)   → EXEMPT  → Detect called ZERO times
//	                                          probe_pipeline_compliance_exclusion_fence_test.go
//	app   pipeline  (/apps/<slug>/...)     → SCANNED → Detect called AT LEAST once
//	                                          app_pipeline_compliance_inclusion_fence_test.go
//	pre-save probe  (aikey_probe_raw_*)    → EXEMPT  → Detect called ZERO times   ← this file
//
// WHY THIS FILE EXISTS — gap G1, registered 2026-08-11.
// `workflow/CI/requirements/2026-06-04-compliance-filter-direction-and-scope.md`
// table B records handleProbeRaw as "not filtered". Unlike the 2026-06-04 claims
// about the App and probe pipelines, this one IS true today — verified line by
// line: handleProbeRaw builds its own http.Client and writes its own JSON
// response, and never reaches serveRoute, the single funnel where
// applyInboundFilter is called.
//
// 🔴 But being true today was never the problem. The 2026-06-04 entry was ALSO
// derived from reading the code — and it was false the day it was written,
// because "the filter is only called in serveRoute" was mistaken for "only
// serveRoute-shaped traffic is filtered" when serveRoute is in fact the shared
// downstream funnel of nine independent entries. G1's justification has exactly
// that shape: "it holds because the code currently happens to be written this
// way". One refactor aimed at reuse — folding probe_raw's hand-rolled forward
// into the common path, which is the obvious cleanup any reviewer would suggest
// on reading probe_raw.go's 150 self-contained lines — silently flips it, and
// before this file nothing anywhere went red.
//
// WHY IT MATTERS. handleProbeRaw serves the connectivity test the Web "Add Key"
// modal and `aikey add` run BEFORE the key is saved, so the caller's plaintext
// provider key travels in X-Aikey-Probe-Bearer. Two harms if this traffic ever
// entered the compliance chain:
//  1. The probe body would be scanned, masked and turned into a compliance event
//     attributing aikey's own fixed probe text to the employee — the same
//     audit-trail pollution documented for the probe pipeline in
//     workflow/CI/bugfix/20260811-probe-traffic-entered-compliance-chain.md.
//  2. Entering the chain at all drags a request whose whole point is "does the
//     network path to this provider work" through the detector, so a probe
//     verdict would start depending on rule-pack state — a connectivity check
//     that can fail for compliance reasons is not a connectivity check.
//
// WHAT IS ASSERTED, AND WHAT DELIBERATELY IS NOT. The assertions are the
// ENTRY-POINT property (was the compliance chain entered for this traffic?) plus
// the byte-level result on the wire. They deliberately do NOT assert "no
// compliance event was produced": that can be green because today's shipped rule
// packs happen not to match today's prompt, and would turn into a permanently
// vacuous assertion after any rule-pack change. Identical reasoning to the other
// two fences.
//
// Red-fence check: delete the `if dispatchAction == Tier2ProbeRaw`
// short-circuit in handlePathPrefixRoute (pipelines.go) so probe_raw traffic
// falls through to the shared forward path and reaches serveRoute. Both subtests
// of TestProbeRaw_IsNeverTouchedByComplianceFilter fail — Detect is called and
// the upstream receives the masked body. The mock vault below is seeded for
// exactly that reason: without a landable binding the regression would surface
// as a 502 rather than as the masking it actually causes, and the fence would be
// failing for the wrong reason.

// probeRawSensitivePrompt is the body carried by the pre-save probe. Chosen so
// that it is CERTAIN to be rewritten if the filter runs at all (the shipped
// intl-PII packs match bare digit runs), so a green result cannot mean "no rule
// matched today".
const probeRawSensitivePrompt = "connectivity check, contact 13812345678 for details."

// newProbeRawFenceVault returns a vault seeded with an active team binding for
// `providerCode` pointing at `upstreamURL`.
//
// 🔴 The seeding is NOT needed by the code under test — handleProbeRaw short-
// circuits before any vault lookup, which is precisely the property being
// fenced. It exists so that the REGRESSION has somewhere to land: if probe_raw
// ever falls through to the shared forward path, the request resolves this
// binding, reaches serveRoute, gets filtered, and the assertions below fail
// describing the real problem instead of a 502.
func newProbeRawFenceVault(providerCode, protocolType, upstreamURL string) *mockActiveVault {
	return &mockActiveVault{
		activeTeamKeys: map[string]*vault.ManagedKey{
			providerCode: {
				VirtualKeyID:     "vk-probe-raw-fence",
				ProviderCode:     providerCode,
				ProtocolType:     protocolType,
				BaseURL:          upstreamURL,
				PlaintextKey:     "sk-upstream-real",
				ProviderBaseURLs: map[string]string{providerCode: upstreamURL},
			},
		},
	}
}

func TestProbeRaw_IsNeverTouchedByComplianceFilter(t *testing.T) {
	cases := []struct {
		name             string
		providerCode     string
		protocolType     string
		requestPath      string
		requestBody      string
		upstreamResponse string
	}{
		{
			name:         "anthropic wire pre-save probe",
			providerCode: "anthropic",
			protocolType: "anthropic",
			requestPath:  "/anthropic/v1/messages",
			requestBody: `{"model":"claude-3-5-sonnet-20241022","max_tokens":16,` +
				`"messages":[{"role":"user","content":"` + probeRawSensitivePrompt + `"}]}`,
			upstreamResponse: `{"id":"msg_probe_raw","type":"message","content":[{"type":"text","text":"ok"}],` +
				`"usage":{"input_tokens":1,"output_tokens":1}}`,
		},
		{
			name:         "openai wire pre-save probe",
			providerCode: "openai",
			protocolType: "openai_compatible",
			requestPath:  "/openai/v1/chat/completions",
			requestBody: `{"model":"gpt-4o","max_tokens":16,` +
				`"messages":[{"role":"user","content":"` + probeRawSensitivePrompt + `"}]}`,
			upstreamResponse: `{"id":"chatcmpl_probe_raw","choices":[{"message":{"content":"ok"}}],` +
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

			av := newProbeRawFenceVault(tc.providerCode, tc.protocolType, upstream.URL)
			p := setupTestProxyWithActive(t, av)
			spy := &spyFilterHook{}
			p.SetFilterHook(spy)

			req := httptest.NewRequest(http.MethodPost, tc.requestPath, strings.NewReader(tc.requestBody))
			req.Header.Set("Authorization", "Bearer aikey_probe_raw_"+tc.providerCode)
			req.Header.Set("X-Aikey-Probe", "1")
			req.Header.Set("X-Aikey-Probe-Bearer", "sk-the-key-being-typed")
			req.Header.Set("X-Aikey-Probe-BaseURL", upstream.URL)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			p.Handle(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("pre-save probe status=%d, want 200; body=%s", w.Code, w.Body.String())
			}

			if n := spy.calls(); n != 0 {
				t.Errorf("compliance filter was invoked %d time(s) for pre-save probe traffic "+
					"(aikey_probe_raw_*); want 0.\n"+
					"handleProbeRaw must stay off the shared forward funnel: it serves the "+
					"connectivity test that runs BEFORE a key is saved, its body is aikey-generated "+
					"and carries no employee content, and scanning it both pollutes the compliance "+
					"audit trail with synthetic text and makes a connectivity verdict depend on "+
					"rule-pack state.\n"+
					"If you just folded probe_raw into the common serveRoute path, that is the "+
					"regression this fence exists to catch (registered gap G1).\n"+
					"See workflow/CI/requirements/2026-06-04-compliance-filter-direction-and-scope.md", n)
			}
			if !strings.Contains(upstreamBody, probeRawSensitivePrompt) {
				t.Errorf("upstream did not receive the pre-save probe body verbatim — something on "+
					"this path rewrote it. The probe forwards the caller's bytes unchanged so the "+
					"result reflects the provider's answer to the real request, not to a masked one."+
					"\n got: %s\nwant to contain: %s", upstreamBody, probeRawSensitivePrompt)
			}

			// Liveness / non-vacuity guard, asserted LAST and on purpose.
			//
			// The two assertions above are both of the form "X did not happen",
			// so they would also be satisfied by a request that quietly did
			// nothing. This pins that the response really is handleProbeRaw's
			// own JSON envelope (probe_ok / upstream_status / latency_ms), which
			// only that handler emits.
			//
			// It is deliberately NOT first and NOT fatal: when probe_raw is
			// folded into the shared forward path, the client gets the upstream
			// LLM response instead of this envelope, so this check fails TOO —
			// and reading it before the real diagnosis above would send the
			// reader hunting for a transport failure that never happened.
			var probeBody map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &probeBody); err != nil {
				t.Errorf("pre-save probe response is not JSON: %v\nbody: %s", err, w.Body.String())
			} else if ok, _ := probeBody["probe_ok"].(bool); !ok {
				t.Errorf("response is not handleProbeRaw's probe_ok envelope: %s\n"+
					"Either the probe never reached upstream (transport failure — then the "+
					"assertions above are vacuous), or this traffic is no longer served by "+
					"handleProbeRaw at all, which is the G1 regression itself.", w.Body.String())
			}
		})
	}
}

// TestProbeRaw_ComplianceExclusionIsPinnedToTheTokenClass pins the DISCRIMINANT
// rather than the one call site, and carries the negative control that makes the
// zero-Detect assertions above mean something.
//
// The discriminant for this exclusion is the token class itself —
// `ClassifyToken(...) == Tier2ProbeRaw` — not a RouteSource, because
// handleProbeRaw never builds a ResolvedRoute. Verified 2026-08-11: exactly ONE
// entry ARRIVES at handleProbeRaw (handlePathPrefixRoute, pipelines.go), but TWO
// production sites classify Tier2ProbeRaw. The second is the legacy /v1/... entry
// (handle_dispatch.go), which rejects the token with 401 before any forwarding.
// Both are pinned here, because "unify the two entries" is precisely the kind of
// change that would route the legacy one through serveRoute.
//
// Why this matters at all: the App fence's lesson is that one pipeline can reach
// the funnel by more than one route (directly, and again through
// serveManagedChain). Pinning a single call site would have missed it there, and
// would miss a second probe_raw entry here.
func TestProbeRaw_ComplianceExclusionIsPinnedToTheTokenClass(t *testing.T) {
	const body = `{"model":"claude-3-5-sonnet-20241022","max_tokens":16,` +
		`"messages":[{"role":"user","content":"` + probeRawSensitivePrompt + `"}]}`

	newFence := func(t *testing.T) (*Proxy, *spyFilterHook) {
		t.Helper()
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"msg","type":"message","content":[{"type":"text","text":"ok"}],` +
				`"usage":{"input_tokens":1,"output_tokens":1}}`))
		}))
		t.Cleanup(upstream.Close)
		p := setupTestProxyWithActive(t, newProbeRawFenceVault("anthropic", "anthropic", upstream.URL))
		spy := &spyFilterHook{}
		p.SetFilterHook(spy)
		return p, spy
	}

	// Second recognition site. It is green today because the legacy entry
	// REJECTS the token rather than serving it — which is a perfectly good way
	// to stay out of the chain, and is recorded here so a future change that
	// starts SERVING probe_raw from this entry has to come back and decide
	// consciously instead of inheriting the filter by default.
	t.Run("legacy /v1 entry never filters a probe_raw token", func(t *testing.T) {
		p, spy := newFence(t)

		req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer aikey_probe_raw_anthropic")
		req.Header.Set("X-Aikey-Probe", "1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		p.Handle(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("legacy /v1 entry status=%d, want 401 — this entry has no path-derived "+
				"canonical provider, so it cannot construct the upstream URL and must reject. "+
				"If it now SERVES probe_raw, the exclusion has to be re-established explicitly "+
				"on whatever funnel it was routed through.\nbody: %s", w.Code, w.Body.String())
		}
		if n := spy.calls(); n != 0 {
			t.Errorf("Detect called %d time(s) for a probe_raw token at the legacy /v1 entry; want 0", n)
		}
	})

	// NEGATIVE CONTROL — without it, every "Detect was not called" assertion in
	// this file could be green simply because the spy is not wired, or because
	// this proxy/vault shape never filters anything.
	//
	// The control is the SAME entry, SAME URL shape, SAME body and even the SAME
	// `X-Aikey-Probe: 1` header. The ONLY variable is the token class. That
	// isolation is what makes it evidence about the discriminant, and it doubles
	// as the machine action behind a second spec rule: `X-Aikey-Probe: 1` is
	// client-settable and therefore does NOT exempt anything from compliance
	// (spec pitfall 2) — only the server-derived token class does.
	t.Run("same request without the probe_raw token IS filtered", func(t *testing.T) {
		p, spy := newFence(t)

		req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+strings.Join([]string{"sk", "a-normal-native-token"}, "-"))
		req.Header.Set("X-Aikey-Probe", "1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		p.Handle(w, req)

		if n := spy.calls(); n == 0 {
			t.Fatalf("Detect was NOT called for ordinary traffic on the same entry — the spy hook "+
				"is not wired or this path stopped filtering, so every zero-Detect assertion in "+
				"this file proves nothing.\nstatus=%d body=%s", w.Code, w.Body.String())
		}
	})
}
