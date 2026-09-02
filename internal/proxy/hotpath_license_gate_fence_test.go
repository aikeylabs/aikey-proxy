//go:build !aikey_license_off

// 🔴 Tagged: this whole fence asserts the gate REFUSES. A -tags aikey_license_off
// build compiles the gate out on purpose, so every assertion here is false there
// by design. The inverse fence for that build is
// hotpath_license_gate_off_fence_test.go, and it is not optional — untagging this
// file without adding that one would leave the licensing-off build with NO
// coverage of the property that matters most about it.

package proxy

// hotpath_license_gate_fence_test.go — the POSITIVE fence under the license
// forwarding gate.
//
// # 🔴 Why a positive fence, and why that word is the whole point
//
// This repository already had a fence about licensing on the request path:
// hotpath_callgraph_fence_test.go asserts that nothing reachable from
// Proxy.Handle imports aikey-license-core. It was green. It had always been
// green. It was green because the proxy did not consult the license AT ALL —
// the control plane computed a forwarding verdict, projected it, and served it
// on /v1/license/plane with a comment naming this process as its reader, and
// nothing here ever asked. A deployment whose license had expired kept
// forwarding every request indefinitely.
//
// So the existing fence proved "we did not do the wrong thing" while the actual
// defect was "we did not do the thing". Those are different assertions and a
// negative fence cannot make the second one. Every guard in this mechanism also
// fails OPEN by design and correctly so — an unwired consumer and a fully
// licensed deployment produce identical observable behavior, which is why this
// survived review, release and a live E2E.
//
// The tests below therefore assert PRESENCE:
//
//	1. the gate is REACHABLE from Proxy.Handle (call-graph)
//	2. a denied gate actually refuses, on every routing branch (behavior)
//	3. the fences themselves can go red (vacuity)
//
// See workflow/CI/bugfix/20260827-forwarding-gate-was-never-wired.md.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// licenseGateFunc is the function that must be reachable from the hot-path entry.
// Keyed the same way the module graph keys everything else.
const licenseGateFunc = "internal/proxy::LicensePlaneCache.ForwardingAllowed"

// TestTheLicenseGateIsReachedFromTheHotPath is the fence whose absence allowed
// the defect.
//
// 🚫 Do not "simplify" this into a grep for the call. A grep matches a line in a
// comment, a line in dead code, and a line in a function nothing calls — all
// three of which are exactly the failure being fenced. Reachability from the real
// per-request entry point is the only assertion that means what it says.
func TestTheLicenseGateIsReachedFromTheHotPath(t *testing.T) {
	g := loadModuleGraph(t)
	reached := g.reachableFrom(hotPathEntry)

	if len(reached) == 0 {
		t.Fatal("the call-graph walk from " + hotPathEntry + " reached nothing; the fence " +
			"is measuring an empty set and would pass no matter what the code did")
	}
	if _, ok := reached[licenseGateFunc]; !ok {
		t.Fatalf("%s is NOT reachable from %s.\n\n"+
			"The deployment's license forwarding gate is not consulted on the request "+
			"path, so an expired, revoked or never-activated deployment forwards "+
			"normally — which is the exact defect of 2026-08-27 "+
			"(workflow/CI/bugfix/20260827-forwarding-gate-was-never-wired.md).\n\n"+
			"🔴 Note that the licensing mechanism fails OPEN at every layer on "+
			"purpose, so nothing else will go red to tell you about this. That is "+
			"why this fence exists.\n\n"+
			"The gate belongs in Handle, after the read-only diagnostics branch and "+
			"before every routing branch.",
			licenseGateFunc, hotPathEntry)
	}
}

// TestTheLicenseGateFenceGoesRedWhenTheGateIsRemoved is the vacuity check for the
// test above.
//
// 🔴 A reachability fence has a specific way of silently rotting: rename the
// entry point, or the function it looks for, and `reached[x]` is simply false —
// or the walk returns nothing and every membership test is false, which reads as
// "not reached" rather than "not measured". This asserts the walk is real by
// checking it finds things it must, and that the key it looks for names a
// function that actually exists.
func TestTheLicenseGateFenceGoesRedWhenTheGateIsRemoved(t *testing.T) {
	g := loadModuleGraph(t)

	if _, ok := g.funcs[licenseGateFunc]; !ok {
		t.Fatalf("%s does not exist in this module, so the fence above is asserting "+
			"membership of a key that can never appear — it would fail for the wrong "+
			"reason, or pass vacuously if somebody inverted it. Update the constant "+
			"when the gate is renamed.", licenseGateFunc)
	}

	// The walk must also reach things unrelated to licensing, or a graph that
	// only ever returns the entry point would satisfy nothing meaningful.
	reached := g.reachableFrom(hotPathEntry)
	if len(reached) < 10 {
		t.Fatalf("the walk from %s reached only %d functions; that is not a real call "+
			"graph and every assertion over it is close to vacuous", hotPathEntry, len(reached))
	}
}

// deniedGate returns a cache whose gate says deny.
func deniedGate(t *testing.T) *LicensePlaneCache {
	t.Helper()
	c := NewLicensePlaneCache()
	c.Observe(licenseGateDeny, time.Now())
	return c
}

// TestADeniedGateRefusesEveryRoutingBranch is the behavioral half.
//
// 🔴 The call-graph fence proves the gate is consulted; it cannot prove it is
// consulted BEFORE the routing branches. Handle dispatches to four different
// pipelines (probe, app, provider-prefix and token-based), and a gate placed
// after any of them would leave that branch forwarding while the other three
// refused — a partial enforcement that would look correct in every test that
// happened to use one of the covered paths.
//
// One placement covers all four only if it precedes all four, and this is what
// asserts that.
func TestADeniedGateRefusesEveryRoutingBranch(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"probe pipeline", "/probe/some-alias/v1/messages"},
		{"app pipeline", "/apps/some-slug/v1/messages"},
		{"provider prefix", "/anthropic/v1/messages"},
		{"token routing", "/v1/messages"},
		{"openai prefix", "/openai/v1/chat/completions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{licensePlane: deniedGate(t)}
			rec := httptest.NewRecorder()
			p.Handle(rec, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(`{}`)))

			if rec.Code != http.StatusPaymentRequired {
				t.Fatalf("%s returned %d, want %d.\nA gate that does not precede this "+
					"branch leaves it forwarding while the others refuse.",
					tc.path, rec.Code, http.StatusPaymentRequired)
			}

			var body struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("refusal body is not JSON: %v (%s)", err, rec.Body)
			}
			if body.Error.Code != "LICENSE_FORWARDING_DENIED" {
				t.Errorf("refusal code = %q, want LICENSE_FORWARDING_DENIED; the code is what "+
					"a client switches on", body.Error.Code)
			}
			// 🔴 The message must not read as a credential problem. 402 rather than
			// 403 was chosen precisely so a developer is not sent to rotate a key
			// that is perfectly fine, and a message that says "unauthorized" would
			// undo that.
			for _, forbidden := range []string{"unauthorized", "forbidden", "invalid key", "api key"} {
				if strings.Contains(strings.ToLower(body.Error.Message), forbidden) {
					t.Errorf("the refusal message contains %q, which reads as a credential "+
						"problem and sends the user to rotate a working key: %q",
						forbidden, body.Error.Message)
				}
			}
		})
	}
}

// TestAnAllowedGateDoesNotRefuse is the other side of the boundary.
//
// Without it, a gate that refused unconditionally would pass every assertion
// above — "it refuses" is only interesting next to "and otherwise it does not".
func TestAnAllowedGateDoesNotRefuse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cache *LicensePlaneCache
	}{
		{"explicitly allowed", func() *LicensePlaneCache {
			c := NewLicensePlaneCache()
			c.Observe(licenseGateAllow, time.Now())
			return c
		}()},
		// Personal, and every deployment before its first poll.
		{"never synced", NewLicensePlaneCache()},
		// A build or harness that wired no cache at all.
		{"no cache wired", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{licensePlane: tc.cache}
			rec := httptest.NewRecorder()
			p.Handle(rec, httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`)))

			if rec.Code == http.StatusPaymentRequired {
				t.Fatalf("a %s gate refused forwarding with 402. Personal has no license "+
					"to check and every edition is unsynced at start-up; refusing here "+
					"stops deployments that have done nothing wrong.", tc.name)
			}
		})
	}
}

// TestTheDiagnosticsBranchSurvivesADeniedGate is R8 at the request path.
//
// 🔴 Every row of licstate's plane table — including the four that deny
// forwarding — carries `ReadExport: allow` and `Process: healthy`. A licensing
// refusal may never take away the operator's ability to see what is wrong. The
// read-only diagnostics endpoint is the proxy-side instance of that rule, which
// is why the gate sits AFTER it in Handle rather than at the very top.
func TestTheDiagnosticsBranchSurvivesADeniedGate(t *testing.T) {
	p := &Proxy{licensePlane: deniedGate(t)}
	rec := httptest.NewRecorder()
	p.Handle(rec, httptest.NewRequest(http.MethodGet, "/v1/diagnostics/pipeline", nil))

	if rec.Code == http.StatusPaymentRequired {
		t.Fatal("the license gate refused the read-only diagnostics endpoint. R8 makes " +
			"read/export `allow` on every plane row, including the ones that deny " +
			"forwarding: an operator diagnosing the refusal must not be locked out " +
			"by it. Move the gate below the 0-diag branch in Handle.")
	}
}
