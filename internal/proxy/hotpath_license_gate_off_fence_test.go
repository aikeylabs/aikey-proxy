//go:build aikey_license_off

package proxy

// hotpath_license_gate_off_fence_test.go — the INVERSE of
// hotpath_license_gate_fence_test.go, for the -tags aikey_license_off build.
//
// 🔴 Why this file has to exist. The normal fence asserts a denied gate refuses
// every routing branch. Tagging it off for this build would leave the licensing
// -off binary with zero coverage of its single most important property — and
// "no test ran" and "the test passed" are the same color in CI output. That is
// the exact ambiguity the forwarding-gate defect lived in for months.
//
// So this build gets the opposite assertions, of equal strength:
//
//   1. a DENIED gate does NOT produce 402 on any routing branch — the gate is
//      genuinely compiled out, not merely defaulted to allow. If someone drops
//      the build tag from license_gate_off.go, this goes red.
//   2. the boot interlock EXISTS in this build. It is the only thing standing
//      between a leaked licensing-off proxy and permanent unmetered forwarding,
//      and it is in a different package that a careless tag edit could sever.
//
// Together with the release gate's marker inversion (release.sh Step 8.9a) this
// makes a licensing-off proxy provably distinguishable from a normal one at
// three layers: source, artifact, and boot.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/licenseoff"
)

func deniedGateOff(t *testing.T) *LicensePlaneCache {
	t.Helper()
	c := NewLicensePlaneCache()
	c.Observe(licenseGateDeny, time.Now())
	return c
}

// TestTheGateIsCompiledOutOnEveryRoutingBranch is the behavioral half.
func TestTheGateIsCompiledOutOnEveryRoutingBranch(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"probe pipeline", "/probe/some-alias/v1/messages"},
		{"app pipeline", "/apps/some-slug/v1/messages"},
		{"provider prefix", "/anthropic/v1/messages"},
		{"token routing", "/v1/messages"},
		{"openai prefix", "/openai/v1/chat/completions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A gate that says DENY as loudly as it can. In a normal build every
			// one of these is a 402; here none may be.
			p := &Proxy{licensePlane: deniedGateOff(t)}
			rec := httptest.NewRecorder()
			p.Handle(rec, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(`{}`)))

			if rec.Code == http.StatusPaymentRequired {
				t.Fatalf("%s returned 402 in a -tags aikey_license_off build.\n"+
					"The gate is supposed to be COMPILED OUT here. A 402 means "+
					"license_gate_off.go is not the half that got built — check its "+
					"build tag. (A licensing-off cluster would then refuse every "+
					"request while its control plane has no license layer to satisfy.)",
					tc.path)
			}
		})
	}
}

// TestTheBootInterlockSurvivesInThisBuild guards the thing that makes the tag safe.
//
// 🚫 Do not "simplify" this by asserting on a literal. The point is that the
// licenseoff package compiled into THIS binary is the off half — a build that
// picked up interlock_on.go would have an empty AcknowledgementEnv, start
// silently anywhere, and forward forever with nothing to notice it.
func TestTheBootInterlockSurvivesInThisBuild(t *testing.T) {
	if licenseoff.AcknowledgementEnv == "" {
		t.Fatal("licenseoff.AcknowledgementEnv is empty in a -tags aikey_license_off " +
			"build: the ON half of the interlock was compiled in, so this proxy has no " +
			"gate AND will start unannounced on any host it is copied to.")
	}
}
