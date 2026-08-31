package supervisor

// license_plane_rail_test.go — fences under the license rail's GATE.
//
// The gate decides which deployments this rail runs on, and getting it wrong is
// invisible in opposite ways on either side: too open and every Personal install
// grows a permanently red rail that means nothing; too closed and a team install
// silently stops learning its license state. Both were observed live on
// 2026-08-27 (see workflow/CI/bugfix/20260827-forwarding-gate-was-never-wired.md).

import (
	"os"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// TestTheRailIdlesWithNoControlPlane is the Personal fence.
//
// 🔴 railset.go counts a missing control URL as a FAILED cycle, which is right
// for rails that only exist on team installs. This rail runs everywhere, so
// without its own gate it would count a failure every 60s on Personal and settle
// into STALE and then OFFLINE in /status — a red signal whose actual meaning is
// "this edition has no license to check". Measured live before the gate existed:
// fails=1 and climbing on a freshly started Personal proxy.
func TestTheRailIdlesWithNoControlPlane(t *testing.T) {
	t.Setenv("AIKEY_HUB_CONTROL_URL", "")
	t.Setenv("HOME", t.TempDir()) // no ~/.aikey/config/config.json either

	s := &Supervisor{licensePlane: proxy.NewLicensePlaneCache()}
	if s.licensePlaneRail().gate(nil) {
		t.Fatal("the license rail is armed on a deployment with no control plane. " +
			"Personal has none by design, so every Personal install would carry a " +
			"licensing rail that fails forever and reports itself OFFLINE.")
	}
}

// TestTheRailRunsWhenThereIsAControlPlane is the other side of that boundary.
//
// Without it, a gate that returned false unconditionally would satisfy the fence
// above while switching the whole mechanism off — which is precisely the shape of
// the defect this change exists to correct.
func TestTheRailRunsWhenThereIsAControlPlane(t *testing.T) {
	t.Setenv("AIKEY_HUB_CONTROL_URL", "http://127.0.0.1:28399")

	s := &Supervisor{licensePlane: proxy.NewLicensePlaneCache()}
	if !s.licensePlaneRail().gate(nil) {
		t.Fatal("the license rail is idle on a deployment that HAS a control plane; " +
			"the gate would never learn this deployment's license state")
	}
}

// TestTheRailIsIdleWithoutACache guards the nil-cache wiring case.
func TestTheRailIsIdleWithoutACache(t *testing.T) {
	t.Setenv("AIKEY_HUB_CONTROL_URL", "http://127.0.0.1:28399")

	s := &Supervisor{}
	if s.licensePlaneRail().gate(nil) {
		t.Fatal("the rail armed itself with no cache to write into")
	}
}

// TestTheRailIsRegisteredInSupervisorGo is the wiring fence.
//
// 🔴 A rail that is declared and never registered is exactly the failure class
// this whole change exists to fix: correct code, nothing calling it, nothing red.
//
// 🔴 It reads supervisor.go's ACTUAL newRailSet call rather than building a rail
// set of its own. The first version of this test did the latter — it constructed
// `newRailSet(..., s.licensePlaneRail())` and asserted the rail was in it, which
// is a tautology: it proved that a list this test wrote contains an element this
// test put there. Deleting the rail from supervisor.go left it GREEN. That is
// the same "reads as coverage" failure the license gate itself was found in, so
// it is recorded here rather than quietly corrected.
//
// 🚫 The scan is anchored to supervisor.go specifically, not a package-wide
// grep, so the fence cannot match its own source and pass on that.
func TestTheRailIsRegisteredInSupervisorGo(t *testing.T) {
	raw, err := os.ReadFile("supervisor.go")
	if err != nil {
		t.Fatalf("read supervisor.go: %v", err)
	}
	src := string(raw)

	start := strings.Index(src, "newRailSet(")
	if start < 0 {
		t.Fatal("supervisor.go no longer calls newRailSet; this fence is measuring nothing")
	}
	end := strings.Index(src[start:], ")\n")
	if end < 0 {
		t.Fatal("could not find the end of the newRailSet call")
	}
	call := src[start : start+end]

	// Vacuity guard: the extracted call must contain the rails we know are there,
	// or the slice is wrong and every assertion over it is meaningless.
	for _, known := range []string{"groupRuntimeRail()", "keyRevocationRail()"} {
		if !strings.Contains(call, known) {
			t.Fatalf("the extracted newRailSet call does not contain %s, so it is not the "+
				"real registration site: %q", known, call)
		}
	}

	if !strings.Contains(call, "licensePlaneRail()") {
		t.Fatalf("supervisor.go does not register the license rail:\n  %s\n\n"+
			"Without it the forwarding gate is never populated, every deployment "+
			"forwards regardless of its license, and nothing else goes red — which "+
			"is the exact defect of 2026-08-27.", call)
	}
}
