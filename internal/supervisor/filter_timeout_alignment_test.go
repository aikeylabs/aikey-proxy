// filter_timeout_alignment_test.go — fences for "the proxy must not time out
// before the detector does" (2026-08-10).
//
// # The defect these pin
//
// filterDefaultTimeout was set to 80ms on 2026-06-01 in the first compliance
// commit and never revisited. On 2026-08-08 the user decided ENGINE-LEVEL tiered
// lane deadlines inside the detector (≤16KB → 100ms, larger → 1s) and made them
// the single source of truth for all four lanes. Nobody reconciled the two, so
// the proxy's budget was 20ms STRICTER than the engine's own smallest tier: the
// proxy abandoned Detect while the engine was still legitimately working, the
// decided 100ms could never be spent, and the only observable effect of the
// mismatch was the degrade path — fail-open, nothing masked, and (because
// degraded verdicts are deliberately not cached) a fresh timeout every turn.
//
// # What "aligned" means, and what must stay true
//
//	proxy deadline  >  detector lane deadline  +  IPC round-trip margin
//
// The detector's deadline is the one that should fire; the proxy's exists for
// the case the detector cannot answer AT ALL (hung child, desynced pipe), which
// is why it must stay finite. Both fences below must go RED if either side
// drifts — that is the whole point, since the two constants live in two repos
// and there is no compiler link between them.
package supervisor

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// TestFilterTimeout_ExceedsDetectorLaneBudget is the always-on half: it pins the
// RELATIONSHIP between the proxy-side constants. It cannot see the detector, so
// it is paired with the mirror check below.
func TestFilterTimeout_ExceedsDetectorLaneBudget(t *testing.T) {
	if filterDefaultTimeout <= detectorLaneDeadlineSmall {
		t.Fatalf("🔴 proxy per-Detect deadline (%s) is not above the detector's own per-lane deadline (%s).\n\n"+
			"The proxy would abandon Detect while the engine is still allowed to work, so the tiered lane "+
			"deadline the user decided on 2026-08-08 can never be spent. The visible effect is NOT lower "+
			"latency — it is degrade → fail-open → nothing masked, re-paid every turn because degraded "+
			"verdicts are not cached.",
			filterDefaultTimeout, detectorLaneDeadlineSmall)
	}
	if detectorIPCMargin <= 0 {
		t.Fatal("detectorIPCMargin must be positive: the lane deadline does not cover the framed pipe " +
			"round-trip, req-id demux, action policy or planner")
	}
	if want := detectorLaneDeadlineSmall + detectorIPCMargin; filterDefaultTimeout != want {
		t.Fatalf("filterDefaultTimeout must be derived (lane deadline + IPC margin) rather than restated: "+
			"got %s, want %s", filterDefaultTimeout, want)
	}
	// Still finite and still bounded: a wedged detector must degrade within about
	// one request's worth of latency, not stall the caller for a second.
	if filterDefaultTimeout > 500*time.Millisecond {
		t.Fatalf("filterDefaultTimeout=%s is too generous to double as hang protection for a wedged "+
			"detector child (§6 #11: never block the main LLM path)", filterDefaultTimeout)
	}
}

// TestFilterTimeout_MirrorsDetectorLaneDeadline is the cross-repo half: it reads
// the detector's OWN source and asserts our mirror still matches, so a change on
// the detector side turns this red instead of silently re-opening the gap.
//
// Gating: the detector is a sibling module in the same go.work tree. When that
// tree is present (the monorepo, and therefore every CI run) the check is
// MANDATORY — a missing file there is a failure, not a skip. Only a standalone
// checkout of aikey-proxy alone (no go.work) is exempt, and that configuration
// cannot build the detector to run against anyway.
func TestFilterTimeout_MirrorsDetectorLaneDeadline(t *testing.T) {
	root, ok := monorepoRoot()
	if !ok {
		t.Skip("standalone aikey-proxy checkout (no sibling go.work): the detector source is not " +
			"available to mirror-check against; TestFilterTimeout_ExceedsDetectorLaneBudget still runs")
	}
	enginePath := filepath.Join(root, "ai-compliance-detector", "internal", "compliance", "engine.go")
	src, err := os.ReadFile(enginePath)
	if err != nil {
		t.Fatalf("go.work names ai-compliance-detector but %s is unreadable (%v).\n"+
			"This fence is the only link between the proxy's per-Detect budget and the detector's lane "+
			"deadline. If the constant moved, update detectorLaneDeadlineSmall AND this path together — "+
			"do not delete the fence.", enginePath, err)
	}
	re := regexp.MustCompile(`laneDeadlineSmall\s*=\s*(\d+)\s*\*\s*time\.(Millisecond|Second)`)
	m := re.FindSubmatch(src)
	if m == nil {
		t.Fatalf("could not find laneDeadlineSmall in %s — the detector's deadline declaration changed "+
			"shape. Re-read it and re-point this fence; leaving it unparsed would silently stop guarding "+
			"the relationship.", enginePath)
	}
	got := parseDuration(t, string(m[1]), string(m[2]))
	if got != detectorLaneDeadlineSmall {
		t.Fatalf("🔴 detector laneDeadlineSmall is now %s but the proxy mirrors %s.\n\n"+
			"The proxy cannot import this constant (separate module, and the detector is a spawned child "+
			"rather than a library), so the mirror is the contract. Update detectorLaneDeadlineSmall in "+
			"filter_hook.go — filterDefaultTimeout is derived from it and will follow.\n"+
			"Source: %s", got, detectorLaneDeadlineSmall, enginePath)
	}
}

// TestFilterTimeout_EnvOverrideKeepsTheRelationship documents what the shipped
// installers configure. Both compliance-enforcing faces (lobster form-② de-proxy
// and cluster nodes) set 200ms — above the lane budget, so the alignment holds
// for them too. This fence catches a future installer edit that drops below it.
func TestFilterTimeout_EnvOverrideKeepsTheRelationship(t *testing.T) {
	const shippedOverrideMs = 200 // openclaw-de-install.sh + cluster-install.sh
	if d := time.Duration(shippedOverrideMs) * time.Millisecond; d <= detectorLaneDeadlineSmall {
		t.Fatalf("the value shipped by the installers (%dms) is at or below the detector lane deadline "+
			"(%s): every enforcing deployment would run in permanent degrade/fail-open",
			shippedOverrideMs, detectorLaneDeadlineSmall)
	}
	t.Setenv(filterTimeoutMsEnv, "1")
	if got := filterTimeout(); got != time.Millisecond {
		t.Fatalf("an explicit override must still be honored (operators own their boxes); got %s", got)
	}
	t.Setenv(filterTimeoutMsEnv, "")
	if got := filterTimeout(); got != filterDefaultTimeout {
		t.Fatalf("empty override must fall back to the derived default; got %s", got)
	}
}

// monorepoRoot walks up from the test's working directory looking for the
// go.work that names both modules.
func monorepoRoot() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", false
}

func parseDuration(t *testing.T, n, unit string) time.Duration {
	t.Helper()
	var mult time.Duration
	switch unit {
	case "Millisecond":
		mult = time.Millisecond
	case "Second":
		mult = time.Second
	default:
		t.Fatalf("unhandled duration unit %q", unit)
	}
	var v int
	for _, c := range n {
		v = v*10 + int(c-'0')
	}
	return time.Duration(v) * mult
}
