package proxy

// license_plane_cache_test.go — the fences under the forwarding gate's cache.
//
// Each of these guards a decision that looks like a detail and is not. The
// staleness ceiling, the never-synced default and hydration are the three rules
// that decide whether the gate is enforceable, whether it is safe, and whether a
// restart clears it. See
// workflow/CI/bugfix/20260827-forwarding-gate-was-never-wired.md.

import (
	"encoding/json"
	"testing"
	"time"
)

// at builds a cache whose clock is fixed, so the ceiling can be exercised
// without waiting seven days.
func atClock(t *testing.T, now time.Time) *LicensePlaneCache {
	t.Helper()
	c := NewLicensePlaneCache()
	c.now = func() time.Time { return now }
	return c
}

var testNow = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

// TestNeverSyncedAllows is the fence under the one fail-open that must survive.
//
// 🔴 Personal has no control plane and no licence, and every deployment passes
// through this state between process start and the rail's first cycle. A cache
// that denied here would be a licensing mechanism that stops correctly licensed
// deployments — R8's "读不到不停服", and the reason PlaneGate on the control side
// starts allowing too.
func TestNeverSyncedAllows(t *testing.T) {
	c := atClock(t, testNow)
	if !c.ForwardingAllowed() {
		t.Fatal("a cache that has never synced refused forwarding. Personal has no " +
			"control plane to ask, and every edition is in this state at start-up: " +
			"denying here stops deployments that have done nothing wrong.")
	}
	if h := c.Health(); h.Source != LicensePlaneSourceNeverSynced || h.Forwarding != licenseGateAllow {
		t.Fatalf("health = %+v; want source=%s forwarding=%s", h, LicensePlaneSourceNeverSynced, licenseGateAllow)
	}
	// 🚫 And a nil cache — an older build, or a test harness that wired none —
	// must behave the same way rather than panicking or denying.
	var nilCache *LicensePlaneCache
	if !nilCache.ForwardingAllowed() {
		t.Error("a nil cache refused forwarding")
	}
}

// TestObservedGateIsHonoured is the base case: the gate actually gates.
func TestObservedGateIsHonoured(t *testing.T) {
	for _, tc := range []struct {
		gate string
		want bool
	}{
		{licenseGateAllow, true},
		{licenseGateDeny, false},
	} {
		c := atClock(t, testNow)
		c.Observe(tc.gate, testNow)
		if got := c.ForwardingAllowed(); got != tc.want {
			t.Errorf("gate %q → ForwardingAllowed()=%v, want %v", tc.gate, got, tc.want)
		}
	}
}

// TestStaleCeilingDenies is the fence under the owner decision of 2026-08-27.
//
// 🔴 Keep-last-known with NO ceiling is the obvious design and it makes the whole
// gate theatre: a customer who firewalls their own control plane the day before
// expiry keeps the last `allow` for ever. This asserts the bound exists, that it
// is the documented seven days, and — the half that is easy to get wrong — that
// it applies to a stale ALLOW rather than only to a stale deny.
func TestStaleCeilingDenies(t *testing.T) {
	observed := testNow.Add(-LicensePlaneStaleCeiling).Add(-time.Minute)
	c := atClock(t, testNow)
	c.Observe(licenseGateAllow, observed)

	if c.ForwardingAllowed() {
		t.Fatalf("an `allow` observed %v ago was still honoured. Without this bound, "+
			"disconnecting the control plane is an unlimited licence.",
			testNow.Sub(observed))
	}
	h := c.Health()
	if h.Source != LicensePlaneSourceStaleCeiling {
		t.Errorf("health source = %q, want %q", h.Source, LicensePlaneSourceStaleCeiling)
	}
	if h.Forwarding != licenseGateDeny {
		t.Errorf("health reported forwarding=%q while requests are being refused. /status "+
			"must report the EFFECTIVE answer, or it sends an operator looking in the "+
			"wrong place.", h.Forwarding)
	}

	// 🔴 And the other side of the boundary, so the fence cannot pass by denying
	// everything. Just inside the ceiling must still be honoured.
	fresh := atClock(t, testNow)
	fresh.Observe(licenseGateAllow, testNow.Add(-LicensePlaneStaleCeiling).Add(time.Minute))
	if !fresh.ForwardingAllowed() {
		t.Error("an `allow` just INSIDE the ceiling was refused; the bound is off by more " +
			"than the test's margin, or it is being applied in the wrong direction")
	}
}

// TestStaleCeilingIsSevenDays pins the number itself.
//
// A separate assertion from the behaviour above because the behaviour would keep
// passing if somebody widened the constant to a year — which is precisely the
// change that would quietly restore the bypass.
func TestStaleCeilingIsSevenDays(t *testing.T) {
	if LicensePlaneStaleCeiling != 7*24*time.Hour {
		t.Fatalf("LicensePlaneStaleCeiling is %v; the owner decision of 2026-08-27 fixes it "+
			"at 7 days. Widening it widens the window in which a deployment that has "+
			"stopped being licensed keeps forwarding — that is a licensing decision, "+
			"not a timeout to tune.", LicensePlaneStaleCeiling)
	}
}

// TestHydrateSurvivesRestart is the fence under "a gate a restart clears is not
// a gate".
//
// 🔴 Without hydration `deny` lives only in memory. Restarting the proxy — which
// any user may do, and which a crash does for them — would return the cache to
// never-synced and forward again, so the enforcement window would be "until
// somebody restarts".
func TestHydrateSurvivesRestart(t *testing.T) {
	// A previous process observed `deny` an hour ago and persisted it.
	first := atClock(t, testNow)
	first.Observe(licenseGateDeny, testNow.Add(-time.Hour))
	gate, observedAt, ok := first.Snapshot()
	if !ok {
		t.Fatal("nothing to persist after an observation")
	}

	// The process restarts.
	restarted := atClock(t, testNow)
	restarted.Hydrate(gate, observedAt)

	if restarted.ForwardingAllowed() {
		t.Fatal("a restarted proxy forwarded again after the control plane had denied it. " +
			"The gate must survive a restart, or its enforcement window is 'until " +
			"somebody restarts the process'.")
	}
	if h := restarted.Health(); h.Source != LicensePlaneSourceHydrated {
		t.Errorf("health source = %q, want %q — an operator reading a deny needs to know "+
			"whether this process has spoken to the control plane since it started",
			h.Source, LicensePlaneSourceHydrated)
	}
}

// TestHydrateNeverOverwritesALiveObservation.
//
// The rail hydrates before its first cycle, so this ordering should not arise —
// which is exactly why it is asserted rather than assumed. A hydrate that could
// overwrite a live answer would let a stale file on disk resurrect a gate the
// control plane had already replaced.
func TestHydrateNeverOverwritesALiveObservation(t *testing.T) {
	c := atClock(t, testNow)
	c.Observe(licenseGateDeny, testNow)
	c.Hydrate(licenseGateAllow, testNow.Add(-time.Hour))

	if c.ForwardingAllowed() {
		t.Fatal("a hydrated `allow` from disk overwrote a live `deny` from the control plane")
	}
	if h := c.Health(); h.Source != LicensePlaneSourceLive {
		t.Errorf("health source = %q, want %q", h.Source, LicensePlaneSourceLive)
	}
}

// TestHydrateRejectsAnEmptyTimestamp.
//
// A zero observedAt would be read as "observed at the Unix epoch", which is
// beyond any ceiling and would therefore DENY — turning a corrupt or truncated
// state file into an outage. The file's own reader validates too; this is the
// second layer, at the type that makes the decision.
func TestHydrateRejectsAnEmptyTimestamp(t *testing.T) {
	c := atClock(t, testNow)
	c.Hydrate(licenseGateAllow, time.Time{})
	if !c.ForwardingAllowed() {
		t.Fatal("a state file with no timestamp denied forwarding; a corrupt file must " +
			"leave the cache never-synced, not stop the deployment")
	}
	if c.Synced() {
		t.Error("a rejected hydration still marked the cache as synced")
	}
}

// TestHealthIsSerialisableAndNamesItsCeiling.
//
// /status is the health-signal-surface contract for this gate: the release E2E
// asserts against these keys rather than against a log line. The ceiling is
// reported so the number in force is readable from outside rather than being a
// constant a reader has to go and find in a source file.
func TestHealthIsSerialisableAndNamesItsCeiling(t *testing.T) {
	c := atClock(t, testNow)
	c.Observe(licenseGateDeny, testNow.Add(-90*time.Second))

	raw, err := json.Marshal(c.Health())
	if err != nil {
		t.Fatalf("marshal health: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal health: %v", err)
	}
	for _, key := range []string{"forwarding", "source", "last_success_at", "age_seconds", "stale_ceiling_seconds"} {
		if _, ok := got[key]; !ok {
			t.Errorf("/status license_plane is missing %q: %s", key, raw)
		}
	}
	if got["stale_ceiling_seconds"].(float64) != float64(LicensePlaneStaleCeiling/time.Second) {
		t.Errorf("reported ceiling %v does not match the constant %v",
			got["stale_ceiling_seconds"], LicensePlaneStaleCeiling)
	}
}

// TestSnapshotReturnsTheStoredValueNotTheEffectiveOne.
//
// 🔴 Persisting the ceiling's `deny` would freeze a deployment into a refusal
// that outlived the outage that caused it: the next process would hydrate a
// `deny` whose timestamp is old, deny again, and re-persist — and a later
// successful poll could no longer be told apart from the stale state it
// replaced.
func TestSnapshotReturnsTheStoredValueNotTheEffectiveOne(t *testing.T) {
	c := atClock(t, testNow)
	stale := testNow.Add(-LicensePlaneStaleCeiling).Add(-time.Hour)
	c.Observe(licenseGateAllow, stale)

	if c.ForwardingAllowed() {
		t.Fatal("precondition: the observation should be past the ceiling")
	}
	gate, at, ok := c.Snapshot()
	if !ok {
		t.Fatal("Snapshot reported nothing to persist")
	}
	if gate != licenseGateAllow {
		t.Errorf("Snapshot returned %q; it must return the STORED gate (%q), not the "+
			"effective one, or the ceiling's verdict gets written to disk as though the "+
			"control plane had said it", gate, licenseGateAllow)
	}
	if !at.Equal(stale) {
		t.Errorf("Snapshot returned observedAt %v, want the original %v", at, stale)
	}
}
