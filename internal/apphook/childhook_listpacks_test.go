package apphook

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestChildHook_ListPacks spawns the real detector and queries its effective
// packs over the shared Detect pipe (op=ListPacks, Option A). Verifies the
// built-in baseline is reported AND that a normal Detect still works on the same
// pipe right after — i.e. the meta query coexists with detection (serialized,
// but each completes).
func TestChildHook_ListPacks(t *testing.T) {
	binary, sealed := requireSealedDetector(t)
	h := NewChildHook(&ChildHookConfig{
		Name:         "ai-compliance-detector-listpacks-test",
		BinaryPath:   binary,
		Timeout:      2 * time.Second,
		ReadyTimeout: 5 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Skipf("child binary unavailable (build first): %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()
	// This test is the reason the door seals: its lane_actions assertion below
	// reads "mask" from the SHIPPED policy, and a policy.json in a real $HOME
	// rewrites it to whatever the operator chose (measured 2026-08-14 → RED).
	sealed.AssertHeld(t, h)

	report, err := h.ListPacks(ctx)
	if err != nil {
		t.Fatalf("ListPacks: %v", err)
	}
	var rep struct {
		BuiltIn []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"built_in"`
		Pulled       []json.RawMessage `json:"pulled"`
		ActionPolicy struct {
			BundleSHA256              string            `json:"bundle_sha256"`
			CandidateBehaviorSHA256   string            `json:"candidate_behavior_sha256"`
			IntegrationBehaviorSHA256 string            `json:"integration_behavior_sha256"`
			HistoryEvidenceSHA256     string            `json:"history_evidence_sha256"`
			MaxAction                 string            `json:"max_action"`
			RiskAccepted              bool              `json:"risk_accepted"`
			QualityGatePassed         bool              `json:"quality_gate_passed"`
			SpikeEquivalencePassed    bool              `json:"spike_equivalence_passed"`
			SpikeBaselinePreserved    bool              `json:"spike_baseline_preserved"`
			SafetyDeltaVerified       bool              `json:"safety_delta_verified"`
			LaneActions               map[string]string `json:"lane_actions"`
			LaneGradeCeilings         map[string]string `json:"lane_grade_ceilings"`
		} `json:"action_policy"`
	}
	if err := json.Unmarshal(report, &rep); err != nil {
		t.Fatalf("decode report: %v (raw=%q)", err, report)
	}
	if len(rep.BuiltIn) == 0 {
		t.Errorf("expected built-in packs in report, got none (raw=%q)", report)
	}
	for _, b := range rep.BuiltIn {
		if b.Kind != "built-in" {
			t.Errorf("built-in kind: got %q", b.Kind)
		}
	}
	// ── This literal is a CROSS-REPO binding, and it is deliberately a literal ──
	//
	// aikey-proxy has no access to the detector SOURCE tree at test time — it
	// locates a BUILT binary (see requireSealedDetector), which may come from
	// AIKEY_TEST_DETECTOR_BINARY or anywhere else. Deriving the expected SHA
	// from the binary's own report would be comparing the binary to itself, so
	// this side of the contract has to state independently which bundle the
	// proxy expects to be talking to. That is the whole value of the assertion.
	//
	// The cost is that every active-bundle migration must update this line.
	// That cost is NOT paid by remembering: aikey-test's
	// TestActiveBundleSHAHasNoStaleMirrors scans every tracks-active mirror in
	// the labs tree against ai-compliance-detector's active-bundle.json pointer
	// and names this file if it goes stale. Wave5 -> Wave6 (2026-08-17) is
	// exactly the miss that fence exists to make impossible.
	//
	// SpikeBaselinePreserved is FALSE for Wave6/Wave7 on purpose: both depart
	// from the frozen Candidate-v9 stage set (Wave7 admits the two anchored
	// password-prefix rules at ordinal 3) and carry their own measured safety
	// delta (SafetyDeltaVerified) instead. actionpolicy/bundle.go pins that
	// per-wave; asserting the value here proves it survives the IPC hop.
	if rep.ActionPolicy.BundleSHA256 != "6a31d257f08d4d18689f656bf3cb957867c4c5e93677d56ab1aaf4b87bc36a04" ||
		rep.ActionPolicy.CandidateBehaviorSHA256 != "da0553054ef45f1aa95aacddfcbbf7ae5c3933d662568aaf29e92c09ea2bd632" ||
		rep.ActionPolicy.IntegrationBehaviorSHA256 != "1da55d2cc3130de7bea5cbf8dafdd1cffd46048e3f3d9e0eba7394c9a0df8d60" ||
		rep.ActionPolicy.HistoryEvidenceSHA256 != "68d8f134f80af7c31916e2a2e62651a667bee3a6463b61fc025e12f61408c4a3" ||
		rep.ActionPolicy.MaxAction != "full" || !rep.ActionPolicy.RiskAccepted || rep.ActionPolicy.QualityGatePassed || rep.ActionPolicy.SpikeEquivalencePassed || rep.ActionPolicy.SpikeBaselinePreserved || !rep.ActionPolicy.SafetyDeltaVerified {
		t.Fatalf("active action policy is not externally readable: %+v", rep.ActionPolicy)
	}
	if rep.ActionPolicy.LaneActions["CN_ADDRESS"] != "mask" ||
		rep.ActionPolicy.LaneGradeCeilings["address.cn_address.tier_warn"] != "warn" ||
		rep.ActionPolicy.LaneGradeCeilings["address.cn_address.tier_mask"] != "mask" {
		t.Fatalf("tier-aware CN_ADDRESS runtime state is not externally readable: %+v", rep.ActionPolicy)
	}

	// Detect still works on the same pipe right after the meta query.
	res := h.Detect(ctx, &Request{Payload: []byte("How do I write a for loop?")})
	if res.Degraded {
		t.Errorf("Detect degraded after ListPacks: %s", res.Reason)
	}
}
