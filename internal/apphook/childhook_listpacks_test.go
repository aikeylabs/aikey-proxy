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
	binary := requireDetectorBinary(t)
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
	if rep.ActionPolicy.BundleSHA256 != "d33a0c33ecd4c5e2859e43deac5b127e03d18b18f8f1932010a5f2c9f566e814" ||
		rep.ActionPolicy.CandidateBehaviorSHA256 != "da0553054ef45f1aa95aacddfcbbf7ae5c3933d662568aaf29e92c09ea2bd632" ||
		rep.ActionPolicy.IntegrationBehaviorSHA256 != "1da55d2cc3130de7bea5cbf8dafdd1cffd46048e3f3d9e0eba7394c9a0df8d60" ||
		rep.ActionPolicy.HistoryEvidenceSHA256 != "68d8f134f80af7c31916e2a2e62651a667bee3a6463b61fc025e12f61408c4a3" ||
		rep.ActionPolicy.MaxAction != "full" || !rep.ActionPolicy.RiskAccepted || rep.ActionPolicy.QualityGatePassed || rep.ActionPolicy.SpikeEquivalencePassed || !rep.ActionPolicy.SpikeBaselinePreserved || !rep.ActionPolicy.SafetyDeltaVerified {
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
