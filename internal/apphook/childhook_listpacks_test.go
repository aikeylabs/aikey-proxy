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
			BundleSHA256              string `json:"bundle_sha256"`
			CandidateBehaviorSHA256   string `json:"candidate_behavior_sha256"`
			IntegrationBehaviorSHA256 string `json:"integration_behavior_sha256"`
			HistoryEvidenceSHA256     string `json:"history_evidence_sha256"`
			MaxAction                 string `json:"max_action"`
			RiskAccepted              bool   `json:"risk_accepted"`
			QualityGatePassed         bool   `json:"quality_gate_passed"`
			SpikeEquivalencePassed    bool   `json:"spike_equivalence_passed"`
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
	if rep.ActionPolicy.BundleSHA256 != "57ea464eaef3fea58e60506439617a5782bf640bc894902e5bf8513f6a07fd6e" ||
		rep.ActionPolicy.CandidateBehaviorSHA256 != "da0553054ef45f1aa95aacddfcbbf7ae5c3933d662568aaf29e92c09ea2bd632" ||
		rep.ActionPolicy.IntegrationBehaviorSHA256 != "0649b62ee67905fdf59cb52b831c8c987817b7294601dd31b63216a0c918033d" ||
		rep.ActionPolicy.HistoryEvidenceSHA256 != "68d8f134f80af7c31916e2a2e62651a667bee3a6463b61fc025e12f61408c4a3" ||
		rep.ActionPolicy.MaxAction != "full" || !rep.ActionPolicy.RiskAccepted || rep.ActionPolicy.QualityGatePassed || !rep.ActionPolicy.SpikeEquivalencePassed {
		t.Fatalf("active action policy is not externally readable: %+v", rep.ActionPolicy)
	}

	// Detect still works on the same pipe right after the meta query.
	res := h.Detect(ctx, &Request{Payload: []byte("How do I write a for loop?")})
	if res.Degraded {
		t.Errorf("Detect degraded after ListPacks: %s", res.Reason)
	}
}
