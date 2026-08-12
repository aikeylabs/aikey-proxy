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
			MaxAction                 string `json:"max_action"`
			RiskAccepted              bool   `json:"risk_accepted"`
			QualityGatePassed         bool   `json:"quality_gate_passed"`
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
	if rep.ActionPolicy.BundleSHA256 != "1fa983ebb670967dd00a10e37b58217a2432761e68783633405952322bc2f01f" ||
		rep.ActionPolicy.CandidateBehaviorSHA256 != "da0553054ef45f1aa95aacddfcbbf7ae5c3933d662568aaf29e92c09ea2bd632" ||
		rep.ActionPolicy.IntegrationBehaviorSHA256 != "1da55d2cc3130de7bea5cbf8dafdd1cffd46048e3f3d9e0eba7394c9a0df8d60" ||
		rep.ActionPolicy.MaxAction != "full" || !rep.ActionPolicy.RiskAccepted || rep.ActionPolicy.QualityGatePassed {
		t.Fatalf("active action policy is not externally readable: %+v", rep.ActionPolicy)
	}

	// Detect still works on the same pipe right after the meta query.
	res := h.Detect(ctx, &Request{Payload: []byte("How do I write a for loop?")})
	if res.Degraded {
		t.Errorf("Detect degraded after ListPacks: %s", res.Reason)
	}
}
