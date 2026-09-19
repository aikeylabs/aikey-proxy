package supervisor

// grading_key_presence_test.go — TODO-61: the proxy must keep "the policy
// response had NO `grading` member" (an old master) apart from "it had one and
// it was `{}`" (a new master whose org configured no ladder) all the way into
// the detector child's AIKEY_COMPLIANCE_GRADING env.
//
// Why it matters: the detector decides from that env alone whether the master
// understands 分级 keys on an intake event (level / leaf_path / max_level). When
// the two answers collapsed into one `{}`, an org that had built a
// classification tree but no ladder saw every finding as 未分级 in the audit
// page, although the tree had graded it. The tree is data, the ladder is
// policy; R-compliance-grading-1 (stamp the leaf's level) must not depend on
// whether a ladder exists.
//
// No field is added (拍板 15): the distinction is already on the wire — the
// member is either there or not — and this fence is about not throwing it away.
//
// 需求包: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
//         task-execution/TODO.md TODO-61
//
// 能红: make normalizeGradingPolicy map `{}` to nil again (the pre-TODO-61
// behaviour) and the "{}" arm fails; make gradingEnvValue spell "no member" as
// "{}" again and the absent arm fails.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

func TestGradingDownlink_KeyPresenceSurvivesToTheChild(t *testing.T) {
	const ladderDoc = `{"labels":{"4":"L4"},"ladder":{"4":{"action":"mask"}}}`
	arms := []struct {
		name     string
		body     string
		wantEnv  string // exact AIKEY_COMPLIANCE_GRADING value the child is spawned with
		wantJSON string // gradingPolicyJSON(); "" ⇒ nil
	}{
		// Old master: the member is absent. The child must receive NO document,
		// which is exactly what a pre-grading proxy handed it (nothing at all).
		{name: "absent", body: `{"enabled":true,"privacy_tier":1}`, wantEnv: "", wantJSON: ""},
		// New master, grading not configured: the member is present and empty.
		{name: "empty object", body: `{"enabled":true,"privacy_tier":1,"grading":{}}`, wantEnv: "{}", wantJSON: "{}"},
		// New master, ladder configured: unchanged behaviour.
		{name: "non-empty", body: `{"enabled":true,"privacy_tier":1,"grading":` + ladderDoc + `}`,
			wantEnv: ladderDoc, wantJSON: ladderDoc},
	}

	envs := map[string]string{}
	sigs := map[string]string{}
	for _, arm := range arms {
		t.Run(arm.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(arm.body))
			}))
			defer srv.Close()

			s := &Supervisor{}
			enabled, tier, adv, grading, ok := fetchComplianceMasterPolicy(t.Context(), srv.URL, "org-1")
			if !ok {
				t.Fatalf("a usable answer must be reported usable (ok=false)")
			}
			s.applyComplianceMasterPolicy(enabled, tier, adv, grading, ok)
			gotJSON := s.gradingPolicyJSON()
			// Recorded before any Fatal so the cross-arm checks below report the
			// real values even when an arm fails.
			envs[arm.name] = s.gradingEnvValue()
			sigs[arm.name] = filterSigWithGrading("base", gotJSON)

			if got := s.gradingEnvValue(); got != arm.wantEnv {
				t.Fatalf("AIKEY_COMPLIANCE_GRADING = %q, want %q — the child can only tell an old "+
					"master from an unconfigured new one by this value (TODO-61)", got, arm.wantEnv)
			}
			if (arm.wantJSON == "") != (gotJSON == nil) || string(gotJSON) != arm.wantJSON {
				t.Fatalf("gradingPolicyJSON() = %q (nil=%v), want %q", gotJSON, gotJSON == nil, arm.wantJSON)
			}

			// Proxy-side enforcement must not tell absent from `{}`: neither
			// declares an escalation rule or a route policy, so both must install
			// nothing — the ACTION does not move, only the audit wiring does.
			p := &proxy.Proxy{}
			applied, refused, err := p.SetComplianceGrading(gotJSON)
			if err != nil || len(refused) != 0 {
				t.Fatalf("SetComplianceGrading(%q): err=%v refused=%v", gotJSON, err, refused)
			}
			if arm.name != "non-empty" && (applied != 0 || len(p.ComplianceEscalationRules()) != 0) {
				t.Fatalf("%s must install no escalation rule, got %d", arm.name, applied)
			}
		})
	}

	// The three states must stay three on every carrier: the env (what the child
	// decides with) and the filter signature (what re-spawns the child when an
	// old master is upgraded to one that answers `{}`).
	if envs["absent"] == envs["empty object"] {
		t.Errorf("absent and `{}` reach the child as the same env %q — the detector cannot tell "+
			"an old master from grading-not-configured (TODO-61)", envs["absent"])
	}
	if sigs["absent"] == sigs["empty object"] {
		t.Error("absent → `{}` does not move the filter signature; the running child keeps the old env")
	}
	if envs["empty object"] == envs["non-empty"] || sigs["empty object"] == sigs["non-empty"] {
		t.Error("`{}` and a configured ladder collapsed")
	}
}
