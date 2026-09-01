package supervisor

// password_tier_downlink_test.go — org password-lane force downlink fences
// (阶段8/合规密码档分级 R-credential-password-tier-4). Mirrors
// privacy_tier_downlink_test.go: the wire decode's failure direction and the
// spawn-signature term that turns a force flip into a re-spawn.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFetchComplianceMasterPolicy_PasswordTierFailureDirection: only the exact
// value "advanced" forces; absent field (old master), unknown values and
// errors all land on "no force" — the fleet fails toward the factory simple
// level, never toward surprise enforcement.
func TestFetchComplianceMasterPolicy_PasswordTierFailureDirection(t *testing.T) {
	cases := []struct {
		name, body   string
		wantAdvanced bool
	}{
		{"forced", `{"enabled":true,"privacy_tier":1,"password_tier":"advanced"}`, true},
		{"absent field (old master)", `{"enabled":true,"privacy_tier":1}`, false},
		{"empty", `{"enabled":true,"privacy_tier":1,"password_tier":""}`, false},
		{"unknown value", `{"enabled":true,"privacy_tier":1,"password_tier":"paranoid"}`, false},
		{"simple is not a force", `{"enabled":true,"privacy_tier":1,"password_tier":"simple"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			_, _, advanced, ok := fetchComplianceMasterPolicy(t.Context(), srv.URL, "org-1")
			if !ok {
				t.Fatal("policy fetch must succeed")
			}
			if advanced != c.wantAdvanced {
				t.Fatalf("passwordAdvanced = %v, want %v", advanced, c.wantAdvanced)
			}
		})
	}
}

// TestFilterSig_ChangesWithPasswordTier: the force is baked into the child env
// at spawn, so flipping it MUST change the filter signature or a running
// detector keeps the level it was born with (the privacy-tier lesson).
// 能红 check: drop the pwtier term from filterSigWithPasswordTier.
func TestFilterSig_ChangesWithPasswordTier(t *testing.T) {
	base := "apps:x|stages:pre_forward"
	off := filterSigWithPasswordTier(base, false)
	on := filterSigWithPasswordTier(base, true)
	if off == on {
		t.Fatal("signature must differ when the org force flips, or no re-spawn happens")
	}
	if filterSigWithPasswordTier(base, true) != on {
		t.Fatal("signature must be deterministic")
	}
}
