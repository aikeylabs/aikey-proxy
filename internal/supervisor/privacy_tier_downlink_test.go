package supervisor

// Fences for the compliance privacy-tier downlink.
//
// WHAT THIS GUARDS
// ----------------
// The org's control-master decides how much of a user's own text the detector
// on this machine may attach to compliance events. The proxy is the courier for
// that decision, and it is the ONLY courier — the whole design rests on the fact
// that nothing on an employee's machine can raise the tier. Three ways this
// courier can quietly fail, one fence each:
//
//	1. it reads a value it does not understand and guesses upward
//	   (an older master that does not send the field at all is the common case)
//	2. it accepts a local override, making the org's decision advisory
//	3. it delivers a change but never re-spawns the child, so the running
//	   detector keeps sending under the OLD policy while everything looks applied
//
// #3 is the sneaky one: an admin lowers the tier, the server dutifully stops
// STORING raw snippets, the audit page goes quiet — and employees' machines keep
// putting raw text on the network for as long as the child lives.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestClampPrivacyTier_FailsClosed pins the normaliser.
//
// 能红 check: make clampPrivacyTier pass unknown values through, or default to
// anything above 1, and this fails.
func TestClampPrivacyTier_FailsClosed(t *testing.T) {
	for _, tier := range []int{-1, 0, 4, 99} {
		if got := clampPrivacyTier(tier); got != privacyTierMetadataOnly {
			t.Errorf("clampPrivacyTier(%d) = %d, want %d — an uninterpretable tier is not "+
				"permission to send content", tier, got, privacyTierMetadataOnly)
		}
	}
	for _, tier := range []int{1, 2, 3} {
		if got := clampPrivacyTier(tier); got != tier {
			t.Errorf("clampPrivacyTier(%d) = %d, want it unchanged", tier, got)
		}
	}
}

// TestFetchCompliancePolicy_TierFromServer covers what the wire can hand us.
//
// The `field absent` case is not hypothetical: every master built before
// 2026-08-11 answers exactly that, and every proxy in the field will meet one
// during a rolling upgrade. Decoding it to Go's zero value and treating that as
// a tier would be a silent widening on the oldest servers in the fleet.
//
// 能红 check: remove the clamp from fetchComplianceMasterPolicy and the
// "field absent" / "tier out of range" rows fail.
func TestFetchCompliancePolicy_TierFromServer(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		status   int
		wantOK   bool
		wantTier int
	}{
		{"tier 3 granted", `{"enabled":true,"privacy_tier":3}`, 200, true, 3},
		{"tier 2", `{"enabled":true,"privacy_tier":2}`, 200, true, 2},
		{"tier 1", `{"enabled":true,"privacy_tier":1}`, 200, true, 1},
		{"field absent (master older than the feature)", `{"enabled":true}`, 200, true, 1},
		{"tier out of range", `{"enabled":true,"privacy_tier":9}`, 200, true, 1},
		{"tier negative", `{"enabled":true,"privacy_tier":-3}`, 200, true, 1},
		{"malformed body", `not json`, 200, false, 1},
		{"server error", `{"enabled":true,"privacy_tier":3}`, 500, false, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()

			_, tier, ok := fetchComplianceMasterPolicy(t.Context(), srv.URL, "org-1")
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if tier != c.wantTier {
				t.Fatalf("tier = %d, want %d — every value the server did not clearly grant "+
					"must come back as metadata-only", tier, c.wantTier)
			}
		})
	}
}

// TestPrivacyTier_HasNoLocalOverride is the fence that makes the whole design
// mean something: on the machine whose text is at stake, there must be no way
// to authorise sending it.
//
// It scans this package's sources for the env var name and asserts the ONLY
// occurrences are the one that WRITES the child's environment. A read here —
// `os.Getenv("AIKEY_COMPLIANCE_PRIVACY_TIER")`, however well-intentioned ("so
// we can test locally") — would let anyone with shell access on an employee
// machine grant themselves tier 3.
//
// Written as a source scan rather than a behaviour test on purpose: the failure
// it guards against is a line of code that does not exist yet, and no runtime
// assertion can observe the absence of a future override.
//
// 能红 check: add `os.Getenv("AIKEY_COMPLIANCE_PRIVACY_TIER")` anywhere in this
// package and this fails.
func TestPrivacyTier_HasNoLocalOverride(t *testing.T) {
	const envName = "AIKEY_COMPLIANCE_PRIVACY_TIER"

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var offenders []string
	writers := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		src := string(b)
		if !strings.Contains(src, envName) {
			continue
		}
		// The one legitimate use: building the child's env string.
		if strings.Contains(src, `"`+envName+`=" +`) {
			writers++
		}
		for _, bad := range []string{
			`os.Getenv("` + envName + `")`,
			`os.LookupEnv("` + envName + `")`,
		} {
			if strings.Contains(src, bad) {
				offenders = append(offenders, e.Name()+": "+bad)
			}
		}
	}

	if len(offenders) > 0 {
		t.Fatalf("🔴 the privacy tier is being READ from this machine's environment: %v\n\n"+
			"The tier decides whether this user's own prompt text is uploaded to the team "+
			"server. Its authorisation is the ORGANISATION's, held on the org's server and "+
			"delivered by pollComplianceMasterPolicy. A local read means anyone with shell "+
			"access on an employee's machine can grant it — and an admin has no way to tell.",
			offenders)
	}
	if writers == 0 {
		t.Fatalf("nothing in this package writes %s into the detector's environment any more. "+
			"Either the downlink was removed (in which case the detector permanently sees no "+
			"tier and this fence is guarding nothing), or it moved — re-point this test.", envName)
	}
}

// TestFilterSig_ChangesWithPrivacyTier proves a tier change actually causes a
// re-spawn.
//
// The signature is what syncManagedKeys compares to decide "reload or not". The
// tier is baked into the child's env at spawn. If the two are not connected, a
// tier change is applied everywhere EXCEPT the process it governs — and the
// symptom (raw text still on the network, nothing stored) looks like a working
// system from the server side.
//
// 能红 check: make filterSigWithPrivacyTier ignore its tier argument.
func TestFilterSig_ChangesWithPrivacyTier(t *testing.T) {
	const base = "ai-compliance-detector:false"
	at1 := filterSigWithPrivacyTier(base, 1)
	at3 := filterSigWithPrivacyTier(base, 3)
	if at1 == at3 {
		t.Fatalf("the filter signature is identical at tier 1 and tier 3 (%q). A tier change "+
			"would not re-spawn the detector, so a RUNNING child keeps uploading under the old "+
			"policy — the server stops storing raw text while machines keep sending it", at1)
	}
	if filterSigWithPrivacyTier(base, 3) != at3 {
		t.Fatal("filterSigWithPrivacyTier is not deterministic")
	}
	if !strings.HasPrefix(at3, base) {
		t.Fatalf("the tier must EXTEND the existing signature, not replace it (%q) — the slug "+
			"set and record_allow still have to trigger reloads", at3)
	}
}

// TestCompliancePolicyWireShape_CarriesTier documents the contract between the
// master's public endpoint and this poller in one runnable place, so a change on
// either side has something to fail against.
func TestCompliancePolicyWireShape_CarriesTier(t *testing.T) {
	var shape struct {
		Enabled     bool `json:"enabled"`
		PrivacyTier int  `json:"privacy_tier"`
	}
	if err := json.Unmarshal([]byte(`{"enabled":true,"privacy_tier":3}`), &shape); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !shape.Enabled || shape.PrivacyTier != privacyTierRawSnippet {
		t.Fatalf("GET /v1/compliance/policy must answer {enabled, privacy_tier}; got %+v", shape)
	}
}
