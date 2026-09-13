package supervisor

// password_tier_downlink_test.go — org policy downlink fences for the two
// members of GET /v1/compliance/policy that ride the same courier as the
// privacy tier: the password-lane force (阶段8/合规密码档分级
// R-credential-password-tier-4) and the grading document
// (阶段9/博时基金合规能力融合 R-compliance-grading-5, appended below).
//
// Mirrors privacy_tier_downlink_test.go in both halves: the wire decode's
// failure direction, and the spawn-signature term that turns a change into a
// re-spawn.

import (
	"net/http"
	"net/http/httptest"
	"strings"
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
			_, _, advanced, _, ok := fetchComplianceMasterPolicy(t.Context(), srv.URL, "org-1")
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

// ---------------------------------------------------------------------------
// Task 3.1 — org GRADING policy downlink (R-compliance-grading-5).
//
// Same courier as the two tiers above, one extra hazard: grading is a DOCUMENT,
// not a scalar, so "we could not use what the master sent" is a state that did
// not exist for a bool or an int. There are three of them and they are NOT the
// same thing (design.md §4b, corrected 2026-09-10 after the original text said
// both "always {}" and "keep the valid policy"):
//
//	① the `grading` key is ABSENT        → an old master → {} → grading OFF.
//	                                       This is CORRECT behaviour, not a failure.
//	② the key is there but UNUSABLE      → keep the last valid policy + WARN.
//	③ non-200 / network error            → keep the last valid policy.
//
// 🔴 Writing {} for ② or ③ would let one bad response — one network blip —
// silently switch off compliance grading for an entire organisation, with a
// normal-looking console on the other end. That is the whole reason ok exists as
// a separate return: without it the fetch layer's nil would mean both "the org
// turned grading off" and "I could not reach the org", which are opposites.

// TestFetchComplianceMasterPolicy_GradingFailureDirection pins the REPORTING
// layer: what each wire shape decodes to, and — crucially — which `ok` it comes
// back with, because that bit is what the caller uses to tell ① from ②③.
//
// 能红 check: return `ok=true` on a malformed grading document, or drop the
// pointer-ness of the wire field (so an absent key and an unusable one both
// arrive as an empty value), and the rows below fail.
func TestFetchComplianceMasterPolicy_GradingFailureDirection(t *testing.T) {
	const valid = `{"enabled":true,"privacy_tier":1,` +
		`"grading":{"labels":{"4":"L4"},"ladder":{"4":{"action":"block"}}}}`
	cases := []struct {
		name       string
		body       string
		status     int
		closeEarly bool
		wantOK     bool
		wantNil    bool
	}{
		// ① absent / explicitly empty ⇒ usable answer meaning "grading off".
		{name: "grading key absent (old master)", body: `{"enabled":true,"privacy_tier":1}`, status: 200, wantOK: true, wantNil: true},
		{name: "grading key null", body: `{"enabled":true,"grading":null}`, status: 200, wantOK: true, wantNil: true},
		{name: "grading empty object", body: `{"enabled":true,"grading":{}}`, status: 200, wantOK: true, wantNil: true},
		// ② present but unusable ⇒ NOT an answer; the caller must keep what it has.
		{name: "grading present but malformed JSON", body: `{"enabled":true,"grading":{"ladder":}}`, status: 200, wantOK: false, wantNil: true},
		{name: "grading present but not an object", body: `{"enabled":true,"grading":"nope"}`, status: 200, wantOK: false, wantNil: true},
		// ③ could not be obtained ⇒ also not an answer.
		{name: "non-200", body: valid, status: 500, wantOK: false, wantNil: true},
		{name: "network error", closeEarly: true, wantOK: false, wantNil: true},
		// The happy path, so the fence cannot be satisfied by always failing.
		{name: "normal", body: valid, status: 200, wantOK: true, wantNil: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			if c.closeEarly {
				srv.Close() // nothing is listening on that port any more
			} else {
				defer srv.Close()
			}
			_, _, _, grading, ok := fetchComplianceMasterPolicy(t.Context(), srv.URL, "org-1")
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v — this bit is what tells 'the org turned grading "+
					"off' apart from 'I could not read the policy'", ok, c.wantOK)
			}
			if gotNil := grading == nil; gotNil != c.wantNil {
				t.Fatalf("gradingJSON == nil is %v, want %v (got %q) — the fetch layer only "+
					"REPORTS; it must never invent a policy", gotNil, c.wantNil, grading)
			}
		})
	}
}

// TestGradingDownlink_ThreeFailureStatesAreDistinct pins the DECISION layer: the
// same three states, now measured where it matters — what the detector child
// would actually be spawned with.
//
// The fetch test above can only prove the report is honest. This one proves the
// report is acted on differently in each case, which is the property the
// 2026-09-10 correction is about.
//
// 能红 check: make applyComplianceMasterPolicy store the fetched value
// unconditionally (i.e. drop the fetchOK gate) and ② + ③ fail with "{}".
func TestGradingDownlink_ThreeFailureStatesAreDistinct(t *testing.T) {
	const validBody = `{"enabled":true,"privacy_tier":1,` +
		`"grading":{"labels":{"5":"L5"},"ladder":{"5":{"action":"block"}}}}`

	// seed returns a supervisor that has already taken one GOOD policy, which is
	// the only state in which "keep the last valid one" is a meaningful claim.
	seed := func(t *testing.T) (*Supervisor, string) {
		t.Helper()
		s := &Supervisor{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(validBody))
		}))
		defer srv.Close()
		enabled, tier, adv, grading, ok := fetchComplianceMasterPolicy(t.Context(), srv.URL, "org-1")
		if !ok || grading == nil {
			t.Fatalf("seed policy must be usable; ok=%v grading=%q", ok, grading)
		}
		s.applyComplianceMasterPolicy(enabled, tier, adv, grading, ok)
		env := s.gradingEnvValue()
		if env == gradingPolicyDisabled {
			t.Fatalf("seed did not take: env is %q", env)
		}
		return s, env
	}

	// ① Absent key = an old master = grading OFF. This one SHOULD become {}.
	t.Run("absent key switches grading off", func(t *testing.T) {
		s, seeded := seed(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"enabled":true,"privacy_tier":1}`))
		}))
		defer srv.Close()
		enabled, tier, adv, grading, ok := fetchComplianceMasterPolicy(t.Context(), srv.URL, "org-1")
		changed := s.applyComplianceMasterPolicy(enabled, tier, adv, grading, ok)
		if got := s.gradingEnvValue(); got != gradingPolicyDisabled {
			t.Fatalf("AIKEY_COMPLIANCE_GRADING = %q, want %q — a master that does not speak "+
				"grading means grading is off, not that the last policy sticks forever "+
				"(was %q)", got, gradingPolicyDisabled, seeded)
		}
		if !changed {
			t.Fatal("switching grading off must be reported as a change, or the running " +
				"detector keeps enforcing the ladder it was born with")
		}
	})

	// ② Present but unusable. 🔴 The one the correction is about.
	for _, c := range []struct{ name, body string }{
		{"malformed JSON", `{"enabled":true,"grading":{"ladder":}}`},
		{"not an object", `{"enabled":true,"grading":"nope"}`},
	} {
		t.Run("unusable grading keeps the last valid policy ("+c.name+")", func(t *testing.T) {
			s, seeded := seed(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			enabled, tier, adv, grading, ok := fetchComplianceMasterPolicy(t.Context(), srv.URL, "org-1")
			changed := s.applyComplianceMasterPolicy(enabled, tier, adv, grading, ok)
			if got := s.gradingEnvValue(); got != seeded {
				t.Fatalf("AIKEY_COMPLIANCE_GRADING = %q, want the last valid %q — one "+
					"unusable response must not disable grading for the whole org "+
					"(DEC-compliance-grading-10)", got, seeded)
			}
			if changed {
				t.Fatal("a rejected policy must not report a change; re-spawning here would " +
					"hand the child the same env for no reason")
			}
		})
	}

	// ③ Could not be obtained. Temporarily unreachable ≠ the policy changed.
	t.Run("non-200 keeps the last valid policy", func(t *testing.T) {
		s, seeded := seed(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		enabled, tier, adv, grading, ok := fetchComplianceMasterPolicy(t.Context(), srv.URL, "org-1")
		s.applyComplianceMasterPolicy(enabled, tier, adv, grading, ok)
		if got := s.gradingEnvValue(); got != seeded {
			t.Fatalf("AIKEY_COMPLIANCE_GRADING = %q, want the last valid %q", got, seeded)
		}
	})
	t.Run("network error keeps the last valid policy", func(t *testing.T) {
		s, seeded := seed(t)
		dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		dead.Close()
		enabled, tier, adv, grading, ok := fetchComplianceMasterPolicy(t.Context(), dead.URL, "org-1")
		s.applyComplianceMasterPolicy(enabled, tier, adv, grading, ok)
		if got := s.gradingEnvValue(); got != seeded {
			t.Fatalf("AIKEY_COMPLIANCE_GRADING = %q, want the last valid %q — a network blip "+
				"is not a policy change", got, seeded)
		}
	})
}

// TestFilterSig_ChangesWithGrading: the grading document is baked into the
// detector child's env at spawn, exactly like the two tiers, so an admin editing
// the ladder must move the filter signature or the running child keeps deciding
// by the OLD ladder while the console shows the new one.
//
// 能红 check: make filterSigWithGrading ignore its gradingJSON argument.
func TestFilterSig_ChangesWithGrading(t *testing.T) {
	const base = "ai-compliance-detector:false"
	off := filterSigWithGrading(base, nil)
	l4block := filterSigWithGrading(base, []byte(`{"ladder":{"4":{"action":"block"}}}`))
	l4warn := filterSigWithGrading(base, []byte(`{"ladder":{"4":{"action":"warn"}}}`))
	if l4block == l4warn {
		t.Fatalf("the signature is identical for block and warn at L4 (%q) — changing the "+
			"ladder would not re-spawn the detector", l4block)
	}
	if off == l4block {
		t.Fatal("turning grading on must change the signature")
	}
	if filterSigWithGrading(base, []byte(`{"ladder":{"4":{"action":"block"}}}`)) != l4block {
		t.Fatal("filterSigWithGrading is not deterministic")
	}
	if !strings.HasPrefix(l4block, base) {
		t.Fatalf("grading must EXTEND the signature, not replace it (%q) — the slug set, "+
			"record_allow and both tiers still have to trigger reloads", l4block)
	}
}

// ---------------------------------------------------------------------------
// Task 3.2 — the ladder must move the CACHE EPOCH too, off the same bytes.
//
// 3.1 made a ladder change re-spawn the detector. That alone leaves the second
// half of R-compliance-grading-5 open: the proxy's per-piece verdict cache keys
// on what the detector reports as its effective content (its PACKS), and a
// ladder change does not move that report by one byte. So the re-spawned child
// decides "warn" while the cache keeps handing back the "mask" it minted under
// the rung the admin just relaxed.
//
// The hazard the fence below guards is the DRIFT, not the feature: three things
// have to move off one document, and any two of them agreeing while the third
// does not is silent in both directions.
// ---------------------------------------------------------------------------

// seedGradingPolicy returns a supervisor holding one valid grading document.
func seedGradingPolicy(t *testing.T, doc string) *Supervisor {
	t.Helper()
	s := &Supervisor{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"enabled":true,"privacy_tier":1,"grading":` + doc + `}`))
	}))
	defer srv.Close()
	enabled, tier, adv, grading, ok := fetchComplianceMasterPolicy(t.Context(), srv.URL, "org-1")
	if !ok || grading == nil {
		t.Fatalf("seed policy must be usable; ok=%v grading=%q", ok, grading)
	}
	s.applyComplianceMasterPolicy(enabled, tier, adv, grading, ok)
	return s
}

// TestGrading_SignatureEnvAndCacheEpochShareTheSameBytes is the anti-drift
// fence: the filter signature (re-spawn), AIKEY_COMPLIANCE_GRADING (what the
// child decides with) and the ChildHookConfig policy token (what the verdict
// cache may replay) must all reduce THE SAME document bytes through THE SAME
// digest.
//
// 能红 check: give any one of the three its own bytes — e.g. let gradingEnvValue
// re-marshal the document instead of handing over the canonical bytes, or let
// gradingContentPolicyToken hash something else — and the rows below fail.
func TestGrading_SignatureEnvAndCacheEpochShareTheSameBytes(t *testing.T) {
	const base = "ai-compliance-detector:false"

	t.Run("with a policy in force", func(t *testing.T) {
		s := seedGradingPolicy(t, `{"labels":{"4":"L4"},"ladder":{"4":{"action":"mask"}}}`)
		env := s.gradingEnvValue()
		if env == gradingPolicyDisabled {
			t.Fatalf("seed did not take: env is %q", env)
		}
		epochToken := s.gradingContentPolicyToken()
		// The epoch token is exactly the component the signature carries …
		if !strings.HasSuffix(filterSigWithGrading(base, s.gradingPolicyJSON()), "|"+epochToken) {
			t.Fatalf("the cache epoch token %q is not the signature's grading component (%q) — "+
				"the fleet would re-spawn under one ladder while the cache keys on another",
				epochToken, filterSigWithGrading(base, s.gradingPolicyJSON()))
		}
		// … and it is a digest of the very bytes handed to the child.
		if got := gradingComponent([]byte(env)); got != epochToken {
			t.Fatalf("AIKEY_COMPLIANCE_GRADING hashes to %q but the cache epoch says %q — the "+
				"env and the epoch are no longer the same document", got, epochToken)
		}
		if !strings.HasPrefix(epochToken, "grading:") || len(epochToken) != len("grading:")+16 {
			t.Errorf("the component must stay grading:<sha256[:16]> (design.md §4b), got %q", epochToken)
		}
	})

	t.Run("relaxing a rung moves all three", func(t *testing.T) {
		mask := seedGradingPolicy(t, `{"ladder":{"4":{"action":"mask"}}}`)
		warn := seedGradingPolicy(t, `{"ladder":{"4":{"action":"warn"}}}`)
		if mask.gradingEnvValue() == warn.gradingEnvValue() {
			t.Fatal("the two ladders must reach the child as different env values")
		}
		if mask.gradingContentPolicyToken() == warn.gradingContentPolicyToken() {
			t.Fatal("relaxing L4 to warn left the cache epoch unchanged — every verdict " +
				"masked under the old rung stays replayable (R-compliance-grading-5.S1)")
		}
		if filterSigWithGrading(base, mask.gradingPolicyJSON()) == filterSigWithGrading(base, warn.gradingPolicyJSON()) {
			t.Fatal("relaxing L4 to warn left the filter signature unchanged — no re-spawn")
		}
	})

	t.Run("no policy is one deliberate asymmetry, not three", func(t *testing.T) {
		s := &Supervisor{} // never took a policy
		// "{}" is the WIRE SPELLING of "no policy" for the child, whose parser
		// needs an object; nil is the same statement on this side. Pinned so the
		// asymmetry stays the documented one and cannot quietly become a second
		// source of bytes.
		if got := s.gradingEnvValue(); got != gradingPolicyDisabled {
			t.Fatalf("no policy must reach the child as %q, got %q", gradingPolicyDisabled, got)
		}
		if s.gradingPolicyJSON() != nil {
			t.Fatalf("no policy must stay nil on this side, got %q", s.gradingPolicyJSON())
		}
		if !strings.HasSuffix(filterSigWithGrading(base, s.gradingPolicyJSON()), "|"+s.gradingContentPolicyToken()) {
			t.Fatal("signature and cache epoch must agree even with no policy in force")
		}
		// And "no policy" must not collide with a real one.
		on := seedGradingPolicy(t, `{"ladder":{"4":{"action":"mask"}}}`)
		if s.gradingContentPolicyToken() == on.gradingContentPolicyToken() {
			t.Fatal("turning grading on must move the cache epoch")
		}
	})
}
