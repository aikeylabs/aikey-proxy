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
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
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

// gradingSeedPolicyBody is the one GOOD org policy every "keep the last valid
// one" fence starts from: grading on, L5 = block. Shared so the fences below all
// prove the same starting state rather than three lookalike literals.
const gradingSeedPolicyBody = `{"enabled":true,"privacy_tier":1,` +
	`"grading":{"labels":{"5":"L5"},"ladder":{"5":{"action":"block"}}}}`

// seedGradingSupervisor returns a supervisor that has already taken one GOOD
// policy — the only state in which "keep the last valid one" is a meaningful
// claim — plus the exact AIKEY_COMPLIANCE_GRADING value that policy produces, so
// a caller can assert the env did not move.
func seedGradingSupervisor(t *testing.T) (*Supervisor, string) {
	t.Helper()
	s := &Supervisor{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(gradingSeedPolicyBody))
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
	if rejects, attempted := s.ComplianceMasterPolicyHealth(); !attempted || rejects != 0 {
		t.Fatalf("a supervisor that just took a good policy must read healthy; "+
			"rejects=%d attempted=%v", rejects, attempted)
	}
	return s, env
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
	seed := seedGradingSupervisor

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

// ---------------------------------------------------------------------------
// Task 3.8 — the runtime size limit, and making "we are enforcing a stale
// ladder" READABLE FROM OUTSIDE the process.
//
// Why these fences exist: task 3.1 made an unusable policy keep the last valid
// one, which is the safe direction — but it also makes the machine LOOK fine
// while it enforces a ladder the console no longer shows. That is harder to
// notice than an outright failure, and 「健康信号必须可被外部读取」 names exactly
// this case: a self-check may not live in a log line only.
// ---------------------------------------------------------------------------

// gradingOversizePolicyBody is a policy response whose grading document is
// deliberately past gradingEnvLimitBytes once compacted. Built from the limit
// constant rather than a second literal so the fence tracks the limit if it
// ever moves (and so nobody has to keep two numbers in step).
func gradingOversizePolicyBody() string {
	return `{"enabled":true,"privacy_tier":1,"grading":{"labels":{"5":"` +
		strings.Repeat("L", gradingEnvLimitBytes) + `"}}}`
}

// TestGradingDownlink_KeepsLastValidOnOversize is the 3.A10 fence
// (R-compliance-grading-14.S2).
//
// A grading document too large for the child's environment is the third way an
// answer can be unusable, alongside 3.1's malformed JSON and non-200. It must
// land in the SAME place: the last valid ladder stays in force, the env is never
// rewritten to "{}", and the health surface says degraded with a reason code so
// an operator can find the machine without reading its logs.
//
// 能红 checks (both verified for the report):
//   - drop the gradingEnvLimitBytes check in normalizeGradingPolicy → the
//     oversize document is accepted and the env moves;
//   - keep the WARN but stop counting the rejection (or stop exposing the
//     counter) → the health assertions below fail while the log still looks
//     right, which is precisely the "logs only" failure this task is about.
func TestGradingDownlink_KeepsLastValidOnOversize(t *testing.T) {
	s, seeded := seedGradingSupervisor(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(gradingOversizePolicyBody()))
	}))
	defer srv.Close()

	enabled, tier, adv, grading, ok := fetchComplianceMasterPolicy(t.Context(), srv.URL, "org-1")
	if ok {
		t.Fatal("an oversize grading document must be reported as UNUSABLE (ok=false); " +
			"reporting it as an answer is what lets it overwrite a good policy")
	}
	if grading != nil {
		t.Fatalf("the fetch layer must not hand back a rejected document, got %d bytes", len(grading))
	}

	changed := s.applyComplianceMasterPolicy(enabled, tier, adv, grading, ok)
	if changed {
		t.Fatal("a rejected policy must not report a change; re-spawning here would hand " +
			"the child the same env for no reason")
	}
	if got := s.gradingEnvValue(); got != seeded {
		t.Fatalf("AIKEY_COMPLIANCE_GRADING = %q, want the last valid %q — one oversize "+
			"response must not disable an organisation's whole ladder "+
			"(DEC-compliance-grading-10)", got, seeded)
	}
	if got := s.gradingEnvValue(); got == gradingPolicyDisabled {
		t.Fatal(`the env was replaced with "{}" — that is the ONE thing this rule forbids`)
	}

	// The half this task adds: the state is readable without a log scrape.
	rejects, attempted := s.ComplianceMasterPolicyHealth()
	if !attempted {
		t.Fatal("the follower has polled, so the health surface must report on it; " +
			"an omitted block reads as 'no follower here'")
	}
	if rejects != 1 {
		t.Fatalf("consecutive rejects = %d, want 1 — the streak is what /health turns into "+
			"degraded and what the escalation counts", rejects)
	}

	// And it self-heals: one good answer clears it, so the signal cannot get
	// stuck red after the admin fixes the policy.
	{
		good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(gradingSeedPolicyBody))
		}))
		defer good.Close()
		enabled, tier, adv, grading, ok := fetchComplianceMasterPolicy(t.Context(), good.URL, "org-1")
		s.applyComplianceMasterPolicy(enabled, tier, adv, grading, ok)
		if rejects, _ := s.ComplianceMasterPolicyHealth(); rejects != 0 {
			t.Fatalf("consecutive rejects = %d after a usable answer, want 0 — a health "+
				"signal that never recovers is a signal operators learn to ignore", rejects)
		}
	}
}

// TestGradingDownlink_OldMasterIsNotDegraded guards the distinction 3.1 built and
// this task must not flatten: ① a master that answers WITHOUT a grading member
// is a legitimate deployment (an older master, or an org that switched grading
// off), not a fault. Reporting it degraded sends operators chasing a failure
// that does not exist.
//
// 能红 check: make ① increment the reject streak (i.e. treat "no grading" the
// same as "unusable grading") and this fails.
func TestGradingDownlink_OldMasterIsNotDegraded(t *testing.T) {
	s, _ := seedGradingSupervisor(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"enabled":true,"privacy_tier":1}`))
	}))
	defer srv.Close()

	enabled, tier, adv, grading, ok := fetchComplianceMasterPolicy(t.Context(), srv.URL, "org-1")
	s.applyComplianceMasterPolicy(enabled, tier, adv, grading, ok)

	if got := s.gradingEnvValue(); got != gradingPolicyDisabled {
		t.Fatalf("AIKEY_COMPLIANCE_GRADING = %q, want %q — ① really does switch grading off",
			got, gradingPolicyDisabled)
	}
	rejects, attempted := s.ComplianceMasterPolicyHealth()
	if !attempted {
		t.Fatal("the follower polled; the health block must be present")
	}
	if rejects != 0 {
		t.Fatalf("consecutive rejects = %d, want 0 — an old master is a supported "+
			"deployment, and marking it degraded makes the signal useless", rejects)
	}
}

// TestGradingDownlink_NeverPolledIsNotDegraded: a proxy with no team/org never
// runs the follower at all (syncComplianceMasterPolicy early-returns), so the
// health block must be OMITTED rather than claiming either verdict. Same posture
// as the usage pipeline and the sync rails, which omit what they cannot speak to.
func TestGradingDownlink_NeverPolledIsNotDegraded(t *testing.T) {
	var s Supervisor
	if rejects, attempted := s.ComplianceMasterPolicyHealth(); attempted || rejects != 0 {
		t.Fatalf("a supervisor that never polled reported rejects=%d attempted=%v; want 0/false",
			rejects, attempted)
	}
}

// TestGradingDownlink_RejectStreakEscalatesPastWarn is the "不能一直停留在 WARN"
// half of the health-signal rule. A single rejection is a WARN; a SUSTAINED one
// means the fleet has been enforcing a stale ladder for minutes, which is a
// different operational fact and must not read the same in the logs.
//
// Shape copied from the canary's unavailable-streak escalation
// (internal/events/canary.go): count the streak, escalate exactly ONCE per
// crossing, reset on recovery.
//
// 能红 check: delete the escalation branch (leaving only the per-cycle WARN) and
// the ERROR assertion fails.
func TestGradingDownlink_RejectStreakEscalatesPastWarn(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	s, _ := seedGradingSupervisor(t)
	for i := 0; i < gradingRejectEscalateAfter+3; i++ {
		s.applyComplianceMasterPolicy(false, privacyTierMetadataOnly, false, nil, false)
	}
	if rejects, _ := s.ComplianceMasterPolicyHealth(); rejects != gradingRejectEscalateAfter+3 {
		t.Fatalf("consecutive rejects = %d, want %d", rejects, gradingRejectEscalateAfter+3)
	}

	logs := buf.String()
	if n := strings.Count(logs, observability.EventComplianceGradingStale); n != 1 {
		t.Fatalf("the sustained-staleness escalation was logged %d times, want exactly 1 "+
			"(once per crossing — a per-cycle ERROR is noise, zero is the bug this fence "+
			"exists for).\nlogs:\n%s", n, logs)
	}
	if !strings.Contains(logs, "level=ERROR") {
		t.Fatalf("the escalation must rise ABOVE the per-cycle WARN, or a sustained "+
			"outage looks exactly like a single blip.\nlogs:\n%s", logs)
	}

	// Recovery re-arms it: a second sustained outage must alarm again.
	buf.Reset()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(gradingSeedPolicyBody))
	}))
	defer good.Close()
	enabled, tier, adv, grading, ok := fetchComplianceMasterPolicy(t.Context(), good.URL, "org-1")
	s.applyComplianceMasterPolicy(enabled, tier, adv, grading, ok)
	if rejects, _ := s.ComplianceMasterPolicyHealth(); rejects != 0 {
		t.Fatalf("consecutive rejects = %d after recovery, want 0", rejects)
	}
	for i := 0; i < gradingRejectEscalateAfter; i++ {
		s.applyComplianceMasterPolicy(false, privacyTierMetadataOnly, false, nil, false)
	}
	if n := strings.Count(buf.String(), observability.EventComplianceGradingStale); n != 1 {
		t.Fatalf("the escalation did not re-arm after recovery (logged %d times, want 1); "+
			"a one-shot alarm goes silent for the rest of the process's life", n)
	}
}
