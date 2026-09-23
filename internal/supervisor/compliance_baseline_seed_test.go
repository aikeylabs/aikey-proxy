package supervisor

// compliance_baseline_seed_test.go — the org compliance policy's COMPARISON
// BASELINE survives a restart (TODO-188 延续: startup phantom change).
//
// What broke: applyComplianceMasterPolicy compares each poll against four
// atomics that nothing restored at boot, so the first poll after EVERY restart
// saw "changed" (zero value vs the cluster's privacy tier 3) and re-spawned the
// detector pool — new pool first, old pool drained after — which on a 1.6 GB
// Cluster worker put four detectors over MemoryHigh (10.0.0.90, 2026-09-21).
// The fix re-reads the policy this node already persisted
// (compliance.master_policy) before the initial generation spawns.
//
// Every case below persists through the REAL writer (applyComplianceMasterPolicy
// on a first supervisor) or writes the raw key the way a local edit would, then
// boots a SECOND supervisor from the same vault — the restart, minus the process.
//
// bugfix: workflow/CI/bugfix/2026-09-21-cluster-worker-livelock-on-grading-reload-and-ingress-keeps-routing.md
// bugfix: workflow/CI/bugfix/20260725-proxy-startup-reload-storm-5s-health-fail.md (腿 3 改点 A)

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/pkg/pipewire"
)

// seedVault is a vault file with just the config table — all the persisted
// policy needs.
func seedVault(t *testing.T) string {
	t.Helper()
	dbPath, _ := newOpenableVault(t, nil)
	return dbPath
}

func supervisorOn(dbPath string) *Supervisor {
	return &Supervisor{cfg: &config.Config{Vault: config.VaultConfig{Path: dbPath}}}
}

// persistViaRealWriter runs one accepted poll (org mandate ON, as on every
// Cluster node) on a throwaway supervisor, so the key holds exactly the bytes
// production writes (no hand-copied JSON shape).
func persistViaRealWriter(t *testing.T, dbPath string, tier int, advanced bool) {
	t.Helper()
	supervisorOn(dbPath).applyComplianceMasterPolicy(true, tier, advanced, nil, true)
	if raw, _ := vault.ReadConfigString(dbPath, complianceMasterPolicyKey); raw == "" {
		t.Fatal("fixture: the real writer persisted nothing")
	}
}

// firstPoll is the first sync after boot (the master answers mandate ON),
// acted on exactly as syncComplianceMasterPolicy does, with a reload spy
// instead of s.Reload.
func firstPoll(s *Supervisor, tier int, advanced bool) (compliancePolicyChange, int) {
	reloads := 0
	change := s.applyComplianceMasterPolicy(true, tier, advanced, nil, true)
	s.actOnCompliancePolicyChange(context.Background(), change, func(context.Context) error {
		reloads++
		return nil
	})
	return change, reloads
}

func captureSeedLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestComplianceBaseline_RestartWithUnchangedPolicyDoesNotRespawn — the fence
// for the 10.0.0.90 livelock. Restart with the master's policy unchanged ⇒ the
// first poll is a no-op: no reload, no new generation, no second detector pool.
//
// 能红: make seedComplianceMasterBaseline a no-op (= the pre-fix code, which
// never read the key back) → enabled/tier/password all flip from zero → 1 reload.
func TestComplianceBaseline_RestartWithUnchangedPolicyDoesNotRespawn(t *testing.T) {
	dbPath := seedVault(t)
	persistViaRealWriter(t, dbPath, privacyTierRawSnippet, true) // the staging cluster's policy

	s := supervisorOn(dbPath)
	s.seedComplianceMasterBaseline()
	// The initial generation spawns from these atomics (installFilterHook reads
	// masterPrivacyTier / masterPasswordTierAdvanced / masterCompliance), so the
	// restored values ARE what the first detector pool is born with.
	if !s.masterCompliance.Load() || s.masterPrivacyTier.Load() != privacyTierRawSnippet || !s.masterPasswordTierAdvanced.Load() {
		t.Fatalf("baseline not restored: enabled=%v tier=%d advanced=%v",
			s.masterCompliance.Load(), s.masterPrivacyTier.Load(), s.masterPasswordTierAdvanced.Load())
	}

	change, reloads := firstPoll(s, privacyTierRawSnippet, true)
	if change.respawn || reloads != 0 {
		t.Fatalf("first poll after a restart with an unchanged policy re-spawned the detector pool "+
			"(respawn=%v reloads=%d) — that is the startup phantom change (four detectors on a 1.6 GB worker)",
			change.respawn, reloads)
	}
}

// TestComplianceBaseline_RealChangeWhileDownStillRespawns — the seed only moves
// the baseline; a policy the master really changed while the node was down must
// still reach the detector through the one respawn it needs.
func TestComplianceBaseline_RealChangeWhileDownStillRespawns(t *testing.T) {
	dbPath := seedVault(t)
	persistViaRealWriter(t, dbPath, privacyTierMetadataOnly, false)

	s := supervisorOn(dbPath)
	s.seedComplianceMasterBaseline()
	change, reloads := firstPoll(s, privacyTierRawSnippet, false)
	if !change.respawn || reloads != 1 {
		t.Fatalf("a tier change made while the node was down must respawn once: respawn=%v reloads=%d", change.respawn, reloads)
	}
	if s.masterPrivacyTier.Load() != privacyTierRawSnippet {
		t.Fatalf("the respawn would spawn with tier %d, want the master's %d", s.masterPrivacyTier.Load(), privacyTierRawSnippet)
	}
}

// TestComplianceBaseline_LocalTamperIsOverruledByTheNextPoll — the security
// premise. The restored value is only a comparison baseline: the master's answer
// is still the verdict on every poll. A key edited locally to something looser
// (mandate off, raw-text tier, password force off) differs from the master's
// answer ⇒ "changed" ⇒ respawn, with the atomics AND the key back on the
// master's values. Out-of-range tiers clamp like the wire does (fail toward
// "carry less").
func TestComplianceBaseline_LocalTamperIsOverruledByTheNextPoll(t *testing.T) {
	dbPath := seedVault(t)
	if err := vault.WriteConfigString(dbPath, complianceMasterPolicyKey,
		`{"enabled":false,"locked":false,"privacy_tier":3,"password_tier":""}`); err != nil {
		t.Fatal(err)
	}

	s := supervisorOn(dbPath)
	s.seedComplianceMasterBaseline()
	change, reloads := firstPoll(s, privacyTierMetadataOnly, true)
	if !change.respawn || reloads != 1 {
		t.Fatalf("a locally loosened key must be overruled by a respawn: respawn=%v reloads=%d", change.respawn, reloads)
	}
	if !s.masterCompliance.Load() || s.masterPrivacyTier.Load() != privacyTierMetadataOnly || !s.masterPasswordTierAdvanced.Load() {
		t.Fatalf("after the poll the node must hold the MASTER's policy: enabled=%v tier=%d advanced=%v",
			s.masterCompliance.Load(), s.masterPrivacyTier.Load(), s.masterPasswordTierAdvanced.Load())
	}
	raw, _ := vault.ReadConfigString(dbPath, complianceMasterPolicyKey)
	if raw != `{"enabled":true,"locked":true,"privacy_tier":1,"password_tier":"advanced"}` {
		t.Fatalf("the persisted key must be rewritten to the master's answer, got %s", raw)
	}

	t.Run("out-of-range tier clamps to metadata-only", func(t *testing.T) {
		if err := vault.WriteConfigString(dbPath, complianceMasterPolicyKey,
			`{"enabled":true,"locked":true,"privacy_tier":9,"password_tier":""}`); err != nil {
			t.Fatal(err)
		}
		s := supervisorOn(dbPath)
		s.seedComplianceMasterBaseline()
		if got := s.masterPrivacyTier.Load(); got != privacyTierMetadataOnly {
			t.Fatalf("tier 9 seeded as %d, want the clamp to %d", got, privacyTierMetadataOnly)
		}
	})
}

// TestComplianceBaseline_MissingOrBrokenKeyBehavesAsBefore — 增强非依赖: no key
// (Personal, first boot) or an unreadable one leaves the zero baseline, i.e.
// exactly the pre-fix behavior (one respawn on the first poll), never a failed
// boot. Broken JSON is WARNed with the central event name; absence is INFO.
func TestComplianceBaseline_MissingOrBrokenKeyBehavesAsBefore(t *testing.T) {
	cases := []struct {
		name, raw string
		wantEvent string
		wantWarn  bool
	}{
		{"absent", "", observability.EventComplianceMasterBaselineAbsent, false},
		{"broken json", `{"enabled":tru`, observability.EventComplianceMasterBaselineUnreadable, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dbPath := seedVault(t)
			if c.raw != "" {
				if err := vault.WriteConfigString(dbPath, complianceMasterPolicyKey, c.raw); err != nil {
					t.Fatal(err)
				}
			}
			logs := captureSeedLogs(t)
			s := supervisorOn(dbPath)
			s.seedComplianceMasterBaseline()
			if s.masterCompliance.Load() || s.masterPrivacyTier.Load() != 0 || s.masterPasswordTierAdvanced.Load() {
				t.Fatal("an absent/unreadable key must leave the zero baseline")
			}
			out := logs.String()
			if !strings.Contains(out, "event.name="+c.wantEvent) {
				t.Fatalf("missing %s in logs:\n%s", c.wantEvent, out)
			}
			if got := strings.Contains(out, "level=WARN"); got != c.wantWarn {
				t.Fatalf("WARN emitted = %v, want %v:\n%s", got, c.wantWarn, out)
			}
			if strings.Contains(out, `"enabled":tru`) || strings.Contains(out, `enabled\":tru`) {
				t.Fatal("the WARN must not quote the persisted bytes")
			}
			if _, reloads := firstPoll(s, privacyTierRawSnippet, false); reloads != 1 {
				t.Fatalf("zero baseline: the first poll must behave as before the fix (1 reload), got %d", reloads)
			}
		})
	}
}

// TestComplianceBaseline_FirstGradingAfterRestartIsHotSwapped — grading is NOT
// persisted in the key (and must not be added to it), so after a restart the
// first poll that carries the org's ladder is a grading-only change. With the
// scalars restored it takes TODO-188 方案 C's hot path: pushed into the running
// detectors, no reload, no second pool.
//
// 能红: no-op seed → enabled flips false→true → classified respawn → 1 reload.
func TestComplianceBaseline_FirstGradingAfterRestartIsHotSwapped(t *testing.T) {
	dbPath, reader := newHotSwapRigVault(t)
	persistViaRealWriter(t, dbPath, privacyTierMetadataOnly, false)

	s := supervisorOn(dbPath)
	s.seedComplianceMasterBaseline()
	r := startHotSwapRig(t, s, reader, "ok", "ok") // the initial generation's pool, born without a ladder

	change := r.edit(t, hotDocA) // first poll: same scalars, and the org ladder
	if change.respawn || !change.grading {
		t.Fatalf("first grading document after a restart must be a grading-only change, got %+v", change)
	}
	if r.reloads != 0 || r.s.active.Load() != r.gen {
		t.Fatalf("first grading document after a restart rebuilt the generation (reloads=%d)", r.reloads)
	}
	want := pipewire.GradingToken([]byte(hotDocA))
	for i, tok := range workerPolicyTokens(r.pool) {
		if tok != want {
			t.Errorf("worker %d enforces %q, want the hot-swapped ladder %q", i, tok, want)
		}
	}
}

// TestComplianceBaseline_SeededBeforeInitialGeneration — the seed is only
// worth anything if it runs BEFORE New() builds the initial generation: after
// it, the first pool would already have spawned with zero values and the
// signature recorded for them. Pinned on source order because New() needs a
// full vault + password to run.
func TestComplianceBaseline_SeededBeforeInitialGeneration(t *testing.T) {
	src, err := os.ReadFile("supervisor.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "\nfunc New(")
	if start < 0 {
		t.Fatal("func New not found in supervisor.go")
	}
	body = body[start:]
	if end := strings.Index(body[1:], "\nfunc "); end > 0 {
		body = body[:end+1]
	}
	seed := strings.Index(body, "s.seedComplianceMasterBaseline()")
	build := strings.Index(body, "s.buildGeneration()")
	if seed < 0 || build < 0 || seed > build {
		t.Fatalf("New() must call s.seedComplianceMasterBaseline() before s.buildGeneration() (seed at %d, build at %d)", seed, build)
	}
}

// TestComplianceBaseline_VaultTickSignatureStableAcrossFirstPoll — the second
// half of the 10.0.0.90 log (00:22:51 "managed key sync: filter-app set
// changed; full reload"). The filter signature folds in masterPrivacyTier /
// masterPasswordTierAdvanced / masterGrading; buildGeneration records it at
// spawn and the 5 s vault tick recomputes it. When the first poll moved the
// tier off its zero value, the tick saw a "changed" signature and queued a
// SECOND full reload behind the first. With the baseline restored, the
// signature recorded at boot equals the one after the first poll.
//
// 能红: no-op seed → recorded "...|tier:0|..." vs recomputed "...|tier:3|...".
func TestComplianceBaseline_VaultTickSignatureStableAcrossFirstPoll(t *testing.T) {
	dbPath := seedVault(t)
	persistViaRealWriter(t, dbPath, privacyTierRawSnippet, true)

	s := supervisorOn(dbPath)
	s.seedComplianceMasterBaseline()
	const base = "apps:ai-compliance-detector|stages:pre_forward"
	recordedAtBoot := s.filterSigFrom(base) // what buildGeneration stores in lastFilterSig

	firstPoll(s, privacyTierRawSnippet, true)
	if got := s.filterSigFrom(base); got != recordedAtBoot {
		t.Fatalf("the vault tick would see a changed filter signature and full-reload:\n boot: %s\n now:  %s", recordedAtBoot, got)
	}
}
