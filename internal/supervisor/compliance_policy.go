// compliance_policy.go — G3: org-level compliance master switch follower.
//
// The supervisor is the LIFECYCLE owner of the compliance detector. The detector
// pulls its own content (packs) once running; whether it RUNS AT ALL is decided
// here — an enterprise mandates compliance centrally (control backend), and a
// member's machine can't refuse. This poller pulls that mandate and force-spawns
// the detector even when the user's local filter_stages is NULL.
//
// Why poll here and not in the detector: the detector is only spawned when
// compliance is already on, so it can't bootstrap "should I be on?" — that's the
// spawner's job. And "off = don't spawn" (save ~50MB on every Personal machine)
// requires the gate to live outside the app.
//
// No-op when no team/org is configured (Personal standalone) — the local user
// toggle (filter_stages) governs, unchanged.
package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

const (
	// complianceMasterPolicyKey holds the persistedComplianceMasterPolicy JSON the
	// UI + CLI read to reflect / enforce the org mandate, and that the supervisor
	// reads back at boot as its comparison baseline (seedComplianceMasterBaseline).
	// Plaintext config (like change_seq) — no vault unlock needed; integrity comes
	// from the authenticated master pull, which overrules it on every poll.
	complianceMasterPolicyKey = "compliance.master_policy"
	compliancePollInterval    = 60 * time.Second

	// gradingPolicyAbsent is what AIKEY_COMPLIANCE_GRADING carries when the
	// master's answer had NO `grading` member (an old master), or when this node
	// has never followed a master (Personal): no document at all — the same
	// thing a pre-grading proxy handed the child. The detector reads it as "the
	// master does not speak 分级" and puts no level / leaf_path / max_level on
	// the intake wire.
	//
	// gradingPolicyDisabled is what it carries when a NEW master answered with an
	// explicit `{}`: the org configured no ladder. Grading enforcement is OFF
	// exactly as with the absent case (neither declares a rung, so the decision
	// layer behaves byte-for-byte as before the feature — R-compliance-grading-3
	// is about the ACTION), but the master understands 分级 keys, so the
	// classification tree's level is still reported (R-compliance-grading-1).
	//
	// 🔴 WHY TWO SPELLINGS (TODO-61). They used to be one (`{}` for both), which
	// made "old master" and "tree built, ladder not configured" indistinguishable
	// to the detector: that org saw 未分级 on every audit row although its tree had
	// graded them. No field was added for this (拍板 15): the member's presence is
	// already on the wire, and collapsing it was losing information.
	// 需求包: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/ task-execution/TODO.md TODO-61
	//
	// 🔴 Neither is EVER the fallback for "the answer was unusable" — see
	// applyComplianceMasterPolicy.
	gradingPolicyAbsent   = ""
	gradingPolicyDisabled = "{}"

	// gradingEnvLimitBytes is the RUNTIME hard limit on the compact grading
	// document, measured on the exact bytes this proxy is about to bake into the
	// detector child's AIKEY_COMPLIANCE_GRADING variable.
	//
	// Why a limit at all: the ladder travels to the child as an environment
	// variable, and an oversize value does not fail politely — it fails at
	// spawn, on the machine, with no way back to the master that sent it. So the
	// document is measured HERE, at the single point of entry, and a document
	// that will not fit is treated as unusable exactly like malformed JSON: keep
	// the last valid ladder, never "{}".
	//
	// 🔴 The master's SAVE-side budget is 7680 bytes and must stay STRICTLY BELOW
	// this number (DEC-compliance-grading-10). The direction is the safety
	// property: anything the console accepted is guaranteed to fit here, so a
	// policy can never be saveable-but-unshippable. Two numbers, one inequality —
	// do NOT collapse them into one shared constant, and do not raise 7680 to
	// 8192; the gap is the margin that keeps the inequality strict as the wire
	// framing around the document changes.
	gradingEnvLimitBytes = 8192

	// gradingRejectEscalateAfter is how many CONSECUTIVE unusable policy answers
	// raise the WARN to an ERROR (once per crossing). Copied from the canary's
	// unavailableEscalateThreshold (internal/events/canary.go), which exists for
	// the same reason and is the repo's convention for "a self-check must not sit
	// at WARN forever": long enough to ride out a deploy-window blip, short
	// enough that a real misconfiguration alarms. At the 60s poll interval this
	// is ~6 minutes of enforcing a ladder the console no longer shows.
	gradingRejectEscalateAfter = 6
)

var complianceHTTPClient = httpx.NewSwappableDirect(10 * time.Second)

// resolveTeamOrgID returns the org this node's team mandates follow — BOTH the
// compliance master policy (this file) AND the conversation-audit capture switch
// (conversation_audit_policy.go) poll with it. Priority:
//  1. AIKEY_HUB_ORG_ID env — a CLUSTER node's fixed org (cluster-node.env).
//  2. The org_id of the active TEAM managed key — a form-① employee's Personal-
//     style proxy has NO such env; its team VK (`aikey use <VK>`) carries the org.
//  3. "" — true Personal (no team key, no env) → caller early-returns, no mandate.
//
// Replaces the old hardcoded "default" placeholder, which made a form-① employee's
// local proxy poll the WRONG org → mandate never applied (audit silently never
// captured; compliance silently never enforced) while usage (not gated on this)
// reported fine. The active team VK is the same source route resolution already
// uses (managedKeyToRoute → mk.OrgID), so this introduces no new source of truth.
// Bugfix 2026-06-17 (conversation-audit) extended to compliance same day.
func (s *Supervisor) resolveTeamOrgID() string {
	envOrg := os.Getenv("AIKEY_HUB_ORG_ID")
	var mks []vault.ManagedKey
	if gen := s.active.Load(); gen != nil && gen.vault != nil {
		mks, _ = gen.vault.GetActiveManagedKeys()
	}
	return resolveTeamOrgIDFromKeys(envOrg, mks)
}

// resolveTeamOrgIDFromKeys is the pure resolution (env wins; else the first team
// key with a non-empty org; else ""), split out so it is unit-testable without a
// live vault/generation.
func resolveTeamOrgIDFromKeys(envOrg string, mks []vault.ManagedKey) string {
	if envOrg != "" {
		return envOrg
	}
	for i := range mks {
		if mks[i].OrgID != "" {
			return mks[i].OrgID
		}
	}
	return ""
}

// pollComplianceMasterPolicy runs until ctx is canceled, refreshing the org
// mandate every compliancePollInterval (plus once immediately).
func (s *Supervisor) pollComplianceMasterPolicy(ctx context.Context) {
	s.syncComplianceMasterPolicy(ctx)
	ticker := time.NewTicker(compliancePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.syncComplianceMasterPolicy(ctx)
		}
	}
}

func (s *Supervisor) syncComplianceMasterPolicy(ctx context.Context) {
	masterURL := readControlPanelURL()
	orgID := s.resolveTeamOrgID() // env → active team VK org → "" (no longer a "default" placeholder)
	if masterURL == "" || orgID == "" {
		return // no team / no org → no mandate; local toggle governs (Personal)
	}
	enabled, tier, passwordAdvanced, gradingJSON, ok := fetchComplianceMasterPolicy(ctx, masterURL, orgID)
	change := s.applyComplianceMasterPolicy(enabled, tier, passwordAdvanced, gradingJSON, ok)
	s.actOnCompliancePolicyChange(ctx, change, s.Reload)
}

// compliancePolicyChange is what one poll changed and therefore what must
// happen to the running detector (TODO-188 方案 C split the old single bool).
//
//	respawn — a value that can ONLY reach the detector through its spawn env
//	          changed (enabled / privacy_tier / password_tier): full reload,
//	          exactly as before C. A grading change riding along is carried by
//	          that same reload.
//	grading — ONLY the grading document changed: hot-swap it into the running
//	          detector (hotSwapGrading) instead of re-spawning the pool.
//	          previousGrading is the document in force before this poll, so a
//	          refusal can restore it.
type compliancePolicyChange struct {
	respawn         bool
	grading         bool
	previousGrading []byte
}

// any reports whether the poll changed anything the detector must learn.
func (c compliancePolicyChange) any() bool { return c.respawn || c.grading }

// actOnCompliancePolicyChange is the testable core of the poll's decision: the
// reload is a parameter (same posture as healFilterStubWithReload) so a fence
// can assert WHETHER the pool was rebuilt without standing up a generation build.
// rule: R-compliance-grading-5
// spec: R-compliance-grading-5.1
func (s *Supervisor) actOnCompliancePolicyChange(ctx context.Context, change compliancePolicyChange, reload func(context.Context) error) {
	switch {
	case change.respawn:
		s.gradingHotSwapRefusals.Store(0) // the re-spawned pool is born with the new document (cold path)
	case change.grading:
		if s.hotSwapGrading(ctx, change.previousGrading) != gradingSwapNeedsReload {
			return
		}
		// Fall through to the pre-C behavior: an old detector, or no usable
		// answer. masterGrading already holds the new document, so the reload
		// spawns with it — byte-for-byte what happened before C.
	default:
		// Nothing changed. If the master reverted to the document this node is
		// enforcing, the console and the node agree again.
		s.gradingHotSwapRefusals.Store(0)
		return
	}
	if err := reload(ctx); err != nil {
		slog.Warn("compliance policy reload failed",
			"event.name", "proxy.compliance.policy_reload_failed", "error", err)
	}
}

// bugfix: 需求包 roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/ (task 3.1)
// R-compliance-grading-5 still lives in the IN-FLIGHT delta
// openspec/changes/add-compliance-grading-fusion/specs/compliance-grading/spec.md,
// so it is referenced with a rule: tag rather than a steady-state anchor —
// check-code-anchors deliberately refuses an anchor to a proposal. They are
// upgraded when §7 writes the delta back to the steady-state layer.
//
// applyComplianceMasterPolicy folds ONE poll result into the supervisor's
// runtime state and reports whether the detector child must be re-spawned.
//
// WHY IT IS SPLIT OUT OF THE POLLER: three of the four values it takes are
// baked into a child process's environment at spawn, and the rule for what to
// do when the master's answer is unusable is DIFFERENT per value — a distinction
// that only exists as behavior, so it needs somewhere to be asserted. The
// poller itself needs a control-panel URL, a team VK and a live generation, so
// nothing could be pinned through it; this method needs a zero Supervisor.
//
// fetchOK=false means "no answer", never "the answer was: nothing". Everything
// this method would set stays as it was, which for the scalars is the long
// standing behavior ("don't flap on a transient miss") and for the grading
// document is DEC-compliance-grading-10: one unusable response must not switch
// an organisation's whole ladder off while its console still shows it on.
// rule: R-compliance-grading-5
func (s *Supervisor) applyComplianceMasterPolicy(enabled bool, tier int, passwordAdvanced bool, gradingJSON []byte, fetchOK bool) compliancePolicyChange {
	// One poll happened, so /health may speak about this follower from now on.
	s.masterPolicyAttempted.Store(true)
	if !fetchOK {
		s.noteCompliancePolicyRejected()
		return compliancePolicyChange{} // ②③: keep the last valid policy; nothing changed, nothing to re-spawn
	}
	// ① and the happy path are BOTH usable answers: the node is following the
	// master, whether or not that master has a grading policy to give.
	s.noteCompliancePolicyAccepted()
	// Persist for the web toggle + CLI guard. locked == enabled for now (master
	// ON ⇒ user can't disable; master OFF ⇒ user free). Kept as two fields so a
	// future "force-off + locked" variant doesn't change the wire shape.
	//
	// privacy_tier and password_tier ride along so the local console can SHOW
	// what the org decided, and so the NEXT boot can restore its comparison
	// baseline from them (seedComplianceMasterBaseline, 2026-09-21).
	// 🔴 Writing them here does NOT make them settable locally. The one reader
	// that decides anything is that boot-time seed, and what it restores is only
	// the value the first poll is COMPARED against: the master's answer is still
	// the verdict on every poll, so a key edited locally differs from it, counts
	// as "changed", and is overwritten (atomics + this key) by the master's
	// values through a respawn. The master also re-checks its own column at
	// ingest. Fenced by TestComplianceBaseline_LocalTamperIsOverruledByTheNextPoll.
	// bugfix: workflow/CI/bugfix/2026-09-21-cluster-worker-livelock-on-grading-reload-and-ingress-keeps-routing.md
	if s.cfg != nil {
		if policy, err := json.Marshal(newPersistedComplianceMasterPolicy(enabled, tier, passwordAdvanced)); err == nil {
			_ = vault.WriteConfigString(s.cfg.Vault.Path, complianceMasterPolicyKey, string(policy))
		}
	}
	// The privacy tier is baked into the detector child's ENV at spawn, so a
	// change only takes effect on a re-spawn. Store it BEFORE the reload decision
	// below so the reload that follows picks up the new value; and treat a tier
	// change as reload-worthy in its own right, because otherwise lowering the
	// tier would change what the server stores while employees' machines kept
	// sending raw text over the network until something else forced a reload.
	tierChanged := s.masterPrivacyTier.Swap(int64(tier)) != int64(tier)
	// Same reload-worthiness reasoning as the privacy tier: the level is baked
	// into the child env at spawn, so a force flip must re-spawn or members
	// keep the enforcement they were born with. spec: R-credential-password-tier-4.S1
	passwordChanged := s.masterPasswordTierAdvanced.Swap(passwordAdvanced) != passwordAdvanced
	enabledChanged := s.masterCompliance.Swap(enabled) != enabled
	// The grading document is stored here too, but it no longer forces a
	// re-spawn on its own (TODO-188 方案 C): when it is the ONLY change, the
	// caller hot-swaps it into the running detector, and restores
	// previousGrading if the detector refuses it (用户拍板 C.7-3). It still
	// rides a re-spawn caused by the values above. rule: R-compliance-grading-5
	previousGrading := s.gradingPolicyJSON()
	gradingChanged := s.swapMasterGrading(gradingJSON)
	if enabledChanged || tierChanged || passwordChanged || gradingChanged {
		slog.Info("compliance master policy changed",
			"event.name", "proxy.compliance.policy_changed",
			"enabled", enabled, "privacy_tier", tier, "grading_changed", gradingChanged)
	}
	respawn := enabledChanged || tierChanged || passwordChanged
	return compliancePolicyChange{
		respawn:         respawn,
		grading:         gradingChanged && !respawn,
		previousGrading: previousGrading,
	}
}

// persistedComplianceMasterPolicy is the ONE shape of complianceMasterPolicyKey:
// written by applyComplianceMasterPolicy, read back by
// seedComplianceMasterBaseline (and by the local UI / CLI guard, which parse
// the same JSON). One struct so the writer and the reader cannot drift apart.
// The field order is the byte order the key has always had.
//
// No grading member, on purpose (用户拍板 2026-09-21: do not grow this key):
// after a restart the first poll that carries the org ladder is a grading-only
// change, which TODO-188 方案 C hot-swaps into the running detector without a
// new generation.
type persistedComplianceMasterPolicy struct {
	Enabled      bool   `json:"enabled"`
	Locked       bool   `json:"locked"`
	PrivacyTier  int    `json:"privacy_tier"`
	PasswordTier string `json:"password_tier"`
}

func newPersistedComplianceMasterPolicy(enabled bool, tier int, passwordAdvanced bool) persistedComplianceMasterPolicy {
	p := persistedComplianceMasterPolicy{Enabled: enabled, Locked: enabled, PrivacyTier: tier}
	if passwordAdvanced {
		p.PasswordTier = "advanced"
	}
	return p
}

// seedComplianceMasterBaseline restores the comparison baseline of
// applyComplianceMasterPolicy — masterCompliance, masterPrivacyTier,
// masterPasswordTierAdvanced — from the policy this node persisted the last
// time it followed its master. New() calls it BEFORE the initial
// buildGeneration, so the first detector pool is spawned with these values
// (installFilterHook reads exactly these atomics) and the first poll compares
// the master's answer against what is actually running.
//
// WHY (the 10.0.0.90 livelock, 2026-09-21): the atomics started at zero on every
// boot while the key sat unread in the vault, so the first poll always saw
// "changed" (tier 0 → the cluster's 3) and re-spawned the pool — new pool first,
// old pool drained after — and the 5 s vault tick, whose filter signature folds
// in the same atomics, queued a second full reload behind it. Four ~235 MB
// detectors on a 1.6 GB worker crossed MemoryHigh and the node stopped
// answering. Same pattern as seedQuotaSig and loaded_vault_change_seq: no new
// state, the already-persisted payload is simply read back.
//
// 增强非依赖: an absent key (Personal, first boot) or an unreadable one leaves
// the zero baseline — the pre-fix behavior, one respawn on the first poll —
// and never blocks the boot. Grading is not seeded: the key carries none (see
// persistedComplianceMasterPolicy).
// bugfix: workflow/CI/bugfix/2026-09-21-cluster-worker-livelock-on-grading-reload-and-ingress-keeps-routing.md
// bugfix: workflow/CI/bugfix/20260725-proxy-startup-reload-storm-5s-health-fail.md (腿 3 改点 A)
func (s *Supervisor) seedComplianceMasterBaseline() {
	if s.cfg == nil {
		return
	}
	raw, err := vault.ReadConfigString(s.cfg.Vault.Path, complianceMasterPolicyKey)
	if err != nil {
		slog.Warn("compliance master policy baseline could not be read; the first policy poll will re-spawn the detector once",
			"event.name", observability.EventComplianceMasterBaselineUnreadable,
			"error.code", observability.ErrCodeComplianceMasterBaselineUnreadable,
			"error", err)
		return
	}
	if raw == "" {
		slog.Info("no persisted compliance master policy; starting from the zero baseline",
			"event.name", observability.EventComplianceMasterBaselineAbsent)
		return
	}
	var p persistedComplianceMasterPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		// No decoder error text and no bytes: either could quote the key.
		slog.Warn("persisted compliance master policy is not decodable; the first policy poll will re-spawn the detector once",
			"event.name", observability.EventComplianceMasterBaselineUnreadable,
			"error.code", observability.ErrCodeComplianceMasterBaselineUnreadable,
			"bytes", len(raw))
		return
	}
	// Same normalisation as the wire (fetchComplianceMasterPolicy): anything that
	// is not an understood rung lands on metadata-only; only "advanced" forces.
	tier := clampPrivacyTier(p.PrivacyTier)
	advanced := p.PasswordTier == "advanced"
	s.masterCompliance.Store(p.Enabled)
	s.masterPrivacyTier.Store(int64(tier))
	s.masterPasswordTierAdvanced.Store(advanced)
	slog.Info("compliance master policy baseline restored from the last persisted policy",
		"event.name", observability.EventComplianceMasterBaselineSeeded,
		"enabled", p.Enabled, "privacy_tier", tier, "password_tier_advanced", advanced)
}

// noteCompliancePolicyRejected records one poll whose answer could not be used
// and escalates a SUSTAINED run of them past the per-poll WARN.
//
// The health surface (GET /health -> compliance_policy) turns the very first
// rejection into `degraded`, without a threshold, because unlike an upload or
// canary blip a rejected policy is not a transport hiccup: from that moment the
// ladder this node enforces and the ladder the console displays are two
// different documents, and that is true whether it lasts one minute or an hour.
// The threshold below governs how LOUD the logs get, not whether the endpoint
// tells the truth. rule: R-compliance-grading-5
func (s *Supervisor) noteCompliancePolicyRejected() {
	streak := s.masterPolicyRejects.Add(1)
	if streak < gradingRejectEscalateAfter || s.masterPolicyEscalated.Swap(true) {
		return
	}
	slog.Error("compliance master policy has been unrefreshable for a sustained run of polls; "+
		"this node is still enforcing the last valid policy, which may no longer match the console. "+
		"Check the control plane's /v1/compliance/policy response for this org",
		"event.name", observability.EventComplianceGradingStale,
		"error.code", "COMPLIANCE_POLICY_STALE",
		"consecutive_rejects", streak)
}

// noteCompliancePolicyAccepted clears the streak after a usable answer and
// re-arms the escalation, so a second outage alarms as loudly as the first. A
// recovery is logged only when there was something to recover FROM (state
// transitions, not steady state).
func (s *Supervisor) noteCompliancePolicyAccepted() {
	previous := s.masterPolicyRejects.Swap(0)
	s.masterPolicyEscalated.Store(false)
	if previous > 0 {
		slog.Info("compliance master policy refreshed again",
			"event.name", "proxy.compliance.policy_recovered",
			"previous_consecutive_rejects", previous)
	}
}

// ComplianceMasterPolicyHealth is the externally readable state of the org
// compliance-policy follower, for GET /health (task 3.8).
//
//	consecutiveRejects — polls in a row whose answer could not be used. 0 means
//	  the node is following the master; anything above 0 means it is enforcing a
//	  policy it could not refresh, i.e. `degraded`.
//	attempted — false until the first poll. A Personal install with no team/org
//	  never polls, and /health omits the block there rather than claiming a
//	  verdict about a follower that is not running.
//
// Deliberately returns raw facts rather than a verdict: internal/admin derives
// the state + reason code, the same split usagePipelineHealth already uses, so
// the wire vocabulary lives in exactly one package. rule: R-compliance-grading-5
func (s *Supervisor) ComplianceMasterPolicyHealth() (consecutiveRejects int, attempted bool) {
	return int(s.masterPolicyRejects.Load()), s.masterPolicyAttempted.Load()
}

// swapMasterGrading stores the org grading document and reports whether it
// actually differs from the one already in force. Compare-then-swap rather than
// swap-then-compare on a pointer: the bytes are what matter, and the poller
// re-decodes an identical document every 60s.
//
// A nil / empty document is stored as "no member" (⇒ gradingPolicyAbsent in
// the child env), which is the ① old-master case only; an explicit `{}` is
// stored as those two bytes (TODO-61). The unusable-answer cases never reach
// here (see applyComplianceMasterPolicy).
func (s *Supervisor) swapMasterGrading(gradingJSON []byte) bool {
	if bytes.Equal(s.gradingPolicyJSON(), gradingJSON) {
		return false
	}
	if len(gradingJSON) == 0 {
		s.masterGrading.Store(nil)
		return true
	}
	stored := append([]byte(nil), gradingJSON...) // own the bytes; the decoder reuses buffers
	s.masterGrading.Store(&stored)
	return true
}

// gradingPolicyJSON is the compact grading document currently in force: nil
// when the master sent no `grading` member, the two bytes `{}` when it sent an
// empty one (TODO-61). Read by the spawn path (env) and the filter signature.
func (s *Supervisor) gradingPolicyJSON() []byte {
	if p := s.masterGrading.Load(); p != nil {
		return *p
	}
	return nil
}

// gradingEnvValue is the exact AIKEY_COMPLIANCE_GRADING value handed to the
// detector child — the single place that decides what "no member" looks like on
// the wire into the child, so the spawn path cannot spell it differently from
// the fences. An explicit `{}` is passed through verbatim; only the absent
// member maps to gradingPolicyAbsent (TODO-61, see the constants).
func (s *Supervisor) gradingEnvValue() string {
	if g := s.gradingPolicyJSON(); len(g) > 0 {
		return string(g)
	}
	return gradingPolicyAbsent
}

// fetchComplianceMasterPolicy GETs the PUBLIC tenant policy endpoint (no JWT,
// mirrors the pack-pull). ok=false on any error so the caller keeps the
// last-known value.
//
// 🔴 THIS LAYER ONLY REPORTS; IT NEVER DECIDES. That matters for gradingJSON,
// which comes back nil in two OPPOSITE situations, told apart by ok:
//
//	nil, ok=true  — the master answered WITHOUT a grading member (an old
//	                master) ⇒ the caller turns grading OFF. An org that switched
//	                grading off answers `{}`, which comes back as those bytes
//	                (ok=true), not nil — TODO-61, see gradingPolicyAbsent.
//	nil, ok=false — the master's answer could not be used (unusable document,
//	                non-200, network error) ⇒ the caller KEEPS the last valid
//	                policy. Never {}: one bad response must not disable an
//	                organisation's whole ladder (DEC-compliance-grading-10).
//
// Collapsing those two into a bare nil is exactly the bug this signature exists
// to prevent. rule: R-compliance-grading-5
//
// 🔴 privacyTier is CLAMPED here, not merely decoded. It decides whether this
// machine attaches its user's raw text to the events it uploads, so every input
// that is not an understood rung must land on the safe one: a field the server
// did not send (an older master) decodes to 0, and 0/negative/out-of-range all
// clamp to 1 (metadata only). The failure direction is always "carry less".
func fetchComplianceMasterPolicy(ctx context.Context, masterURL, orgID string) (enabled bool, privacyTier int, passwordAdvanced bool, gradingJSON []byte, ok bool) {
	u := masterURL + "/v1/compliance/policy?tenant=" + url.QueryEscape(orgID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return false, privacyTierMetadataOnly, false, nil, false
	}
	resp, err := complianceHTTPClient.Get().Do(req)
	if err != nil {
		return false, privacyTierMetadataOnly, false, nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, privacyTierMetadataOnly, false, nil, false
	}
	var body struct {
		Enabled bool `json:"enabled"`
		// Absent on a master older than 2026-08-11 ⇒ 0 ⇒ clamped to 1. An old
		// server must never be read as permission.
		PrivacyTier int `json:"privacy_tier"`
		// Absent on a master older than 2026-08-31 ⇒ "" ⇒ no force: the
		// machine's own password-lane level governs (factory simple). Only the
		// exact value "advanced" forces; anything else is not a third state.
		PasswordTier string `json:"password_tier"`
		// A POINTER on purpose: it is the capability probe. A master that
		// answers without the member is older than 2026-09-12 and knows nothing
		// about grading, which is a different statement from one that answers
		// with something we cannot read. Absent ⇒ nil ⇒ grading off; unusable ⇒
		// ok=false ⇒ keep what we have. (`grading: null` also lands on nil,
		// which says the same thing as absent.) And `{}` is a THIRD statement —
		// "I speak grading, nothing is configured" — kept apart from absent all
		// the way into the child (TODO-61).
		Grading *json.RawMessage `json:"grading"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		// spec: R-compliance-grading-14.S2 一次非法下发恰好一条 WARN（带原因码）
		// Used to return silently: /health still went degraded, but the logs held
		// no trace of the first rejection. One WARN per rejected document, emitted
		// HERE in the failing branch rather than in noteCompliancePolicyRejected,
		// because that counter also sees network errors and non-200 answers, which
		// the 2026-09-15 decision (TODO-103) deliberately left out of this clause.
		// No decoder error text: it can quote bytes of the body.
		slog.Warn("compliance master policy response is not decodable JSON; "+
			"keeping the last valid policy",
			"event.name", observability.EventCompliancePolicyUndecodable,
			"error.code", observability.ErrCodeCompliancePolicyUndecodable)
		return false, privacyTierMetadataOnly, false, nil, false
	}
	grading, gradingUsable := normalizeGradingPolicy(body.Grading)
	if !gradingUsable {
		// Loud, because the only other symptom is a fleet quietly enforcing an
		// older ladder than the console displays (失败要显眼). No content: the
		// document is org policy, but it is still not ours to log.
		// spec: R-compliance-grading-14.S2 — carries the reason code too.
		slog.Warn("compliance master policy carries an unusable grading document; "+
			"keeping the last valid one",
			"event.name", observability.EventComplianceGradingInvalid,
			"error.code", observability.ErrCodeComplianceGradingUnusable,
			"bytes", len(*body.Grading))
		return false, privacyTierMetadataOnly, false, nil, false
	}
	return body.Enabled, clampPrivacyTier(body.PrivacyTier), body.PasswordTier == "advanced", grading, true
}

// normalizeGradingPolicy turns the raw `grading` member into the exact bytes the
// detector child will be handed, or reports that it is unusable.
//
//	(nil, true)   — no grading member (absent / null) ⇒ an old master ⇒ grading OFF.
//	("{}", true)  — explicit empty document ⇒ a new master, nothing configured ⇒
//	                grading enforcement OFF, but the key's presence is KEPT.
//	(bytes, true) — usable, already compact.
//	(nil, false)  — present but unusable ⇒ the caller keeps the last valid one.
//
// WHY `{}` IS NOT FOLDED INTO nil (TODO-61): it used to be ("an explicit no
// policy says the same as an absent one"), and it does say the same thing to
// the ENFORCEMENT layer. It does not say the same thing about the master: only a
// master that knows grading sends the member, and the detector needs exactly
// that bit to decide whether level / leaf_path / max_level may go on the intake
// wire. Folding it away made an org with a classification tree but no ladder
// report every finding as 未分级.
//
// WHY COMPACT HERE and not at spawn: the filter signature is taken over these
// bytes, and the signature is what re-spawns every detector in the fleet. A
// master that merely re-indents the same policy (a serialiser change, a proxy in
// front of it) would otherwise churn every machine. Compacting at the single
// point of entry makes the bytes canonical for the signature, the child env and
// the comparison in swapMasterGrading all at once.
//
// WHY THE OBJECT CHECK: a string / number / array where an object belongs would
// travel all the way into the child and fail inside the detector's own parser,
// far from anything that can say which master sent it. Rejecting it here is the
// difference between one WARN naming the cause and a silent loss of the ladder.
//
// WHY THE SIZE CHECK IS HERE and not at spawn: these compact bytes ARE the value
// gradingEnvValue hands to the child, so this is the only place that can measure
// the real thing before it is stored. Measuring at spawn would be too late in
// the way that matters — by then the oversize document has already replaced the
// last valid one in masterGrading, and "keep the last valid ladder" would have
// nothing left to keep. rule: R-compliance-grading-5
func normalizeGradingPolicy(raw *json.RawMessage) ([]byte, bool) {
	if raw == nil || len(*raw) == 0 {
		return nil, true
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, *raw); err != nil {
		return nil, false
	}
	b := compact.Bytes()
	switch {
	case string(b) == "null":
		return nil, true // `null` says the same as an absent member
	case string(b) == gradingPolicyDisabled:
		// Kept, not folded into nil: the member's PRESENCE is the capability
		// probe the detector reads (TODO-61). Same verdict for enforcement.
		return b, true
	case len(b) == 0 || b[0] != '{':
		return nil, false
	case len(b) > gradingEnvLimitBytes:
		// Too large for the child's environment. Same verdict as malformed:
		// unusable, so the caller keeps the last valid ladder. The console
		// enforces 7680 on save, so reaching this branch means the document did
		// not come through the console's save path — which is exactly why the
		// runtime cannot assume the ceiling was already applied.
		return nil, false
	}
	return b, true
}

// Privacy tier ladder, mirrored from the control-master org domain. Named
// constants so no caller writes a bare 3 — the number appears in the org
// policy, on the wire, here, in the detector env and in the detector itself.
const (
	privacyTierMetadataOnly = 1 // findings + offsets only; no content leaves the box
	privacyTierRawSnippet   = 3 // + the raw matched text and a small window
)

// clampPrivacyTier is the single normaliser on this side. See the note on
// fetchComplianceMasterPolicy for why every unrecognized value must fail closed.
func clampPrivacyTier(tier int) int {
	if tier < privacyTierMetadataOnly || tier > privacyTierRawSnippet {
		return privacyTierMetadataOnly
	}
	return tier
}
