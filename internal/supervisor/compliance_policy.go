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
	"fmt"
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
	// complianceMasterPolicyKey holds the JSON {enabled,locked} the UI + CLI read
	// to reflect / enforce the org mandate. Plaintext config (like change_seq) —
	// no vault unlock needed; integrity comes from the authenticated master pull.
	complianceMasterPolicyKey = "compliance.master_policy"
	compliancePollInterval    = 60 * time.Second

	// gradingPolicyDisabled is what AIKEY_COMPLIANCE_GRADING carries when this
	// org has no grading policy: an empty object, i.e. grading OFF, and the
	// detector's decision layer behaves byte-for-byte as it did before the
	// feature existed (R-compliance-grading-3).
	//
	// 🔴 It is ONLY ever reached from a master that answered and did not mention
	// grading. It is NOT the fallback for "the answer was unusable" — see
	// applyComplianceMasterPolicy.
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
	if s.applyComplianceMasterPolicy(enabled, tier, passwordAdvanced, gradingJSON, ok) {
		if err := s.Reload(ctx); err != nil {
			slog.Warn("compliance policy reload failed",
				"event.name", "proxy.compliance.policy_reload_failed", "error", err)
		}
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
// that only exists as behaviour, so it needs somewhere to be asserted. The
// poller itself needs a control-panel URL, a team VK and a live generation, so
// nothing could be pinned through it; this method needs a zero Supervisor.
//
// fetchOK=false means "no answer", never "the answer was: nothing". Everything
// this method would set stays as it was, which for the scalars is the long
// standing behaviour ("don't flap on a transient miss") and for the grading
// document is DEC-compliance-grading-10: one unusable response must not switch
// an organisation's whole ladder off while its console still shows it on.
// rule: R-compliance-grading-5
func (s *Supervisor) applyComplianceMasterPolicy(enabled bool, tier int, passwordAdvanced bool, gradingJSON []byte, fetchOK bool) bool {
	// One poll happened, so /health may speak about this follower from now on.
	s.masterPolicyAttempted.Store(true)
	if !fetchOK {
		s.noteCompliancePolicyRejected()
		return false // ②③: keep the last valid policy; nothing changed, nothing to re-spawn
	}
	// ① and the happy path are BOTH usable answers: the node is following the
	// master, whether or not that master has a grading policy to give.
	s.noteCompliancePolicyAccepted()
	// Persist for the web toggle + CLI guard. locked == enabled for now (master
	// ON ⇒ user can't disable; master OFF ⇒ user free). Kept as two fields so a
	// future "force-off + locked" variant doesn't change the wire shape.
	//
	// privacy_tier rides along so the local console can SHOW what the org decided.
	// 🔴 Writing it here does NOT make it settable locally: nothing reads this key
	// back to decide anything — the detector env comes from the atomic below, and
	// the master re-checks its own column at ingest. This value is for display.
	// password_tier rides along for DISPLAY as well (same 🔴 note as privacy_tier:
	// nothing reads this key back to decide anything — the detector env comes
	// from the atomic below).
	passwordTier := ""
	if passwordAdvanced {
		passwordTier = "advanced"
	}
	policy := fmt.Sprintf(`{"enabled":%t,"locked":%t,"privacy_tier":%d,"password_tier":%q}`, enabled, enabled, tier, passwordTier)
	if s.cfg != nil {
		_ = vault.WriteConfigString(s.cfg.Vault.Path, complianceMasterPolicyKey, policy)
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
	// Same reasoning once more for the grading document: the ladder reaches the
	// detector as AIKEY_COMPLIANCE_GRADING at spawn, so an admin changing L4 from
	// mask to warn changes nothing on a machine whose child is already running
	// until something forces a re-spawn. rule: R-compliance-grading-5
	gradingChanged := s.swapMasterGrading(gradingJSON)
	if enabledChanged || tierChanged || passwordChanged || gradingChanged {
		slog.Info("compliance master policy changed",
			"event.name", "proxy.compliance.policy_changed",
			"enabled", enabled, "privacy_tier", tier, "grading_changed", gradingChanged)
		return true
	}
	return false
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
// A nil / empty document is stored as "no policy" (⇒ gradingPolicyDisabled in
// the child env), which is the ① old-master case only — the unusable-answer
// cases never reach here (see applyComplianceMasterPolicy).
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

// gradingPolicyJSON is the compact grading document currently in force, or nil
// when the org has none. Read by the spawn path (env) and the filter signature.
func (s *Supervisor) gradingPolicyJSON() []byte {
	if p := s.masterGrading.Load(); p != nil {
		return *p
	}
	return nil
}

// gradingEnvValue is the exact AIKEY_COMPLIANCE_GRADING value handed to the
// detector child — the single place that decides what "no policy" looks like on
// the wire into the child, so the spawn path cannot spell it differently from
// the fences.
func (s *Supervisor) gradingEnvValue() string {
	if g := s.gradingPolicyJSON(); len(g) > 0 {
		return string(g)
	}
	return gradingPolicyDisabled
}

// fetchComplianceMasterPolicy GETs the PUBLIC tenant policy endpoint (no JWT,
// mirrors the pack-pull). ok=false on any error so the caller keeps the
// last-known value.
//
// 🔴 THIS LAYER ONLY REPORTS; IT NEVER DECIDES. That matters for gradingJSON,
// which comes back nil in two OPPOSITE situations, told apart by ok:
//
//	nil, ok=true  — the master answered and does not have a grading policy
//	                (an old master, or an org that switched grading off) ⇒ the
//	                caller turns grading OFF.
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
		// which says the same thing as absent.)
		Grading *json.RawMessage `json:"grading"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, privacyTierMetadataOnly, false, nil, false
	}
	grading, gradingUsable := normalizeGradingPolicy(body.Grading)
	if !gradingUsable {
		// Loud, because the only other symptom is a fleet quietly enforcing an
		// older ladder than the console displays (失败要显眼). No content: the
		// document is org policy, but it is still not ours to log.
		slog.Warn("compliance master policy carries an unusable grading document; "+
			"keeping the last valid one",
			"event.name", observability.EventComplianceGradingInvalid,
			"bytes", len(*body.Grading))
		return false, privacyTierMetadataOnly, false, nil, false
	}
	return body.Enabled, clampPrivacyTier(body.PrivacyTier), body.PasswordTier == "advanced", grading, true
}

// normalizeGradingPolicy turns the raw `grading` member into the exact bytes the
// detector child will be handed, or reports that it is unusable.
//
//	(nil, true)   — no grading policy (absent / null / {}) ⇒ grading OFF.
//	(bytes, true) — usable, already compact.
//	(nil, false)  — present but unusable ⇒ the caller keeps the last valid one.
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
	case string(b) == "null", string(b) == "{}":
		return nil, true // an explicit "no policy" says the same as an absent one
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
