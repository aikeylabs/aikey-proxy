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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

const (
	// complianceMasterPolicyKey holds the JSON {enabled,locked} the UI + CLI read
	// to reflect / enforce the org mandate. Plaintext config (like change_seq) —
	// no vault unlock needed; integrity comes from the authenticated master pull.
	complianceMasterPolicyKey = "compliance.master_policy"
	compliancePollInterval    = 60 * time.Second
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
	enabled, tier, passwordAdvanced, ok := fetchComplianceMasterPolicy(ctx, masterURL, orgID)
	if !ok {
		return // unreachable → keep last known (don't flap on a transient miss)
	}
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
	if enabledChanged || tierChanged || passwordChanged {
		slog.Info("compliance master policy changed",
			"event.name", "proxy.compliance.policy_changed",
			"enabled", enabled, "privacy_tier", tier)
		if err := s.Reload(ctx); err != nil {
			slog.Warn("compliance policy reload failed",
				"event.name", "proxy.compliance.policy_reload_failed", "error", err)
		}
	}
}

// fetchComplianceMasterPolicy GETs the PUBLIC tenant policy endpoint (no JWT,
// mirrors the pack-pull). Returns (enabled, privacyTier, ok); ok=false on any
// error so the caller keeps the last-known value.
//
// 🔴 privacyTier is CLAMPED here, not merely decoded. It decides whether this
// machine attaches its user's raw text to the events it uploads, so every input
// that is not an understood rung must land on the safe one: a field the server
// did not send (an older master) decodes to 0, and 0/negative/out-of-range all
// clamp to 1 (metadata only). The failure direction is always "carry less".
func fetchComplianceMasterPolicy(ctx context.Context, masterURL, orgID string) (enabled bool, privacyTier int, passwordAdvanced, ok bool) {
	u := masterURL + "/v1/compliance/policy?tenant=" + url.QueryEscape(orgID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return false, privacyTierMetadataOnly, false, false
	}
	resp, err := complianceHTTPClient.Get().Do(req)
	if err != nil {
		return false, privacyTierMetadataOnly, false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, privacyTierMetadataOnly, false, false
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
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, privacyTierMetadataOnly, false, false
	}
	return body.Enabled, clampPrivacyTier(body.PrivacyTier), body.PasswordTier == "advanced", true
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
