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

var complianceHTTPClient = httpx.NewDirectClient(10 * time.Second)

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
	enabled, ok := fetchComplianceMasterPolicy(ctx, masterURL, orgID)
	if !ok {
		return // unreachable → keep last known (don't flap on a transient miss)
	}
	// Persist for the web toggle + CLI guard. locked == enabled for now (master
	// ON ⇒ user can't disable; master OFF ⇒ user free). Kept as two fields so a
	// future "force-off + locked" variant doesn't change the wire shape.
	policy := fmt.Sprintf(`{"enabled":%t,"locked":%t}`, enabled, enabled)
	if s.cfg != nil {
		_ = vault.WriteConfigString(s.cfg.Vault.Path, complianceMasterPolicyKey, policy)
	}
	// Re-evaluate spawn only when the mandate actually flips.
	if s.masterCompliance.Swap(enabled) != enabled {
		slog.Info("compliance master policy changed",
			"event.name", "proxy.compliance.policy_changed", "enabled", enabled)
		if err := s.Reload(ctx); err != nil {
			slog.Warn("compliance policy reload failed",
				"event.name", "proxy.compliance.policy_reload_failed", "error", err)
		}
	}
}

// fetchComplianceMasterPolicy GETs the PUBLIC tenant policy endpoint (no JWT,
// mirrors the pack-pull). Returns (enabled, ok); ok=false on any error so the
// caller keeps the last-known value.
func fetchComplianceMasterPolicy(ctx context.Context, masterURL, orgID string) (enabled, ok bool) {
	u := masterURL + "/v1/compliance/policy?tenant=" + url.QueryEscape(orgID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return false, false
	}
	resp, err := complianceHTTPClient.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, false
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, false
	}
	return body.Enabled, true
}
