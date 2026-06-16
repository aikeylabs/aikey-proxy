// conversation_audit_policy.go — org-level conversation-audit capture switch
// follower (v1.0.1-alpha.2). Mirrors compliance_policy.go (G3): a 60s poll of
// the PUBLIC master policy endpoint that gates whether the proxy CAPTURES
// employee conversation content for the enterprise Conversation Audit feature.
//
// Difference vs compliance: a flip does NOT spawn or kill anything. The capture
// hook on the forward path just reads ConversationAuditEnabled() per request, so
// turning the switch on/off only changes whether the bypass capture runs. Default
// OFF (atomic zero value); fail-safe — an unreachable master keeps the last-known
// value (never flaps capture on a transient miss). No-op when no team/org is
// configured (Personal) → capture stays off.
package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

const (
	// conversationAuditPolicyKey holds the JSON {enabled,max_bytes} the web toggle
	// + CLI read. Plaintext config (like the compliance policy) — integrity comes
	// from the authenticated master pull, no vault unlock needed.
	conversationAuditPolicyKey    = "conversation_audit.master_policy"
	conversationAuditPollInterval = 60 * time.Second
)

// ConversationAuditEnabled reports whether the org turned conversation capture ON.
// The forward-path capture hook reads this per request; false (default) → no
// capture. Lock-free atomic read, safe on the hot path.
func (s *Supervisor) ConversationAuditEnabled() bool { return s.convAuditEnabled.Load() }

// ConversationAuditMaxBytes is the org-configured per-turn content cap (0 → the
// capture's built-in default applies). Atomic read.
func (s *Supervisor) ConversationAuditMaxBytes() int64 { return s.convAuditMaxBytes.Load() }

// pollConversationAuditPolicy runs until ctx is cancelled, refreshing the org
// capture mandate every conversationAuditPollInterval (plus once immediately).
func (s *Supervisor) pollConversationAuditPolicy(ctx context.Context) {
	s.syncConversationAuditPolicy(ctx)
	ticker := time.NewTicker(conversationAuditPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.syncConversationAuditPolicy(ctx)
		}
	}
}

func (s *Supervisor) syncConversationAuditPolicy(ctx context.Context) {
	masterURL := readControlPanelURL()
	orgID := complianceOrgID() // same node-follows-the-org resolution as compliance
	if masterURL == "" || orgID == "" {
		return // no team / no org → capture stays off (Personal)
	}
	enabled, maxBytes, ok := fetchConversationAuditPolicy(ctx, masterURL, orgID)
	if !ok {
		return // unreachable → keep last-known (fail-safe, don't flap capture)
	}
	s.convAuditMaxBytes.Store(maxBytes)
	if s.cfg != nil {
		policy := fmt.Sprintf(`{"enabled":%t,"max_bytes":%d}`, enabled, maxBytes)
		_ = vault.WriteConfigString(s.cfg.Vault.Path, conversationAuditPolicyKey, policy)
	}
	if s.convAuditEnabled.Swap(enabled) != enabled {
		slog.Info("conversation audit policy changed",
			"event.name", "proxy.conversation_audit.policy_changed", "enabled", enabled)
		// No spawn/Reload: the capture hook reads the atomic each request.
	}
}

// fetchConversationAuditPolicy GETs the PUBLIC tenant policy endpoint (no JWT,
// mirrors the compliance pull). Returns (enabled, maxBytes, ok); ok=false on any
// error so the caller keeps the last-known value.
func fetchConversationAuditPolicy(ctx context.Context, masterURL, orgID string) (enabled bool, maxBytes int64, ok bool) {
	u := masterURL + "/v1/conversation-audit/policy?tenant=" + url.QueryEscape(orgID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, 0, false
	}
	resp, err := complianceHTTPClient.Do(req) // reuse the package HTTP client (10s timeout)
	if err != nil {
		return false, 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, 0, false
	}
	var body struct {
		Enabled  bool  `json:"enabled"`
		MaxBytes int64 `json:"max_bytes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, 0, false
	}
	return body.Enabled, body.MaxBytes, true
}
