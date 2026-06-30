// quota_policy.go — C′ (2026-06-17): org quota policy follower.
//
// Problem it fixes: quota was the only org-level policy that reached a running
// proxy ONLY via a CLI sync (and the reliable CLI path is gated behind the master
// password). So "admin sets a limit on the master" did NOT enforce until the
// employee happened to run a password-bearing `aikey list/use/key sync` — a long-
// running proxy with an idle CLI kept serving past the limit. Confirmed live
// 2026-06-16: changing only the master left the proxy enforcing the stale limit.
//
// Fix: put quota on the SAME master-poll rail compliance + conversation-audit
// already use (compliance_policy.go). Every quotaPollInterval (plus once at
// startup) this pulls the org's quota for the seats THIS node serves and, only
// when it actually changed, rewrites quota_rules_cache and triggers a Reload so
// the existing reloadQuotaSnapshot path applies it. No employee command, no
// password.
//
// No-op when no team/org is configured, no active seats, or quota is disabled
// (Personal standalone) — exactly like the compliance poller.
package supervisor

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/quota"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

const quotaPollInterval = 60 * time.Second

var quotaHTTPClient = httpx.NewDirectClient(10 * time.Second)

// pollQuotaPolicy runs until ctx is canceled, refreshing the org quota policy
// every quotaPollInterval (plus once immediately).
func (s *Supervisor) pollQuotaPolicy(ctx context.Context) {
	s.syncQuotaPolicy(ctx)
	ticker := time.NewTicker(quotaPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.syncQuotaPolicy(ctx)
		}
	}
}

func (s *Supervisor) syncQuotaPolicy(ctx context.Context) {
	if !s.quotaEnabled {
		return // quota subsystem off → the whole rail is bypassed
	}
	gen := s.active.Load()
	if gen == nil || gen.vault == nil {
		return
	}
	masterURL := readControlPanelURL()
	if masterURL == "" {
		return // no control plane → nothing to follow
	}
	// org + the seats THIS node serves come from the active team managed keys —
	// the same source route resolution uses (no new source of truth). A node with
	// no team key (Personal) yields org="" / seats=nil → no-op, which is also what
	// prevents a transient empty-seats poll from wiping a CLI-written cache.
	mks, _ := gen.vault.GetActiveManagedKeys()
	orgID := resolveTeamOrgIDFromKeys(os.Getenv("AIKEY_HUB_ORG_ID"), mks)
	seats := distinctSeatIDsFromKeys(mks)
	if orgID == "" || len(seats) == 0 {
		return
	}

	subjects, sig, ok := fetchQuotaPolicy(ctx, masterURL, orgID, seats)
	if !ok {
		return // unreachable / bad response → keep last-known (don't flap)
	}
	// Apply only on real change: a successful poll with the same answer is a no-op,
	// so steady state never rewrites the vault or reloads. An empty subjects list IS
	// a valid change (the last rule for these seats was deleted) and clears the cache.
	if prev := s.lastQuotaSig.Load(); prev != nil && *prev == sig {
		return
	}
	if err := quota.WriteSubjects(s.cfg.Vault.Path, subjects); err != nil {
		slog.Warn("quota policy cache write failed",
			"event.name", "proxy.quota.policy_write_failed", "error", err.Error())
		return // leave lastQuotaSig unchanged → retry next tick
	}
	s.lastQuotaSig.Store(&sig)
	slog.Info("quota master policy changed",
		"event.name", "proxy.quota.policy_changed", "subjects", len(subjects))
	// Reload reruns buildGeneration → reloadQuotaSnapshot, which reads the freshly
	// written quota_rules_cache and swaps the in-memory snapshot. Single-path (no
	// concurrent reload race with the 5s loop). Mirrors the compliance poller.
	if err := s.Reload(ctx); err != nil {
		slog.Warn("quota policy reload failed",
			"event.name", "proxy.quota.policy_reload_failed", "error", err.Error())
	}
}

// fetchQuotaPolicy GETs the PUBLIC tenant quota endpoint (no JWT, mirrors
// CompliancePolicy / pack-pull). Returns (subjects, signature, ok); ok=false on
// any error so the caller keeps the last-known value. The signature is the raw
// response body so "did the answer change?" is exact (no re-marshal ambiguity).
func fetchQuotaPolicy(ctx context.Context, masterURL, orgID string, seats []string) ([]quota.PolicySubject, string, bool) {
	u := masterURL + "/v1/quota/policy?tenant=" + url.QueryEscape(orgID) +
		"&seats=" + url.QueryEscape(strings.Join(seats, ","))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, "", false
	}
	resp, err := quotaHTTPClient.Do(req)
	if err != nil {
		return nil, "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", false
	}
	var body struct {
		Subjects []quota.PolicySubject `json:"subjects"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&body); decErr != nil {
		return nil, "", false
	}
	// Signature from the decoded+re-marshaled subjects (order-stabilized): the
	// server returns subjects in a stable order, but re-marshaling a normalized
	// slice makes the change-signal independent of whitespace/key-order quirks.
	sort.Slice(body.Subjects, func(i, j int) bool { return body.Subjects[i].SubjectID < body.Subjects[j].SubjectID })
	sigBytes, err := json.Marshal(body.Subjects)
	if err != nil {
		return nil, "", false
	}
	return body.Subjects, string(sigBytes), true
}

// distinctSeatIDsFromKeys collects the unique, non-empty seat ids from the active
// managed keys — the seats THIS node enforces quota for. Sorted for a stable
// query string (so the signature/caching is order-independent).
func distinctSeatIDsFromKeys(mks []vault.ManagedKey) []string {
	seen := make(map[string]bool, len(mks))
	out := make([]string, 0, len(mks))
	for i := range mks { // index, not value-copy: vault.ManagedKey is a large struct
		seatID := mks[i].SeatID
		if seatID == "" || seen[seatID] {
			continue
		}
		seen[seatID] = true
		out = append(out, seatID)
	}
	sort.Strings(out)
	return out
}
