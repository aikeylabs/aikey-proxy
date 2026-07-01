// group_runtime_policy.go — N7c-2: proxy-side channel-③ group-runtime follower.
//
// The always-on proxy pulls the account-level group-runtime endpoint from master
// (GET /accounts/me/group-runtime, account-JWT), encrypts each candidate
// account's token/key with the vault key, and writes it into the group VK's
// managed_virtual_keys_cache.group_runtime column. The route resolver (N8) reads
// it at request time to pick + inject an account.
//
// WHY proxy (not CLI): access_token refresh is high-frequency (Kimi 15min) and
// the CLI isn't always running — same rail compliance/quota already use
// (quota_policy.go). System design: update/20260625-通道3-组物料下发-proxy拉取系统设计.md.
//
// SECURITY: refresh_token is NEVER fetched or stored (the master response has no
// such field). access_token/key arrive plaintext over TLS and are re-encrypted
// with the vault derivedKey before they touch disk — same at-rest protection as
// provider_account_tokens.
package supervisor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/seatassign"
)

func defaultGroupRuntimeClient() *http.Client { return httpx.NewDirectClient(10 * time.Second) }

const groupRuntimePollInterval = 60 * time.Second

// pollGroupRuntime runs until ctx is canceled, pulling the account's group
// runtime every groupRuntimePollInterval (plus once at start). No-op unless the
// oauth-group feature is enabled. The account-JWT credential is built ONCE and
// reused across cycles (one Bearer refresh window, not one per cycle); the
// control-plane refresh_token is reusable (same as the collector credential's
// re-refresh-on-restart design), so reuse is safe.
func (s *Supervisor) pollGroupRuntime(ctx context.Context) {
	if !oauthGroupRoutingEnabled() {
		return // feature off → the whole rail is bypassed (direct-bind unchanged)
	}
	gen := s.active.Load()
	if gen == nil || gen.vault == nil {
		return
	}
	creds := buildCollectorCredentials(s.cfg.Events.CollectorCredentials, gen.vault)
	cred := creds["team"] // the account-JWT used for team-scoped master calls
	if cred == nil {
		// Pre-login / no team credential → nothing to pull with. A reload after
		// `aikey account login` re-runs startup and picks it up.
		return
	}

	s.syncGroupRuntime(ctx, cred)
	ticker := time.NewTicker(groupRuntimePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.syncGroupRuntime(ctx, cred)
		}
	}
}

// syncGroupRuntime pulls the account-level group runtime and, only when the
// material actually changed, rewrites each group VK's group_runtime column and
// reloads so the resolver (N8) picks up the fresh tokens. Mirrors syncQuotaPolicy.
func (s *Supervisor) syncGroupRuntime(ctx context.Context, cred events.Credential) {
	gen := s.active.Load()
	if gen == nil || gen.vault == nil {
		return
	}
	masterURL := readControlPanelURL()
	if masterURL == "" {
		return
	}
	mks, _ := gen.vault.GetActiveManagedKeys()
	hasGroup := false
	for i := range mks {
		if mks[i].OauthGroupID != "" {
			hasGroup = true
			break
		}
	}
	if !hasGroup {
		return // no local group VK → nothing to pull/store
	}
	bearer, err := cred.Bearer(ctx)
	if err != nil {
		return // can't auth → keep last-known
	}
	// Path Z (通道3 §14): piggyback the proxy's observed window-reset epochs so
	// master re-rolls each account's window_max_util_pct per window.
	var observedResets map[string]int64
	if gen.proxy != nil {
		observedResets = gen.proxy.ObservedResetsSnapshot()
	}
	groups, sig, ok := fetchGroupRuntime(ctx, masterURL, bearer, observedResets)
	if !ok {
		return // unreachable / bad response → keep last-known (don't flap)
	}
	// Steady state: same material (no token refresh) → no rewrite/reload.
	if prev := s.lastGroupRuntimeSig.Load(); prev != nil && *prev == sig {
		return
	}
	// s.routingOverrides.Assignment is nil-safe (guards nil receiver → "" = rank-0),
	// so the routed-account stamp degrades to the local pick when overrides are unset.
	if err := writeGroupRuntimeForGroups(s.cfg.Vault.Path, gen.vault.DerivedKey(), mks, groups, s.routingOverrides.Assignment); err != nil {
		slog.Warn("group_runtime write failed",
			"event.name", "proxy.group_runtime.write_failed", "error", err.Error())
		return // leave lastGroupRuntimeSig unchanged → retry next tick
	}
	s.lastGroupRuntimeSig.Store(&sig)
	slog.Info("group runtime material changed",
		"event.name", "proxy.group_runtime.changed", "groups", len(groups))
	if err := s.Reload(ctx); err != nil {
		slog.Warn("group_runtime reload failed",
			"event.name", "proxy.group_runtime.reload_failed", "error", err.Error())
	}
}

// ── master response (mirrors groupruntime.GroupDelivery / AccountMaterial) ──

type grDeliveryResp struct {
	Groups []grGroup `json:"groups"`
}

type grGroup struct {
	OauthGroupID  string      `json:"oauth_group_id"`
	RoutingConfig string      `json:"routing_config"`
	Accounts      []grAccount `json:"accounts"`
}

// grAccount is one candidate account's PLAINTEXT material from master (TLS-only).
// NOTE: there is intentionally no refresh_token field — master never sends it.
type grAccount struct {
	AccountID      string `json:"account_id"`
	CredentialID   string `json:"credential_id"`
	CredentialType string `json:"credential_type"` // oauth_account | api_key
	// NeedsLogin: master delivered this OAuth account as "member not logged in"
	// (no token) — the proxy returns LOGIN_REQUIRED for it (vs an absent account =
	// material not pulled yet → retryable skip). P1.
	NeedsLogin bool `json:"needs_login"`
	// OAuth-only:
	AccessToken      string `json:"access_token"`
	ExpiresAt        int64  `json:"expires_at"`
	WindowMaxUtilPct *int   `json:"window_max_util_pct"`
	WindowStatus     string `json:"window_status"`
	WindowResetAt    *int64 `json:"window_reset_at"`
	// ExternalID is the OAuth provider's account UUID. Required for Claude's
	// metadata.user_id injection (N8); empty for non-Claude. Master's N7a
	// producer must populate it for Claude OAuth group accounts — until then it
	// arrives empty and Claude OAuth group routing is degraded (see N8 finding).
	ExternalID string `json:"external_id"`
	// KEY-only:
	Key      string `json:"key"`
	BaseURL  string `json:"base_url"`
	Revision string `json:"revision"`
}

// The stored group_runtime contract (map[account_id]vkeys.GroupRuntimeAccount)
// lives in package vkeys so the writer here and the reader in package proxy (N8)
// share one definition. The secret (access_token for OAuth / key for KEY) is
// AES-GCM encrypted with the vault key; nonce + ciphertext are base64 in the
// JSON. N8 base64-decodes + vault.Decrypt.

var groupRuntimeHTTPClient = defaultGroupRuntimeClient()

// fetchGroupRuntime GETs the account-level group-runtime endpoint with an
// account-JWT Bearer. Returns (groups, rawBody, ok); ok=false on any error so the
// caller keeps the last-known group_runtime (don't flap). rawBody is the change
// signature — same plaintext response = no token change = skip the vault rewrite
// (the encrypted form can't be compared: a fresh nonce each encrypt).
// observedResetsHeader piggybacks the proxy's observed per-account window-reset
// epochs on the pull (Path Z, 通道3 §14): base64(JSON {account_id: epoch}).
// master re-rolls window_max_util_pct when an epoch is newer than its stored
// window_reset_at. Optional — master ignores it when absent (backward compatible).
const observedResetsHeader = "X-Aikey-Observed-Resets"

func fetchGroupRuntime(ctx context.Context, masterURL, bearer string, observedResets map[string]int64) ([]grGroup, string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, masterURL+"/accounts/me/group-runtime", http.NoBody)
	if err != nil {
		return nil, "", false
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if len(observedResets) > 0 {
		if b, mErr := json.Marshal(observedResets); mErr == nil {
			req.Header.Set(observedResetsHeader, base64.StdEncoding.EncodeToString(b))
		}
	}
	resp, err := groupRuntimeHTTPClient.Do(req)
	if err != nil {
		return nil, "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, "", false
	}
	var out grDeliveryResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, "", false
	}
	return out.Groups, string(body), true
}

// restampCurrentRouted recomputes IsCurrentRouted on every local group VK's EXISTING
// group_runtime after a routing-override change — WITHOUT refetching material from
// master or re-encrypting secrets (it reads the already-loaded mk.GroupRuntime and
// flips only the plaintext display flag). This couples the routing-override rail to
// the group_runtime display column (owner-approved 2026-06-30) so /user/vault reflects
// an engine redirect within one override poll, not only on the next material refresh.
//
// NO Reload: IsCurrentRouted is display-only (the hot-path resolver never reads it),
// and the CLI/web read the vault column directly — so writing the column suffices.
// The actual routing redirect already took effect via the RoutingOverrideCache the
// resolver reads at request time; this only keeps the DISPLAY in step.
func (s *Supervisor) restampCurrentRouted() {
	gen := s.active.Load()
	if gen == nil || gen.vault == nil {
		return
	}
	mks, err := gen.vault.GetActiveManagedKeys()
	if err != nil {
		return
	}
	for i := range mks {
		mk := mks[i]
		if mk.OauthGroupID == "" || mk.GroupRuntime == "" {
			continue
		}
		newJSON, changed, err := stampCurrentRoutedJSON(mk.GroupRuntime, computeRoutedAccountID(mk, s.routingOverrides.Assignment))
		if err != nil {
			slog.Warn("group_runtime restamp parse failed",
				"event.name", "proxy.group_runtime.restamp_failed",
				"virtual_key_id", mk.VirtualKeyID, "error", err.Error())
			continue
		}
		if !changed {
			continue
		}
		if err := vault.WriteGroupRuntime(s.cfg.Vault.Path, mk.VirtualKeyID, newJSON); err != nil {
			slog.Warn("group_runtime restamp write failed",
				"event.name", "proxy.group_runtime.restamp_failed",
				"virtual_key_id", mk.VirtualKeyID, "error", err.Error())
		}
	}
}

// buildGroupRuntimeMap encrypts each account's secret (access_token | key) with the
// vault key and returns the per-account material map for one group. It is
// ROUTED-AGNOSTIC — IsCurrentRouted (C2 display) is stamped per-VK later by
// marshalGroupRuntime, because "which account is routed" is per-seat and the same
// group's VKs belong to different seats. An account whose encryption fails is skipped
// (best-effort — one bad account must not blank the whole group).
func buildGroupRuntimeMap(derivedKey []byte, accounts []grAccount) map[string]vkeys.GroupRuntimeAccount {
	out := make(map[string]vkeys.GroupRuntimeAccount, len(accounts))
	for _, a := range accounts {
		// needs_login marker carries NO secret — store it as-is so the resolver can
		// return LOGIN_REQUIRED for it (P1), distinct from an absent account.
		if a.NeedsLogin {
			out[a.AccountID] = vkeys.GroupRuntimeAccount{CredentialType: a.CredentialType, NeedsLogin: true}
			continue
		}
		secret := a.AccessToken
		if a.CredentialType == "api_key" {
			secret = a.Key
		}
		nonce, ct, err := vault.Encrypt(derivedKey, []byte(secret))
		if err != nil {
			continue // skip this account; keep the rest
		}
		gra := vkeys.GroupRuntimeAccount{
			CredentialType:   a.CredentialType,
			SecretNonce:      base64.StdEncoding.EncodeToString(nonce),
			SecretCiphertext: base64.StdEncoding.EncodeToString(ct),
		}
		if a.CredentialType == "api_key" {
			gra.BaseURL = a.BaseURL
			gra.Revision = a.Revision
		} else {
			gra.ExpiresAt = a.ExpiresAt
			gra.WindowMaxUtilPct = a.WindowMaxUtilPct
			gra.WindowStatus = a.WindowStatus
			gra.WindowResetAt = a.WindowResetAt
			gra.ExternalID = a.ExternalID
		}
		out[a.AccountID] = gra
	}
	return out
}

// marshalGroupRuntime renders the material map, stamping IsCurrentRouted=true on the
// single routedAccountID (C2 display). routedAccountID "" (or absent from the map) →
// no account is flagged. The input map is NOT mutated (entries are copied by value).
func marshalGroupRuntime(base map[string]vkeys.GroupRuntimeAccount, routedAccountID string) (string, error) {
	out := make(map[string]vkeys.GroupRuntimeAccount, len(base))
	for id, acc := range base {
		acc.IsCurrentRouted = id == routedAccountID
		out[id] = acc
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("marshal group_runtime: %w", err)
	}
	return string(b), nil
}

// buildGroupRuntimeJSON renders the routed-agnostic group_runtime JSON for one group
// (no IsCurrentRouted flag). Retained for callers/tests that don't need per-seat
// routing display.
func buildGroupRuntimeJSON(derivedKey []byte, accounts []grAccount) (string, error) {
	return marshalGroupRuntime(buildGroupRuntimeMap(derivedKey, accounts), "")
}

// computeRoutedAccountID returns the account this seat's traffic is routed to in
// STEADY STATE (C2 display) = routing-override (when it still names a candidate in the
// group) ?? seatassign rank-0. It reuses seatassign.Rank — the SAME primitive the
// hot-path resolver (group_resolve.go) uses — so the displayed account matches what
// routing picks when nothing is cooled down. It DELIBERATELY omits the resolver's
// per-request cooldown / material / needs-login skips: owner chose the stable,
// non-flapping pick (2026-06-30), so transient failover is intentionally not surfaced.
// "" when the candidate list is absent/unparseable. overrideFor may be nil (→ rank-0).
func computeRoutedAccountID(mk vault.ManagedKey, overrideFor func(string) string) string {
	var refs []vkeys.GroupAccountRef
	if mk.GroupAccounts == "" || json.Unmarshal([]byte(mk.GroupAccounts), &refs) != nil || len(refs) == 0 {
		return ""
	}
	accounts := make([]seatassign.Account, 0, len(refs))
	inSet := make(map[string]bool, len(refs))
	for _, r := range refs {
		accounts = append(accounts, seatassign.Account{AccountID: r.AccountID, Priority: r.Priority})
		inSet[r.AccountID] = true
	}
	ordered := seatassign.Rank(mk.SeatID, accounts)
	if len(ordered) == 0 {
		return ""
	}
	routed := ordered[0].AccountID // rank-0 default
	if overrideFor != nil {
		if ov := overrideFor(mk.SeatID); ov != "" && inSet[ov] {
			routed = ov // engine redirect — apply only when it still names a candidate
		}
	}
	return routed
}

// stampCurrentRoutedJSON rewrites an EXISTING group_runtime JSON so ONLY
// routedAccountID carries IsCurrentRouted (C2 re-stamp on a routing-override change —
// no master fetch, no re-encryption, secrets untouched). Returns (json, changed, err);
// changed=false when nothing moved (caller skips the write). Unparseable input is
// returned unchanged with the error so a corrupt column can't crash the poll.
func stampCurrentRoutedJSON(runtimeJSON, routedAccountID string) (string, bool, error) {
	if runtimeJSON == "" || runtimeJSON == "{}" {
		return runtimeJSON, false, nil
	}
	var m map[string]vkeys.GroupRuntimeAccount
	if err := json.Unmarshal([]byte(runtimeJSON), &m); err != nil {
		return runtimeJSON, false, err
	}
	changed := false
	for id, acc := range m {
		want := id == routedAccountID
		if acc.IsCurrentRouted != want {
			acc.IsCurrentRouted = want
			m[id] = acc
			changed = true
		}
	}
	if !changed {
		return runtimeJSON, false, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return runtimeJSON, false, fmt.Errorf("marshal group_runtime: %w", err)
	}
	return string(b), true, nil
}

// writeGroupRuntimeForGroups writes the encrypted material into every group VK's
// group_runtime column, stamping IsCurrentRouted PER-VK (per-seat) via
// computeRoutedAccountID — the same group's VKs belong to different seats and can
// route to different accounts. A VK belongs to a group when its OauthGroupID matches;
// a group with no local VK is simply skipped (the proxy only stores what it routes).
// overrideFor supplies the engine's seat→account routing override (nil → rank-0 only).
func writeGroupRuntimeForGroups(dbPath string, derivedKey []byte, mks []vault.ManagedKey, groups []grGroup, overrideFor func(string) string) error {
	// group_id → its locally-known managed keys (need the whole mk for SeatID +
	// GroupAccounts to compute the per-seat routed account, not just the VK id).
	mksByGroup := make(map[string][]vault.ManagedKey)
	for i := range mks {
		if mks[i].OauthGroupID != "" {
			mksByGroup[mks[i].OauthGroupID] = append(mksByGroup[mks[i].OauthGroupID], mks[i])
		}
	}
	delivered := make(map[string]bool, len(groups))
	for _, g := range groups {
		delivered[g.OauthGroupID] = true
		groupMks := mksByGroup[g.OauthGroupID]
		if len(groupMks) == 0 {
			continue
		}
		// Encrypt the material ONCE per group (routed-agnostic), then stamp the
		// per-seat routed flag per VK — avoids re-encrypting for each seat.
		base := buildGroupRuntimeMap(derivedKey, g.Accounts)
		for _, mk := range groupMks {
			jsonVal, err := marshalGroupRuntime(base, computeRoutedAccountID(mk, overrideFor))
			if err != nil {
				return err
			}
			if err := vault.WriteGroupRuntime(dbPath, mk.VirtualKeyID, jsonVal); err != nil {
				return err
			}
		}
	}
	// Access gate (defense-in-depth): a local group VK whose group is NO LONGER in
	// the delivery — its seat was unbound, so master stopped delivering it (channel
	// ③'s oauth_group_member gate) — must have its cached token WIPED, so a stale
	// secret can't keep serving. The master-side snapshot candidate-set gate already
	// cuts the route on the next key sync; this clears the residual material on the
	// proxy's own poll (independent of the CLI), closing the window either way.
	// group_runtime is a JSON object {account_id:{...}}, so empty = "{}".
	// Only reached after a SUCCESSFUL delivery fetch (caller gates on ok), so this
	// never wipes on a transient master error.
	for gid, groupMks := range mksByGroup {
		if delivered[gid] {
			continue
		}
		for _, mk := range groupMks {
			if err := vault.WriteGroupRuntime(dbPath, mk.VirtualKeyID, "{}"); err != nil {
				return err
			}
		}
	}
	return nil
}
