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

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/seatassign"
)

func defaultGroupRuntimeClient() *http.Client { return httpx.NewDirectClient(10 * time.Second) }

const groupRuntimePollInterval = 60 * time.Second

// groupRuntimeRail declares this rail for the SyncRail framework (railset.go,
// 2026-07-03): gate/generation/URL/credential re-evaluated every cycle, failures
// counted into the visibility state machine. The old hand-written loop built its
// team credential once at start and early-returned forever on any startup
// precondition miss — silently (bugfix
// 2026-07-03-routing-override-rail-silent-stall.md).
func (s *Supervisor) groupRuntimeRail() railSpec {
	return railSpec{
		name:         "group_runtime",
		interval:     groupRuntimePollInterval,
		needsTeamJWT: true,
		gate: func(gen *generation) bool {
			if !oauthGroupRoutingEnabled() {
				return false // feature off → the whole rail is bypassed (direct-bind unchanged)
			}
			mks, _ := gen.vault.GetActiveManagedKeys()
			for i := range mks {
				if mks[i].OauthGroupID != "" {
					return true
				}
			}
			return false // no local group VK → nothing to pull/store (idle, not broken)
		},
		sync: s.syncGroupRuntime,
	}
}

// syncGroupRuntime runs one pull of the account-level group runtime and, only
// when the material actually changed, rewrites each group VK's group_runtime
// column and reloads so the resolver (N8) picks up the fresh tokens. Any error
// keeps the last-known material (don't flap) and is COUNTED by the framework.
func (s *Supervisor) syncGroupRuntime(ctx context.Context, gen *generation, masterURL, bearer string) error {
	mks, err := gen.vault.GetActiveManagedKeys()
	if err != nil {
		return err
	}
	// Path Z (通道3 §14): piggyback the proxy's observed window-reset epochs so
	// master re-rolls each account's window_max_util_pct per window.
	var observedResets map[string]int64
	if gen.proxy != nil {
		observedResets = gen.proxy.ObservedResetsSnapshot()
	}
	groups, sig, err := fetchGroupRuntime(ctx, masterURL, bearer, observedResets)
	if err != nil {
		return err // unreachable / bad response → keep last-known (don't flap)
	}
	// Steady state: same material (no token refresh) → no rewrite/reload.
	if prev := s.lastGroupRuntimeSig.Load(); prev != nil && *prev == sig {
		return nil
	}
	// s.routingOverrides.Assignment is nil-safe (guards nil receiver → "" = rank-0),
	// so the routed-account stamp degrades to the local pick when overrides are unset.
	// Same cooldown view the hot path uses, so is_current_routed reflects cooling failover.
	var grSkip map[string]bool
	if gen.proxy != nil {
		grSkip = gen.proxy.CooldownSkipSet()
	}
	if err := writeGroupRuntimeForGroups(s.cfg.Vault.Path, gen.vault.DerivedKey(), mks, groups, s.routingOverrides.Assignment, grSkip); err != nil {
		slog.Warn("group_runtime write failed",
			"event.name", "proxy.group_runtime.write_failed", "error", err.Error())
		return err // leave lastGroupRuntimeSig unchanged → retry next tick
	}
	s.lastGroupRuntimeSig.Store(&sig)
	slog.Info("group runtime material changed",
		"event.name", "proxy.group_runtime.changed", "groups", len(groups))
	if err := s.Reload(ctx); err != nil {
		// Local reload hiccup, not a master-sync failure: the material IS stored
		// (next reload picks it up), so the cycle still counts as a success.
		slog.Warn("group_runtime reload failed",
			"event.name", "proxy.group_runtime.reload_failed", "error", err.Error())
	}
	return nil
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
	// Display meta (non-secret, 2026-07-01) so the client's candidate LIST membership
	// refreshes off this fast rail (a fast-rail-only account renders with its
	// email/provider, not a bare UUID). Threaded straight through to group_runtime.
	Identity     string `json:"identity"`
	ProviderCode string `json:"provider_code"`
	Priority     int    `json:"priority"`
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

// groupRuntimeSwap is the group-runtime + member-token-writeback control-plane
// client, registered in the CENTRAL self-heal registry (internal/httpx). A host
// network change stalls long-lived direct clients with no-route errors (see
// selfheal.go); httpx.RebuildAllControlPlane() then installs a FRESH client (new
// dialer + empty pool) for THIS rail and every other control-plane rail at once.
// Both the poll (fetchGroupRuntime) and the writeback read the LIVE client via
// groupRuntimeClient(). WHY a whole new client rather than CloseIdleConnections():
// closing idle conns alone does NOT reliably clear the stale post-network-change
// state (golang/go#23427); a fresh Transport is the reliable reset.
var groupRuntimeSwap = httpx.NewSwappable(defaultGroupRuntimeClient)

// groupRuntimeClient returns the live (swappable) control-plane HTTP client.
func groupRuntimeClient() *http.Client { return groupRuntimeSwap.Get() }

// fetchGroupRuntime GETs the account-level group-runtime endpoint with an
// account-JWT Bearer. Returns (groups, rawBody, err); a non-nil error means the
// caller keeps the last-known group_runtime (don't flap) and the SyncRail
// framework surfaces the cause (2026-07-03: a bare ok=false hid the
// connection-refused detail that mattered most in the incident). rawBody is the
// change signature — same plaintext response = no token change = skip the vault
// rewrite (the encrypted form can't be compared: a fresh nonce each encrypt).
// observedResetsHeader piggybacks the proxy's observed per-account window-reset
// epochs on the pull (Path Z, 通道3 §14): base64(JSON {account_id: epoch}).
// master re-rolls window_max_util_pct when an epoch is newer than its stored
// window_reset_at. Optional — master ignores it when absent (backward compatible).
const observedResetsHeader = "X-Aikey-Observed-Resets"

func fetchGroupRuntime(ctx context.Context, masterURL, bearer string, observedResets map[string]int64) ([]grGroup, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, masterURL+"/accounts/me/group-runtime", http.NoBody)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if len(observedResets) > 0 {
		if b, mErr := json.Marshal(observedResets); mErr == nil {
			req.Header.Set(observedResetsHeader, base64.StdEncoding.EncodeToString(b))
		}
	}
	resp, err := groupRuntimeClient().Do(req)
	if err != nil {
		// Self-heal (2026-07-01): a host network change can stall the long-lived
		// client with a routing-layer error while master is perfectly reachable
		// from a fresh process. The poll is the steady 60s heartbeat that drives
		// recovery: Tier1 rebuilds the client, and after `threshold` consecutive
		// stuck cycles (with master confirmed reachable) escalates to a guarded
		// self-restart. Non-net-change errors (master 5xx, timeout) don't touch
		// the healer — they aren't a routing-stale symptom.
		if isNetChangeDialErr(err) {
			if d := controlPlaneHeal.onPollNetChange(masterURL); d == restartSkipBreaker {
				slog.Error("control-plane stuck reaching master after network change; restart budget exhausted — manual `aikey proxy restart` may be needed",
					"event.name", observability.EventProxyControlPlaneRestartExhausted, "error", err.Error())
			} else {
				slog.Warn("control-plane client rebuilt after network-change dial error",
					"event.name", observability.EventProxyControlPlaneClientRebuilt, "caller", "group_runtime_poll",
					"error", err.Error())
			}
		}
		return nil, "", err
	}
	// Reached master (any HTTP response proves the routing path is alive) → clear
	// the net-change stuck counter so a later transient can't ride an old tally.
	controlPlaneHeal.onPollOK()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("GET /accounts/me/group-runtime: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, "", err
	}
	var out grDeliveryResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, "", fmt.Errorf("decode group-runtime response: %w", err)
	}
	return out.Groups, string(body), nil
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
	// Same cooldown view the hot-path resolver uses, so the stamp names the account the
	// proxy actually forwards to (cooling-driven failover included).
	var skip map[string]bool
	if gen.proxy != nil {
		skip = gen.proxy.CooldownSkipSet()
	}
	nowUnix := time.Now().Unix()
	for i := range mks {
		mk := mks[i]
		if mk.OauthGroupID == "" || mk.GroupRuntime == "" {
			continue
		}
		// Feed the STORED material to the shared pick so the re-stamp applies the same
		// usability gates as the hot path (unparseable → nil = blind mode, nominal pick).
		var material map[string]vkeys.GroupRuntimeAccount
		_ = json.Unmarshal([]byte(mk.GroupRuntime), &material)
		newJSON, changed, err := stampCurrentRoutedJSON(mk.GroupRuntime, computeRoutedAccountID(mk, material, s.routingOverrides.Assignment, skip, nowUnix))
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
			out[a.AccountID] = vkeys.GroupRuntimeAccount{
				CredentialType: a.CredentialType, NeedsLogin: true,
				Identity: a.Identity, ProviderCode: a.ProviderCode, Priority: a.Priority,
			}
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
			Identity:         a.Identity,     // non-secret display meta → client list refresh
			ProviderCode:     a.ProviderCode, //
			Priority:         a.Priority,     //
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

// computeRoutedAccountID returns the account this seat's traffic is routed to (C2
// display, the is_current_routed / current_routed stamp).
//
// SINGLE SOURCE OF TRUTH (2026-07-01 unification): the pick itself is
// vkeys.PickRoutedAccount — the EXACT function the hot-path resolver
// (proxy.resolveGroupCredential) forwards with, fed the same override view (the shared
// RoutingOverrideCache via overrideFor), the same cooldown skip view
// (proxy.CooldownSkipSet), and the same material usability gates. Display == forwarding
// by construction; do NOT re-derive routing here. A needs_login pick IS the routed
// account (owner rule: the engine may route a member to an account they haven't logged
// into — the stamp shows it so the member logs into THAT one).
//
// material is the group's CURRENT runtime material map (pass the freshly built map when
// writing, or the parsed stored column when re-stamping); empty/nil → the picker's blind
// mode (rank/override-only — pre-poll display still shows a nominal pick). Residual
// (accepted): the hot path also skips undecryptable secrets per request (decrypt needs
// the vault key, can't be in the pure pick), and the stamp persists at the 60s poll +
// override-change cadence, so mid-cycle changes converge within ≤60s. skip may be nil.
// "" when the candidate list is absent/unparseable. overrideFor may be nil (→ rank-0).
func computeRoutedAccountID(mk vault.ManagedKey, material map[string]vkeys.GroupRuntimeAccount, overrideFor func(seatID, groupID string) string, skip map[string]bool, nowUnix int64) string {
	var refs []vkeys.GroupAccountRef
	if mk.GroupAccounts == "" || json.Unmarshal([]byte(mk.GroupAccounts), &refs) != nil || len(refs) == 0 {
		return ""
	}
	override := ""
	if overrideFor != nil {
		override = overrideFor(mk.SeatID, mk.OauthGroupID)
	}
	if acc, oc := vkeys.PickRoutedAccount(mk.SeatID, refs, material, override, skip, nowUnix); oc != vkeys.PickNone {
		return acc
	}
	// Nothing pickable (hot path would 429/ALL_UNUSABLE) → show the nominal seatassign
	// rank-0 rather than blank (display-only fallback; no traffic is served here anyway).
	accounts := make([]seatassign.Account, 0, len(refs))
	for _, r := range refs {
		accounts = append(accounts, seatassign.Account{AccountID: r.AccountID, Priority: r.Priority})
	}
	if ordered := seatassign.Rank(mk.SeatID, accounts); len(ordered) > 0 {
		return ordered[0].AccountID
	}
	return ""
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
// skip is the current cooldown view (proxy.CooldownSkipSet) so the routed stamp reflects
// cooling-driven failover, matching the hot path (nil → no cooldown view).
func writeGroupRuntimeForGroups(dbPath string, derivedKey []byte, mks []vault.ManagedKey, groups []grGroup, overrideFor func(seatID, groupID string) string, skip map[string]bool) error {
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
		// per-seat routed flag per VK — avoids re-encrypting for each seat. The pick is
		// fed the FRESH material map being written (not the stale stored column) so the
		// stamp's usability gates see exactly what the hot path will read next.
		base := buildGroupRuntimeMap(derivedKey, g.Accounts)
		nowUnix := time.Now().Unix()
		for _, mk := range groupMks {
			jsonVal, err := marshalGroupRuntime(base, computeRoutedAccountID(mk, base, overrideFor, skip, nowUnix))
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
