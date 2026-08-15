package vkeys

import (
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"sync"
)

var errCredentialEgressInconsistent = errors.New("credential has inconsistent egress material")

// Registry maps virtual key tokens to resolved routes.
// Thread-safe for concurrent proxy use.
type Registry struct {
	byToken map[string]*ResolvedRoute
	mu      sync.RWMutex
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		byToken: make(map[string]*ResolvedRoute),
	}
}

// Registry.Load (taking []config.VirtualKeyConfig) was removed in
// Stage C-2.c along with VirtualKeyConfig itself — its only caller was
// the supervisor's static-yaml loader, also removed. Routes now flow in
// exclusively via Merge / ReplaceAll from vault-backed sources.

// Merge adds pre-resolved routes to the registry without replacing existing ones.
// Used to register team-managed virtual keys loaded from managed_virtual_keys_cache.
// Tokens that already exist in the registry are overwritten (managed key wins).
func (r *Registry) Merge(routes map[string]*ResolvedRoute) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for token, route := range routes {
		r.byToken[token] = route
	}
	slog.Info("managed virtual keys merged into registry", "count", len(routes))
}

// ReplaceAll atomically replaces the entire registry with a new set of routes.
// Unlike Merge (additive), this removes tokens no longer present in the new map.
// Used by reload-registry to ensure deleted/revoked tokens are immediately invalidated.
func (r *Registry) ReplaceAll(routes map[string]*ResolvedRoute) {
	r.mu.Lock()
	r.byToken = routes
	r.mu.Unlock()
	slog.Info("virtual key registry replaced", "count", len(routes))
}

// Resolve looks up a virtual key token and returns the route, or nil.
//
// Contract: this is a hashmap exact-key lookup, NOT prefix / substring
// matching. Callers must pass the full token string. The exact-match guarantee
// is critical for the 2026-04-29 namespace-authority dispatch — token form
// validation lives in dispatch.ClassifyToken; this function only resolves
// the legitimate, fully-validated token. Future maintainers: do NOT change
// to prefix lookup or fuzzy match — that would let `aikey_personal_<63-hex>`
// or other malformed tokens silently match a valid key by accident.
func (r *Registry) Resolve(token string) *ResolvedRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byToken[token]
}

// Count returns the number of registered virtual keys.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byToken)
}

// AccountEgressSpec is one pool account's configured per-account egress spec,
// for the `aikey test` / `aikey doctor` self-check (§5.4). Label is the account's
// own display identity (email/alias) — NEVER an internal id / group name — so the
// self-check output stays user-facing (feedback_terse_user_messages_no_commercial_leak).
type AccountEgressSpec struct {
	Label string
	Spec  string
}

// EgressSpecs returns the DISTINCT per-account egress specs across all group
// routes, one row per account. The same group_runtime appears under every seat's
// VK token, and pool accounts recur across seats, so results are deduped by
// account id (identical specs collapse to one). Sorted by label for stable
// output. Empty result = no per-account egress configured on this node (the
// common Personal case). Read-only: parses the routes' at-rest GroupRuntime JSON,
// no dialing here — connectivity is the caller's job (egress.TestDial).
func (r *Registry) EgressSpecs() []AccountEgressSpec {
	r.mu.RLock()
	routes := make([]*ResolvedRoute, 0, len(r.byToken))
	for _, rt := range r.byToken {
		routes = append(routes, rt)
	}
	r.mu.RUnlock()

	byAccount := make(map[string]AccountEgressSpec)
	for _, rt := range routes {
		if rt == nil || rt.GroupRuntime == "" {
			continue
		}
		var mat map[string]GroupRuntimeAccount
		if err := json.Unmarshal([]byte(rt.GroupRuntime), &mat); err != nil {
			// Malformed material is a routing problem surfaced elsewhere; the
			// self-check just skips it rather than failing the whole enumeration.
			continue
		}
		for accountID, acc := range mat {
			if acc.EgressProxyURL == "" {
				continue
			}
			label := acc.Identity
			if label == "" {
				label = "account " + accountID
			}
			byAccount[accountID] = AccountEgressSpec{Label: label, Spec: acc.EgressProxyURL}
		}
	}

	out := make([]AccountEgressSpec, 0, len(byAccount))
	for _, s := range byAccount {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// EgressSpecForGroupCredential resolves one selected pool credential's
// effective egress from that pool's already-synchronized runtime material.
// Scoping by the Master-resolved group prevents malformed material from an
// unrelated pool from blocking this login, while malformed or conflicting
// material inside the selected pool still fails closed. The raw proxy URL stays
// inside aikey-proxy: neither the Personal page nor the remote Master page
// receives it. found=false means the selected material has not reached this
// node yet; callers must fail visibly instead of silently using another exit.
func (r *Registry) EgressSpecForGroupCredential(oauthGroupID, credentialID string) (spec string, found bool, err error) {
	r.mu.RLock()
	routes := make([]*ResolvedRoute, 0, len(r.byToken))
	for _, rt := range r.byToken {
		routes = append(routes, rt)
	}
	r.mu.RUnlock()

	for _, rt := range routes {
		if rt == nil || rt.OauthGroupID != oauthGroupID || rt.GroupRuntime == "" {
			continue
		}
		var material map[string]*GroupRuntimeAccount
		if json.Unmarshal([]byte(rt.GroupRuntime), &material) != nil {
			return "", false, errors.New("group runtime egress material is malformed")
		}
		for _, account := range material {
			if account == nil {
				continue
			}
			if account.CredentialID != credentialID {
				continue
			}
			if found && spec != account.EgressProxyURL {
				return "", false, errCredentialEgressInconsistent
			}
			spec, found = account.EgressProxyURL, true
		}
	}
	return spec, found, nil
}
