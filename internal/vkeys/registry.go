package vkeys

import (
	"log/slog"
	"sync"
)

// Registry maps virtual key tokens to resolved routes.
// Thread-safe for concurrent proxy use.
type Registry struct {
	mu      sync.RWMutex
	byToken map[string]*ResolvedRoute
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
