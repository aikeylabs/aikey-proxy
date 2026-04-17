package vkeys

import (
	"log/slog"
	"sync"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
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

// Load replaces the entire registry from config.
// Used at startup and on config reload.
func (r *Registry) Load(keys []config.VirtualKeyConfig) {
	newMap := make(map[string]*ResolvedRoute, len(keys))
	for _, k := range keys {
		newMap[k.Token] = &ResolvedRoute{
			VirtualKeyID:  k.ID,
			Provider:      k.Provider,
			BaseURL:       k.BaseURL,
			KeyAlias:      k.KeyAlias,
			AllowedModels: k.AllowedModels,
			// For static YAML keys the provider field IS the protocol type
			// (e.g. "anthropic", "openai"). Managed keys set this separately.
			ProtocolType: k.Provider,
			RouteSource:  "personal_byok",
		}
	}

	r.mu.Lock()
	r.byToken = newMap
	r.mu.Unlock()

	slog.Info("virtual key registry loaded", "count", len(newMap))
}

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
