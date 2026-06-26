// routing_override.go — I-side §6.5 keystone (proxy consumption): the in-memory
// cache of the allocation engine's seat→account routing overrides pulled from
// master's GET /accounts/me/routing.
//
// This is a THIN redirect layer over the local seatassign pick. The supervisor's
// pollRoutingOverrides (mirror of pollGroupRuntime) GETs the sparse assignments
// map every ~60s and Store()s it here; handleSeatGroupRoute looks up the seat and
// hands the override account to resolveGroupCredential, which applies it ONLY when
// it is still a valid candidate (§6.5 member-validity re-check). On any doubt the
// resolver falls back to the local pick — the engine can redirect serving, never
// break it.
//
// MAIN-LINK SAFETY (架构第一优先级 = 主链路健壮): lookup is a lock-free atomic.Value
// read on the hot path; a nil receiver / unset cache / unknown seat returns "" so
// the caller always has the local pick as the default. Store is ONLY called with a
// fresh successful pull — a poll error never clears the cache (keep-last-known),
// so a master outage degrades to "no redirect", never to "no serving".
//
// The cache is SHARED across proxy generations: one instance lives on the
// supervisor and is injected into every Proxy (SetRoutingOverrides), so a vault
// reload never loses the overrides (mirrors why quotaSnapshot/quotaCounter are
// supervisor-scoped, not per-generation).
package proxy

import "sync/atomic"

// RoutingOverrideCache holds the engine's sparse seat_id→account_id assignments
// plus the routing_version they came from.
type RoutingOverrideCache struct {
	m       atomic.Value // map[string]string; immutable once Stored (poll builds a fresh map each pull)
	version atomic.Int64
}

// NewRoutingOverrideCache returns an empty cache (every lookup misses → local pick).
func NewRoutingOverrideCache() *RoutingOverrideCache { return &RoutingOverrideCache{} }

// Store atomically replaces the whole assignments map and records the version.
// A nil map is normalized to empty so readers can always type-assert. The map is
// treated as read-only after Store, so lookup needs no lock.
func (c *RoutingOverrideCache) Store(version int64, assignments map[string]string) {
	if c == nil {
		return
	}
	if assignments == nil {
		assignments = map[string]string{} // empty = engine redirects nothing
	}
	c.m.Store(assignments)
	c.version.Store(version)
}

// Version returns the last Stored routing_version (0 when nothing stored yet) so
// the poll can skip re-applying an unchanged version.
func (c *RoutingOverrideCache) Version() int64 {
	if c == nil {
		return 0
	}
	return c.version.Load()
}

// lookup returns the engine's override account_id for seatID, or "" when the
// feature is off / nothing stored / no override for this seat. nil-safe so the
// hot path can call it unconditionally.
func (c *RoutingOverrideCache) lookup(seatID string) string {
	if c == nil || seatID == "" {
		return ""
	}
	v := c.m.Load()
	if v == nil {
		return ""
	}
	return v.(map[string]string)[seatID]
}

// SetRoutingOverrides injects the shared, supervisor-owned routing-override cache
// (one instance across all generations). nil-safe: an unset cache makes every
// lookup miss → the local seatassign pick is always the default.
func (p *Proxy) SetRoutingOverrides(c *RoutingOverrideCache) { p.routingOverrides = c }
