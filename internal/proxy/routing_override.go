// routing_override.go — I-side §6.5 keystone (proxy consumption): the in-memory
// cache of the allocation engine's seat→account routing overrides pulled from
// master's GET /accounts/me/routing.
//
// This is a THIN redirect layer over the local seatassign pick. The supervisor's
// pollRoutingOverrides (mirror of pollGroupRuntime) GETs the sparse assignments
// map every ~60s and Store()s it here; handleOauthGroupRoute looks up the seat and
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

import (
	"sync/atomic"

	"github.com/AiKeyLabs/pkg/routingwire"
)

// routeKey is the composite (seat, group) key of the in-memory override maps — a
// PACKAGE-PRIVATE cache implementation detail. The wire itself carries structured
// routingwire.RouteEntry objects (shared DTO module, 2026-07-02), so there is no
// cross-repo key-format contract anymore; only StoreRoutes below builds these keys.
// A multi-pool seat (member of >1 group) has a distinct binding per group. "|" is
// safe: seat/group ids are UUIDs.
func routeKey(seatID, groupID string) string { return seatID + "|" + groupID }

// StoreRoutes ingests the wire's structured route entries (pkg/routingwire) and
// atomically replaces the cache — the ONLY place wire entries become cache keys, so
// the composite-key encoding never leaks past this package. Returns the bound/blocked
// counts for the caller's log line.
func (c *RoutingOverrideCache) StoreRoutes(version int64, routes []routingwire.RouteEntry) (bound, blocked int) {
	assignments := make(map[string]string, len(routes))
	blockedSet := map[string]bool{}
	for _, r := range routes {
		if r.Blocked {
			blockedSet[routeKey(r.SeatID, r.GroupID)] = true
			continue
		}
		if r.AccountID != "" {
			assignments[routeKey(r.SeatID, r.GroupID)] = r.AccountID
		}
	}
	c.StoreAll(version, assignments, blockedSet)
	return len(assignments), len(blockedSet)
}

// RoutingOverrideCache holds the engine's sparse seat_id→account_id assignments
// plus the routing_version they came from.
type RoutingOverrideCache struct {
	m       atomic.Value // map[string]string; immutable once Stored (poll builds a fresh map each pull)
	blocked atomic.Value // map[string]bool; seats the engine left UNBOUND (pool at the ≤3-人/号 cap)
	version atomic.Int64
	stored  atomic.Bool // false until the first Store — distinguishes "never pulled" from "pulled at version 0"
}

// NewRoutingOverrideCache returns an empty cache (every lookup misses → local pick).
func NewRoutingOverrideCache() *RoutingOverrideCache { return &RoutingOverrideCache{} }

// Store replaces assignments at a version with NO blocked seats — kept for callers
// that don't carry the blocked set; delegates to StoreAll.
func (c *RoutingOverrideCache) Store(version int64, assignments map[string]string) {
	c.StoreAll(version, assignments, nil)
}

// StoreAll atomically replaces the assignments map AND the blocked set and records
// the version. nil maps are normalized to empty so readers can always type-assert;
// the maps are read-only after StoreAll, so lookup/Blocked need no lock.
func (c *RoutingOverrideCache) StoreAll(version int64, assignments map[string]string, blocked map[string]bool) {
	if c == nil {
		return
	}
	if assignments == nil {
		assignments = map[string]string{} // empty = engine redirects nothing
	}
	if blocked == nil {
		blocked = map[string]bool{} // empty = no seat is pool-full-blocked
	}
	c.m.Store(assignments)
	c.blocked.Store(blocked)
	c.version.Store(version)
	c.stored.Store(true)
}

// Stored reports whether anything has ever been Stored. The poll uses it to
// distinguish "never pulled" (version 0 because the atomic is zero-valued) from
// "pulled at routing_version 0" — without it, master's first non-empty payload
// carrying routing_version:0 would match Version()==0 and be skipped forever.
func (c *RoutingOverrideCache) Stored() bool {
	return c != nil && c.stored.Load()
}

// Version returns the last Stored routing_version (0 when nothing stored yet) so
// the poll can skip re-applying an unchanged version.
func (c *RoutingOverrideCache) Version() int64 {
	if c == nil {
		return 0
	}
	return c.version.Load()
}

// lookup returns the engine's override account_id for (seatID, groupID), or "" when
// the feature is off / nothing stored / no override for this (seat,group). Keyed by
// the composite routeKey so a multi-pool seat gets the RIGHT group's override (not just
// its first group's). nil-safe so the hot path can call it unconditionally.
func (c *RoutingOverrideCache) lookup(seatID, groupID string) string {
	if c == nil || seatID == "" || groupID == "" {
		return ""
	}
	v := c.m.Load()
	if v == nil {
		return ""
	}
	return v.(map[string]string)[routeKey(seatID, groupID)]
}

// Assignment returns the engine's override account_id for (seatID, groupID) (exported
// wrapper over lookup), or "" when nothing is overridden. Used by the supervisor's
// group_runtime writer to stamp IsCurrentRouted (C2 display) with the SAME override
// the hot-path resolver applies — one definition of "which account is routed".
func (c *RoutingOverrideCache) Assignment(seatID, groupID string) string {
	return c.lookup(seatID, groupID)
}

// Blocked reports whether the engine left (seatID, groupID) UNBOUND — every pool
// account at the ≤3-人/号 cap, or no usable account at all. The proxy 429s a
// blocked seat instead of falling back to the cap-blind local pick (which would
// route a 4th user onto a full account). nil-safe; false when the feature is off /
// nothing stored.
func (c *RoutingOverrideCache) Blocked(seatID, groupID string) bool {
	if c == nil || seatID == "" || groupID == "" {
		return false
	}
	v := c.blocked.Load()
	if v == nil {
		return false
	}
	return v.(map[string]bool)[routeKey(seatID, groupID)]
}

// SetRoutingOverrides injects the shared, supervisor-owned routing-override cache
// (one instance across all generations). nil-safe: an unset cache makes every
// lookup miss → the local seatassign pick is always the default.
func (p *Proxy) SetRoutingOverrides(c *RoutingOverrideCache) { p.routingOverrides = c }
