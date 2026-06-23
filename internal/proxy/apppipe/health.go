package apppipe

import (
	"sort"
	"sync"
	"time"
)

// HealthCache is an in-memory record of "the most recent app pipeline call,
// per app_slug". Lives in proxy process memory and is intentionally NOT
// persisted — the goal is to give the Web "Connected Apps" list a real-time
// snapshot of each app's last-call health, NOT to replace the event log
// (which collector + DWD already own as the CQRS read side).
//
// CQRS posture:
//   - The event log is `usage_event_ods` (write side) and `usage_fact_dwd`
//     (canonical read projection — durable, queried by query-service).
//   - This cache is an additional ephemeral observability surface owned by
//     the proxy process itself; it answers "show me, right now, what each
//     app's last response looked like" without going through a projector
//     lag window. It is NOT used for billing, auditing, or any business
//     rule — only the Connected Apps list display.
//
// Persistence: deliberately none. Restarting the proxy returns the cache to
// an empty state and the UI renders "No recent calls" for every app until
// fresh traffic populates it again. That is the honest semantic — the proxy
// has no recent observation. Persisting to disk would force us to reconcile
// with DWD on cold start (duplicate source of truth) and is the wrong cost
// trade for "list-page health badge".
//
// Concurrency: a single RWMutex protects the map. RecordCall acquires Write,
// Snapshot acquires Read. App-pipeline traffic is the only writer; readers
// are admin-endpoint requests (one per Web page load). Lock contention is
// negligible.
type HealthCache struct {
	entries map[string]AppHealth
	mu      sync.RWMutex
}

// AppHealth describes the most recent observed call for one app_slug.
// Fields are all valued (not pointers) — a zero StatusCode means "we have
// no recorded call for this slug" which is also the absent-from-map case.
type AppHealth struct {
	LastCallAt time.Time `json:"last_call_at"`
	// AppSlug is redundant when this struct is held as a map value, but
	// kept for the JSON snapshot the admin endpoint returns so the Web
	// side can consume an array form without re-key projecting.
	AppSlug string `json:"app_slug"`
	// ErrorType carries the upstream error envelope's `type` field (e.g.
	// "rate_limit_error") or one of the proxy-side categories ("timeout",
	// "binding_not_found") when the proxy itself synthesized the response.
	// Empty for 2xx success.
	ErrorType  string `json:"error_type,omitempty"`
	StatusCode int    `json:"status_code"`
}

// NewHealthCache returns an empty cache. Tests may call this directly; the
// production proxy gets its instance via Proxy.New().
func NewHealthCache() *HealthCache {
	return &HealthCache{entries: make(map[string]AppHealth)}
}

// RecordCall stores the most recent call's outcome for the given slug,
// overwriting any prior entry. Slug must be non-empty (the app pipeline
// guarantees this — every call routed through /apps/<slug>/v1/... has a
// resolved AppSlug); empty-slug calls are dropped silently to avoid a
// "synthetic empty bucket" leaking in via a bug elsewhere.
//
// `now` is parameterised so tests can fix the clock; production callers
// pass time.Now().
func (c *HealthCache) RecordCall(slug string, statusCode int, errorType string, now time.Time) {
	if slug == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[slug] = AppHealth{
		AppSlug:    slug,
		LastCallAt: now,
		StatusCode: statusCode,
		ErrorType:  errorType,
	}
}

// Snapshot returns a stable-sorted slice copy of all recorded entries.
// Sorting by AppSlug gives the admin endpoint a deterministic order so
// snapshot tests don't flake on Go map iteration randomness.
//
// The returned slice does not share backing memory with the cache —
// callers may safely mutate it.
func (c *HealthCache) Snapshot() []AppHealth {
	c.mu.RLock()
	out := make([]AppHealth, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e)
	}
	c.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].AppSlug < out[j].AppSlug })
	return out
}

// Lookup returns the cached health for a single slug, plus an `ok` bool
// indicating presence. Used by future single-app queries (e.g. detail
// page); the list endpoint goes through Snapshot.
func (c *HealthCache) Lookup(slug string) (AppHealth, bool) {
	c.mu.RLock()
	e, ok := c.entries[slug]
	c.mu.RUnlock()
	return e, ok
}
