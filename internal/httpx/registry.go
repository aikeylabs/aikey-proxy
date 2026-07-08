package httpx

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// registry.go — central self-heal registry for CONTROL-PLANE HTTP clients.
//
// Every long-lived direct client the proxy uses to reach master / collector /
// hub (group-runtime, member-token writeback, routing-override, quota,
// compliance, signals, JWT refresh, events/canary/preflight, cluster register)
// can go STALE after a host network change (WiFi switch / tether / interface
// up-down): a fresh dial returns "no route to host" until the PROCESS restarts,
// even though master is reachable from a fresh process.
//
// SwappableClient makes each such client hot-swappable behind an atomic pointer;
// registering it lets the proxy's self-heal (supervisor/selfheal.go + netmon.go)
// call RebuildAllControlPlane() to install a fresh client (new dialer + empty
// pool) for EVERY control-plane rail at once on a network change — no per-client
// wiring, no rail left stale.

// SwappableClient is a hot-swappable *http.Client. Get() returns the live client
// (safe for concurrent use); Rebuild() atomically installs a fresh one from the
// factory. Construct via NewSwappable so it's registered for RebuildAllControlPlane.
type SwappableClient struct {
	ptr     atomic.Pointer[http.Client]
	factory func() *http.Client
}

// NewSwappable builds a swappable client from factory, stores the first instance,
// and registers it so RebuildAllControlPlane() rebuilds it on a network change.
func NewSwappable(factory func() *http.Client) *SwappableClient {
	s := &SwappableClient{factory: factory}
	s.ptr.Store(factory())
	registerControlPlane(s)
	return s
}

// NewSwappableDirect is the common-case constructor: a registered swappable
// direct control-plane client with the given timeout. One factory for every
// control-plane rail so callers don't repeat the closure.
func NewSwappableDirect(timeout time.Duration) *SwappableClient {
	return NewSwappable(func() *http.Client { return NewDirectClient(timeout) })
}

// NewSwappableFixed wraps an already-built *http.Client (e.g. one injected by a
// test or a caller) as a SwappableClient WITHOUT registering it — Rebuild is a
// no-op reinstall of the same client. Lets a struct field be *SwappableClient
// uniformly while honoring an injected client (which must not be globally
// rebuilt out from under the injector).
func NewSwappableFixed(c *http.Client) *SwappableClient {
	s := &SwappableClient{factory: func() *http.Client { return c }}
	s.ptr.Store(c)
	return s
}

// Get returns the live client — always call this at request time (never cache the
// result) so a mid-flight Rebuild takes effect on the next request.
func (s *SwappableClient) Get() *http.Client { return s.ptr.Load() }

// Rebuild installs a fresh client from the factory (new transport + empty pool).
func (s *SwappableClient) Rebuild() { s.ptr.Store(s.factory()) }

var (
	cpMu      sync.Mutex
	cpClients []*SwappableClient
)

func registerControlPlane(s *SwappableClient) {
	cpMu.Lock()
	cpClients = append(cpClients, s)
	cpMu.Unlock()
}

// RebuildAllControlPlane rebuilds every registered control-plane client. Called by
// the proxy self-heal on a host network change (proactive) or a persistent
// no-route error (reactive). Cheap + idempotent — a fresh client is just a cloned
// transport with an empty connection pool. Returns the count rebuilt (for logs).
func RebuildAllControlPlane() int {
	cpMu.Lock()
	defer cpMu.Unlock()
	for _, s := range cpClients {
		s.Rebuild()
	}
	return len(cpClients)
}
