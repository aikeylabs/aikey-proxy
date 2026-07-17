// egress_engine.go — per-account egress transport wiring over the pluggable
// engine registry (pkg/egress). The registry + Engine interface live in the
// PUBLIC pkg/egress so a separate private module can register the mihomo
// multi-protocol engine without linking GPL code into the open-source build (see
// 20260716-多协议出口代理-嵌mihomo库-技术方案.md). This file only turns a
// resolved dialer into the cached per-account outbound transport.
package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/sysproxy"
	"github.com/AiKeyLabs/pkg/egress"
	xproxy "golang.org/x/net/proxy"
)

// accountEgressEntry is a memoized build result: either a ready transport or the
// build error (cached too, so a misconfigured spec fails fast and identically
// until the config changes). closer is non-nil ONLY for a group-backed dialer
// (mihomo fallback/url-test/load-balance): it stops the background health-check
// goroutines. A running health-check loop keeps its dialer reachable, so GC can
// NEVER reclaim a leaked group dialer — it MUST be Closed explicitly. lastUsedUnix
// is touched on every hit so the idle sweeper can reclaim a spec that stopped
// being routed (an account whose egress config changed → old spec goes idle).
type accountEgressEntry struct {
	rt           http.RoundTripper
	closer       io.Closer
	err          error
	lastUsedUnix atomic.Int64
}

// accountEgressTransport returns the RoundTripper for THIS account's egress
// chain, dispatched through the engine registry and cached per spec string.
// spec is guaranteed non-empty by the caller (serveRoute only calls when the
// route pins one).
func (p *Proxy) accountEgressTransport(spec string) (http.RoundTripper, error) {
	if v, ok := p.accountEgressTransports.Load(spec); ok {
		e := v.(*accountEgressEntry)
		e.lastUsedUnix.Store(time.Now().Unix())
		return e.rt, e.err
	}
	rt, closer, err := buildEgressTransport(spec)
	entry := &accountEgressEntry{rt: rt, closer: closer, err: err}
	entry.lastUsedUnix.Store(time.Now().Unix())
	// LoadOrStore so concurrent first-requests for the same spec don't each keep a
	// distinct transport. Only one wins the cache; for a plain socks5 chain the
	// loser is GC'd unused, but a GROUP dialer carries a live health-check loop that
	// GC can't reclaim — Close the loser explicitly so its probes stop.
	actual, loaded := p.accountEgressTransports.LoadOrStore(spec, entry)
	if loaded && closer != nil {
		_ = closer.Close()
	}
	e := actual.(*accountEgressEntry)
	e.lastUsedUnix.Store(time.Now().Unix())
	return e.rt, e.err
}

// evictEgress drops a cached egress transport and stops its health-check
// goroutines (group-backed dialers only). Call when an account's egress config
// changes or the account goes idle, so the old group's background probes don't
// linger (the stateful-design cleanup the fallback-group方案 §5.2 requires).
func (p *Proxy) evictEgress(spec string) {
	if v, ok := p.accountEgressTransports.LoadAndDelete(spec); ok {
		if e := v.(*accountEgressEntry); e.closer != nil {
			_ = e.closer.Close()
		}
	}
}

// egressIdleTTL / egressSweepInterval bound how long an unused egress transport
// (and its health-check goroutines) lingers after its account stops routing
// through it (config change / idle). Generous: a still-serving egress touches
// lastUsed on every request and is never swept.
const (
	egressIdleTTL       = 30 * time.Minute
	egressSweepInterval = 5 * time.Minute
)

// sweepIdleEgress Closes + removes every cached egress transport not used within
// maxIdle of now. Returns the number reclaimed (for tests / observability).
func (p *Proxy) sweepIdleEgress(now time.Time, maxIdle time.Duration) int {
	cutoff := now.Add(-maxIdle).Unix()
	reclaimed := 0
	p.accountEgressTransports.Range(func(k, v any) bool {
		e := v.(*accountEgressEntry)
		if e.lastUsedUnix.Load() <= cutoff {
			if p.accountEgressTransports.CompareAndDelete(k, v) {
				if e.closer != nil {
					_ = e.closer.Close()
				}
				reclaimed++
			}
		}
		return true
	})
	return reclaimed
}

// startEgressSweeper runs the idle-egress reclaimer until the proxy context is
// canceled. Started once from New(); cheap when no egress is configured (ranges an
// empty map). ctx nil (tests constructing &Proxy{} directly) → no-op.
func (p *Proxy) startEgressSweeper() {
	if p.proxyCtx == nil {
		return
	}
	go func() {
		t := time.NewTicker(egressSweepInterval)
		defer t.Stop()
		for {
			select {
			case <-p.proxyCtx.Done():
				return
			case now := <-t.C:
				p.sweepIdleEgress(now, egressIdleTTL)
			}
		}
	}()
}

// buildEgressTransport resolves the spec through the engine registry and wraps
// the resulting dialer into the outbound transport. The returned closer is
// non-nil only when the dialer owns background state (a group's health check).
func buildEgressTransport(spec string) (http.RoundTripper, io.Closer, error) {
	return BuildEgressTransport(spec)
}

// BuildEgressTransport is the exported node-level entry: the /user/settings
// upstream (app.buildTransport) reuses the SAME engine + transport tuning as the
// per-account path so a multi-protocol / chain node upstream behaves identically
// to a per-account one (config alignment, 2026-07-16). The closer is non-nil
// only for a group-backed dialer (mihomo fallback/url-test/load-balance) and
// MUST be Closed when the node upstream is swapped, or its health-check
// goroutines leak. Returns the concrete *http.Transport so the caller can store
// it in the same atomic.Pointer[http.Transport] the single-URL path uses.
func BuildEgressTransport(spec string) (*http.Transport, io.Closer, error) {
	d, err := egress.BuildDialer(spec)
	if err != nil {
		return nil, nil, err
	}
	var closer io.Closer
	if c, ok := d.(io.Closer); ok {
		closer = c
	}
	return dialerToTransport(d), closer, nil
}

// EgressDialError tags a failure to establish the per-account egress connection
// (a socks5 hop refused, or a fallback/url-test group has NO reachable member).
// The forward path's ErrorHandler detects it and returns a clear "egress connect
// fail" to the caller instead of a generic upstream error — and crucially, the
// engine FAILS here rather than dialing direct, so traffic never leaks out the
// node IP (单账号单出口 IP).
type EgressDialError struct{ err error }

func (e *EgressDialError) Error() string { return "egress connect fail: " + e.err.Error() }
func (e *EgressDialError) Unwrap() error { return e.err }

// dialerToTransport wraps an egress dialer into the outbound http.Transport used
// for per-account egress — shared by all engines so their transports are tuned
// identically (HTTP/1.1 for widest proxy compat, generous idle pool; only the
// raw TCP DialContext is overridden, TLS to the upstream is still done here). A
// dial failure is wrapped in *EgressDialError so the forward path can surface it
// as an egress-specific error (this transport is ONLY used for account egress).
//
// Internal destinations (loopback / NO_PROXY) dial DIRECT, never through the
// account egress chain — the same bypass the node-level explicit upstream honors
// (app.buildTransport), so a self-hosted/intranet target isn't forced out the
// account's exit IP. Both layers share sysproxy.NoProxyBypass (single NO_PROXY
// source). (2026-07-16 gap fix — the node-upstream paths already bypassed; this
// closes the per-account egress path.)
// egressBypass yields the NO_PROXY/loopback bypass predicate for the per-account
// egress transport (internal destinations dial direct — the 2026-07-16 gap fix).
// A package var so hermetic tests, which dial LOOPBACK targets THROUGH the egress
// as a stand-in for a public upstream, can disable the always-on loopback bypass
// that would otherwise short-circuit them. Production always uses the real one.
var egressBypass = sysproxy.NoProxyBypass

func dialerToTransport(d xproxy.Dialer) *http.Transport {
	dial := dialerDialContext(d)
	bypass := egressBypass()
	directDial := (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if host, _, herr := net.SplitHostPort(addr); herr == nil && bypass(host) {
				return directDial(ctx, network, addr) // internal → direct, not through egress
			}
			conn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, &EgressDialError{err: err}
			}
			return conn, nil
		},
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// dialerDialContext adapts an x/net/proxy dialer to http.Transport.DialContext,
// honoring the context when the dialer supports it (all our hops + Direct do).
func dialerDialContext(d xproxy.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if cd, ok := d.(xproxy.ContextDialer); ok {
		return cd.DialContext
	}
	return func(_ context.Context, network, addr string) (net.Conn, error) {
		return d.Dial(network, addr)
	}
}
