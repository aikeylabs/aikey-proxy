// egress_engine.go — per-account egress transport wiring over the pluggable
// engine registry (pkg/egress). The registry + Engine interface live in the
// PUBLIC pkg/egress so a separate private module can register the mihomo
// multi-protocol engine without linking GPL code into the open-source build (see
// 20260716-多协议出口代理-嵌mihomo库-技术方案.md). This file only turns a
// resolved dialer into the cached per-account outbound transport.
package proxy

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/pkg/egress"
	xproxy "golang.org/x/net/proxy"
)

// accountEgressEntry is a memoized build result: either a ready transport or the
// build error (cached too, so a misconfigured spec fails fast and identically
// until the config changes).
type accountEgressEntry struct {
	rt  http.RoundTripper
	err error
}

// accountEgressTransport returns the RoundTripper for THIS account's egress
// chain, dispatched through the engine registry and cached per spec string.
// spec is guaranteed non-empty by the caller (serveRoute only calls when the
// route pins one).
func (p *Proxy) accountEgressTransport(spec string) (http.RoundTripper, error) {
	if v, ok := p.accountEgressTransports.Load(spec); ok {
		e := v.(accountEgressEntry)
		return e.rt, e.err
	}
	rt, err := buildEgressTransport(spec)
	// LoadOrStore so concurrent first-requests for the same spec don't each keep a
	// distinct transport (only one wins the cache; the other is GC'd unused).
	actual, _ := p.accountEgressTransports.LoadOrStore(spec, accountEgressEntry{rt: rt, err: err})
	e := actual.(accountEgressEntry)
	return e.rt, e.err
}

// buildEgressTransport resolves the spec through the engine registry and wraps
// the resulting dialer into the outbound transport.
func buildEgressTransport(spec string) (http.RoundTripper, error) {
	d, err := egress.BuildDialer(spec)
	if err != nil {
		return nil, err
	}
	return dialerToTransport(d), nil
}

// dialerToTransport wraps an egress dialer into the outbound http.Transport used
// for per-account egress — shared by all engines so their transports are tuned
// identically (HTTP/1.1 for widest proxy compat, generous idle pool; only the
// raw TCP DialContext is overridden, TLS to the upstream is still done here).
func dialerToTransport(d xproxy.Dialer) *http.Transport {
	return &http.Transport{
		DialContext:         dialerDialContext(d),
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
