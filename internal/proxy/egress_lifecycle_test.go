package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/egresstest"
	"github.com/AiKeyLabs/pkg/egress"
	xproxy "golang.org/x/net/proxy"
)

// TestEgressDialError_WrapsDialFailure: a per-account egress whose upstream is
// unreachable must fail with *EgressDialError, so the forward path can surface a
// clear "egress connect fail" (用户拍板 #1) instead of a generic upstream error —
// and it must NEVER succeed via a direct dial.
func TestEgressDialError_WrapsDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close() // nothing listening now → any dial to deadAddr refuses

	tr, _, berr := buildEgressTransport("socks5://" + deadAddr)
	if berr != nil {
		t.Fatalf("build egress transport: %v", berr)
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	_, reqErr := client.Get("http://example.invalid/")
	if reqErr == nil {
		t.Fatal("request through a dead egress must fail, not succeed (direct leak)")
	}
	var egErr *EgressDialError
	if !errors.As(reqErr, &egErr) {
		t.Fatalf("egress dial failure must surface as *EgressDialError (so chat shows 'egress connect fail'), got: %v", reqErr)
	}
	if !strings.HasPrefix(egErr.Error(), "egress connect fail:") {
		t.Fatalf("EgressDialError message %q must start with 'egress connect fail:'", egErr.Error())
	}
}

// A group-backed egress dialer owns a background health-check loop that GC can
// never reclaim — it must be Closed explicitly on cache collision / eviction.
// These tests use a fake engine whose dialer is an io.Closer spy (the real group
// dialer, mihomo, isn't linked into the open-source build). They guard the
// lifecycle wiring the fallback-group方案 §5.2 requires.

type spyDialer struct{ closed *atomic.Int32 }

func (d spyDialer) Dial(network, addr string) (net.Conn, error) {
	return nil, context.Canceled // never actually dialed in these tests
}
func (d spyDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, context.Canceled
}
func (d spyDialer) Close() error { d.closed.Add(1); return nil }

type spyEngine struct {
	prefix  string
	built   *atomic.Int32
	closed  *atomic.Int32
	enter   chan struct{} // signaled on Build entry (nil = no gate)
	release chan struct{} // Build blocks until closed (nil = no block)
}

func (e spyEngine) Name() string { return "spy-" + e.prefix }
func (e spyEngine) Claims(spec string) bool {
	return len(spec) >= len(e.prefix) && spec[:len(e.prefix)] == e.prefix
}
func (e spyEngine) Build(string) (xproxy.Dialer, error) {
	if e.enter != nil {
		e.enter <- struct{}{}
	}
	if e.release != nil {
		<-e.release
	}
	e.built.Add(1)
	return spyDialer{closed: e.closed}, nil
}

// TestEgressLifecycle_ClosesLoserOnCacheCollision: when two goroutines build the
// SAME group spec concurrently, only one entry wins the cache; the losing dialer's
// health-check MUST be Closed (else it leaks — GC can't reclaim a running probe
// loop). The build gate makes both goroutines pass the initial Load-miss and reach
// LoadOrStore together, so the collision is deterministic.
func TestEgressLifecycle_ClosesLoserOnCacheCollision(t *testing.T) {
	closed := &atomic.Int32{}
	built := &atomic.Int32{}
	enter := make(chan struct{}, 2)
	release := make(chan struct{})
	egress.Register(spyEngine{prefix: "spycollision://", built: built, closed: closed, enter: enter, release: release})
	spec := "spycollision://G"

	p := &Proxy{}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.accountEgressTransport(spec) }()
	}
	<-enter // both goroutines passed the Load-miss and are inside Build
	<-enter
	close(release) // let both proceed to LoadOrStore → one wins, one loses
	wg.Wait()

	if built.Load() != 2 {
		t.Fatalf("both goroutines should have built (Load-miss race): built=%d", built.Load())
	}
	if closed.Load() != 1 {
		t.Fatalf("exactly one losing group dialer must be Closed (leak guard), got closed=%d", closed.Load())
	}
}

// TestEgressLifecycle_EvictClosesDialer: evictEgress must stop the cached group
// dialer's health check (config change / idle cleanup).
func TestEgressLifecycle_EvictClosesDialer(t *testing.T) {
	closed := &atomic.Int32{}
	built := &atomic.Int32{}
	egress.Register(spyEngine{prefix: "spyevict://", built: built, closed: closed})
	spec := "spyevict://G"

	p := &Proxy{}
	_, _ = p.accountEgressTransport(spec) // builds + caches the spy dialer
	if closed.Load() != 0 {
		t.Fatalf("dialer closed prematurely: %d", closed.Load())
	}
	p.evictEgress(spec)
	if closed.Load() != 1 {
		t.Fatalf("evictEgress did not close the group dialer's health-check: closed=%d", closed.Load())
	}
	// Idempotent: second evict is a no-op (already deleted).
	p.evictEgress(spec)
	if closed.Load() != 1 {
		t.Fatalf("double evict re-closed: %d", closed.Load())
	}
}

// TestEgressLifecycle_SweepReclaimsIdle: the idle sweeper Closes + removes a
// group dialer whose account stopped routing through it (config change / idle),
// but keeps a still-recently-used one.
func TestEgressLifecycle_SweepReclaimsIdle(t *testing.T) {
	closed := &atomic.Int32{}
	built := &atomic.Int32{}
	egress.Register(spyEngine{prefix: "spysweep://", built: built, closed: closed})
	p := &Proxy{}
	_, _ = p.accountEgressTransport("spysweep://idle")
	_, _ = p.accountEgressTransport("spysweep://fresh")

	// Make "idle" look last-used 1h ago; "fresh" stays now.
	if v, ok := p.accountEgressTransports.Load("spysweep://idle"); ok {
		v.(*accountEgressEntry).lastUsedUnix.Store(time.Now().Add(-time.Hour).Unix())
	}
	n := p.sweepIdleEgress(time.Now(), 30*time.Minute)
	if n != 1 {
		t.Fatalf("sweep should reclaim exactly the idle entry, reclaimed=%d", n)
	}
	if closed.Load() != 1 {
		t.Fatalf("idle group dialer's health-check not closed on sweep: closed=%d", closed.Load())
	}
	if _, ok := p.accountEgressTransports.Load("spysweep://idle"); ok {
		t.Fatal("idle entry should be removed after sweep")
	}
	if _, ok := p.accountEgressTransports.Load("spysweep://fresh"); !ok {
		t.Fatal("fresh entry must survive the sweep")
	}
}

// noEgressBypass makes the per-account egress dial loopback / NO_PROXY targets
// THROUGH the chain (not direct) for the duration of the test — hermetic tests use
// a loopback server as a stand-in for a public upstream, so the always-on loopback
// bypass would otherwise short-circuit them.
func noEgressBypass(t *testing.T) {
	t.Helper()
	prev := egressBypass
	egressBypass = func() func(string) bool { return func(string) bool { return false } }
	t.Cleanup(func() { egressBypass = prev })
}

// TestEgressBypassesInternalDestination: an account egress must dial an internal
// (loopback / NO_PROXY) target DIRECT, never through the egress chain — so a
// self-hosted/intranet upstream isn't forced out the account's exit IP (2026-07-16
// NO_PROXY gap fix). Here the bypass is LEFT ON (production default): a loopback
// target must NOT traverse the egress socks5.
func TestEgressBypassesInternalDestination(t *testing.T) {
	// A loopback target — always "internal" per httpproxy canon.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer target.Close()
	go func() {
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			_ = c.Close()
		}
	}()

	sock := egresstest.NewSocks5Server(t, "", "")
	tr, _, berr := buildEgressTransport("socks5://" + sock.Addr())
	if berr != nil {
		t.Fatalf("build: %v", berr)
	}
	// Dial the loopback target through the account egress transport's DialContext.
	dc := tr.(*http.Transport).DialContext
	conn, derr := dc(context.Background(), "tcp", target.Addr().String())
	if derr != nil {
		t.Fatalf("dial internal target: %v", derr)
	}
	_ = conn.Close()

	if n, _ := sock.Stats(); n != 0 {
		t.Fatalf("internal destination was routed THROUGH the egress socks5 (connects=%d) — must dial direct", n)
	}
}
