package httpx

import (
	"net/http"
	"testing"
	"time"
)

// TestSwappableDirect_BypassesEnvProxy is the REGRESSION guard for the whole
// point of these clients: control-plane clients MUST bypass the env HTTP proxy.
// Wrapping them in a SwappableClient — and rebuilding them on a network change
// — must NOT reintroduce env-proxy routing. Asserted behaviourally under a
// hostile env; see direct_test.go assertDirect for why the old structural
// `Proxy == nil` check was replaced.
func TestSwappableDirect_BypassesEnvProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:7890")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:7890")
	assertBypass := func(when string, c *http.Client) {
		tr, ok := c.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("%s: transport is %T, want *http.Transport", when, c.Transport)
		}
		assertDirect(t, when, tr)
	}
	s := NewSwappableDirect(2 * time.Second)
	assertBypass("initial", s.Get())
	s.Rebuild()
	assertBypass("after Rebuild", s.Get())
}

// TestRebuildAllControlPlane_RebuildsRegistered proves RebuildAllControlPlane
// swaps every REGISTERED client instance (not just one).
func TestRebuildAllControlPlane_RebuildsRegistered(t *testing.T) {
	a := NewSwappableDirect(time.Second)
	b := NewSwappableDirect(time.Second)
	a0, b0 := a.Get(), b.Get()
	if n := RebuildAllControlPlane(); n < 2 {
		t.Fatalf("RebuildAllControlPlane rebuilt %d, want >=2 (a,b registered)", n)
	}
	if a.Get() == a0 || b.Get() == b0 {
		t.Fatal("a registered client was not rebuilt")
	}
	// The rebuilt clients must STILL bypass the proxy.
	assertDirect(t, "rebuilt client", a.Get().Transport.(*http.Transport))
}

// TestSwappableFixed_NotRegistered_PreservesInjected proves an injected client is
// wrapped verbatim and is NOT swapped out by a global rebuild (so a test/caller
// injection survives, and its proxy behavior is whatever the caller chose).
func TestSwappableFixed_NotRegistered_PreservesInjected(t *testing.T) {
	injected := &http.Client{Timeout: 3 * time.Second}
	f := NewSwappableFixed(injected)
	if f.Get() != injected {
		t.Fatal("NewSwappableFixed did not preserve the injected client")
	}
	RebuildAllControlPlane() // must not touch the unregistered fixed client
	if f.Get() != injected {
		t.Fatal("RebuildAllControlPlane swapped an unregistered fixed client")
	}
}
