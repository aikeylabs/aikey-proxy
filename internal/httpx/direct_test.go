package httpx

import (
	"net/http"
	"testing"
	"time"
)

// TestNewDirectClient_NoProxy locks the core invariant: a control-plane client
// NEVER routes through HTTP_PROXY / HTTPS_PROXY / ALL_PROXY. This is the fence
// for the 2026-06-30 bug where the proxy inherited Clash on :7890 and misrouted
// its team-master writeback / collector upload through it → "context deadline
// exceeded". 防退化.
//
// The assertion is BEHAVIOURAL (resolve a real target under a hostile env)
// rather than the old structural `Proxy == nil`. Since 2026-08-03 the transport
// carries a proxy FUNC — that is what lets an operator opt into a control-plane
// proxy (pkg/httpdirect.SetProxyOverride) — so "nil field" stopped being the
// invariant while "does not route through the env proxy" still is. The
// behavioural form is also strictly stronger: it would catch a regression to
// http.ProxyFromEnvironment, which the structural check could not.
func TestNewDirectClient_NoProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:7890")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:7890")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:7891")

	c := NewDirectClient(5 * time.Second)

	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is not *http.Transport: %T", c.Transport)
	}
	assertDirect(t, "NewDirectClient", tr)
	if c.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", c.Timeout)
	}
	// Cloned from DefaultTransport → keeps the connection-pool defaults.
	if tr.MaxIdleConns == 0 {
		t.Error("expected cloned http.DefaultTransport defaults (MaxIdleConns > 0)")
	}
}

// TestNewDirectClient_DoesNotMutateDefaultTransport guards against Clone() being
// dropped: overriding Proxy must act on a COPY, never the shared global (which
// the AI-egress / forwarding paths rely on to honor the env proxy).
func TestNewDirectClient_DoesNotMutateDefaultTransport(t *testing.T) {
	_ = NewDirectClient(time.Second)
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skip("http.DefaultTransport is not *http.Transport")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:7890")
	if dt.Proxy == nil {
		t.Fatal("NewDirectClient mutated the shared http.DefaultTransport.Proxy — must clone, not modify the global")
	}
	// And it still resolves via the environment, which egress paths depend on.
	if _, err := dt.Proxy(req); err != nil {
		t.Fatalf("DefaultTransport proxy lookup broke: %v", err)
	}
}

// assertDirect fails unless the transport resolves the given control-plane
// targets to a DIRECT dial (proxy func present, but yielding no proxy URL).
func assertDirect(t *testing.T, when string, tr *http.Transport) {
	t.Helper()
	if tr.Proxy == nil {
		t.Fatalf("%s: Transport.Proxy is nil — direct must be an explicit decision (the override is read there), not an accident", when)
	}
	for _, target := range []string{"https://master.internal:3000/v1/x", "http://10.0.0.9:8080/health"} {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		u, err := tr.Proxy(req)
		if err != nil {
			t.Fatalf("%s: proxy lookup for %s errored: %v", when, target, err)
		}
		if u != nil {
			t.Fatalf("%s: control-plane call to %s would route through %s", when, target, u)
		}
	}
}
