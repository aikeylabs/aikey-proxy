package httpx

import (
	"net/http"
	"testing"
	"time"
)

// TestNewDirectClient_NoProxy locks the core invariant: a control-plane client
// must have NO proxy function, so it NEVER routes through HTTP_PROXY/HTTPS_PROXY.
// This is the fence for the 2026-06-30 bug where the proxy inherited Clash on
// :7890 and misrouted its team-master writeback / collector upload through it →
// "context deadline exceeded". 防退化.
func TestNewDirectClient_NoProxy(t *testing.T) {
	c := NewDirectClient(5 * time.Second)

	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is not *http.Transport: %T", c.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("NewDirectClient transport has a Proxy func — must be nil so control-plane calls bypass HTTP_PROXY")
	}
	if c.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", c.Timeout)
	}
	// Cloned from DefaultTransport → keeps the connection-pool defaults.
	if tr.MaxIdleConns == 0 {
		t.Error("expected cloned http.DefaultTransport defaults (MaxIdleConns > 0)")
	}
}

// TestNewDirectClient_DoesNotMutateDefaultTransport guards against Clone() being
// dropped: setting Proxy=nil must act on a COPY, never the shared global (which
// the AI-egress / forwarding paths rely on to honor the env proxy).
func TestNewDirectClient_DoesNotMutateDefaultTransport(t *testing.T) {
	_ = NewDirectClient(time.Second)
	if dt, ok := http.DefaultTransport.(*http.Transport); ok && dt.Proxy == nil {
		t.Fatal("NewDirectClient mutated the shared http.DefaultTransport.Proxy — must clone, not modify the global")
	}
}
