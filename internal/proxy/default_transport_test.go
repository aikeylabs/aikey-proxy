package proxy

// N2 fence (容量 P0-4 方案 · N2 定案 2026-08-19): the default upstream
// transport must never fall back to Go's per-host idle capacity of 2 — that
// default made the worker discard a connection per request against its single
// provider host, exhausting the host's ephemeral ports under load (heartbeats
// died → hub marked nodes dead → no_live_node). Proxy env semantics must
// survive the replacement (clone, not a hand-built Transport).

import (
	"net/http"
	"testing"
)

func TestDefaultUpstreamTransport_PerHostIdleCapacityAndProxyEnv(t *testing.T) {
	ht, ok := defaultUpstreamTransport.(*http.Transport)
	if !ok {
		t.Fatalf("defaultUpstreamTransport is %T, want *http.Transport", defaultUpstreamTransport)
	}
	if ht.MaxIdleConnsPerHost < 100 {
		t.Fatalf("MaxIdleConnsPerHost=%d, want >=100 (Go default 2 caused the N2 ephemeral-port exhaustion)", ht.MaxIdleConnsPerHost)
	}
	if ht.Proxy == nil {
		t.Fatal("Proxy hook lost — HTTP_PROXY/HTTPS_PROXY env semantics must survive (clone http.DefaultTransport, do not hand-build)")
	}
}
