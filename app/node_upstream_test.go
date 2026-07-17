package app

// Fence for the node-level /user/settings upstream dispatch (2026-07-16):
// single-URL forms work in EVERY build; multi-protocol chains/fragments are
// gated on the enterprise engine. This is the open-source build (no mihomo
// blank-import), so MultiProtocolAvailable() is false and chains/fragments must
// be rejected at write time and degrade to direct at build time — "personal
// degrades to the original single-URL mode".

import (
	"net/http"
	"testing"
)

func TestValidateNodeUpstream_OSS(t *testing.T) {
	ok := []string{
		"",                          // clear
		"http://127.0.0.1:7890",     // single http
		"https://proxy.example:8443", // single https
		"socks5://127.0.0.1:1080",   // single socks5
	}
	for _, s := range ok {
		if err := validateNodeUpstream(s); err != nil {
			t.Errorf("validateNodeUpstream(%q) unexpected error: %v", s, err)
		}
	}

	// Chains + fragments require the enterprise engine → rejected here with an
	// actionable "single URL only" message.
	rejected := []string{
		"socks5://a:1080,socks5://b:1080",
		`{"proxies":[]}`,
		"proxies:\n  - name: x",
		"proxy-groups:\n  - name: g",
	}
	for _, s := range rejected {
		if err := validateNodeUpstream(s); err == nil {
			t.Errorf("validateNodeUpstream(%q) = nil, want rejection (no multi-protocol engine in this build)", s)
		}
	}

	// Bad single URLs.
	bad := []string{
		"ftp://host:21",       // unsupported scheme
		"http://",             // missing host
	}
	for _, s := range bad {
		if err := validateNodeUpstream(s); err == nil {
			t.Errorf("validateNodeUpstream(%q) = nil, want error", s)
		}
	}
}

func TestBuildTransport_DegradesChainToDirect_OSS(t *testing.T) {
	// Pin proxy env empty so "degrade to env/system" resolves to a clean direct
	// (dev Macs export https_proxy, which is itself a valid fallback but would
	// mask the assertion that the chain is NOT used).
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}

	// A chain spec in a build without the engine must degrade to env/system (here
	// direct — env pinned empty), NEVER trying to dial the bogus chain.
	tr, closer := buildTransport("socks5://a:1080,socks5://b:1080", nil)
	if closer != nil {
		t.Fatal("degrade path must not return a closer")
	}
	if tr == nil {
		t.Fatal("degrade path must still return a usable transport")
	}
	if tr.Proxy != nil {
		req, _ := http.NewRequest(http.MethodGet, "https://api.anthropic.com/", nil)
		if u, _ := tr.Proxy(req); u != nil {
			t.Fatalf("degraded transport must be direct (env pinned empty), got proxy=%v", u)
		}
	}

	// Single URL still builds a proxied transport.
	tr2, closer2 := buildTransport("http://127.0.0.1:7890", nil)
	if closer2 != nil {
		t.Fatal("single-URL path has no closer")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.anthropic.com/", nil)
	if u, _ := tr2.Proxy(req); u == nil || u.Host != "127.0.0.1:7890" {
		t.Fatalf("single-URL transport must proxy through the URL, got %v", u)
	}
}

// Internal-destination bypass (option B): even with an explicit single-URL
// upstream set, loopback + NO_PROXY destinations resolve DIRECT (nil proxy),
// while public providers still go through the proxy. Guards the escape hatch for
// self-hosted providers on internal IPs.
func TestBuildTransport_InternalDestinationsBypassUpstream(t *testing.T) {
	t.Setenv("NO_PROXY", "internal.corp,10.0.0.0/8")
	t.Setenv("no_proxy", "internal.corp,10.0.0.0/8")

	tr, _ := buildTransport("http://proxy.example:7890", nil)

	proxied := func(host string) bool {
		req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		u, _ := tr.Proxy(req)
		return u != nil
	}
	// Public provider → through the proxy.
	if !proxied("api.anthropic.com") {
		t.Error("public provider must go through the explicit upstream")
	}
	// Loopback → direct (always, per httpproxy canon).
	if proxied("127.0.0.1") || proxied("localhost") {
		t.Error("loopback destinations must bypass the explicit upstream (direct)")
	}
	// NO_PROXY suffix + CIDR → direct.
	if proxied("internal.corp") {
		t.Error("NO_PROXY domain must bypass the explicit upstream (direct)")
	}
	if proxied("10.1.2.3") {
		t.Error("NO_PROXY CIDR (10.0.0.0/8) must bypass the explicit upstream (direct)")
	}
}
