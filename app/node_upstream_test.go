package app

// Fence for the node-level /user/settings upstream dispatch. Settled semantics
// (溯源收敛 2026-07-17, requirements/2026-07-17-egress-spec-capability-by-edition.md):
// single URL + socks5 CHAIN work in EVERY build (built-in GPL-free engine); ONLY a
// multi-protocol FRAGMENT (ss/vmess/trojan/… or a proxy-group) needs the enterprise
// mihomo engine. This is the open-source build (no mihomo blank-import), so
// MultiProtocolAvailable() is false → chains are accepted + build; fragments are
// rejected at write time and degrade to direct at build time.
//
// (This test previously asserted chains were rejected on OSS — that was the M7
// over-degradation bug, corrected on convergence; see the requirements spec.)

import (
	"net/http"
	"testing"
)

func TestValidateNodeUpstream_OSS(t *testing.T) {
	ok := []string{
		"",                                       // clear
		"http://127.0.0.1:7890",                  // single http
		"https://proxy.example:8443",             // single https
		"socks5://127.0.0.1:1080",                // single socks5
		"socks5://front:1080,socks5://exit:1080", // socks5 CHAIN — built-in, ALL builds
	}
	for _, s := range ok {
		if err := validateNodeUpstream(s); err != nil {
			t.Errorf("validateNodeUpstream(%q) unexpected error: %v", s, err)
		}
	}

	// Only multi-protocol FRAGMENTS require the enterprise engine → rejected on OSS.
	rejectedFragments := []string{
		`{"proxies":[]}`,
		"proxies:\n  - name: x",
		"proxy-groups:\n  - name: g",
	}
	for _, s := range rejectedFragments {
		if err := validateNodeUpstream(s); err == nil {
			t.Errorf("validateNodeUpstream(%q) = nil, want rejection (multi-protocol fragment needs the enterprise engine)", s)
		}
	}

	// Bad single URLs.
	bad := []string{
		"ftp://host:21", // unsupported scheme
		"http://",       // missing host
	}
	for _, s := range bad {
		if err := validateNodeUpstream(s); err == nil {
			t.Errorf("validateNodeUpstream(%q) = nil, want error", s)
		}
	}
}

func TestBuildTransport_FragmentDegradesToDirect_OSS(t *testing.T) {
	// Pin proxy env empty so "degrade to env/system" resolves to a clean direct.
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}

	// A multi-protocol FRAGMENT in a build without the engine degrades to
	// env/system (here direct — env pinned empty), never trying to build it.
	tr, closer := buildTransport("proxies:\n  - name: x\n    type: ss\n    server: h\n    port: 8002\n    cipher: rc4-md5", nil)
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

	// A socks5 CHAIN is NOT degraded — the built-in engine builds it on OSS. It
	// returns a real engine transport (no closer for a plain chain; not the direct
	// fallback). Actual chain dialing is proven by the built-in engine's own tests
	// (internal/proxy TestAccountEgressTransport_TwoHopChainOrder, same BuildDialer).
	trChain, _ := buildTransport("socks5://127.0.0.1:11080,socks5://127.0.0.1:11081", nil)
	if trChain == nil {
		t.Fatal("socks5 chain must build a transport on OSS (built-in engine), not nil")
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
