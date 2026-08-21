package proxy

// Fence for the staging P0-1 fix (2026-08-19): a resident-Mock OAUTH-GROUP
// route must dial its runtime base_url DIRECTLY even when the process
// transport carries a node-upstream Proxy hook. Before the fix the Mock's
// private base_url was tunneled out through the node upstream (RST → breaker
// open → every Team OAuth request 503 pre-dial while control/cache/Mock all
// looked healthy). The fence wires a REAL *http.Transport whose Proxy points
// at a black hole and asserts the request still lands on the local mock
// upstream with the black hole seeing ZERO connections (anti-vacuity: the
// mock server must actually record the hit).

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func TestGroupServe_ResidentMockBypassesNodeUpstreamProxy(t *testing.T) {
	// Local "resident Mock" upstream the runtime base_url points at.
	var mockHits atomic.Int64
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","status":"completed","output":[]}`))
	}))
	defer mock.Close()

	// Black-holed node upstream: accepts and never answers. If the buggy
	// tunnel path is ever reintroduced, the dial goes here and the request
	// dies (red).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blackhole listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	var proxyConns atomic.Int64
	hold := make(chan struct{})
	defer close(hold)
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			proxyConns.Add(1)
			go func(c net.Conn) { <-hold; _ = c.Close() }(c)
		}
	}()
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())

	key := grKey()
	refs := []vkeys.GroupAccountRef{{
		AccountID: "acc-mock-direct", ProviderCode: "mock", ProtocolType: "openai_compatible",
	}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-mock-direct": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account",
			ProviderCode:   "mock",
			ProtocolType:   "openai_compatible",
			BaseURL:        mock.URL, // non-loopback in staging; loopback here — the judgment is provider-identity, not IP
			ExpiresAt:      9_000_000_000,
		}, "mock-oauth-token"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", ProtocolType: "openai_compatible", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-mock-direct",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_grouptest": route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	// REAL node-upstream-shaped transport (the exact production shape the fix
	// discriminates on): *http.Transport with a Proxy hook.
	nodeUpstream := http.DefaultTransport.(*http.Transport).Clone()
	nodeUpstream.Proxy = http.ProxyURL(proxyURL)
	p.SetTransport(nodeUpstream)

	req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5-codex","input":"hi"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_grouptest")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if proxyConns.Load() != 0 {
		t.Fatalf("resident mock group traffic traversed the node upstream (%d conns) — the P0-1 tunnel bug is back", proxyConns.Load())
	}
	if mockHits.Load() == 0 {
		t.Fatalf("mock upstream saw no request (status=%d body=%s) — fence is vacuous or dial failed entirely",
			w.Code, w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Fatalf("resident mock group route status=%d body=%s", w.Code, w.Body.String())
	}
}

// TestGroupServe_ResidentMockBypassesEngineShapedNodeUpstream is the
// ENGINE-shaped leg (2026-08-20, staging 回执排查定案): a mihomo
// multi-protocol node upstream (VLESS/Reality on staging) is still handed to
// the supervisor as a *http.Transport — but its tunnel lives in DialContext
// with a NIL Proxy hook, so the original "strip Proxy on a clone" judgment
// never fired and the Mock kept tunneling AFTER the fix was deployed
// (post-deploy 11:28 CST scheduling-log events: GROUP_UPSTREAM_UNAVAILABLE,
// transport=node, dial EOF). This fence models exactly that shape: Proxy nil,
// DialContext routing EVERYTHING into a black hole. The mock group route must
// bypass it entirely.
func TestGroupServe_ResidentMockBypassesEngineShapedNodeUpstream(t *testing.T) {
	var mockHits atomic.Int64
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","status":"completed","output":[]}`))
	}))
	defer mock.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blackhole listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	var tunnelConns atomic.Int64
	hold := make(chan struct{})
	defer close(hold)
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			tunnelConns.Add(1)
			go func(c net.Conn) { <-hold; _ = c.Close() }(c)
		}
	}()

	key := grKey()
	refs := []vkeys.GroupAccountRef{{
		AccountID: "acc-mock-engine", ProviderCode: "mock", ProtocolType: "openai_compatible",
	}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-mock-engine": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account",
			ProviderCode:   "mock",
			ProtocolType:   "openai_compatible",
			BaseURL:        mock.URL,
			ExpiresAt:      9_000_000_000,
		}, "mock-oauth-token"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp", ProtocolType: "openai_compatible", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-mock-engine",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_grouptest": route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	// Engine-shaped node upstream: *http.Transport, Proxy NIL, tunnel in
	// DialContext (dials the black hole regardless of address).
	engineShaped := http.DefaultTransport.(*http.Transport).Clone()
	engineShaped.Proxy = nil
	// Fast-red: the black hole HOLDS connections; without this the pre-fix
	// failure mode is a hang until the upstream timeout instead of a quick 503.
	engineShaped.ResponseHeaderTimeout = 500 * time.Millisecond
	blackholeAddr := ln.Addr().String()
	engineShaped.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, blackholeAddr)
	}
	p.SetTransport(engineShaped)

	req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"model":"gpt-5-codex","input":"hi"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_grouptest")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if tunnelConns.Load() != 0 {
		t.Fatalf("resident mock group traffic entered the engine tunnel (%d conns) — "+
			"the staging shape (Proxy=nil, DialContext tunnel) is not bypassed", tunnelConns.Load())
	}
	if mockHits.Load() == 0 || w.Code != http.StatusOK {
		t.Fatalf("mock upstream hits=%d status=%d body=%s — direct dial did not happen",
			mockHits.Load(), w.Code, w.Body.String())
	}
}
