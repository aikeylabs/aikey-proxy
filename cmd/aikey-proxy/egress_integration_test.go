package main

// Egress integration test for the 2026-07-08 system-proxy auto-refresh
// requirement: a RUNNING transport must egress through the NEW system proxy
// on the very next request after a change — no daemon restart.
//
// WHY this test exists (the gap unit tests can't cover): sysproxy unit tests
// prove the resolver returns the right URL; this test proves the REAL
// buildTransport + Watcher chain — the exact objects production wires in
// main() — actually routes live HTTP traffic through the switched proxy.
//
// Hermetic by construction: both "system proxies" are local httptest servers
// acting as plain-HTTP forward proxies (they receive absolute-form request
// URIs and answer themselves — no DNS, no real egress, no Anthropic). The
// destination host is a fake non-loopback name because ProxyFunc deliberately
// sends loopback destinations direct.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/sysproxy"
)

// fakeForwardProxy is a recording plain-HTTP forward proxy: it asserts it was
// reached AS a proxy (absolute-form URI) and answers with its own tag.
func fakeForwardProxy(t *testing.T, tag string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.RequestURI, "http://") {
			t.Errorf("%s: expected absolute-form proxy request, got %q", tag, r.RequestURI)
		}
		hits.Add(1)
		_, _ = io.WriteString(w, tag)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// clearProxyEnvMain pins the proxy env empty so assertions are hermetic
// against the runner's shell (dev Macs export https_proxy; since the
// 2026-07-08 refinement an empty snapshot falls through to inherited env).
func clearProxyEnvMain(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
		"ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "AIKEY_PROXYENV_KEYS",
	} {
		t.Setenv(k, "")
	}
}

func TestEgress_FollowsSystemProxySwitch_NoRestart(t *testing.T) {
	clearProxyEnvMain(t)
	proxyA, hitsA := fakeForwardProxy(t, "via-A")
	proxyB, hitsB := fakeForwardProxy(t, "via-B")

	var mu sync.Mutex
	cur := sysproxy.Snapshot{HTTP: proxyA.URL, HTTPS: proxyA.URL}
	setSystemProxy := func(s sysproxy.Snapshot) { mu.Lock(); cur = s; mu.Unlock() }
	watcher := sysproxy.NewWatcherWithReader(func() (sysproxy.Snapshot, error) {
		mu.Lock()
		defer mu.Unlock()
		return cur, nil
	})

	// The REAL production transport for direct mode (upstream_proxy.url empty).
	transport := buildTransport("", watcher.ProxyFunc())
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	egress := func() string {
		t.Helper()
		resp, err := client.Get("http://provider.test/v1/ping")
		if err != nil {
			t.Fatalf("egress request failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	// 1. Primed at construction: request #1 already goes through system proxy A.
	if got := egress(); got != "via-A" {
		t.Fatalf("initial egress: want via-A, got %q", got)
	}

	// 2. "Clash 换端口": system proxy flips A→B; after ONE poll the very next
	// request must egress through B — the core acceptance of the requirement.
	setSystemProxy(sysproxy.Snapshot{HTTP: proxyB.URL, HTTPS: proxyB.URL})
	if !watcher.PollOnce() {
		t.Fatal("watcher must observe the A→B switch")
	}
	if got := egress(); got != "via-B" {
		t.Fatalf("post-switch egress: want via-B, got %q", got)
	}
	if hitsA.Load() != 1 || hitsB.Load() != 1 {
		t.Fatalf("want exactly 1 hit per proxy (A then B), got A=%d B=%d", hitsA.Load(), hitsB.Load())
	}

	// 3. "系统代理关闭": toggle off refreshes to direct — the resolver must
	// return nil (we assert the resolver, not a live dial: provider.test has
	// no DNS on purpose).
	setSystemProxy(sysproxy.Snapshot{})
	if !watcher.PollOnce() {
		t.Fatal("watcher must observe the toggle-off")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://provider.test/v1/ping", nil)
	if u, err := transport.Proxy(req); err != nil || u != nil {
		t.Fatalf("after toggle-off egress must be direct, got proxy=%v err=%v", u, err)
	}
}

// Explicit upstream_proxy.url must OUTRANK the system proxy (approved
// precedence): with the system proxy pointing at A, an explicit URL of B must
// carry the traffic.
func TestEgress_ExplicitURLOutranksSystemProxy(t *testing.T) {
	proxyA, hitsA := fakeForwardProxy(t, "via-A")
	proxyB, _ := fakeForwardProxy(t, "via-B")

	watcher := sysproxy.NewWatcherWithReader(func() (sysproxy.Snapshot, error) {
		return sysproxy.Snapshot{HTTP: proxyA.URL, HTTPS: proxyA.URL}, nil
	})
	transport := buildTransport(proxyB.URL, watcher.ProxyFunc())
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	resp, err := client.Get("http://provider.test/v1/ping")
	if err != nil {
		t.Fatalf("egress request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "via-B" {
		t.Fatalf("explicit URL must win: want via-B, got %q", body)
	}
	if hitsA.Load() != 0 {
		t.Fatalf("system proxy A must not be touched when explicit URL is set, got %d hits", hitsA.Load())
	}
}

// Fence for egressState (the /admin/upstream-proxy "egress" block that
// `aikey env` renders): each layer must be reported, and the effective value
// must match what the transport's resolver would do.
func TestEgressState_LayeredReporting(t *testing.T) {
	clearProxyEnvMain(t)
	sys := sysproxy.Snapshot{HTTP: "http://127.0.0.1:7890", HTTPS: "http://127.0.0.1:7890", SOCKS: "socks5://127.0.0.1:7891"}
	watcher := sysproxy.NewWatcherWithReader(func() (sysproxy.Snapshot, error) { return sys, nil })

	// No explicit URL → system proxy wins and all layer fields are visible.
	st := egressState("", watcher)
	if st.EffectiveSource != "system" || st.EffectiveURL != "http://127.0.0.1:7890" {
		t.Fatalf("want system/http://127.0.0.1:7890, got %s/%s", st.EffectiveSource, st.EffectiveURL)
	}
	if !st.SystemSupported || st.SystemHTTPS != sys.HTTPS || st.SystemSOCKS != sys.SOCKS {
		t.Fatalf("system layer misreported: %+v", st)
	}

	// Explicit URL outranks the same system snapshot.
	st = egressState("socks5://10.0.0.1:1080", watcher)
	if st.EffectiveSource != "explicit" || st.EffectiveURL != "socks5://10.0.0.1:1080" {
		t.Fatalf("want explicit win, got %s/%s", st.EffectiveSource, st.EffectiveURL)
	}
	if st.SystemHTTPS != sys.HTTPS {
		t.Fatal("lower layers must stay visible even when outranked (逐级显示)")
	}

	// System proxy toggled off → direct.
	empty := sysproxy.NewWatcherWithReader(func() (sysproxy.Snapshot, error) { return sysproxy.Snapshot{}, nil })
	st = egressState("", empty)
	if st.EffectiveSource != "direct" || st.EffectiveURL != "" {
		t.Fatalf("want direct, got %s/%s", st.EffectiveSource, st.EffectiveURL)
	}
}

// Explicit (proxy.env-marked) env: flagged authoritative, listed in the
// explicit map with credentials redacted, and effective through the real
// resolver. Uses the REAL NewWatcher (explicit env keeps it inert, so no OS
// read happens even on macOS).
func TestEgressState_ExplicitEnvReported(t *testing.T) {
	clearProxyEnvMain(t)
	t.Setenv("HTTPS_PROXY", "http://user:secret@127.0.0.1:7899")
	t.Setenv("AIKEY_PROXYENV_KEYS", "HTTPS_PROXY")
	watcher := sysproxy.NewWatcher()
	st := egressState("", watcher)
	if !st.EnvAuthoritative {
		t.Fatal("proxy.env-marked HTTPS_PROXY must be authoritative")
	}
	got, ok := st.EnvVars["HTTPS_PROXY"]
	if !ok {
		t.Fatalf("explicit vars must list HTTPS_PROXY, got %v", st.EnvVars)
	}
	if strings.Contains(got, "secret") {
		t.Fatalf("credentials must be redacted, got %q", got)
	}
	if st.EffectiveSource != "env" {
		t.Fatalf("effective source must be env, got %s", st.EffectiveSource)
	}
	if strings.Contains(st.EffectiveURL, "secret") {
		t.Fatalf("effective URL must be redacted, got %q", st.EffectiveURL)
	}
}

// Inherited (unmarked) env: NOT authoritative, listed as layer 4, and only
// effective when the system snapshot is empty (2026-07-08 refinement — the
// field case from the user's Mac .zshrc and the Windows HKCU\Environment).
func TestEgressState_InheritedEnvDemotedBelowSystem(t *testing.T) {
	clearProxyEnvMain(t)
	t.Setenv("https_proxy", "http://127.0.0.1:7890") // no marker → inherited

	// System proxy present → it wins; inherited env is visible but outranked.
	withSys := sysproxy.NewWatcherWithReader(func() (sysproxy.Snapshot, error) {
		return sysproxy.Snapshot{HTTPS: "http://127.0.0.1:9999"}, nil
	})
	st := egressState("", withSys)
	if st.EnvAuthoritative {
		t.Fatal("inherited env must not be authoritative")
	}
	if st.EnvInheritedVars["https_proxy"] == "" {
		t.Fatalf("inherited vars must list https_proxy, got %v", st.EnvInheritedVars)
	}
	if st.EffectiveSource != "system" || st.EffectiveURL != "http://127.0.0.1:9999" {
		t.Fatalf("system must outrank inherited env, got %s/%s", st.EffectiveSource, st.EffectiveURL)
	}

	// No system proxy → inherited env is the fallback.
	noSys := sysproxy.NewWatcherWithReader(func() (sysproxy.Snapshot, error) {
		return sysproxy.Snapshot{}, nil
	})
	st = egressState("", noSys)
	if st.EffectiveSource != "env_inherited" || st.EffectiveURL != "http://127.0.0.1:7890" {
		t.Fatalf("want env_inherited fallback, got %s/%s", st.EffectiveSource, st.EffectiveURL)
	}
}

// Transport-level layer-4 proof: with no system proxy, live traffic egresses
// through the INHERITED env proxy (old headless/manual behavior preserved).
func TestEgress_InheritedEnvFallbackCarriesTraffic(t *testing.T) {
	clearProxyEnvMain(t)
	proxyC, hitsC := fakeForwardProxy(t, "via-C")
	t.Setenv("http_proxy", proxyC.URL) // inherited: no marker
	watcher := sysproxy.NewWatcherWithReader(func() (sysproxy.Snapshot, error) {
		return sysproxy.Snapshot{}, nil
	})
	transport := buildTransport("", watcher.ProxyFunc())
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Get("http://provider.test/v1/ping")
	if err != nil {
		t.Fatalf("egress request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "via-C" || hitsC.Load() != 1 {
		t.Fatalf("want inherited-env egress via-C (1 hit), got %q hits=%d", body, hitsC.Load())
	}
}
