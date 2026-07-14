package sysproxy

import (
	"context"
	"errors"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// --- fixture parsers (one test per wire format, per test-fixture rule) ---

// Real `scutil --proxy` output shape on macOS with Clash-style system proxy.
const scutilClashFixture = `<dictionary> {
  ExceptionsList : <array> {
    0 : 192.168.0.0/16
    1 : localhost
  }
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 7890
  HTTPSProxy : 127.0.0.1
  SOCKSEnable : 1
  SOCKSPort : 7891
  SOCKSProxy : 127.0.0.1
}`

func TestParseScutilProxy_ClashAllOn(t *testing.T) {
	got := parseScutilProxy(scutilClashFixture)
	want := Snapshot{
		HTTP:  "http://127.0.0.1:7890",
		HTTPS: "http://127.0.0.1:7890",
		SOCKS: "socks5://127.0.0.1:7891",
	}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestParseScutilProxy_DisabledAndPACOnly(t *testing.T) {
	// Toggled off: Enable flags 0 (or absent) must yield empty even when
	// stale Proxy/Port keys linger — macOS keeps them after disable.
	off := `<dictionary> {
  HTTPEnable : 0
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://127.0.0.1:7890/pac
}`
	if got := parseScutilProxy(off); !got.Empty() {
		t.Fatalf("disabled/PAC-only must parse as empty (direct), got %+v", got)
	}
	if got := parseScutilProxy("<dictionary> {\n}"); !got.Empty() {
		t.Fatalf("empty dictionary must parse as empty, got %+v", got)
	}
}

func TestParseWindowsProxyServer(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Snapshot
	}{
		{"single host:port applies to http+https", "127.0.0.1:7890",
			Snapshot{HTTP: "http://127.0.0.1:7890", HTTPS: "http://127.0.0.1:7890"}},
		{"scheme prefix tolerated", "http://127.0.0.1:7890",
			Snapshot{HTTP: "http://127.0.0.1:7890", HTTPS: "http://127.0.0.1:7890"}},
		{"per-protocol list", "http=127.0.0.1:7890;https=127.0.0.1:7891;ftp=1.2.3.4:21;socks=127.0.0.1:7892",
			Snapshot{HTTP: "http://127.0.0.1:7890", HTTPS: "http://127.0.0.1:7891", SOCKS: "socks5://127.0.0.1:7892"}},
		{"empty", "", Snapshot{}},
	}
	for _, c := range cases {
		if got := parseWindowsProxyServer(c.in); got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
}

// --- watcher behavior ---

func reqTo(t *testing.T, rawurl string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// clearProxyEnv makes the test hermetic against the RUNNER's shell env (a dev
// Mac usually exports https_proxy): since the 2026-07-08 refinement, an empty
// snapshot falls through to inherited env — so tests asserting "direct" must
// pin the env to empty BEFORE constructing the watcher (envProxy is built at
// construction from the frozen env).
func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, k := range proxyEnvNames {
		t.Setenv(k, "")
	}
	t.Setenv(explicitEnvKeyMarker, "")
}

func TestProxyFunc_FollowsLiveSnapshot(t *testing.T) {
	clearProxyEnv(t)
	cur := Snapshot{HTTP: "http://127.0.0.1:7890", HTTPS: "http://127.0.0.1:7890"}
	var readErr error
	w := newWatcherForTest(func() (Snapshot, error) { return cur, readErr }, false)
	fn := w.ProxyFunc()

	// Primed at construction: request #1 already proxied.
	u, err := fn(reqTo(t, "https://api.anthropic.com/v1/messages"))
	if err != nil || u == nil || u.String() != "http://127.0.0.1:7890" {
		t.Fatalf("want primed proxy, got %v err %v", u, err)
	}

	// Clash port change: next observe flips, next request uses the NEW port
	// — the core 2026-07-08 requirement.
	cur = Snapshot{HTTP: "http://127.0.0.1:9999", HTTPS: "http://127.0.0.1:9999"}
	if _, _, changed := w.observe(); !changed {
		t.Fatal("port change must be observed")
	}
	if u, _ := fn(reqTo(t, "https://api.anthropic.com/v1/messages")); u == nil || u.Port() != "9999" {
		t.Fatalf("want refreshed proxy :9999, got %v", u)
	}

	// System proxy toggled OFF: refresh to direct (env cleared above, so the
	// layer-4 inherited fallback has nothing to offer).
	cur = Snapshot{}
	if _, _, changed := w.observe(); !changed {
		t.Fatal("toggle-off must be observed")
	}
	if u, _ := fn(reqTo(t, "https://api.anthropic.com/v1/messages")); u != nil {
		t.Fatalf("want direct after toggle-off, got %v", u)
	}
}

// Layer 4 (2026-07-08 refinement): with no system proxy, INHERITED shell env
// (unmarked) is the fallback; when a system proxy appears it takes over —
// inherited env is outranked.
func TestProxyFunc_InheritedEnvIsBelowSystemProxy(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:7890") // inherited: no marker
	cur := Snapshot{}
	w := newWatcherForTest(func() (Snapshot, error) { return cur, nil }, false)
	fn := w.ProxyFunc()

	// No system proxy → inherited env fallback engages (old Linux/manual
	// behavior preserved).
	if u, _ := fn(reqTo(t, "https://api.anthropic.com/v1/messages")); u == nil || u.Port() != "7890" {
		t.Fatalf("want inherited env fallback :7890, got %v", u)
	}

	// System proxy turns on → it outranks the inherited env (the whole point
	// of the refinement: Clash users' .zshrc exports must not pin the port).
	cur = Snapshot{HTTPS: "http://127.0.0.1:9999"}
	if _, _, changed := w.observe(); !changed {
		t.Fatal("system proxy appearance must be observed")
	}
	if u, _ := fn(reqTo(t, "https://api.anthropic.com/v1/messages")); u == nil || u.Port() != "9999" {
		t.Fatalf("system proxy must outrank inherited env, got %v", u)
	}
}

// Explicit proxy.env config (marker) still outranks everything below it,
// including the system proxy — the enterprise no-GUI contract is unchanged.
func TestProxyFunc_ExplicitEnvOutranksSystemProxy(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:7890")
	t.Setenv(explicitEnvKeyMarker, "HTTPS_PROXY")
	if !envProxyExplicit(os.Getenv) {
		t.Fatal("marked HTTPS_PROXY must be explicit")
	}
	w := newWatcherForTest(func() (Snapshot, error) {
		return Snapshot{HTTPS: "http://127.0.0.1:9999"}, nil
	}, envProxyExplicit(os.Getenv))
	if w.active() {
		t.Fatal("explicit env must keep the watcher inert")
	}
	u, err := w.ProxyFunc()(reqTo(t, "https://api.anthropic.com/v1/messages"))
	if err != nil || u == nil || u.Port() != "7890" {
		t.Fatalf("explicit env must win over system proxy, got %v err %v", u, err)
	}
}

func TestProxyFunc_SkipsLoopbackDestinations(t *testing.T) {
	w := newWatcherForTest(func() (Snapshot, error) {
		return Snapshot{HTTP: "http://127.0.0.1:7890", HTTPS: "http://127.0.0.1:7890"}, nil
	}, false)
	fn := w.ProxyFunc()
	for _, dest := range []string{"http://localhost:8080/x", "http://127.0.0.1:9100/x", "http://[::1]:9100/x"} {
		if u, _ := fn(reqTo(t, dest)); u != nil {
			t.Errorf("loopback dest %s must go direct, got %v", dest, u)
		}
	}
}

func TestObserve_ReadFailureKeepsLastKnown(t *testing.T) {
	snap := Snapshot{HTTPS: "http://127.0.0.1:7890"}
	fail := false
	w := newWatcherForTest(func() (Snapshot, error) {
		if fail {
			return Snapshot{}, errors.New("scutil exploded")
		}
		return snap, nil
	}, false)

	fail = true
	if _, cur, changed := w.observe(); changed || cur != snap {
		t.Fatalf("read failure must keep last-known, got changed=%v cur=%+v", changed, cur)
	}
	if !w.readFailing {
		t.Fatal("failure streak flag must be set (WARN dedup)")
	}
	fail = false
	if _, _, changed := w.observe(); changed {
		t.Fatal("recovery to identical snapshot must not report change")
	}
	if w.readFailing {
		t.Fatal("recovery must clear the failure streak flag")
	}
}

func TestEnvAuthoritative_WatcherInert(t *testing.T) {
	reads := 0
	w := newWatcherForTest(func() (Snapshot, error) { reads++; return Snapshot{HTTP: "http://x:1"}, nil }, true)
	if reads != 0 {
		t.Fatal("env-authoritative watcher must not even prime from the OS")
	}
	if got := w.BrokerEgressURL(); got != "" {
		t.Fatalf("env-authoritative BrokerEgressURL must be empty, got %q", got)
	}
	// Run must return immediately (no poll loop) even with a live context.
	done := make(chan struct{})
	go func() { w.Run(context.Background(), nil); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run must be inert when env config is authoritative")
	}
}

func TestSnapshotProxyForFallbacks(t *testing.T) {
	socksOnly := Snapshot{SOCKS: "socks5://127.0.0.1:7891"}
	if got := socksOnly.ProxyFor("https"); got != "socks5://127.0.0.1:7891" {
		t.Fatalf("https must fall back to SOCKS, got %q", got)
	}
	httpOnly := Snapshot{HTTP: "http://127.0.0.1:7890"}
	if got := httpOnly.ProxyFor("https"); got != "http://127.0.0.1:7890" {
		t.Fatalf("https must fall back to HTTP entry, got %q", got)
	}
}

// 2026-07-08 precedence refinement: only proxy vars MARKED as coming from
// proxy.env (AIKEY_PROXYENV_KEYS) count as explicit; inherited shell exports
// must NOT disable OS detection.
func TestEnvProxyExplicit_MarkerGated(t *testing.T) {
	get := func(env map[string]string) func(string) string {
		return func(k string) string { return env[k] }
	}
	// Inherited only (the .zshrc-export field case): NOT explicit.
	if envProxyExplicit(get(map[string]string{"https_proxy": "http://127.0.0.1:7890"})) {
		t.Fatal("inherited shell env must not be explicit")
	}
	// Marked via proxy.env (case-insensitive match): explicit.
	if !envProxyExplicit(get(map[string]string{
		"https_proxy":         "http://127.0.0.1:7890",
		"AIKEY_PROXYENV_KEYS": "HTTPS_PROXY,DEGRADE_DETECTOR_PROXY_TOKEN",
	})) {
		t.Fatal("proxy.env-marked https_proxy must be explicit")
	}
	// Marker lists non-proxy keys only: NOT explicit.
	if envProxyExplicit(get(map[string]string{
		"https_proxy":         "http://127.0.0.1:7890",
		"AIKEY_PROXYENV_KEYS": "DEGRADE_DETECTOR_PROXY_TOKEN",
	})) {
		t.Fatal("marker without proxy keys must not be explicit")
	}
}

// Split by provenance: marked vars → explicit map, unmarked → inherited map.
func TestEnvProxyVarsSplit_ByMarker(t *testing.T) {
	get := func(k string) string {
		switch k {
		case "HTTPS_PROXY":
			return "http://127.0.0.1:7890"
		case "all_proxy":
			return "socks5://127.0.0.1:7890"
		case "AIKEY_PROXYENV_KEYS":
			return "https_proxy"
		}
		return ""
	}
	explicit, inherited := envProxyVarsSplitFrom(get)
	if len(explicit) != 1 || explicit["HTTPS_PROXY"] == "" {
		t.Fatalf("HTTPS_PROXY must be explicit (marker is case-insensitive), got %v", explicit)
	}
	if len(inherited) != 1 || inherited["all_proxy"] == "" {
		t.Fatalf("all_proxy must be inherited, got %v", inherited)
	}
}

// Layer-4 fallback: system snapshot empty → ProxyFunc falls through to the
// inherited env (ProxyFromEnvironment) instead of going direct.
// NOTE: not asserted via a live ProxyFromEnvironment call here — its
// process-global sync.Once cache would make the assertion order-dependent
// across the package's tests. The fall-through branch is asserted by
// TestEgress_InheritedEnvFallback in cmd/aikey-proxy (fresh binary run).

// 2026-07-08 Windows field report: env keys are case-insensitive on Windows,
// so both Getenv("HTTP_PROXY") and Getenv("http_proxy") return the same
// variable — the display must not list it twice.
func TestEnvProxyVars_WindowsCaseInsensitiveDedupe(t *testing.T) {
	winGet := func(k string) string { // case-insensitive like Windows
		switch strings.ToUpper(k) {
		case "HTTP_PROXY", "HTTPS_PROXY":
			return "http://127.0.0.1:7890"
		}
		return ""
	}
	got := envProxyVarsFrom(winGet)
	want := map[string]string{
		"HTTP_PROXY":  "http://127.0.0.1:7890",
		"HTTPS_PROXY": "http://127.0.0.1:7890",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want deduped %v, got %v", want, got)
	}
}

// Unix: case-sensitive env — genuinely distinct lowercase twins stay visible.
func TestEnvProxyVars_UnixDistinctCasesBothShown(t *testing.T) {
	unixGet := func(k string) string {
		switch k {
		case "HTTPS_PROXY":
			return "http://127.0.0.1:7890"
		case "https_proxy":
			return "http://127.0.0.1:9999"
		}
		return ""
	}
	got := envProxyVarsFrom(unixGet)
	if got["HTTPS_PROXY"] != "http://127.0.0.1:7890" || got["https_proxy"] != "http://127.0.0.1:9999" {
		t.Fatalf("distinct twins must both be shown, got %v", got)
	}
}
