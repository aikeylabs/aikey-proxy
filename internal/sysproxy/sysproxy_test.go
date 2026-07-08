package sysproxy

import (
	"context"
	"errors"
	"net/http"
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

func TestProxyFunc_FollowsLiveSnapshot(t *testing.T) {
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

	// System proxy toggled OFF: refresh to direct.
	cur = Snapshot{}
	if _, _, changed := w.observe(); !changed {
		t.Fatal("toggle-off must be observed")
	}
	if u, _ := fn(reqTo(t, "https://api.anthropic.com/v1/messages")); u != nil {
		t.Fatalf("want direct after toggle-off, got %v", u)
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

func TestEnvProxyConfigured(t *testing.T) {
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	if envProxyConfigured() {
		t.Fatal("clean env must not be authoritative")
	}
	t.Setenv("https_proxy", "http://127.0.0.1:7890")
	if !envProxyConfigured() {
		t.Fatal("https_proxy must make env authoritative")
	}
}
