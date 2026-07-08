// Package sysproxy detects the OS-level system proxy (macOS scutil, Windows
// registry) and keeps a live snapshot the egress transport reads per request.
//
// WHY this package exists (2026-07-08 需求: 代理更新时 proxy 自动刷新):
// aikey-proxy is a long-lived daemon. Before this package its egress proxy was
// frozen three times over: (1) env vars are snapshotted at process spawn,
// (2) Go's http.ProxyFromEnvironment permanently caches the env via sync.Once
// on the first request, (3) there was NO system-proxy detection at all — a
// launchd/systemd-spawned daemon never sees the login shell's HTTP_PROXY, so a
// user driving egress through Clash's *system proxy* was invisible to us, and
// any Clash port change / toggle stranded requests until `aikey proxy restart`.
//
// Design (方案 A, user-approved 2026-07-08): the direct-mode Transport.Proxy is
// a FUNCTION reading an atomic snapshot refreshed by a poll loop — never
// http.ProxyFromEnvironment's cached global. Precedence (single source of
// truth, user-approved):
//
//	explicit upstream_proxy.url  >  process env (frozen, authoritative if set)  >  OS system proxy (live)
//
// The explicit layer stays OUTSIDE this package (buildTransport keeps using
// http.ProxyURL for it); this package resolves the other two.
//
// WHY poll (not events): netmon's fingerprint is the set of interface IPs —
// toggling/re-porting a system proxy does NOT change interface IPs, so the
// existing net-change monitor can never observe it. Polling `scutil --proxy` /
// the registry every pollInterval is the only reliable, dependency-free signal.
//
// Failure posture (增强非依赖): detection is a bypass. Read errors keep the
// last-known snapshot and WARN once per failure streak; unsupported platforms
// (Linux servers) return an inert watcher — behavior is byte-identical to the
// pre-2026-07-08 daemon there.
package sysproxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// pollInterval matches supervisor's netChangePollInterval cadence: fast enough
// that a Clash toggle heals well inside a user's "retry the request" window,
// cheap enough (~10ms scutil exec / registry read) to be negligible.
const pollInterval = 20 * time.Second

// Snapshot is one observation of the OS system proxy. Empty string = that
// protocol has no system proxy. Values are normalized absolute URLs
// (http://host:port, socks5://host:port).
type Snapshot struct {
	HTTP  string
	HTTPS string
	SOCKS string
}

// Empty reports whether no system proxy is configured at all.
func (s Snapshot) Empty() bool { return s.HTTP == "" && s.HTTPS == "" && s.SOCKS == "" }

// ProxyFor returns the proxy URL string for a request scheme, or "" for
// direct. https prefers the HTTPS entry, http the HTTP entry; SOCKS is the
// last resort for both (Clash-style setups usually set all three identically).
func (s Snapshot) ProxyFor(scheme string) string {
	if scheme == "https" {
		return firstNonEmpty(s.HTTPS, s.HTTP, s.SOCKS)
	}
	return firstNonEmpty(s.HTTP, s.SOCKS)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Watcher owns the live snapshot. Construct with NewWatcher (primes
// synchronously so the first outbound request already sees the system proxy),
// then start Run in a goroutine.
type Watcher struct {
	mu   sync.Mutex
	cur  Snapshot
	read func() (Snapshot, error) // platform reader; injectable in tests

	// supported mirrors the platform const as a field so tests exercise the
	// full watcher on any development/CI OS.
	supported bool

	// envAuthoritative: the process environment carries proxy intent
	// (HTTP(S)_PROXY / ALL_PROXY / NO_PROXY via proxy.env or the spawn env).
	// Env is EXPLICIT user config, so it outranks OS detection — including its
	// NO_PROXY exclusions, which must not "fall through" to the system layer.
	envAuthoritative bool

	// readFailing dedups WARN logs: one WARN per failure streak, one INFO on
	// recovery, never a 20s WARN drumbeat.
	readFailing bool
}

// NewWatcher builds and synchronously primes a watcher using the platform
// reader. On unsupported platforms or with authoritative env config the
// watcher is inert (Run returns immediately, ProxyFunc delegates to env).
func NewWatcher() *Watcher {
	w := &Watcher{read: readSystemProxy, supported: platformSupported, envAuthoritative: envProxyConfigured()}
	w.prime()
	return w
}

// NewWatcherWithReader is the HARNESS constructor: a Watcher driven by an
// injected reader instead of the OS. Exported (internal/ only) so integration
// tests outside this package — e.g. cmd/aikey-proxy's egress switch test —
// can drive the REAL Watcher + buildTransport chain hermetically on any OS.
// Always "supported" and env-independent; never use in production wiring
// (production is NewWatcher, which honors platform + env precedence).
func NewWatcherWithReader(read func() (Snapshot, error)) *Watcher {
	w := &Watcher{read: read, supported: true}
	w.prime()
	return w
}

// PollOnce performs exactly one poll outside Run's ticker and reports whether
// the snapshot changed — the harness seam that advances the watcher
// deterministically (tests must not wait out the 20s production cadence).
func (w *Watcher) PollOnce() bool {
	_, _, changed := w.observe()
	return changed
}

// newWatcherForTest injects a fake reader and env-authority flag; always
// "supported" so the full poll/observe path runs on any test OS.
func newWatcherForTest(read func() (Snapshot, error), envAuthoritative bool) *Watcher {
	w := &Watcher{read: read, supported: true, envAuthoritative: envAuthoritative}
	w.prime()
	return w
}

func (w *Watcher) prime() {
	if !w.active() {
		return
	}
	snap, err := w.read()
	if err != nil {
		w.readFailing = true
		slog.Warn("system proxy read failed at startup; assuming none",
			"event.name", observability.EventProxyEgressSysProxyReadFailed,
			"error", err)
		return
	}
	w.cur = snap
	if !snap.Empty() {
		slog.Info("system proxy detected",
			"event.name", observability.EventProxyEgressSysProxyChanged,
			"http", snap.HTTP, "https", snap.HTTPS, "socks", snap.SOCKS)
	}
}

// active reports whether OS detection participates at all.
func (w *Watcher) active() bool { return w.supported && !w.envAuthoritative }

// Current returns the last-known snapshot (zero value when inactive).
func (w *Watcher) Current() Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cur
}

// EnvAuthoritative reports whether the process env carries proxy intent and
// therefore outranks OS detection. Read-only observability accessor (admin
// egress state / `aikey env`).
func (w *Watcher) EnvAuthoritative() bool { return w.envAuthoritative }

// Supported reports whether this platform has OS system-proxy detection.
// Read-only observability accessor.
func (w *Watcher) Supported() bool { return w.supported }

// EnvProxyVars returns the proxy-relevant environment variables THIS process
// sees (the daemon's frozen spawn env — deliberately not the user's shell),
// with any embedded URL credentials redacted. Observability only: the egress
// decision itself goes through ProxyFunc, never this map.
func EnvProxyVars() map[string]string {
	out := map[string]string{}
	for _, k := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"ALL_PROXY", "all_proxy",
		"NO_PROXY", "no_proxy",
	} {
		if v := os.Getenv(k); v != "" {
			out[k] = redactURLCredentials(v)
		}
	}
	return out
}

// redactURLCredentials masks user:password inside a proxy URL (rare but legal,
// e.g. http://user:pass@host:port) so the value is safe to expose over the
// admin API and in CLI output. Non-URL values pass through unchanged.
func redactURLCredentials(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	return u.Redacted()
}

// Run polls the OS until ctx is done, invoking onChange(old, cur) after the
// internal snapshot flips. Inert (returns immediately) when env config is
// authoritative or the platform is unsupported.
func (w *Watcher) Run(ctx context.Context, onChange func(old, cur Snapshot)) {
	if !w.active() {
		return
	}
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if old, cur, changed := w.observe(); changed {
				onChange(old, cur)
			}
		}
	}
}

// observe performs one poll: reads the OS, updates the snapshot, logs
// transitions. Split from Run so tests drive it without a ticker (same
// pattern as supervisor's changeDetector).
func (w *Watcher) observe() (old, cur Snapshot, changed bool) {
	snap, err := w.read()
	w.mu.Lock()
	defer w.mu.Unlock()
	if err != nil {
		// Keep last-known: a transient scutil/registry hiccup must not flap
		// the egress path to direct and back.
		if !w.readFailing {
			w.readFailing = true
			slog.Warn("system proxy read failed; keeping last-known value",
				"event.name", observability.EventProxyEgressSysProxyReadFailed,
				"error", err)
		}
		return w.cur, w.cur, false
	}
	if w.readFailing {
		w.readFailing = false
		slog.Info("system proxy read recovered",
			"event.name", observability.EventProxyEgressSysProxyReadRecovered)
	}
	if snap == w.cur {
		return w.cur, w.cur, false
	}
	old, w.cur = w.cur, snap
	slog.Info("system proxy changed; egress refreshed",
		"event.name", observability.EventProxyEgressSysProxyChanged,
		"http", snap.HTTP, "https", snap.HTTPS, "socks", snap.SOCKS,
		"old_http", old.HTTP, "old_https", old.HTTPS, "old_socks", old.SOCKS)
	return old, snap, true
}

// ProxyFunc returns the Transport.Proxy for the DIRECT egress mode
// (upstream_proxy.url empty). Layering per the approved precedence:
//   - env authoritative → exactly the pre-existing behavior
//     (http.ProxyFromEnvironment; its sync.Once cache is harmless because the
//     process env is immutable anyway), including NO_PROXY handling;
//   - otherwise → the live system-proxy snapshot, re-read on every request so
//     a mid-flight Clash change applies to the very next request;
//   - no system proxy → direct.
func (w *Watcher) ProxyFunc() func(*http.Request) (*url.URL, error) {
	if !w.active() {
		return http.ProxyFromEnvironment
	}
	return func(req *http.Request) (*url.URL, error) {
		// Never proxy loopback destinations (local relays, self-probes) —
		// parity with ProxyFromEnvironment's localhost rule.
		if isLoopbackHost(req.URL.Hostname()) {
			return nil, nil
		}
		raw := w.Current().ProxyFor(req.URL.Scheme)
		if raw == "" {
			return nil, nil
		}
		return url.Parse(raw)
	}
}

// BrokerEgressURL is the system-derived egress for clients that take a static
// proxy URL string (the OAuth ImpersonateChrome client). "" when env config is
// authoritative (the client's own env fallback applies) or no system proxy is
// set. Callers must re-invoke this on change (main's onChange rebuilds the
// broker client) — the returned string is a point-in-time value by design.
func (w *Watcher) BrokerEgressURL() string {
	if !w.active() {
		return ""
	}
	return w.Current().ProxyFor("https")
}

// envProxyConfigured reports whether the process env carries any proxy intent.
// Mirrors the variable set golang.org/x/net/http/httpproxy consults. NO_PROXY
// alone counts too: it expresses "I curated env-level proxy rules".
func envProxyConfigured() bool {
	for _, k := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"ALL_PROXY", "all_proxy",
		"NO_PROXY", "no_proxy",
	} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
