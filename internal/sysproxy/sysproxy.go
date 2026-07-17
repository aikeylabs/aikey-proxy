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
// truth, user-approved; refined same day after field evidence from two
// machines — see below):
//
//	explicit upstream_proxy.url  >  proxy.env EXPLICIT env  >  OS system proxy (live)  >  inherited shell env  >  direct
//
// WHY the env layer is split in two (2026-07-08 refinement, user-approved):
// "process env" conflates the user's EXPLICIT aikey config (~/.aikey/proxy.env,
// which the CLI injects at spawn) with ACCIDENTAL shell inheritance (.zshrc
// exports, stale terminal sessions). Clash-style users practically always have
// shell exports, so an undivided env layer permanently masked the system-proxy
// auto-follow this package exists for — and made behavior differ between
// launchd auto-start (no shell env) and manual restart (shell env). The CLI
// marks its proxy.env injections via AIKEY_PROXYENV_KEYS; only marked proxy
// vars outrank OS detection, inherited ones fall below it as a last resort
// (still covering headless/Linux manual starts).
//
// The explicit-URL layer stays OUTSIDE this package (buildTransport keeps
// using http.ProxyURL for it); this package resolves the rest.
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
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"

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

	// envProxy resolves proxy env vars (both layers 2 and 4). Built ONCE at
	// construction from the frozen process env via x/net/httpproxy — the same
	// implementation net/http delegates to, but WITHOUT the process-global
	// sync.Once cache, so tests can drive it deterministically with t.Setenv.
	envProxy func(*url.URL) (*url.URL, error)

	// envExplicit: the process env carries proxy vars that the CLI marked as
	// coming from ~/.aikey/proxy.env (AIKEY_PROXYENV_KEYS). That is EXPLICIT
	// user config, so it outranks OS detection — including its NO_PROXY
	// exclusions, which must not "fall through" to the system layer.
	// Inherited (unmarked) proxy vars do NOT set this; they participate only
	// as the below-system fallback inside ProxyFunc.
	envExplicit bool

	// readFailing dedups WARN logs: one WARN per failure streak, one INFO on
	// recovery, never a 20s WARN drumbeat.
	readFailing bool
}

// NewWatcher builds and synchronously primes a watcher using the platform
// reader. On unsupported platforms or with authoritative env config the
// watcher is inert (Run returns immediately, ProxyFunc delegates to env).
func NewWatcher() *Watcher {
	w := &Watcher{
		read:        readSystemProxy,
		supported:   platformSupported,
		envExplicit: envProxyExplicit(os.Getenv),
		envProxy:    httpproxy.FromEnvironment().ProxyFunc(),
	}
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
	w := &Watcher{
		read:      read,
		supported: true,
		envProxy:  httpproxy.FromEnvironment().ProxyFunc(),
	}
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

// newWatcherForTest injects a fake reader and explicit-env flag; always
// "supported" so the full poll/observe path runs on any test OS.
func newWatcherForTest(read func() (Snapshot, error), envExplicit bool) *Watcher {
	w := &Watcher{
		read:        read,
		supported:   true,
		envExplicit: envExplicit,
		envProxy:    httpproxy.FromEnvironment().ProxyFunc(),
	}
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

// active reports whether OS detection participates at all. Only EXPLICIT
// (proxy.env-marked) env config disables it — inherited shell env does not,
// because the system proxy now outranks inheritance.
func (w *Watcher) active() bool { return w.supported && !w.envExplicit }

// Current returns the last-known snapshot (zero value when inactive).
func (w *Watcher) Current() Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cur
}

// EnvExplicit reports whether proxy.env-marked (explicit) proxy vars are
// present and therefore outrank OS detection. Read-only observability
// accessor (admin egress state / `aikey env`).
func (w *Watcher) EnvExplicit() bool { return w.envExplicit }

// Supported reports whether this platform has OS system-proxy detection.
// Read-only observability accessor.
func (w *Watcher) Supported() bool { return w.supported }

// EnvProxyVarsSplit returns the proxy-relevant environment variables THIS
// process sees (the daemon's frozen spawn env — deliberately not the user's
// shell), split by provenance: explicit = injected from ~/.aikey/proxy.env
// (AIKEY_PROXYENV_KEYS-marked), inherited = everything else (shell exports,
// stale terminals). Credentials in URLs are redacted. Observability only:
// the egress decision itself goes through ProxyFunc, never these maps.
func EnvProxyVarsSplit() (explicit, inherited map[string]string) {
	return envProxyVarsSplitFrom(os.Getenv)
}

// NoProxyBypass returns a predicate reporting whether a destination host should
// BYPASS an explicit egress proxy and dial DIRECT: loopback IPs / "localhost" are
// always direct, plus any host matching NO_PROXY / no_proxy (domain suffix or
// CIDR). Reuses Go's httpproxy canon (a sentinel proxy makes ProxyFunc return
// non-nil for a NON-bypassed host; nil ⇒ bypass) so there's no hand-rolled
// matching. Shared by BOTH the node-level explicit upstream (app.buildTransport)
// and the per-account egress transport (proxy.dialerToTransport) so internal
// destinations honor the same NO_PROXY the operator configured, regardless of
// which egress layer is in play.
//
// NOTE (intentional, do NOT "unify" with Watcher.ProxyFunc): this is a distinct
// concern from Watcher.ProxyFunc. ProxyFunc answers "with NO explicit upstream,
// which env/system proxy applies" (returns a proxy URL); NoProxyBypass answers
// "with an explicit upstream set, does this host SKIP it" (returns a bool). Both
// delegate NO_PROXY matching to x/net/httpproxy, so their NO_PROXY semantics are
// already identical — there is no duplicated matcher to converge. Merging the two
// different-purpose functions would be over-abstraction (2026-07-16 assessment).
func NoProxyBypass() func(host string) bool {
	cfg := &httpproxy.Config{
		HTTPProxy:  "http://sentinel.invalid:1",
		HTTPSProxy: "http://sentinel.invalid:1",
		NoProxy:    os.Getenv("NO_PROXY") + "," + os.Getenv("no_proxy"),
	}
	pf := cfg.ProxyFunc()
	return func(host string) bool {
		if host == "" {
			return false
		}
		u, _ := pf(&url.URL{Scheme: "https", Host: host})
		return u == nil
	}
}

func envProxyVarsSplitFrom(get func(string) string) (explicit, inherited map[string]string) {
	marked := explicitEnvKeySet(get)
	explicit, inherited = map[string]string{}, map[string]string{}
	for k, v := range envProxyVarsFrom(get) {
		if marked[strings.ToUpper(k)] {
			explicit[k] = v
		} else {
			inherited[k] = v
		}
	}
	return explicit, inherited
}

// envProxyVarsFrom is the injectable core (tests fake the getter). WHY the
// twin-dedupe (2026-07-08 Windows field report): Windows env keys are
// case-INsensitive — Getenv("http_proxy") returns the SAME variable as
// Getenv("HTTP_PROXY"), so the naive 8-key loop displayed every variable
// twice in `aikey env`. The lowercase twin is listed only when it's a
// genuinely distinct value (possible on Unix, where env is case-sensitive).
func envProxyVarsFrom(get func(string) string) map[string]string {
	out := map[string]string{}
	for _, pair := range [][2]string{
		{"HTTP_PROXY", "http_proxy"},
		{"HTTPS_PROXY", "https_proxy"},
		{"ALL_PROXY", "all_proxy"},
		{"NO_PROXY", "no_proxy"},
	} {
		upper, lower := get(pair[0]), get(pair[1])
		if upper != "" {
			out[pair[0]] = redactURLCredentials(upper)
		}
		if lower != "" && lower != upper {
			out[pair[1]] = redactURLCredentials(lower)
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
//   - explicit proxy.env env (marked) → env resolution with full NO_PROXY
//     handling (x/net httpproxy — identical semantics to
//     http.ProxyFromEnvironment, minus its process-global cache);
//   - otherwise → the live system-proxy snapshot, re-read on every request so
//     a mid-flight Clash change applies to the very next request;
//   - no system proxy → INHERITED shell env as last-resort fallback (covers
//     headless/Linux manual starts and unsupported platforms, where this
//     equals the pre-detection behavior);
//   - nothing anywhere → direct.
func (w *Watcher) ProxyFunc() func(*http.Request) (*url.URL, error) {
	if !w.active() {
		return func(req *http.Request) (*url.URL, error) { return w.envProxy(req.URL) }
	}
	return func(req *http.Request) (*url.URL, error) {
		// Never proxy loopback destinations (local relays, self-probes) —
		// parity with ProxyFromEnvironment's localhost rule.
		if isLoopbackHost(req.URL.Hostname()) {
			return nil, nil
		}
		if raw := w.Current().ProxyFor(req.URL.Scheme); raw != "" {
			return url.Parse(raw)
		}
		// Layer 4: inherited shell env (unmarked vars) as fallback.
		return w.envProxy(req.URL)
	}
}

// BrokerEgressURL is the layered egress for clients that take a static proxy
// URL string (the OAuth ImpersonateChrome client). "" when explicit env
// config applies or nothing is detected — in both cases the client's own env
// fallback yields the same result (explicit or inherited env respectively).
// Callers must re-invoke this on change (main's onChange rebuilds the broker
// client) — the returned string is a point-in-time value by design.
func (w *Watcher) BrokerEgressURL() string {
	if !w.active() {
		return ""
	}
	return w.Current().ProxyFor("https")
}

// proxyEnvNames is the variable set golang.org/x/net/http/httpproxy consults.
// NO_PROXY counts too: it expresses "I curated env-level proxy rules".
var proxyEnvNames = []string{
	"HTTP_PROXY", "http_proxy",
	"HTTPS_PROXY", "https_proxy",
	"ALL_PROXY", "all_proxy",
	"NO_PROXY", "no_proxy",
}

// explicitEnvKeyMarker is set by aikey-cli at spawn: comma-separated env keys
// it injected from ~/.aikey/proxy.env (the user's EXPLICIT aikey config).
const explicitEnvKeyMarker = "AIKEY_PROXYENV_KEYS"

// explicitEnvKeySet parses the marker into an upper-cased key set. Upper-cased
// on both sides because Windows env keys are case-insensitive and proxy.env
// keys are user-typed in either case.
func explicitEnvKeySet(get func(string) string) map[string]bool {
	out := map[string]bool{}
	for _, k := range strings.Split(get(explicitEnvKeyMarker), ",") {
		if k = strings.TrimSpace(k); k != "" {
			out[strings.ToUpper(k)] = true
		}
	}
	return out
}

// envProxyExplicit reports whether any proxy var is BOTH set and marked as
// coming from proxy.env — the only condition that outranks OS detection.
func envProxyExplicit(get func(string) string) bool {
	marked := explicitEnvKeySet(get)
	if len(marked) == 0 {
		return false
	}
	for _, k := range proxyEnvNames {
		if get(k) != "" && marked[strings.ToUpper(k)] {
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
