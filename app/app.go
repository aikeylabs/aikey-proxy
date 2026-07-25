package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"

	"github.com/AiKeyLabs/aikey-proxy/internal/admin"
	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
	proxyruntime "github.com/AiKeyLabs/aikey-proxy/internal/runtime"
	"github.com/AiKeyLabs/aikey-proxy/internal/server"
	"github.com/AiKeyLabs/aikey-proxy/internal/supervisor"
	"github.com/AiKeyLabs/aikey-proxy/internal/sysproxy"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"

	broker "github.com/AiKeyLabs/aikey-auth-broker"
	"github.com/AiKeyLabs/pkg/aikeycompat"
	"github.com/AiKeyLabs/pkg/buildinfo"
	"github.com/AiKeyLabs/pkg/egress"

	// Protocol-translator pair registrations (Phase 2). Each blank-import
	// fires the pair package's init() which registers (from, to) transforms
	// with translator.DefaultRegistry(). The App pipeline reads from the
	// same default registry. New pairs (Codex / Kimi /阶段 1+) land here.
	_ "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator/pairs/openai_anthropic"

	// Phase 4 M2 first-party observer registrations. Each blank-import
	// fires the plugin package's init() which calls
	// observer.RegisterObserver to add its descriptor to the process-
	// global registration sink. The supervisor's buildObserverRegistry
	// reads from that sink at proxy-generation construction time.
	//
	// Adding a new first-party observer requires exactly TWO lines in this
	// file: one import line here + (separately) one entry in
	// observer.FirstPartyAllowlist (in pkg/observer/registry.go). No
	// changes to internal/proxy/* or internal/supervisor/* are required —
	// the framework picks up the new descriptor automatically.
	_ "github.com/aikeylabs/ai-degrade-detector/proxy-plugin/rhythm"

	// P3 step 2c (2026-05-23, credential-mode-architecture SPEC §1.4):
	// proxy-bundled ndjson-fanout observer. Reads vault `observe_streams`
	// at Build time and writes per-subscriber NDJSON files for any
	// app that subscribes. Owner slug "aikey-proxy-core" is the
	// proxy-infrastructure synthetic (FirstPartyAllowlist) — special-cased
	// always-on by supervisor.buildObserverRegistry. Vault is injected by
	// supervisor at generation-build time (which is where vault.Open
	// happens); main.go just blank-imports for init() side effect.
	_ "github.com/AiKeyLabs/aikey-proxy/internal/observer/ndjson_fanout"

	// Enterprise Cluster conversation-audit capture observer (payload_level=full).
	// Reuses the "aikey-proxy-core" first-party slug (already allow-listed), so
	// only this import line is needed. Its deps (content outbox sink + live org
	// policy) are injected by supervisor.buildGeneration via
	// conversation_audit.SetDeps before BuildObservers; absent a team collector
	// the supervisor passes a nil sink and the observer is skipped at build.
	_ "github.com/AiKeyLabs/aikey-proxy/internal/observer/conversation_audit"
)

const defaultConfigName = "aikey-proxy.yaml"

// resolveConfigPath finds the proxy config file in priority order:
//  1. Explicit --config argument
//  2. Current working directory (aikey-proxy.yaml)
//  3. $HOME/.aikey/config/aikey-proxy.yaml  (respects HOME env var for sandbox isolation)
func resolveConfigPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	// cwd
	if _, err := os.Stat(defaultConfigName); err == nil {
		return defaultConfigName, nil
	}
	// $HOME/.aikey/config/
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".aikey", "config", defaultConfigName)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf(
		"%s not found. Searched: current directory, ~/.aikey/config/. "+
			"Use --config to specify explicitly.", defaultConfigName)
}

func Run() {
	// Handle "version" subcommand before flag parsing (flags expect --config etc.)
	if len(os.Args) > 1 && os.Args[1] == "version" {
		bi := buildinfo.Get()
		if len(os.Args) > 2 && (os.Args[2] == "--json" || os.Args[2] == "-j") {
			fmt.Println(string(bi.JSON()))
		} else {
			fmt.Println("aikey-proxy", bi.String())
		}
		os.Exit(0)
	}

	// "wal vacuum" subcommand — manually trigger one retention sweep
	// (费用小票 §12 验收 #3). Safe to run beside a live proxy: the sweep only
	// touches files days past retention, never the open current-hour file,
	// and the events DB is WAL-mode SQLite (multi-process safe).
	if len(os.Args) > 2 && os.Args[1] == "wal" && os.Args[2] == "vacuum" {
		os.Exit(runWALVacuum(os.Args[3:]))
	}

	configPath := flag.String("config", "", "path to config file (default: search cwd then ~/.aikey/)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("aikey-proxy", buildinfo.Get().String())
		os.Exit(0)
	}

	// Minimal stderr-only logger until config is loaded and log dir is known.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	// Handle graceful shutdown — see pkg/aikeycompat for the per-OS signal set
	// (Windows: SIGINT only; Unix: SIGINT + SIGTERM).
	//
	// WHY Notify is installed FIRST, before any init (2026-07-08 bugfix, e2e
	// i3): a service manager may forward SIGTERM at any moment after exec
	// (systemd stop right after start, restart storms), and the CLI writes the
	// ownership meta while we are still initializing (vault/broker/observers —
	// hundreds of ms). Before this move an early SIGTERM hit Go's default
	// disposition and killed the process ("signal: 15", non-zero exit) instead
	// of draining gracefully. The buffered channel captures the early signal;
	// the select at the bottom of main consumes it right after init completes →
	// same graceful drain path, exit 0.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, aikeycompat.ShutdownSignals()...)

	// 1. Resolve and load config.
	resolvedPath, err := resolveConfigPath(*configPath)
	if err != nil {
		slog.Error("config not found", "error", err)
		os.Exit(1)
	}
	cfg, err := config.Load(resolvedPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// 2. Initialize structured logging: stderr text + async JSONL file.
	logLevel := parseLogLevel(cfg.Log.Level)
	logWriter, err := observability.SetupLogger(cfg.Log.Dir, "aikey-proxy", buildinfo.Get().String(), logLevel)
	if err != nil {
		// Non-fatal: fall back to text-only stderr logging.
		slog.Warn("failed to initialize JSONL log writer, falling back to stderr only", "error", err)
		setupTextLogging(logLevel)
	}

	// Wire GoSafe / HTTP recover to the same log directory so panic dumps
	// live alongside current.jsonl, and register a flush hook so Fatal-mode
	// goroutine panics drain the async writer before exit(2).
	observability.SetCrashDumpDir(cfg.Log.Dir)
	if logWriter != nil {
		observability.SetFatalFlushHook(func() {
			logWriter.Flush(2 * time.Second)
		})
	}

	// Stable, debug-only sentinel used by E2E cond18 (config-split
	// system+user §6 Phase 1 S2) to prove AIKEY_PROXY_LOG_LEVEL=debug
	// actually reached the handler. slog drops Debug-level events when
	// the handler is at Info, so the sentinel only appears under debug.
	// Operators can also tail it as a "is my debug actually on" check.
	slog.Debug("debug logging enabled")
	slog.Info("config loaded",
		"event.name", observability.EventProxyConfigLoaded,
		"listen", cfg.Listen.Addr(),
		"vault", cfg.Vault.Path,
	)

	// 3. Get master password.
	password, err := getVaultPassword()
	if err != nil {
		slog.Error("failed to get master password", "error", err)
		os.Exit(1)
	}

	// 4. Bind the TCP listener once — it is never closed during graceful reloads.
	// supervisor.Listen drifts to port+1..port+drift_max when the configured
	// port is occupied (per 20260430-端口偏移能力修复.md).
	ln, configuredAddr, actualAddr, driftOffset, err := supervisor.Listen(cfg)
	if err != nil {
		slog.Error("failed to bind listener", "error", err)
		os.Exit(1)
	}
	if driftOffset > 0 {
		slog.Warn("port drift: configured port occupied, fell back",
			"configured", configuredAddr,
			"actual", actualAddr,
			"drift_offset", driftOffset,
		)
	}
	slog.Info("listener bound",
		"event.name", observability.EventProxyListenerBound,
		"addr", actualAddr,
	)

	// 4b. Write the runtime snapshot so CLI / web can discover the actual
	// bound port. Per 20260428 ownership: the proxy process is the sole
	// writer of its runtime state; install-state.json is desired/configured
	// state and is owned by the installer. Snapshot is removed on graceful
	// exit (deferred below) — crashed-process residue is overwritten by the
	// next start.
	snapshot := proxyruntime.Snapshot{
		IncarnationID: proxyruntime.NewIncarnationID(),
		PID:           os.Getpid(),
		Listen: proxyruntime.Listen{
			ConfiguredAddr: configuredAddr,
			ActualAddr:     actualAddr,
			DriftOffset:    driftOffset,
		},
		StartedAt: time.Now().UTC(),
	}
	if wErr := proxyruntime.Write(&snapshot); wErr != nil {
		slog.Warn("failed to write proxy-runtime.json (non-fatal)", "error", wErr)
	}

	// 5. Create the Supervisor (starts the initial generation).
	// NB: the proxy-runtime.json cleanup defer is registered AFTER this check —
	// os.Exit below would skip a defer (gocritic exitAfterDefer), so on this
	// fatal path we remove the snapshot explicitly and defer it only once the
	// supervisor is up (normal-shutdown cleanup).
	// P1 error-origin (20260719): fix this process's component label for the
	// X-Aikey-Error-Origin header BEFORE serving — "worker-proxy" when a cluster
	// node id is set, else "local-proxy". Single source: cluster.node_id.
	proxy.SetErrorOriginComponent(cfg.Cluster.NodeID)

	sup, err := supervisor.New(cfg, resolvedPath, password, buildinfo.Get().Version)
	if err != nil {
		slog.Error("failed to start supervisor", "error", err)
		if rmErr := proxyruntime.Remove(); rmErr != nil {
			slog.Warn("failed to remove proxy-runtime.json on shutdown", "error", rmErr)
		}
		os.Exit(1)
	}
	defer func() {
		if err := proxyruntime.Remove(); err != nil {
			slog.Warn("failed to remove proxy-runtime.json on shutdown", "error", err)
		}
	}()

	slog.Info("aikey-proxy started",
		"event.name", observability.EventProxyProcessStarted,
		"version", buildinfo.Get().String(),
		"listen", ln.Addr(),
	)

	// 5a. OS system-proxy watcher (2026-07-08 需求: 代理更新时自动刷新).
	// Primes synchronously so both the broker client below and the forwarding
	// transport see the CURRENT system proxy from request #1. Precedence
	// (user-approved): explicit upstream_proxy.url > process env > OS system
	// proxy (live). The poll loop is started after egress wiring (below) so
	// its change callback can reach the live transport + broker swap.
	sysWatcher := sysproxy.NewWatcher()
	// effectiveBrokerEgress: static egress URL for the OAuth impersonate
	// client — explicit config wins; else the system-derived URL ("" = client
	// falls back to its own env handling, the pre-2026-07-08 behavior).
	effectiveBrokerEgress := func(cfgURL string) string {
		s := strings.TrimSpace(cfgURL)
		if s != "" && !egress.IsEngineSpec(s) {
			return s
		}
		// Engine specs are handled by installBrokerClient's dialer path; reaching
		// here with one means that path declined it, so fall back like an empty
		// value does.
		return sysWatcher.BrokerEgressURL()
	}

	// brokerEgressCloser holds the group dialer backing the CURRENT broker client
	// (non-nil only for mihomo fallback/url-test/load-balance groups). Swapping the
	// node upstream must Close the previous one or its health-check goroutines leak
	// — the same contract BuildEgressTransport documents for the forwarding path.
	var (
		brokerEgressMu     sync.Mutex
		brokerEgressCloser io.Closer
	)

	// installBrokerClient points the OAuth broker at the node's CURRENT egress.
	//
	// One egress, both paths (2026-07-24). A multi-protocol spec has no URL form,
	// so OAuth used to fall back to the system/env proxy while AI forwarding rode
	// the engine — one node, two exits. On a machine whose system proxy is stale
	// that surfaced as a bare `token exchange request failed: ... proxyconnect tcp`
	// and looked to the user like their new egress "didn't take effect" (Win10 VM
	// field case). Now an engine spec builds a dialer and the impersonate client
	// dials THROUGH it; URL/empty specs keep the previous proxy-URL behavior.
	//
	// A dialer that fails to build is NOT fatal: OAuth degrades to the URL path
	// rather than becoming unusable, and the WARN says which spec failed. The live
	// forwarding transport reports the same failure separately.
	installBrokerClient := func(spec string) {
		var newCloser io.Closer
		if s := strings.TrimSpace(spec); s != "" && egress.IsEngineSpec(s) {
			dial, closer, err := proxy.BuildEgressDialContext(s)
			if err == nil {
				broker.SetHTTPClient(broker.NewImpersonateChromeHTTPClientWithDialer(dial))
				newCloser = closer
				slog.Info("OAuth broker egress: multi-protocol engine (same exit as forwarding)")
			} else {
				slog.Warn("OAuth broker egress: engine spec failed to build, using system/env proxy for token exchange",
					"error", err)
				broker.SetHTTPClient(broker.NewImpersonateChromeHTTPClient(effectiveBrokerEgress(spec)))
			}
		} else {
			broker.SetHTTPClient(broker.NewImpersonateChromeHTTPClient(effectiveBrokerEgress(spec)))
		}
		brokerEgressMu.Lock()
		old := brokerEgressCloser
		brokerEgressCloser = newCloser
		brokerEgressMu.Unlock()
		if old != nil {
			_ = old.Close()
		}
	}

	// 5b. Build OAuth broker (embedded, uses vault stores).
	//     Reuse the supervisor's vault connection to avoid double-open conflicts.
	brokerVault := sup.VaultReader()
	var oauthHandler server.RouteRegistrar
	var poolHandler server.RouteRegistrar // C10: pool login (memory-store broker → writeback master)
	if brokerVault != nil {
		tokenStore := vault.NewTokenStore(brokerVault.DB(), brokerVault.DerivedKey())
		accountStore := vault.NewAccountStore(brokerVault.DB())

		// Inject ImpersonateChrome HTTP client for Claude token endpoint (Cloudflare bypass).
		// Impl lives in the shared broker module (moved 2026-06-26) so aikey-control-master
		// can inject the same client for its server-side OAuth flow — single source of truth.
		//
		// 2026-06-30 (egress fix): pass the SAME configured egress as AI forwarding
		// (cfg.UpstreamProxy.URL) instead of "". Why: launchd-spawned proxies don't
		// inherit the login shell's HTTP_PROXY, so a "" client went DIRECT and got
		// 403 "Request not allowed" from Anthropic's edge (only Chrome-TLS THROUGH the
		// egress reaches the OAuth logic). Mirrors the old master pattern (egress URL →
		// impersonate proxyURL). Empty url ⇒ "" ⇒ falls back to env (no regression).
		// Forwarding uses the same cfg.UpstreamProxy.URL via buildTransport below;
		// control-plane clients deliberately bypass it (internal/httpx.NewDirectClient).
		// 2026-07-08: "" no longer means "hope the env has it" — the system
		// proxy watcher supplies the live OS value (launchd-spawned proxies
		// have no login-shell env), keeping OAuth on the same egress as AI
		// forwarding.
		// Mirror the forwarding transport's 2026-07-17 async pattern (the bootSpec
		// block below): an ENGINE-spec broker egress primes a health-check that
		// DIALS possibly-slow/unreachable exit nodes, and installBrokerClient does
		// that build synchronously — which blocks the pre-serve startup path past
		// the CLI's 5s health gate when a node is down (bugfix
		// 20260725-proxy-startup-broker-egress-engine-build-blocks-serve: a
		// persisted engine upstream with an unreachable node landed serve at
		// ~5.04s, 0.04s over the gate). OAuth egress is a BYPASS (only OAuth login
		// uses it), so — exactly like AI forwarding — install a fast fallback
		// client now and build the real engine dialer in the background, hot-
		// swapping when ready. installBrokerClient is atomic (mutex + closer swap).
		if brokerBootSpec := strings.TrimSpace(cfg.UpstreamProxy.URL); brokerBootSpec == "" || !egress.IsEngineSpec(brokerBootSpec) {
			installBrokerClient(cfg.UpstreamProxy.URL) // single-URL/empty: builds without dialing
		} else {
			installBrokerClient("") // interim: fast fallback client, no engine build
			observability.GoSafe("app.broker_egress_async_build", observability.Isolated, func() {
				installBrokerClient(cfg.UpstreamProxy.URL)
			})
		}

		brk := broker.NewEmbedded(tokenStore, accountStore)
		oauthHandler = broker.NewHandler(brk)
		// Wire broker into supervisor so all proxy generations can resolve OAuth credentials
		sup.SetBroker(&brokerAdapter{inner: brk, accounts: accountStore})
		// C10/RW8: pool login handler — its own MEMORY-store broker (per-member
		// tokens never touch the vault) reusing the global impersonate client set
		// above; exchanges then write back to master RW10 over the team JWT.
		poolHandler = sup.NewPoolLoginHandler()
		slog.Info("OAuth broker initialized")
	} else {
		slog.Warn("OAuth broker disabled: vault not available")
	}

	// 6. Build the admin handler, wiring Supervisor callbacks.
	adminHandler := admin.NewHandler(cfg, sup.Registry(), sup.EventStore())
	adminHandler.TotalRequestsFn = sup.TotalRequests
	adminHandler.TotalErrorsFn = sup.TotalErrors
	adminHandler.ReloadFn = sup.Reload
	adminHandler.KeyChecksFn = sup.GetKeyCheckTargets
	adminHandler.ReporterMetricsFn = sup.ReporterMetrics
	adminHandler.CollectorMetricsFn = sup.CollectorMetrics
	adminHandler.ReplayDeadLetterFn = sup.ReplayDeadLetter
	adminHandler.CanaryResultFn = sup.CanaryResult
	adminHandler.DebugUpstreamHeadersStateFn = proxy.UpstreamHeadersDebugState
	adminHandler.DebugUpstreamHeadersSetFn = proxy.SetUpstreamHeadersDebugAPIOverride
	adminHandler.AppHealthFn = sup.AppHealthSnapshot
	// Oauth-group routing health (N9): omitted from /status unless the feature is
	// on, so non-pool deployments are unchanged. Surfaces which pool accounts are
	// currently cooled, for the operator monitoring the first pool batch.
	adminHandler.PoolHealthFn = func() *admin.PoolRoutingHealth {
		if !vkeys.OauthGroupRoutingEnabled() {
			return nil
		}
		h := &admin.PoolRoutingHealth{Enabled: true}
		for id, secs := range sup.PoolCooldownSnapshot() {
			h.CooledAccounts = append(h.CooledAccounts, admin.CooledAccount{AccountID: id, CooldownSeconds: secs})
		}
		return h
	}
	// SyncRail health (2026-07-03): per-rail control-plane sync state for /status
	// (health-signal-surface rule — the release E2E asserts this, not the UI).
	// Empty map (no rail ever attempted — personal installs) → field omitted.
	adminHandler.SyncHealthFn = func() map[string]admin.SyncRailStatus {
		snap := sup.ControlPlaneSyncSnapshot()
		if len(snap) == 0 {
			return nil
		}
		out := make(map[string]admin.SyncRailStatus, len(snap))
		for name, st := range snap {
			out[name] = admin.SyncRailStatus{
				State:               st.State,
				ConsecutiveFailures: st.ConsecutiveFailures,
				LastSuccessAt:       st.LastSuccessAt,
				LastError:           st.LastError,
			}
		}
		return out
	}
	adminHandler.EffectivePacksFn = sup.EffectivePacks
	adminHandler.AuditStatusFn = sup.AuditStatus
	adminHandler.ReconcileGapsFn = sup.ReconcileGaps

	// Egress (upstream) proxy config endpoints (GET/PUT /admin/upstream-proxy), the
	// runtime home of the egress proxy after R25 出口收敛. Get returns the live URL;
	// Set persists it to aikey-user.yaml (survives re-render) and HOT-SWAPS the
	// forwarding transport + OAuth impersonate client in place — no restart. egressMu
	// guards the cached URL Get reads (the transport/broker swaps are themselves
	// atomic). Decision: user chose hot-swap (B) + plaintext storage (i).
	var egressMu sync.Mutex
	egressURL := cfg.UpstreamProxy.URL
	adminHandler.GetUpstreamProxyFn = func() string {
		egressMu.Lock()
		defer egressMu.Unlock()
		return egressURL
	}
	// liveTransport tracks the transport currently serving forwarding, so the
	// system-proxy change callback can flush its idle pool (pooled connections
	// to a dead Clash port would otherwise be reused until IdleConnTimeout).
	var liveTransport atomic.Pointer[http.Transport]
	// liveEgressCloser owns the CURRENT node upstream's background state (only a
	// mihomo group dialer has any: its health-check goroutines). Guarded by
	// egressMu. installTransport Closes the PREVIOUS one on every swap so a
	// hot-swap between two multi-protocol specs (or engine→single-URL) never leaks
	// a health-check loop — GC can't reclaim it because the loop keeps it live.
	var liveEgressCloser io.Closer
	installTransport := func(t *http.Transport, closer io.Closer) {
		liveTransport.Store(t)
		sup.SetTransport(t)
		egressMu.Lock()
		old := liveEgressCloser
		liveEgressCloser = closer
		egressMu.Unlock()
		if old != nil {
			_ = old.Close()
		}
	}
	adminHandler.SetUpstreamProxyFn = func(rawURL string) error {
		spec := strings.TrimSpace(rawURL)
		if err := validateNodeUpstream(spec); err != nil {
			return err
		}
		if err := config.PersistUpstreamProxyURL(resolvedPath, spec); err != nil {
			return err
		}
		installTransport(buildTransport(spec, sysWatcher.ProxyFunc()))
		// 2026-07-18 (reversed the L1 override): the node upstream serves only
		// non-egress traffic; per-account egress stays independent, so setting/clearing
		// the node upstream no longer touches per-account egress precedence.
		installBrokerClient(spec)
		egressMu.Lock()
		egressURL = spec
		egressMu.Unlock()
		return nil
	}
	// EgressStateFn (2026-07-08): layered egress decision for `aikey env`.
	adminHandler.EgressStateFn = func() admin.EgressState {
		egressMu.Lock()
		explicit := egressURL
		egressMu.Unlock()
		return egressState(explicit, sysWatcher)
	}

	// Escape hatch (2026-07-19): apply the persisted opt-in flag at boot so it
	// survives restart, then expose GET/PUT. Set persists to aikey-user.yaml +
	// hot-applies across generations (sup.SetOAuthEgressOverride). Node-local.
	sup.SetOAuthEgressOverride(cfg.UpstreamProxy.OAuthEgressOverride)
	adminHandler.GetOAuthEgressOverrideFn = func() bool { return sup.OAuthEgressOverride() }
	adminHandler.SetOAuthEgressOverrideFn = func(on bool) error {
		if err := config.PersistOAuthEgressOverride(resolvedPath, on); err != nil {
			return err
		}
		sup.SetOAuthEgressOverride(on)
		return nil
	}

	// LiveUpstreamTransportFn hands ProbePing the transport currently serving
	// forwarding, so an engine-spec upstream (mihomo fragment / socks5 chain) is
	// pinged through the ALREADY-BUILT runtime route instead of rebuilding the
	// engine per call (seconds of build cost — over the CLI's 4s ping budget;
	// bugfix 2026-07-19). During the engine boot window this is the interim
	// direct transport — truthful, that IS what forwarding would use right then.
	adminHandler.LiveUpstreamTransportFn = func() http.RoundTripper {
		if t := liveTransport.Load(); t != nil {
			return t
		}
		return nil
	}

	// ProbeUpstreamProxyFn tests a CANDIDATE egress URL end-to-end WITHOUT persisting
	// it, so the web "Test connectivity" button can verify before Save. Extracted to
	// probeUpstreamProxy so the strict-vs-fallback choice is reachable by a test —
	// as a closure it was not, and that choice IS the bug this fixes.
	adminHandler.ProbeUpstreamProxyFn = func(rawURL string) (int, int64, error) {
		return probeUpstreamProxy(rawURL, sysWatcher.ProxyFunc(), upstreamProbeTarget())
	}

	// EgressSelfCheckFn (§5.4): the per-account egress self-check for `aikey test`
	// (presence — no dial, hot-path safe) / `aikey doctor` (dial=true). Enumerates
	// the registry's per-account specs and, when dialing, probes each ONCE through
	// the shared egress.TestDial (same engine the proxy routes with; the deleted
	// duplicate probeEgress must NOT come back). Stateless: one-shot, no health
	// loop. Neutral echo — never claude.ai (§5.4 #2).
	adminHandler.EgressSelfCheckFn = func(ctx context.Context, dial bool) []admin.EgressCheckResult {
		specs := sup.Registry().EgressSpecs()
		out := make([]admin.EgressCheckResult, 0, len(specs))
		for _, s := range specs {
			if !dial {
				out = append(out, admin.EgressCheckResult{Label: s.Label, Dialed: false})
				continue
			}
			res, err := egress.TestDial(ctx, s.Spec, egressSelfCheckEcho(), egressSelfCheckDialTimeout)
			if err != nil {
				out = append(out, admin.EgressCheckResult{Label: s.Label, Dialed: true, OK: false, Reason: err.Error()})
				continue
			}
			out = append(out, admin.EgressCheckResult{
				Label: s.Label, Dialed: true, OK: true,
				Engine: res.Engine, ExitIP: res.ExitIP, LatencyMs: res.LatencyMs,
			})
		}
		return out
	}

	// Build the outbound transport for upstream providers. Always non-nil now:
	// even the direct path needs MaxIdleConnsPerHost tuning (see buildTransport).
	// P2 error-origin (20260719): wrap the data plane so every error response
	// (status ≥ 400) is captured — reusing the X-Aikey-Error-* headers P1 set —
	// into the last-errors ring for `aikey doctor --last-errors`. Best-effort,
	// response-direction only; never touches the upstream request.
	dataHandler := proxy.WrapLastErrorCapture(sup.Handler())
	// A single-URL / empty upstream builds without dialing → install synchronously.
	// A CHAIN / multi-protocol / group upstream is different: building it primes a
	// health-check that DIALS the (possibly slow or unreachable) exit nodes. Doing
	// that on the startup critical path blocks the proxy from becoming healthy — and
	// a BYPASS upstream must NEVER stall main-line startup (主链路优先, bugfix
	// 2026-07-17: a persisted fallback-group upstream with real, slow nodes made the
	// proxy miss its 5s health gate). So we start on DIRECT now and hot-swap the real
	// transport in from a background goroutine once it (and its health-check) is
	// ready. installTransport is atomic and closes the interim direct transport.
	bootSpec := strings.TrimSpace(cfg.UpstreamProxy.URL)
	if bootSpec == "" || !egress.IsEngineSpec(bootSpec) {
		installTransport(buildTransport(cfg.UpstreamProxy.URL, sysWatcher.ProxyFunc()))
	} else {
		installTransport(buildTransport("", sysWatcher.ProxyFunc())) // interim: direct
		go func() {
			installTransport(buildTransport(cfg.UpstreamProxy.URL, sysWatcher.ProxyFunc()))
		}()
	}
	// Start the system-proxy poll loop (inert when env config is authoritative,
	// on unsupported platforms, and — via the explicit-egress guard below —
	// effectively when upstream_proxy.url is set). On change: flush the idle
	// pool so no request reuses a connection through the OLD proxy, and rebuild
	// the OAuth client (it takes a static URL, not a per-request func).
	observability.GoSafe("sysproxy.watch", observability.Isolated, func() {
		sysWatcher.Run(context.Background(), func(_, _ sysproxy.Snapshot) {
			egressMu.Lock()
			explicit := egressURL != ""
			egressMu.Unlock()
			if explicit {
				return // user-configured egress outranks the system proxy
			}
			if t := liveTransport.Load(); t != nil {
				t.CloseIdleConnections()
			}
			installBrokerClient("")
		})
	})

	// 7. Build and start the HTTP server. Only non-nil registrars are passed
	// (server.New does not nil-guard; oauthHandler/poolHandler are nil when the
	// vault/broker is unavailable).
	extraRegistrars := make([]server.RouteRegistrar, 0, 2)
	if oauthHandler != nil {
		extraRegistrars = append(extraRegistrars, oauthHandler)
	}
	if poolHandler != nil {
		extraRegistrars = append(extraRegistrars, poolHandler)
	}
	srv := server.New(ln, dataHandler, adminHandler, extraRegistrars...)

	// Fatal: server.Serve is the process's reason for being. If it dies the
	// proxy cannot serve requests, so exit(2) and let the OS supervisor
	// restart us rather than lingering as a zombie that accepts nothing.
	observability.GoSafe("main.server.serve", observability.Fatal, func() {
		fmt.Fprintf(os.Stderr, "\naikey-proxy %s listening on %s\n\n", buildinfo.Get().String(), ln.Addr())
		if err := srv.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	})

	// Start the master-policy pollers (compliance / quota / group_runtime rails)
	// only AFTER the serve goroutine is launched, so their first-sync reloads —
	// and any ai-compliance-detector cold start on a mandate org — run in the
	// background instead of racing the pre-serve setup and tripping the CLI's 5s
	// /health gate. See Supervisor.StartPolicyPollers. Bugfix
	// 20260725-proxy-startup-reload-storm-5s-health-fail.
	sup.StartPolicyPollers()

	// Wait for either an OS shutdown signal OR a graceful self-restart request
	// from the control-plane healer (selfheal.go): the proxy went stale after a
	// host network change and confirmed master is reachable, so it wants a clean
	// relaunch. BOTH paths run the identical drain below (code reuse); the restart
	// path just exits non-zero afterwards so launchd/systemd relaunch it.
	restartRequested := false
	select {
	case sig := <-sigCh:
		slog.Info("received signal, shutting down", "signal", sig)
	case <-sup.RestartRequested():
		restartRequested = true
		slog.Warn("control-plane self-heal: graceful restart requested — draining then relaunching",
			"event.name", observability.EventProxyControlPlaneSelfRestart)
	}

	// Graceful shutdown: stop accepting new connections, drain active generation.
	if err := srv.Shutdown(30 * time.Second); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	sup.Shutdown(30 * time.Second)

	slog.Info("aikey-proxy stopped",
		"event.name", observability.EventProxyProcessStopped,
	)

	// Flush the async log writer before exiting so no records are lost.
	if logWriter != nil {
		logWriter.Flush(3 * time.Second)
		_ = logWriter.Close()
	}

	// Self-restart requests exit non-zero (EX_TEMPFAIL) AFTER the graceful drain
	// above, so the OS service manager relaunches a clean process. A plain signal
	// shutdown returns normally (exit 0) and is NOT relaunched.
	if restartRequested {
		os.Exit(75)
	}
}

// getVaultPassword reads the master password from AIKEY_MASTER_PASSWORD env var
// or prompts on stdin.
func getVaultPassword() (string, error) {
	if pw := os.Getenv("AIKEY_MASTER_PASSWORD"); pw != "" {
		return pw, nil
	}

	fmt.Fprint(os.Stderr, "Enter Master Password: ")
	// Stage 1.7 windows-compat: `int(syscall.Stdin)` is fragile on
	// Windows (Stdin is a HANDLE, not an fd) — `os.Stdin.Fd()` returns
	// the right uintptr on every platform that golang.org/x/term knows
	// about and avoids a panic on the Windows MSVC runtime.
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after password input
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}

	return string(pw), nil
}

// buildTransport returns the outbound http.Transport for upstream providers.
//
// Direct (no upstream_proxy): a Clone of http.DefaultTransport — with Proxy
// swapped to sysProxy (2026-07-08): the sysproxy.Watcher's per-request
// resolver, which preserves env-var behavior (HTTP_PROXY / HTTPS_PROXY /
// NO_PROXY) when the env is set and otherwise follows the LIVE OS system
// proxy, so a Clash port change / toggle applies without a daemon restart.
// HTTP/2 is preserved, with MaxIdleConnsPerHost raised. Go's default of 2
// idle conns per host means that
// under >2 concurrent requests to one provider, finished connections are
// dropped and the next request pays a fresh TCP+TLS handshake. HTTP/2
// multiplexing masks this against h2 upstreams, but HTTP/1.1 fallbacks and
// custom gateways hit it directly (2026-06-10 perf review P1).
//
// Proxied (upstream_proxy set): explicit HTTP/1.1 transport through proxyURL.
// MaxIdleConnsPerHost matters MOST here — ForceAttemptHTTP2=false means every
// in-flight request needs its own connection, so 2 idle slots per host caused
// a reconnect storm under any real concurrency.
//
// Supported proxy schemes: http, https, socks5.
// cloneDefaultTransport returns a clone of http.DefaultTransport, falling back
// to a fresh *http.Transport if the standard library ever changes the concrete
// type (the comma-ok keeps the type assertion safe).
func cloneDefaultTransport() *http.Transport {
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		return dt.Clone()
	}
	return &http.Transport{}
}

// probeUpstreamProxy dials `target` THROUGH a candidate egress spec and reports the
// outcome. Any HTTP response (even 401/404) proves the tunnel carries traffic; a
// transport error means the proxy could not reach out.
//
// It builds the transport STRICTLY (buildTransportStrict, not buildTransport): a
// test must exercise the spec it was handed. Under the live path's fallback an
// unparseable fragment silently became "dial through the machine's system proxy",
// and the button reported THAT proxy's timeout — users debugged a node that was
// never contacted while mihomo's real complaint sat in an unread WARN log
// (2026-07-24). Returning the build error puts that diagnostic in front of the
// person who can act on it.
func probeUpstreamProxy(
	rawURL string,
	sysProxy func(*http.Request) (*url.URL, error),
	target string,
) (status int, elapsedMs int64, err error) {
	probeT, probeCloser, buildErr := buildTransportStrict(rawURL, sysProxy)
	if buildErr != nil {
		return 0, 0, buildErr
	}
	if probeCloser != nil {
		defer probeCloser.Close() // throwaway group dialer: stop its health checks
	}
	client := &http.Client{Transport: probeT, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		return 0, 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return 0, elapsed, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, elapsed, nil
}

// upstreamProbeTarget is what the "Test connectivity" probe reaches for THROUGH a
// candidate egress proxy. Neutral IP-echo by default, sharing AIKEY_EGRESS_TEST_ECHO
// with egressSelfCheckEcho and the admin egress-test endpoint so all three probes
// behave identically across control-plane and node (and one env var points an
// air-gapped deployment at an internal echo).
//
// It used to be a hardcoded https://api.anthropic.com/. Two reasons that was wrong,
// and the second one is why it also made the button unreliable (2026-07-24):
//
//   - Same rule egressSelfCheckEcho already states: never probe a provider from the
//     user's freshly configured residential/datacenter exit. This probe is the WORST
//     place to violate it — it is user-triggered right after pasting a new node, so
//     the very first packet that exit sends to Anthropic is an unauthenticated GET.
//   - Providers fronted by Cloudflare silently BLACKHOLE datacenter IP ranges: no
//     RST, no response, just the 10s client timeout. Field case: a working GCP
//     Shadowsocks node tunneled fine but the probe reported "context deadline
//     exceeded", i.e. a healthy egress was rendered as broken and could not be saved.
//     A neutral echo answers from anywhere, so the probe measures the TUNNEL rather
//     than one provider's opinion of the exit IP.
//
// Probe semantics are unchanged: any HTTP response proves the tunnel carries traffic
// (no credential is ever sent). The echo additionally returns the exit IP, which is
// what a user configuring an egress actually wants to confirm.
func upstreamProbeTarget() string {
	if v := strings.TrimSpace(os.Getenv("AIKEY_EGRESS_TEST_ECHO")); v != "" {
		return v
	}
	return "https://api.ipify.org"
}

// proxyResolutionTarget is a PROVIDER URL used only to ASK http.Transport which
// proxy it would pick — egressState builds a Request from it and dials NOTHING
// (see its call site). It must stay a provider host precisely because the answer
// is proxy-rule dependent: a NO_PROXY listing ipify.org but not anthropic.com
// would make a neutral-echo resolution report "direct" while real provider
// traffic goes through the proxy, i.e. `aikey env` would display an egress that
// contradicts the hot path.
//
// This is deliberately NOT upstreamProbeTarget: that one leaves the machine and
// must be neutral; this one never leaves the process and must be representative.
const proxyResolutionTarget = "https://api.anthropic.com/"

// egressState assembles the layered egress decision for GET /admin/upstream-proxy
// (`aikey env`, 2026-07-08 逐级显示需求). The effective value is computed through
// watcher.ProxyFunc() — the SAME resolver the forwarding transport runs per
// request — so what the CLI displays can never diverge from what traffic does.
// Pulled out of main() so the decision logic sits behind a fence test
// (egress_integration_test.go).
func egressState(explicit string, watcher *sysproxy.Watcher) admin.EgressState {
	snap := watcher.Current()
	envExplicit, envInherited := sysproxy.EnvProxyVarsSplit()
	st := admin.EgressState{
		ExplicitURL:      explicit,
		MultiProtocol:    egress.MultiProtocolAvailable(),
		EnvAuthoritative: watcher.EnvExplicit(),
		EnvVars:          envExplicit,
		EnvInheritedVars: envInherited,
		SystemSupported:  watcher.Supported(),
		SystemHTTP:       snap.HTTP,
		SystemHTTPS:      snap.HTTPS,
		SystemSOCKS:      snap.SOCKS,
	}
	if explicit != "" {
		st.EffectiveSource, st.EffectiveURL = "explicit", explicit
		return st
	}
	// Resolve exactly like the transport would for a provider target.
	// Request object only — nothing is dialed.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, proxyResolutionTarget, http.NoBody)
	if err != nil {
		st.EffectiveSource = "direct"
		return st
	}
	u, perr := watcher.ProxyFunc()(req)
	switch {
	case perr != nil || u == nil:
		st.EffectiveSource = "direct"
	case st.EnvAuthoritative:
		st.EffectiveSource, st.EffectiveURL = "env", u.Redacted()
	case snap.ProxyFor("https") != "":
		st.EffectiveSource, st.EffectiveURL = "system", u.Redacted()
	default:
		// Layers 1-3 empty, ProxyFunc fell through to inherited shell env.
		st.EffectiveSource, st.EffectiveURL = "env_inherited", u.Redacted()
	}
	return st
}

// buildTransport builds the outbound transport for a node-level upstream spec.
// The returned io.Closer is non-nil ONLY for a multi-protocol group dialer
// (mihomo fallback/url-test/load-balance): it owns background health-check
// goroutines and MUST be Closed when this transport is swapped out (installTransport
// closes the previous one; the probe path closes its throwaway one). nil closer =
// nothing to clean up (direct / single-URL / non-group engine dialer).
//
// Dispatch (single source: pkg/egress):
//   - single URL (http/https/socks5, no comma, not a fragment) → http.ProxyURL,
//     the original path that works in EVERY build (net/http speaks all three).
//   - chain / config fragment → the pluggable egress engine, but only when the
//     enterprise multi-protocol engine is compiled (MultiProtocolAvailable). The
//     open-source build lacks it, so a chain/fragment degrades to WARN + direct:
//     "personal degrades to the original single-URL mode" (user decision
//     2026-07-16). Validation at SetUpstreamProxyFn rejects it upfront too; this
//     is the belt-and-suspenders fallback so a persisted-then-downgraded config
//     never hard-fails the daemon.
// egressSelfCheckDialTimeout bounds ONE account's egress dial in the self-check
// (§5.4). Per-account; a node's few accounts dial sequentially, so the CLI uses a
// generous overall client timeout.
const egressSelfCheckDialTimeout = 10 * time.Second

// egressSelfCheckEcho is the neutral IP-echo the self-check dials THROUGH each
// account's egress to learn its exit IP. Mirrors the master endpoint's env +
// default (one behavior across control-plane and node). Neutral on purpose —
// NEVER default to claude.ai, so an on-demand self-check doesn't probe Claude
// from the residential exit on a cadence (§5.4 #2). A private deployment with no
// external internet points AIKEY_EGRESS_TEST_ECHO at an internal echo.
func egressSelfCheckEcho() string {
	if v := strings.TrimSpace(os.Getenv("AIKEY_EGRESS_TEST_ECHO")); v != "" {
		return v
	}
	return "https://api.ipify.org"
}

// buildTransport builds the egress transport for the LIVE request path, falling
// back to env/system proxy whenever the spec can't be honored. The fallback is
// deliberate there: a request in flight should degrade rather than fail hard.
//
// It must NOT be used to TEST a candidate spec — see buildTransportStrict.
func buildTransport(proxyURL string, sysProxy func(*http.Request) (*url.URL, error)) (*http.Transport, io.Closer) {
	t, closer, err := buildTransportStrict(proxyURL, sysProxy)
	if err != nil {
		// Same WARN text the hot path has always emitted, so log-based alerting
		// and the operator runbooks keep matching.
		slog.Warn("upstream_proxy engine spec failed to build, falling back to env/system proxy", "error", err)
		return directTransport(sysProxy), nil
	}
	return t, closer
}

// directTransport is the "no egress spec" transport: env/system proxy only.
func directTransport(sysProxy func(*http.Request) (*url.URL, error)) *http.Transport {
	t := cloneDefaultTransport()
	if sysProxy != nil {
		t.Proxy = sysProxy
	}
	t.MaxIdleConnsPerHost = transportPerHostIdle
	return t
}

// transportPerHostIdle — all providers resolve to a handful of hosts
// (api.anthropic.com etc.), so a generous per-host idle pool is bounded in
// practice by MaxIdleConns.
const transportPerHostIdle = 100

// buildTransportStrict is buildTransport WITHOUT the fallback: an unusable spec
// is returned as an error instead of silently degrading to env/system proxy.
//
// WHY BOTH EXIST (2026-07-24). The fallback is right for the live path and wrong
// for the "Test connectivity" button, and the difference is user-visible:
//
//	A malformed mihomo fragment (a YAML-vs-JS syntax slip is the common case)
//	made BuildEgressTransport fail, the probe fell back to the machine's system
//	proxy, and then reported THAT proxy's timeout. The user reads
//	`Get "https://api.ipify.org": context deadline exceeded` and debugs their
//	node — while the node was never dialed and the real fault, sitting in a WARN
//	log they never see, was "expected a proxies/proxy-groups fragment".
//
// A test must exercise exactly what it was given. 失败要显眼，不要沉默.
func buildTransportStrict(proxyURL string, sysProxy func(*http.Request) (*url.URL, error)) (*http.Transport, io.Closer, error) {
	const perHost = transportPerHostIdle

	direct := func() *http.Transport { return directTransport(sysProxy) }

	spec := strings.TrimSpace(proxyURL)
	if spec == "" {
		return direct(), nil, nil
	}

	if egress.IsEngineSpec(spec) {
		// Only multi-protocol FRAGMENTS (ss/vmess/trojan/… or a proxy-group) need the
		// enterprise mihomo engine. A socks5 CHAIN is handled by the built-in,
		// GPL-free engine on EVERY build (P8 line 106/225 "socks5 链 → 全构建行为一致";
		// symmetric with per-account egress). So gate ONLY fragments; let chains
		// build. requirements/2026-07-17-egress-spec-capability-by-edition.md.
		if egress.IsFragment(spec) && !egress.MultiProtocolAvailable() {
			return nil, nil, fmt.Errorf("multi-protocol egress (ss/vmess/trojan/…) needs the offline enterprise package; this build supports a single URL or a socks5 chain")
		}
		// The engine transport (dialerToTransport) already applies the shared
		// NO_PROXY/loopback bypass — internal targets dial direct, the SAME code
		// path + single source (sysproxy.NoProxyBypass) per-account egress uses. So
		// no extra wrapping here.
		t, closer, err := proxy.BuildEgressTransport(spec)
		if err != nil {
			return nil, nil, err
		}
		slog.Info("upstream proxy configured (egress engine)")
		return t, closer, nil
	}

	parsed, err := url.Parse(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid upstream proxy URL %q: %w", proxyURL, err)
	}
	// Internal-destination bypass (option ②, 2026-07-16): even with an explicit
	// single-URL upstream, loopback + NO_PROXY targets go DIRECT (a self-hosted /
	// intranet provider isn't forced through the proxy). Uses the SAME predicate
	// (sysproxy.NoProxyBypass, single source) the engine path applies via
	// dialerToTransport — replaces http.ProxyURL, which proxies EVERYTHING.
	bypass := sysproxy.NoProxyBypass()
	t := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			if bypass(req.URL.Hostname()) {
				return nil, nil
			}
			return parsed, nil
		},
		ForceAttemptHTTP2:   false, // keep HTTP/1.1 for widest proxy compat
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: perHost,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	slog.Info("upstream proxy configured", "url", proxyURL)
	return t, nil, nil
}

// validateNodeUpstream gates a candidate /user/settings upstream spec at write
// time (SetUpstreamProxyFn) so a bad value is rejected there rather than silently
// going direct at request time.
//
// SINGLE SOURCE OF TRUTH (收敛 2026-07-17): delegates to the low-layer
// config.ValidateUpstreamProxyURL so this runtime gate and the admin PUT handler
// (internal/admin/upstream_proxy.go) accept EXACTLY the same forms — no drift.
// Semantics per requirements/2026-07-17-egress-spec-capability-by-edition.md:
// single URL + socks5 chain accepted on ALL builds (built-in engine); only a
// multi-protocol FRAGMENT requires the enterprise mihomo engine. (Previously this
// duplicated the dispatch and wrongly rejected socks5 chains on OSS.)
func validateNodeUpstream(spec string) error {
	return config.ValidateUpstreamProxyURL(spec)
}

// runWALVacuum implements `aikey-proxy wal vacuum [--config path]`: loads the
// same config the daemon uses, runs ONE retention sweep (WAL archive/expiry +
// usage_events prune — see internal/events/retention.go), prints a summary,
// and exits. Exit codes: 0 = swept clean, 1 = config/setup failure, 2 = sweep
// finished but some items failed (partial success — details on stderr).
func runWALVacuum(args []string) int {
	fs := flag.NewFlagSet("wal vacuum", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to config file (default: search cwd then ~/.aikey/)")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	resolvedPath, err := resolveConfigPath(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wal vacuum: config not found:", err)
		return 1
	}
	cfg, err := config.Load(resolvedPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wal vacuum: failed to load config:", err)
		return 1
	}
	if cfg.Events.WALDir == "" {
		fmt.Fprintln(os.Stderr, "wal vacuum: events.wal_dir is not configured — nothing to sweep")
		return 1
	}
	if cfg.Events.WALRetentionDays <= 0 {
		fmt.Fprintln(os.Stderr, "wal vacuum: retention disabled (events.wal_retention_days <= 0)")
		return 1
	}

	var store *events.Store
	if cfg.Events.DBPath != "" {
		if s, serr := events.OpenStore(cfg.Events.DBPath); serr != nil {
			// WAL-only sweep still proceeds; surface the skip loudly.
			fmt.Fprintln(os.Stderr, "wal vacuum: events db unavailable, skipping table prune:", serr)
		} else {
			store = s
			defer store.Close()
		}
	}

	res := events.RunRetentionSweep(events.RetentionConfig{
		WALDir:        cfg.Events.WALDir,
		RetentionDays: cfg.Events.WALRetentionDays,
		ArchiveDays:   cfg.Events.WALArchiveDays,
	}, store, time.Now())

	fmt.Printf("wal vacuum: archived=%d archive_deleted=%d events_pruned=%d (retention=%dd archive=%dd, dir=%s)\n",
		res.WALArchived, res.ArchiveDeleted, res.EventsPruned,
		cfg.Events.WALRetentionDays, cfg.Events.WALArchiveDays, cfg.Events.WALDir)
	if len(res.Errors) > 0 {
		for _, e := range res.Errors {
			fmt.Fprintln(os.Stderr, "wal vacuum: item failed:", e)
		}
		return 2
	}
	return 0
}

// parseLogLevel converts a config string to a slog.Level.
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// setupTextLogging configures the global logger to write text to stderr only
// (fallback when the JSONL writer cannot be initialized).
func setupTextLogging(level slog.Level) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})))
}

// brokerAdapter adapts broker.EmbeddedBroker to proxy.OAuthBroker interface.
// Needed because broker uses typed AccountStatus while proxy uses plain string.
type brokerAdapter struct {
	inner    *broker.EmbeddedBroker
	accounts *vault.VaultAccountStore // for ExternalID lookup
}

func (a *brokerAdapter) EnsureFresh(ctx context.Context, accountID string) error {
	return a.inner.EnsureFresh(ctx, accountID)
}

func (a *brokerAdapter) ResolveCredential(ctx context.Context, accountID string) (*proxy.OAuthCredential, error) {
	cred, err := a.inner.ResolveCredential(ctx, accountID)
	if err != nil {
		return nil, err
	}
	// Look up ExternalID (account UUID from OAuth provider) for persona injection.
	// Why: Claude OAuth requires metadata.user_id with the real account UUID.
	// Without it, Anthropic returns 429 business rejection.
	var externalID string
	if a.accounts != nil {
		if acct, err := a.accounts.GetByID(ctx, accountID); err == nil && acct != nil {
			externalID = acct.ExternalID
		}
	}
	return &proxy.OAuthCredential{
		AccessToken: cred.AccessToken,
		Provider:    cred.Provider,
		AccountID:   cred.AccountID,
		ExternalID:  externalID,
		ExpiresAt:   cred.ExpiresAt,
		Identity:    cred.Identity,
	}, nil
}

func (a *brokerAdapter) GetAccountStatus(ctx context.Context, accountID string) (string, error) {
	status, err := a.inner.GetAccountStatus(ctx, accountID)
	return string(status), err
}
