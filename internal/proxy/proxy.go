package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/apppipe"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/probepipe"
	"github.com/AiKeyLabs/aikey-proxy/internal/quota"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
)

// VaultGetter retrieves decrypted secrets by alias.
type VaultGetter interface {
	GetSecret(alias string) (string, error)
}

// groupKeyProvider exposes the vault's derived key so the oauth-group resolver
// (N8) can decrypt per-account group material at request time. *vault.Reader
// implements it; an injected mock that doesn't disables group routing (safe).
type groupKeyProvider interface {
	DerivedKey() []byte
}

// ActiveKeyReader extends VaultGetter with active-key lookups used by
// path-prefix routing (/anthropic/v1/..., /openai/v1/...).
// Implemented by *vault.Reader when the vault supports managed and personal keys.
type ActiveKeyReader interface {
	VaultGetter
	GetActiveKeyConfig() (*vault.ActiveKeyConfig, error)
	GetActiveTeamKeyByProvider(providerCode, protocolType string) (*vault.ManagedKey, error)
	GetPersonalKeyByAlias(alias string) (plaintext, providerCode, baseURL string, err error)
	// v1.0.2: provider-level binding from user_profile_provider_bindings.
	GetProviderBinding(providerCode string) (*vault.ProviderBinding, error)
	// v1.0.2: resolve team key by exact virtual_key_id (no local_state filter).
	// P1e (D-11): targetProviderCode selects the matching binding (one row per
	// binding, ciphertext per row) — empty falls back to the primary binding.
	GetTeamKeyByID(virtualKeyID, targetProviderCode, protocolType string) (*vault.ManagedKey, error)
}

// OAuthBroker is the minimal interface the proxy data-plane needs from the broker.
// Defined here (not imported from broker module) to keep proxy decoupled from
// broker implementation. The broker.EmbeddedBroker satisfies this interface.
type OAuthBroker interface {
	// EnsureFresh ensures the token for accountID is valid (refreshes if needed).
	EnsureFresh(ctx context.Context, accountID string) error
	// ResolveCredential returns the decrypted access_token for request injection.
	ResolveCredential(ctx context.Context, accountID string) (*OAuthCredential, error)
	// GetAccountStatus returns the lifecycle status (active/reauth_required/...).
	GetAccountStatus(ctx context.Context, accountID string) (string, error)
}

// OAuthCredential is the resolved OAuth credential for injection.
// Mirrors broker.ResolvedCredential but defined locally to avoid import dependency.
type OAuthCredential struct {
	AccessToken string
	Provider    string
	AccountID   string
	ExternalID  string // Account UUID from OAuth provider (e.g. Claude account.uuid)
	Identity    string // Email or display name (for logging only, never sent upstream)
	ExpiresAt   int64
}

// Proxy is the core reverse proxy that handles virtual key resolution
// and request forwarding.
type Proxy struct {
	// transport is the outbound RoundTripper for AI provider forwarding, held in an
	// atomic.Pointer so the egress upstream-proxy URL can be HOT-SWAPPED at runtime
	// (Settings → Upstream proxy, 2026-06-30) without racing the per-request read in
	// forward_and_resolve. Nil box / nil rt → http.DefaultTransport (honors
	// HTTP_PROXY env). Read via currentTransport, written via SetTransport.
	transport atomic.Pointer[transportBox]
	// accountEgressTransports caches one built *http.Transport per egress chain
	// spec (the whole egress_proxy_url string) so the socks5 dialer chain is built
	// once, not per request. The account chain is SELF-CONTAINED (§11.7, P7) — it
	// does not consult the node upstream_proxy — so the spec string is the whole
	// cache key. Only populated for accounts that configure an egress proxy; the
	// default hot path never touches it.
	accountEgressTransports sync.Map // map[string]accountEgressEntry
	// oauthEgressOverride is the OPT-IN emergency escape hatch (2026-07-19): when
	// true, an OAuth pool account's per-account egress (②) is IGNORED and its
	// traffic falls back to the NODE-level chain (currentTransport: /user/settings
	// upstream > env > system > direct), the SAME transport non-egress traffic
	// uses. Default false → coexist behavior is byte-unchanged (the 2026-07-18
	// invariant): a per-account egress applies unconditionally. This re-introduces
	// a GATED form of the removed nodeExplicitEgress override, but driven by an
	// EXPLICIT member toggle (Settings → Upstream proxy), never auto-derived —
	// so it stays inert until a member deliberately flips it to self-rescue when
	// the admin's egress line is down. Node-local (this proxy only): flipping it
	// changes only THIS machine's outbound, never master or other members. The
	// cost (surfaced in the UI): while on, all OAuth accounts share this node's
	// exit IP → single-IP-per-account anti-ban is temporarily off for this node.
	oauthEgressOverride atomic.Bool
	activeReader        ActiveKeyReader       // non-nil when vault implements ActiveKeyReader
	appVault            apppipe.VaultReader   // non-nil when vault implements the App pipeline read surface (Phase 4)
	probeVault          probepipe.VaultReader // non-nil when vault implements the Probe pipeline read surface (mode C, SPEC 2026-05-23)
	broker              OAuthBroker           // OAuth credential provider (nil = OAuth not available)
	vault               VaultGetter
	// groupKey exposes the vault derived key for oauth-group material decryption
	// (N8). nil when the injected vault doesn't implement DerivedKey() (tests) →
	// group routing degrades to GROUP_KEY_UNAVAILABLE rather than panicking.
	groupKey groupKeyProvider
	// poolCooldown holds per-account reactive fallback state (N8c): an account
	// whose upstream failed (401 / exhaustion-429) is skipped by the resolver
	// until its cooldown lapses. Always non-nil (set in New); the request path
	// only consults it for group routes.
	poolCooldown *poolCooldownStore
	// bindingCooldown is the BINDING axis's equivalent (P0a upstream fallback,
	// task 2.13). 🔴 A separate store, never a shared map: binding ids and
	// account ids are unrelated id spaces, so one collision would make two
	// unrelated decisions contaminate each other with a symptom — an upstream
	// mysteriously skipped — that points nowhere near the cause. Always non-nil.
	bindingCooldown *bindingCooldownStore
	// fallbackSwitches counts actual switches to a next candidate, for /metrics
	// and alerting (task 3.6). Counted at the moment a switch is DECIDED, so it
	// stays comparable with the `proxy.route.fallback` event stream.
	fallbackSwitches atomic.Int64
	// chainActivity decides when to come back to the primary upstream (task
	// 2.19). Process-local by design (I23): derived numbers may travel, live
	// state may not.
	chainActivity *chainActivityStore
	// pathHealth owns transient outbound-path reachability independently of
	// account health. Supervisor replaces the per-Proxy default with one shared
	// instance so network recovery state survives generation reloads.
	pathHealth *ProviderPathHealthManager
	// signalReporter ships parsed unified-* utilization to master (I5, best-effort,
	// off the forward hot path). nil = feature off. Set via EnableSignalReporting.
	signalReporter *signalReporter
	// routingOverrides is the allocation engine's seat→account routing-override
	// cache (I-side §6.5). Shared across generations, polled by the supervisor; the
	// group-route hot path reads it to redirect a seat off an unhealthy default.
	// nil-safe → empty/unset means every request uses the local seatassign pick.
	// Set via SetRoutingOverrides. See routing_override.go.
	routingOverrides *RoutingOverrideCache
	// poolObservedResets holds the latest upstream window-reset epoch observed per
	// pool account (Path Z, 通道3 §14). The N7c pull piggybacks it to master so it
	// re-rolls window_max_util_pct per window. Always non-nil; only written on
	// group-route responses.
	poolObservedResets *poolResetStore
	// consoleURL is Config.ConsoleURL — the co-installed local console base used
	// to assemble the member-login URL in OAUTH_GROUP_MEMBER_LOGIN_REQUIRED
	// responses (20260703 update). "" ⇒ URL-less fallback wording. Set once via
	// SetConsoleURL before serving; not hot-swapped.
	consoleURL string
	// groupLoginState is the bypass ~/.aikey/run/group-login-required.json store
	// consumed by `aikey statusline`. Always non-nil (set in New); written on
	// login-required 401s, cleared on the next successful group resolve.
	groupLoginState *groupLoginStateStore
	// routingRailHealth probes the routing_override SyncRail state (SyncRail
	// §5.4, 2026-07-03): stale/offline → the login-required 401 wording says
	// "routing sync unreachable" instead of a possibly-misdirected sign-in
	// prompt (the incident shape: local pick ≠ engine assignment). nil = ok.
	routingRailHealth func() (state string, failingSeconds int64)
	// filterHook is the P4 filter dispatcher — a generic apphook.Hook
	// (ai-compliance-detector / DLP / etc.) that inspects the inbound
	// request body before forwarding. Nil = no filter (the common default
	// for traffic without a filter app installed); when nil, serveRoute's
	// filter injection is a no-op (zero hot-path cost).
	//
	// CRITICAL: proxy MUST NOT know what business the hook does (方案 §6
	// 不变量 #16). It calls Detect, gets a generic Action verdict, applies it.
	// Set during supervisor.buildGeneration when a filter app is registered
	// AND its child binary spawned successfully.
	filterHook apphook.Hook
	// filterCache memoizes per-piece scan verdicts so the full-scan path doesn't
	// re-scan unchanged history every turn (设计 20260616-…-内容哈希缓存 §4). nil =
	// cache OFF (dispatcher skips the content-hash entirely → stateless full scan).
	// Lives behind the hook==nil gate, so compliance OFF pays nothing (INV-6).
	filterCache MaskCache
	proxyCtx    context.Context   // canceled when the proxy shuts down
	reporter    *events.Reporter  // usage reporting to collector-service (nil = disabled)
	wal         *events.WALWriter // local JSONL WAL (shared with reporter when both set; sole writer when reporter is nil)
	// quota is the Phase 2 enterprise token-quota gate (Stage 3). nil-safe +
	// flag-gated: when nil or disabled it is a pure no-op, so the request path is
	// never blocked by quota machinery — only by an actual confirmed over-limit.
	// Wired via SetQuotaEnforcer from the supervisor's snapshot+counter.
	quota *quota.Enforcer
	// appHealthCache records the most recent app-pipeline call per slug,
	// in process memory only (no persistence). Powers the Web "Connected
	// Apps" list Health column via the admin /admin/apps/health endpoint.
	// Always non-nil after New(); the cache itself is safe for concurrent
	// readers/writers (sync.RWMutex internal). See
	// apppipe/health.go for the rationale on why this isn't a DWD-side
	// projection.
	appHealthCache *apppipe.HealthCache
	collector      *events.Collector
	seqAlloc       *events.SeqAllocator
	providers      *provider.Registry
	registry       *vkeys.Registry
	// observerRegistry holds the Phase 4 M2 plugin observer fan-out.
	// Nil when no first-party observer is built (the common default for
	// rc.5 ship traffic without degrade-detector installed). When set:
	//   - handleAppPipeline calls NotifyStart on app pipeline entry,
	//     NotifyEnd on exit (always, success or error).
	//   - streamDrainer calls NotifySSEEvent per upstream SSE frame
	//     BEFORE any ResponseTransform (the doc-anchor invariant from
	//     plugin-架构设计.md §5.1 + observer/registry.go package doc).
	// Tier 1 / Tier 2 routes never reach the Notify* hooks (they only
	// fire inside the App pipeline branch), so the field being non-nil
	// has zero cost on the legacy proxy path.
	observerRegistry *observer.Registry
	// translatorRegistry holds the protocol-translator pair registry the
	// App pipeline consults when an inbound URL protocol differs from
	// the binding's upstream protocol (Phase 2). Defaults to
	// translator.DefaultRegistry() in New() — pair packages register
	// themselves via blank-import side effect in cmd/aikey-proxy/main.go.
	// Tests can swap via SetTranslatorRegistry to isolate from globals.
	//
	// Tier 1 / Tier 2 routes never read this field — it is referenced
	// only inside handleAppPipeline, so the field's existence has no
	// effect on the legacy proxy path.
	translatorRegistry *translator.Registry
	proxyConfigVersion string // generation ID or config revision
	loggedInAccountID  string // current platform_account.account_id (for personal key events)
	clientVersion      string // build version for audit metadata in usage events
	// Delivery integrity (2026-05-30). sourceID is the vault's stable source
	// identity stamped on every reported event; seqAlloc hands out the
	// per-source never-reused sequence. Both nil/empty until SetDeliveryIntegrity
	// wires them (offline-only or pre-seqalloc builds report v1-shaped events).
	sourceID        string
	proxyInstanceID string
	requests        atomic.Int64
	errors          atomic.Int64
	// Model-mapping runtime health (task 7.9 / 3.5 four-surface visibility): the
	// read-only /v1/diagnostics/pipeline endpoint reads these to answer "was a
	// mapping configured but not taking effect?". `mapPassthrough`/`mapRejected`
	// are the "configured-but-missing" signal (a provider HAS a model_map yet the
	// client's request didn't match a rule); `mapApplied` is the healthy path.
	mapApplied     atomic.Int64
	mapRejected    atomic.Int64
	mapPassthrough atomic.Int64
	// lastMapApplyNano / lastMapMissNano make the mapping-health verdict
	// RECOVERABLE rather than a monotonic latch (health-signal-surface: assert
	// transition, not terminal). mappingHealth reports `degraded` only when a
	// passthrough-miss is MORE RECENT than the last successful apply — the
	// CURRENT state — so a later successful apply flips it back to `ok`. A
	// `reject` (unmatched=reject policy WORKED) deliberately does NOT stamp
	// lastMapMissNano, so a working reject policy never trips degraded.
	lastMapApplyNano atomic.Int64
	lastMapMissNano  atomic.Int64
	lastMapMiss      atomic.Pointer[mapMissRecord]
	loadedControlSeq int64 // vault change_seq loaded at generation build time
	// Configurable slow-request thresholds (milliseconds).
	SlowRequestMs     int64
	VerySlowRequestMs int64
	// UpstreamTimeout caps how long a detached upstream call may run after
	// the client disconnects. Default: defaultUpstreamTimeout (10 min).
	UpstreamTimeout time.Duration
	// filterStub501Active is set at proxy generation build time when the
	// vault contains any app_records row with filter_stages != NULL BUT no
	// working filter dispatcher could be constructed (e.g. detector binary
	// missing). While active, ALL data-plane traffic returns 501
	// FILTER_NOT_IMPLEMENTED — SPEC §1.5.7 / §6.6 anti-example F mandate that
	// an unimplemented/broken filter chain must NOT silently let traffic
	// through (would be "pseudo-security": looks configured, actually inert).
	// Set during supervisor.buildGeneration; not flipped at runtime.
	//
	// Mutually exclusive with filterHook: supervisor sets EITHER a working
	// filterHook (dispatcher present) OR filterStub501Active (declared but
	// no working dispatcher), never both.
	filterStub501Active bool
	// filterIncremental, when true, makes the inbound filter scan ONLY the
	// latest user turn (the new content) instead of re-scanning system + the
	// whole conversation history every request. WHY: clients like OpenClaw
	// resend the full context (10-28KB) each turn; re-scanning it all is the
	// dominant latency (12KB varied CJK ≈ 81ms on a 2-core box → straddles the
	// 80ms detector budget → intermittent fail-open). Scanning only the new user
	// message cuts that to <5ms. Premise (caller-accepted): sensitive content
	// only enters via the current user input. Safety: extractLatestUserContent
	// returns ok=false on any unexpected shape → caller falls back to a full
	// scan, never silently under-scanning. Default false (full scan); the
	// form-② lobster install opts in (AIKEY_PROXY_FILTER_INCREMENTAL_SCAN=1).
	// RCA: 2026-06-13 form-② filter-degrade (NER/CRF size-linear cost).
	//
	// DEPRECATED 2026-06-16 (history-leak fix): the "latest-user-turn-only" premise
	// is false in multi-turn conversations — the user's earlier sensitive message
	// stays in HISTORY and is resent verbatim every turn, which incremental never
	// re-scans → forwarded unmasked. applyInboundFilter no longer reads this field;
	// it always full-scans (+ optional content-hash cache below). Field/setter/env
	// retained only until the systemd units drop AIKEY_PROXY_FILTER_INCREMENTAL_SCAN.
	filterIncremental bool
}

// SetTransport sets a custom RoundTripper for outbound requests to AI providers.
// Must be called before serving requests. A nil value restores the default
// behavior (http.DefaultTransport, which honors HTTP_PROXY / HTTPS_PROXY env vars).
func (p *Proxy) SetTransport(t http.RoundTripper) {
	p.transport.Store(&transportBox{rt: t})
	if t != nil {
		slog.Info("proxy: custom transport set")
	}
}

// transportBox boxes the RoundTripper so it can live in an atomic.Pointer (atomics
// can't hold an interface value directly). A nil rt means "use the default".
type transportBox struct{ rt http.RoundTripper }

// currentTransport returns the live RoundTripper (nil → caller falls back to the
// default). Lock-free atomic read: safe on the hot path concurrently with a
// SetTransport hot-swap.
func (p *Proxy) currentTransport() http.RoundTripper {
	if b := p.transport.Load(); b != nil {
		return b.rt
	}
	return nil
}

// SetOAuthEgressOverride flips the opt-in escape hatch (2026-07-19). true → an
// OAuth account's per-account egress is bypassed and its traffic uses the node
// chain; false (default) → per-account egress applies unconditionally (coexist).
// Hot-applied: the next request reads the flag on the hot path. Node-local.
func (p *Proxy) SetOAuthEgressOverride(on bool) {
	p.oauthEgressOverride.Store(on)
	slog.Info("proxy: oauth per-account egress override set", "event.name", "proxy.egress.oauth_override_set", "enabled", on)
}

// OAuthEgressOverride reports the current escape-hatch state (for GET /admin and
// the hot-path gate).
func (p *Proxy) OAuthEgressOverride() bool { return p.oauthEgressOverride.Load() }

// New creates a new Proxy. ctx is the proxy lifecycle context; canceling it
// stops all detached upstream calls (called on proxy shutdown).
// If v also implements ActiveKeyReader, path-prefix routing is enabled automatically.
func New(v VaultGetter, reg *vkeys.Registry, prov *provider.Registry, coll *events.Collector, ctx context.Context) *Proxy {
	p := &Proxy{
		vault:              v,
		registry:           reg,
		providers:          prov,
		collector:          coll,
		proxyCtx:           ctx,
		translatorRegistry: translator.DefaultRegistry(),
		SlowRequestMs:      2000,
		VerySlowRequestMs:  10000,
		UpstreamTimeout:    defaultUpstreamTimeout,
		appHealthCache:     apppipe.NewHealthCache(),
		poolCooldown:       newPoolCooldownStore(),
		bindingCooldown:    newBindingCooldownStore(),
		chainActivity:      newChainActivityStore(),
		pathHealth:         NewProviderPathHealthManager(),
		poolObservedResets: newPoolResetStore(),
		groupLoginState:    newGroupLoginStateStore(),
	}
	if ar, ok := v.(ActiveKeyReader); ok {
		p.activeReader = ar
	}
	// AKL-205: if the vault also implements the App-pipeline read surface
	// (GetProviderBindingWithScope + GetAppRecord, added by AKL-102), wire
	// it so /apps/<slug>/v1/... requests can resolve. *vault.Reader
	// satisfies both interfaces in production; tests that only need the
	// App pipeline can inject via SetAppVault below.
	if av, ok := v.(apppipe.VaultReader); ok {
		p.appVault = av
	}
	// Probe pipeline (mode C) needs GetAliasCredential — auto-wire when
	// the vault implements it. *vault.Reader satisfies probepipe.VaultReader
	// in production; tests can swap via SetProbeVault.
	if pv, ok := v.(probepipe.VaultReader); ok {
		p.probeVault = pv
	}
	// Oauth-group routing (N8) decrypts per-account group material at request
	// time with the vault derived key. *vault.Reader exposes DerivedKey(); a
	// mock that doesn't simply leaves p.groupKey nil → group routing degrades
	// (GROUP_KEY_UNAVAILABLE) instead of panicking. Tests can swap via
	// SetGroupKeyProvider.
	if kp, ok := v.(groupKeyProvider); ok {
		p.groupKey = kp
	}
	// Reclaim idle per-account egress transports (+ their group health-check
	// goroutines) until shutdown. Cheap no-op for proxies without egress configured.
	p.startEgressSweeper()
	return p
}

// SetBroker injects the OAuth broker for credential resolution.
// Must be called before the proxy handles any OAuth-credential requests.
func (p *Proxy) SetBroker(b OAuthBroker) {
	p.broker = b
}

// SetProviderPathHealthManager installs the Supervisor-scoped transient path
// breaker. A nil manager restores an isolated empty manager instead of disabling
// recovery guards.
func (p *Proxy) SetProviderPathHealthManager(m *ProviderPathHealthManager) {
	if m == nil {
		m = NewProviderPathHealthManager()
	}
	p.pathHealth = m
}

// SetAppVault injects a vault reader for App pipeline requests.
// Mirrors SetBroker — provided for tests that build a Proxy with a
// VaultGetter mock and need to expose the App-pipeline read surface
// without satisfying the full ActiveKeyReader interface. In production
// New(...) auto-wires this when the VaultGetter argument also implements
// apppipe.VaultReader.
func (p *Proxy) SetAppVault(av apppipe.VaultReader) {
	p.appVault = av
}

// SetProbeVault injects a vault reader for Probe pipeline requests (mode C).
// Mirrors SetAppVault — auto-wired by New(...) when the VaultGetter argument
// also implements probepipe.VaultReader.
func (p *Proxy) SetProbeVault(pv probepipe.VaultReader) {
	p.probeVault = pv
}

// SetGroupKeyProvider injects the vault derived-key accessor for oauth-group
// material decryption (N8). Mirrors SetProbeVault — auto-wired by New(...) when
// the VaultGetter argument implements DerivedKey(); tests that exercise group
// routing inject it explicitly.
func (p *Proxy) SetGroupKeyProvider(kp groupKeyProvider) {
	p.groupKey = kp
}

// SetQuotaEnforcer injects the Phase 2 token-quota gate (Stage 3). Wired by the
// supervisor from the per-process snapshot+counter. Safe to leave unset — a nil
// enforcer is a no-op (no enforcement), which is the correct behavior for
// editions/tests that don't run quota.
func (p *Proxy) SetQuotaEnforcer(e *quota.Enforcer) {
	p.quota = e
}

// SetConsoleURL injects Config.ConsoleURL (20260703 update) — the co-installed
// local console base used to assemble the member-login URL in group
// login-required responses. Safe to leave unset: "" degrades to URL-less
// wording (cluster nodes / server-side proxies have no local console).
func (p *Proxy) SetConsoleURL(u string) {
	p.consoleURL = u
}

// SetRoutingRailHealth injects the supervisor's routing_override SyncRail
// health probe (SyncRail §5.4, 2026-07-03). respondLoginRequired consults it:
// when the assignment rail is stale/offline the local ranked pick may
// contradict the engine (the 2026-07-03 incident shape), so the 401 must say
// "routing sync unreachable" instead of directing the member to sign into a
// possibly-wrong account. nil (tests / framework off) → treated as healthy.
func (p *Proxy) SetRoutingRailHealth(fn func() (state string, failingSeconds int64)) {
	p.routingRailHealth = fn
}

// AppHealthSnapshot returns the in-process record of the most recent
// app-pipeline call per slug. Used by the admin /admin/apps/health endpoint
// (wired through admin.Handler.AppHealthFn) to populate the Web "Connected
// Apps" list's Health column.
//
// Returns an empty slice (not nil) when no calls have been observed —
// including immediately after proxy restart, which is the expected steady
// state until traffic resumes. See apppipe/health.go for why we don't
// persist this surface.
func (p *Proxy) AppHealthSnapshot() []apppipe.AppHealth {
	if p.appHealthCache == nil {
		return []apppipe.AppHealth{}
	}
	return p.appHealthCache.Snapshot()
}

// PoolCooldownSnapshot returns the oauth-group accounts currently in reactive
// cooldown (account_id → seconds remaining) for the admin /status health surface
// (N9 组路由健康). nil when nothing is cooling. The cmd layer wraps this into the
// admin DTO so the operator monitoring the first pool batch can see which
// accounts are being routed around.
func (p *Proxy) PoolCooldownSnapshot() map[string]int {
	return p.poolCooldown.snapshot()
}

// ProviderPathHealthSnapshot returns only unhealthy OAuth-group paths. It is
// non-secret and safe for the existing /status health surface.
func (p *Proxy) ProviderPathHealthSnapshot() []ProviderPathHealth {
	return p.pathHealth.Snapshot()
}

// CooldownSkipSet returns the EXACT set of accounts the hot-path group resolver skips
// right now (poolCooldown.skipSet) so the supervisor's is_current_routed stamp can be
// computed with the SAME cooldown view the forward path uses — closing the display↔actual
// gap for cooling-driven switches (2026-07-01). Same function as group_serve.go's resolver
// call, so the two can't diverge in which accounts are considered cooled.
func (p *Proxy) CooldownSkipSet() map[string]bool {
	return p.poolCooldown.skipSet()
}

// CooldownRouteStateSnapshot returns display metadata for the same active
// whole-account cooldown set CooldownSkipSet exposes to routing. It is a
// detached snapshot; callers may safely project it into the local vault.
func (p *Proxy) CooldownRouteStateSnapshot() map[string]PoolAccountRouteState {
	return p.poolCooldown.routeStateSnapshot()
}

// AuthFailureRouteSnapshot returns member-scoped hard-revocation state. It is
// separate from whole-account cooldowns because one Cluster Worker can serve
// several seats whose tokens for the same pool account differ.
func (p *Proxy) AuthFailureRouteSnapshot() []PoolAuthFailureState {
	return p.poolCooldown.authFailureSnapshot()
}

// SetPoolCooldownChangeHook installs a non-blocking wake-up hook for changes to
// the whole-account cooldown set. The supervisor uses it to refresh the
// display-only is_current_routed projection; routing itself reads poolCooldown
// directly and never depends on this hook. Tier-only cooldowns do not fire it
// because a single current_routed flag cannot represent per-model choices.
func (p *Proxy) SetPoolCooldownChangeHook(hook func()) {
	if p == nil || p.poolCooldown == nil {
		return
	}
	p.poolCooldown.setAccountSetChangedHook(hook)
}

// ObservedResetsSnapshot returns the latest upstream window-reset epoch observed
// per pool account (account_id → epoch). The supervisor's N7c pull piggybacks
// it to master (Path Z) so master re-rolls window_max_util_pct per window. nil
// when nothing observed yet.
func (p *Proxy) ObservedResetsSnapshot() map[string]ObservedWindowResets {
	return p.poolObservedResets.snapshot()
}

// recordAppHealth is the proxy-internal hook called from handleAppPipeline
// after each request completes (success OR error path). Centralized so the
// "what counts as a health observation" decision lives in one place: any
// app-pipeline request whose AppSlug is known at finalization time updates
// the cache, regardless of where in the pipeline it terminated (400 from
// the BASE_URL_MISCONFIGURED guard, 401 from authn, 502 from upstream, 200
// from a clean stream — all record).
//
// errorType is a free-form category string used by the Web UI for tooltip
// detail. Empty for 2xx; otherwise either the upstream envelope's `type`
// (forensic-logged path) or a proxy-internal category ("base_url_misconfigured",
// "binding_not_found", etc.).
func (p *Proxy) recordAppHealth(slug string, statusCode int, errorType string) {
	if p.appHealthCache == nil || slug == "" {
		return
	}
	p.appHealthCache.RecordCall(slug, statusCode, errorType, time.Now())
}

// SetFilterStub501Active is the supervisor wiring entry for the SPEC
// §1.5.7 P3 stub: when the vault has any app declaring filter_stages
// but the real filter dispatcher is not yet shipped, the proxy must
// fail-loud rather than silent-allow. Called once at generation build;
// must not be flipped at runtime (the filterpipe implementation will
// land in P4 alongside its own runtime wiring).
func (p *Proxy) SetFilterStub501Active(active bool) {
	p.filterStub501Active = active
}

// SetFilterHook installs the P4 filter dispatcher hook. Called once at
// generation build time by the supervisor when a filter app is registered
// AND its child binary spawned OK. Passing a working hook is the signal that
// the dispatcher IS present, so the supervisor leaves filterStub501Active
// false (the two are mutually exclusive).
//
// nil hook = no filter (serveRoute's injection is a no-op).
func (p *Proxy) SetFilterHook(h apphook.Hook) {
	p.filterHook = h
}

// SetFilterIncrementalScan toggles latest-user-turn-only scanning (see the
// filterIncremental field). Called once at generation build by the supervisor
// from AIKEY_PROXY_FILTER_INCREMENTAL_SCAN. Default (unset) = full scan.
func (p *Proxy) SetFilterIncrementalScan(on bool) {
	p.filterIncremental = on
}

// SetFilterCache installs (or clears, with nil) the per-piece content-hash cache
// used by the inbound filter. nil = cache OFF (dispatcher does no hashing →
// stateless full scan). Pluggable: the supervisor wires an lruMaskCache when
// AIKEY_PROXY_FILTER_CACHE is enabled. See filter_cache.go + 设计 §4.
func (p *Proxy) SetFilterCache(c MaskCache) {
	p.filterCache = c
}

// SetFilterCacheEnabled turns the inbound-filter content-hash cache on/off with
// the default LRU+TTL. on=false clears it (→ stateless full scan, INV-6). The
// supervisor calls this from AIKEY_PROXY_FILTER_CACHE; tests inject a custom cache
// via SetFilterCache instead.
func (p *Proxy) SetFilterCacheEnabled(on bool, window int) {
	if on {
		if window < 1 {
			window = defaultMaskCacheWindow
		}
		p.filterCache = newSessionMaskCache(defaultMaxSessions, window, defaultMaskCacheTTL)
	} else {
		p.filterCache = nil
	}
}

// FilterHook returns the installed filter dispatcher hook (nil if none).
// Used by status reporting + tests.
func (p *Proxy) FilterHook() apphook.Hook {
	return p.filterHook
}

// SetObserverRegistry attaches the Phase 4 M2 plugin observer registry.
// Must be called BEFORE serving requests (typically in main.go right
// after BuildObservers). nil disables the observer pipeline entirely
// (Notify* hooks become zero-cost no-ops because the field's nil-check
// short-circuits before reaching the registry's own len(observers)==0
// check; saves one function call per request).
//
// Why a setter rather than a constructor arg: keeps `New(...)`'s
// signature stable for the many test helpers + tooling that already
// pass v/reg/prov/coll/ctx; first-party observers are opt-in feature
// rather than a core dependency.
func (p *Proxy) SetObserverRegistry(reg *observer.Registry) {
	p.observerRegistry = reg
}

// SetReporter sets the usage reporter for collector-service upload.
// clientVersion is the proxy build version (e.g. "0.1.0"), used as audit metadata.
// configVersion identifies the proxy generation/config revision.
// loadedControlSeq is the vault change_seq the proxy loaded at startup.
func (p *Proxy) SetReporter(r *events.Reporter, instanceID, clientVersion, configVersion string, loadedControlSeq int64, loggedInAccountID string) {
	p.reporter = r
	p.proxyInstanceID = instanceID
	p.clientVersion = clientVersion
	p.proxyConfigVersion = configVersion
	p.loadedControlSeq = loadedControlSeq
	p.loggedInAccountID = loggedInAccountID
}

// EnableSignalReporting wires the allocation-engine util signal reporter (I5): the
// proxy parses upstream unified-* utilization and best-effort POSTs it to master's
// /accounts/me/signals, authed with the same team account-JWT the group-runtime
// poll uses. nil controlURL/bearer → feature stays off (newSignalReporter returns nil).
func (p *Proxy) EnableSignalReporting(controlURL string, bearer func(ctx context.Context) (string, error)) {
	p.signalReporter = newSignalReporter(controlURL, bearer, slog.Default())
}

// EnableOrgSignalReporting is the Cluster-worker sibling of
// EnableSignalReporting. A worker has no member refresh token, so it reports to
// the org-scoped svcAuth endpoint with the already-configured control service
// token. The token authenticates only the control hop and is never forwarded to
// an LLM upstream.
func (p *Proxy) EnableOrgSignalReporting(controlURL, orgID, serviceToken string) {
	if controlURL == "" || orgID == "" || serviceToken == "" {
		return
	}
	endpoint := strings.TrimRight(controlURL, "/") + "/internal/org/" + url.PathEscape(orgID) + "/signals"
	p.signalReporter = newSignalReporterEndpoint(endpoint, func(context.Context) (string, error) {
		return serviceToken, nil
	}, slog.Default())
}

// StopSignalReporting stops the signal reporter's upload loop (idempotent,
// nil-safe). Called from generation.close() so the per-generation reporter's
// goroutine + ticker don't leak across reloads.
func (p *Proxy) StopSignalReporting() {
	if p.signalReporter != nil {
		_ = p.signalReporter.Close()
	}
}

// SetWAL attaches a local WAL writer for offline-mode usage events.
// When a reporter is configured the WAL is shared with it (set once at
// supervisor level) and the reporter performs the append.  When the reporter
// is nil, reportUsage falls back to appending directly via this writer so
// local consumers (aikey statusline / watch) always see events — even without
// a collector_url.
func (p *Proxy) SetWAL(w *events.WALWriter) {
	p.wal = w
}

// SetDeliveryIntegrity wires the per-source identity + sequence allocator used
// to stamp source_id / source_seq on reported usage events. Called once per
// generation by the supervisor. When seqAlloc is nil (e.g. WAL init failed),
// reportUsage falls back to emitting v1-shaped events (no source_seq), which
// are still stored locally but excluded from server-side gap detection.
func (p *Proxy) SetDeliveryIntegrity(sourceID string, seqAlloc *events.SeqAllocator) {
	p.sourceID = sourceID
	p.seqAlloc = seqAlloc
}

// TotalRequests returns the total number of proxied requests.
func (p *Proxy) TotalRequests() int64 { return p.requests.Load() }

// TotalErrors returns the total number of error responses.
func (p *Proxy) TotalErrors() int64 { return p.errors.Load() }

// BindingCooldownSnapshot exposes the binding-axis cooldown state for /status
// (task 3.4). Read-only: 🔴 a GET status endpoint must never mutate, and there is
// deliberately no clear-cooldown entry point at all (see PolicyRailHealth).
func (p *Proxy) BindingCooldownSnapshot() map[string]int {
	if p == nil || p.bindingCooldown == nil {
		return nil
	}
	return p.bindingCooldown.snapshot(time.Now())
}

// FallbackSwitches is the number of upstream switches since start (task 3.6).
func (p *Proxy) FallbackSwitches() int64 {
	if p == nil {
		return 0
	}
	return p.fallbackSwitches.Load()
}

// UpstreamFallbackHealth is the /status component for the chain (task 3.4).
//
// 🔴 A GET status endpoint is READ-ONLY. It also reports a state TRANSITION
// surface rather than only a terminal one: a state machine that has died also
// reports "ok" forever, so a health check that only ever shows the current label
// cannot distinguish healthy from stopped.
type UpstreamFallbackHealth struct {
	Component       string         `json:"component"`
	ChainsLoaded    int            `json:"chains_loaded"`
	Switches        int64          `json:"switches_total"`
	CoolingBindings map[string]int `json:"cooling_bindings,omitempty"`
}
