package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
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
	// declaredUpstreamsLogged remembers which explicitly-declared base_urls have
	// already had their "not in provider_routes" notice emitted, so a supported
	// third-party gateway is announced ONCE per generation instead of once per
	// request. 2026-08-15: a single relay produced 92 identical WARN lines in one
	// session; a permanent, supported configuration that shouts on every request
	// trains operators to filter WARN out, which is how a real one gets missed
	// ("失败要显眼" only works if WARN stays rare). The signal itself is kept —
	// P1j requires the degraded stitch to be observable — just not repeated.
	// Bounded by the number of distinct declared base_urls (single digits) and
	// discarded with the generation.
	declaredUpstreamsLogged sync.Map // map[string]struct{}
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
	// off the forward hot path). A Supervisor-built Proxy shares the process-owned
	// reporter across hot-reload generations; standalone proxies own reporters
	// created through EnableSignalReporting. nil = feature off.
	signalReporter *signalReporter
	// ownsSignalReporter distinguishes standalone/test Proxy ownership from the
	// Supervisor's process lifetime. A generation must never close the shared
	// reporter while a draining sibling can still publish into it.
	ownsSignalReporter bool
	// schedRouted tracks each (group|seat)'s last routed account so the unified
	// scheduling log receives one row per ROUTE CHANGE, never one per request
	// (拍板 2026-08-17 #3 — see noteSchedRouteSettled).
	schedRouted sync.Map // map[string]string: "<group>|<seat>" → account_id
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
	// filterCacheSuspended latches whether the LAST request observed the verdict
	// cache as unusable (apphook.CacheEpoch said "I cannot state my content set"),
	// so the dispatcher can log that transition ONCE instead of once per request.
	//
	// WHY a latch and not a plain per-request log: the suspension persists — a
	// detector too old to answer op=ListPacks never starts answering on its own —
	// so an unconditional line would emit at full request rate for the lifetime of
	// the deployment (review finding B6; same reasoning as the 16 KiB truncation
	// aggregate, which logs once per request rather than once per piece).
	//
	// Generation-scoped like every other counter here: a hot reload builds a new
	// Proxy, so the first request after a reload re-announces the state. That is
	// correct — the new generation has not said it yet.
	filterCacheSuspended atomic.Bool
	// filterPerformance is a bounded, content-free rolling latency window for
	// the externally readable compliance health surface. It lives with the
	// generation so a reload cannot mix samples from different detector builds.
	filterPerformance filterPerformanceMetrics
	proxyCtx          context.Context   // canceled when the proxy shuts down
	reporter          *events.Reporter  // usage reporting to collector-service (nil = disabled)
	wal               *events.WALWriter // local JSONL WAL (shared with reporter when both set; sole writer when reporter is nil)
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
	// maskFidelity is the compliance placeholder 保真率 signal (方案 20260808
	// §3.2 L3): how many mask placeholders this GENERATION put into forwarded
	// prompts vs how many came back from the models intact enough to restore.
	// A falling ratio is the ONLY way to notice that some model started
	// rewriting/dropping `{{ADDR_1}}`-style placeholders — the request itself
	// succeeds either way, so nothing else in the system would report it.
	// Read-only surface: /v1/diagnostics/pipeline (see maskRestoreHealth).
	// Counts only — never a label, a code or any masked content.
	//
	// 🔴 Generation-scoped, NOT process-scoped: see generationID below.
	maskFidelity maskFidelity
	// scanCoverage is the compliance SCAN-COVERAGE signal (bugfix 2026-08-13
	// 20260813-pipe-input-cap-truncates-silently): how many content pieces were
	// cut at pipeInputCap and how many bytes consequently reached the upstream
	// LLM without ever being inspected.
	//
	// WHY it must be externally readable: every one of those requests returns
	// 200, produces no mask and no compliance event, and looks identical to a
	// clean scan from the outside — so an operator has literally no other way to
	// discover that part of their traffic is unscanned. Agent tool blocks (file
	// reads, pasted logs) routinely exceed 16 KiB, which makes the audit-coverage
	// numbers on the compliance dashboard systematically optimistic until this is
	// read alongside them.
	// Read-only surface: /v1/diagnostics/pipeline (see maskRestoreHealth).
	// Counts only — never an index, a length distribution or any content.
	//
	// 🔴 Generation-scoped, NOT process-scoped: see generationID below.
	scanCoverage scanCoverage
	// generationID is the supervisor generation that built this Proxy
	// (supervisor.buildGeneration → s.genID.Add(1)). It is published on
	// /v1/diagnostics/pipeline as `generation_id`.
	//
	// WHY it must be externally readable (health-signal-surface): the proxy
	// hot-reloads IN-PROCESS. A reload keeps the PID but constructs a brand new
	// Proxy, so every counter on that endpoint (mapping applied/rejected/
	// passthrough, mask placeholders issued/restored) restarts at zero while the
	// process uptime keeps climbing. A release assertion that polls the endpoint
	// and treats the numbers as process-lifetime totals will silently read a
	// post-reset value as a cumulative one and conclude "healthy". Publishing the
	// generation makes the reset observable: the ID changing between two reads is
	// the ONLY evidence that the counters were zeroed in between.
	//
	// 0 means "not wired by a supervisor" (unit tests, embedded uses); it is
	// never a valid supervisor generation, which start at 1.
	generationID     atomic.Int64
	loadedControlSeq int64 // vault change_seq loaded at generation build time
	// Configurable slow-request thresholds (milliseconds).
	SlowRequestMs     int64
	VerySlowRequestMs int64
	// UpstreamTimeout caps how long a detached upstream call may run after
	// the client disconnects. Default: defaultUpstreamTimeout (10 min).
	UpstreamTimeout time.Duration
	// filterStub501 is set (non-nil) at proxy generation build time when a
	// compliance filter is REQUIRED (vault filter_stages declaration or org
	// mandate) but no working filter dispatcher could be constructed. While
	// set, ALL data-plane traffic returns 501 — SPEC §1.5.7 / §6.6
	// anti-example F mandate that a broken filter chain must NOT silently let
	// traffic through (would be "pseudo-security": looks configured, actually
	// inert). Set during supervisor.buildGeneration; not flipped at runtime.
	//
	// The cause carries WHY (bugfix 2026-08-19 filterpipe-501-stale-copy):
	// the supervisor always knew the real reason and the fix path, but the
	// P3-era user-facing string kept claiming "dispatcher not implemented /
	// wait for the build / server-side / temporary" long after the P4
	// dispatcher shipped — three lies and zero actionable steps while the
	// logs told the truth. The 501 body must render the SAME facts the
	// supervisor logs.
	//
	// Mutually exclusive with filterHook: supervisor sets EITHER a working
	// filterHook (dispatcher present) OR filterStub501 (declared but no
	// working dispatcher), never both.
	filterStub501 *FilterStubCause
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
	// filterScanRoles is the message-role allow-list the inbound filter scans
	// (P4, 方案 §3.4). nil = defaultScanRoles ({user, assistant}) so a Proxy built
	// without explicit configuration is already correct — the setter only exists
	// for operators who need to widen (tool/function) or narrow it. See
	// scanRoleSet in filter_content.go for the fail-safe semantics.
	filterScanRoles scanRoleSet
}

// SetTransport sets a custom RoundTripper for outbound requests to AI providers.
// Must be called before serving requests. A nil value restores the default
// behavior (defaultUpstreamTransport — http.DefaultTransport semantics incl.
// HTTP_PROXY / HTTPS_PROXY, with per-host idle capacity raised, see below).
func (p *Proxy) SetTransport(t http.RoundTripper) {
	p.transport.Store(&transportBox{rt: t})
	if t != nil {
		slog.Info("proxy: custom transport set")
	}
}

// transportBox boxes the RoundTripper so it can live in an atomic.Pointer (atomics
// can't hold an interface value directly). A nil rt means "use the default".
type transportBox struct{ rt http.RoundTripper }

// defaultUpstreamTransport is the fallback outbound transport when no custom
// transport (node-upstream chain / test interception) is set. It is
// http.DefaultTransport CLONED (Proxy env semantics and HTTP/2 wiring stay
// identical) with MaxIdleConnsPerHost raised from Go's default of 2: a worker
// fans hundreds of concurrent requests into a SINGLE provider host, so
// per-host idle capacity 2 discards almost every connection after use —
// TIME_WAIT piles up until the host exhausts ephemeral ports (EADDRNOTAVAIL)
// and unrelated local dials (cluster heartbeats!) start failing, and every
// discarded connection is an extra TLS handshake toward the provider (WAF
// exposure). N2 定案 2026-08-19 (容量 P0-4 方案): reproduced 3× at 120 users.
// The egress engine already used 100 (egress_engine.go) — this closes the gap
// on the default path.
var defaultUpstreamTransport = func() http.RoundTripper {
	// Comma-ok, not a bare assertion: errcheck rejects the unguarded form, and a
	// panic here would kill the proxy at package-init time — before any log line
	// exists to explain it. http.DefaultTransport is *http.Transport in every
	// stdlib we build against, so the fallback is unreachable in practice; it
	// exists so a future stdlib change degrades to the stock transport (smaller
	// idle pool) instead of taking the process down.
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultTransport
	}
	t := base.Clone()
	t.MaxIdleConns = 100
	t.MaxIdleConnsPerHost = 100
	return t
}()

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
	return newProxy(v, reg, prov, coll, ctx, nil)
}

// NewWithOAuthPoolRuntime creates a Proxy generation backed by process-owned
// OAuth-pool cooldown/tombstone and signal-reporting state. The runtime must be
// created once by Supervisor and closed only during process shutdown.
func NewWithOAuthPoolRuntime(v VaultGetter, reg *vkeys.Registry, prov *provider.Registry, coll *events.Collector, ctx context.Context, runtime *OAuthPoolRuntimeState) *Proxy {
	return newProxy(v, reg, prov, coll, ctx, runtime)
}

func newProxy(v VaultGetter, reg *vkeys.Registry, prov *provider.Registry, coll *events.Collector, ctx context.Context, runtime *OAuthPoolRuntimeState) *Proxy {
	var poolCooldown *poolCooldownStore
	var signalReporter *signalReporter
	if runtime != nil {
		poolCooldown = runtime.poolCooldown
		signalReporter = runtime.signalReporter
	} else {
		poolCooldown = newPoolCooldownStore()
	}
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
		poolCooldown:       poolCooldown,
		bindingCooldown:    newBindingCooldownStore(),
		chainActivity:      newChainActivityStore(),
		pathHealth:         NewProviderPathHealthManager(),
		poolObservedResets: newPoolResetStore(),
		groupLoginState:    newGroupLoginStateStore(),
		signalReporter:     signalReporter,
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

// FilterStubCause says WHY the fail-loud filter 501 is active, in enough
// detail for the 501 body to give the user the SAME facts and fix path the
// supervisor logs carry (they must never diverge again — bugfix 2026-08-19).
type FilterStubCause struct {
	// Reason is one of the FilterStubReason* constants.
	Reason string
	// Slug is the filter app whose dispatcher could not be built.
	Slug string
	// ExpectedPath is where the binary was looked for (empty when unknown,
	// e.g. spawn failures report the resolved binary path instead).
	ExpectedPath string
	// Mandated marks the org-mandate flavor: the block cannot be lifted by
	// clearing local settings — only installing the detector (or the org
	// dropping the mandate) unblocks traffic.
	Mandated bool
}

// Reason vocabulary for FilterStubCause (also emitted as the additive
// `reason_code` field on the 501 body; error-code-changelog entry required
// when this list changes).
const (
	// FilterStubReasonMandateNotInstalled: org mandates compliance but the
	// detector binary is absent on this machine.
	FilterStubReasonMandateNotInstalled = "COMPLIANCE_MANDATED_NOT_INSTALLED"
	// FilterStubReasonBinaryMissing: vault declares a filter app but its
	// binary was not found at the canonical path.
	FilterStubReasonBinaryMissing = "FILTER_BINARY_MISSING"
	// FilterStubReasonSpawnFailed: binary present but every detector process
	// failed to start.
	FilterStubReasonSpawnFailed = "FILTER_SPAWN_FAILED"
)

// SetFilterStub501 is the supervisor wiring entry for the SPEC §1.5.7 /
// §6.6 fail-loud guard: when a compliance filter is required (vault
// declaration or org mandate) but no working dispatcher could be built, the
// proxy must fail-loud rather than silent-allow. nil clears the guard.
// Called once at generation build; must not be flipped at runtime.
func (p *Proxy) SetFilterStub501(cause *FilterStubCause) {
	p.filterStub501 = cause
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

// SetFilterScanRoles configures which message roles the inbound compliance
// filter scans (方案 §3.4). Called once at generation build by the supervisor
// from AIKEY_PROXY_FILTER_SCAN_ROLES; unset leaves the default {user, assistant}.
//
// Returns the roles actually applied plus the rejected (unrecognized) names so
// the caller can WARN — an operator typo must be visible, not silently dropped
// (日志规范). An input with no recognized role at all keeps the DEFAULT rather
// than scanning nothing: a misconfiguration must never disable masking.
func (p *Proxy) SetFilterScanRoles(roles []string) (applied, rejected []string) {
	set, rejected := newScanRoleSet(roles)
	p.filterScanRoles = set
	return set.list(), rejected
}

// FilterScanRoles returns the effective scan-role policy (sorted), for status
// reporting and diagnostics.
func (p *Proxy) FilterScanRoles() []string { return p.filterScanRoles.list() }

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

// FilterPerformanceSnapshot returns the current generation's bounded latency
// distribution. It is safe during concurrent request processing.
func (p *Proxy) FilterPerformanceSnapshot() FilterPerformanceSnapshot {
	return p.filterPerformance.snapshot()
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

// GenerationLabel renders the canonical label for a supervisor generation. It
// lives in this package — not in the supervisor — so the string stamped on every
// usage event as config_version and the ID published on
// /v1/diagnostics/pipeline can never drift into two different notions of
// "which generation".
func GenerationLabel(id int64) string { return "gen-" + strconv.FormatInt(id, 10) }

// SetGenerationID records which supervisor generation built this Proxy, and
// derives the config-version label from it.
//
// Called unconditionally by supervisor.buildGeneration right after proxy.New —
// deliberately NOT folded into SetReporter, because SetReporter is skipped
// whenever no upload destination and no WAL are configured. A generation
// identity that is only present on the reporting build would be absent from the
// exact offline/standalone deployments where an operator has the fewest other
// ways to tell that a reload zeroed the diagnostics counters.
func (p *Proxy) SetGenerationID(id int64) {
	p.generationID.Store(id)
	p.proxyConfigVersion = GenerationLabel(id)
}

// GenerationID returns the supervisor generation that built this Proxy, or 0
// when no supervisor wired one. See the generationID field for why it is part
// of the read-only diagnostics surface.
func (p *Proxy) GenerationID() int64 { return p.generationID.Load() }

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
// poll uses. nil controlURL/bearer leaves a shared reporter dormant without
// discarding durable pending work; a standalone Proxy remains feature-off.
func (p *Proxy) EnableSignalReporting(controlURL string, bearer func(ctx context.Context) (string, error)) {
	endpoint := ""
	if controlURL != "" {
		endpoint = strings.TrimRight(controlURL, "/") + "/accounts/me/signals"
	}
	p.configureSignalReporting(endpoint, bearer)
}

// EnableOrgSignalReporting is the Cluster-worker sibling of
// EnableSignalReporting. A worker has no member refresh token, so it reports to
// the org-scoped svcAuth endpoint with the already-configured control service
// token. The token authenticates only the control hop and is never forwarded to
// an LLM upstream.
func (p *Proxy) EnableOrgSignalReporting(controlURL, orgID, serviceToken string) {
	if controlURL == "" || orgID == "" || serviceToken == "" {
		p.DisableSignalReporting()
		return
	}
	endpoint := strings.TrimRight(controlURL, "/") + "/internal/org/" + url.PathEscape(orgID) + "/signals"
	p.configureSignalReporting(endpoint, func(context.Context) (string, error) {
		return serviceToken, nil
	})
}

func (p *Proxy) configureSignalReporting(endpoint string, bearer func(context.Context) (string, error)) {
	if p == nil {
		return
	}
	if p.signalReporter == nil {
		p.signalReporter = newSignalReporterEndpoint(endpoint, p.sourceID, bearer, slog.Default())
		p.ownsSignalReporter = p.signalReporter != nil
		return
	}
	p.signalReporter.configure(endpoint, p.sourceID, bearer)
}

// DisableSignalReporting disables uploads without destroying process-owned
// pending state. A later successful generation activation can re-enable the
// same outbox and retry it.
func (p *Proxy) DisableSignalReporting() {
	if p == nil || p.signalReporter == nil {
		return
	}
	p.signalReporter.configure("", p.sourceID, nil)
}

// SignalReportingHealthSnapshot exposes the current allocation-signal pipeline
// state for /status. A live Proxy with no reporter returns disabled explicitly;
// an OAuth-pool deployment must not look healthy merely because wiring is absent.
func (p *Proxy) SignalReportingHealthSnapshot() *SignalReportingHealth {
	if p == nil {
		return nil
	}
	if p.signalReporter == nil {
		return &SignalReportingHealth{Status: "disabled"}
	}
	snapshot := p.signalReporter.healthSnapshot()
	return &snapshot
}

// StopSignalReporting stops a standalone Proxy's signal reporter (idempotent,
// nil-safe). Supervisor generations reference a process-owned reporter and do
// not own its lifecycle; Supervisor closes it during process shutdown.
func (p *Proxy) StopSignalReporting() {
	if p.signalReporter != nil && p.ownsSignalReporter {
		_ = p.signalReporter.Close()
		p.signalReporter = nil
		p.ownsSignalReporter = false
	}
}

// StopObservers retires this generation's observer registry (idempotent,
// nil-safe). Unlike the process-owned allocation signal reporter, this registry
// is rebuilt per generation (supervisor.buildObserverRegistry), so whatever its
// observers started in Build — rhythm's 5s settings poller and reporter worker
// pool — leaks on every reload without this. See observer.ClosableObserver.
func (p *Proxy) StopObservers() {
	p.observerRegistry.Close()
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
