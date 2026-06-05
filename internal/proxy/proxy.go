package proxy

import (
	"context"
	"log/slog"
	"net/http"
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

// ActiveKeyReader extends VaultGetter with active-key lookups used by
// path-prefix routing (/anthropic/v1/..., /openai/v1/...).
// Implemented by *vault.Reader when the vault supports managed and personal keys.
type ActiveKeyReader interface {
	VaultGetter
	GetActiveKeyConfig() (*vault.ActiveKeyConfig, error)
	GetActiveTeamKeyByProvider(providerCode string) (*vault.ManagedKey, error)
	GetPersonalKeyByAlias(alias string) (plaintext, providerCode, baseURL string, err error)
	// v1.0.2: provider-level binding from user_profile_provider_bindings.
	GetProviderBinding(providerCode string) (*vault.ProviderBinding, error)
	// v1.0.2: resolve team key by exact virtual_key_id (no local_state filter).
	GetTeamKeyByID(virtualKeyID string) (*vault.ManagedKey, error)
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
	ExpiresAt   int64
	Identity    string // Email or display name (for logging only, never sent upstream)
}

// Proxy is the core reverse proxy that handles virtual key resolution
// and request forwarding.
type Proxy struct {
	vault              VaultGetter
	activeReader       ActiveKeyReader       // non-nil when vault implements ActiveKeyReader
	appVault           apppipe.VaultReader   // non-nil when vault implements the App pipeline read surface (Phase 4)
	probeVault         probepipe.VaultReader // non-nil when vault implements the Probe pipeline read surface (mode C, SPEC 2026-05-23)
	broker             OAuthBroker           // OAuth credential provider (nil = OAuth not available)
	registry           *vkeys.Registry
	providers          *provider.Registry
	collector          *events.Collector
	reporter           *events.Reporter  // usage reporting to collector-service (nil = disabled)
	wal                *events.WALWriter // local JSONL WAL (shared with reporter when both set; sole writer when reporter is nil)
	transport          http.RoundTripper // nil → http.DefaultTransport (reads env vars)
	proxyCtx           context.Context   // canceled when the proxy shuts down
	proxyInstanceID    string
	// Delivery integrity (2026-05-30). sourceID is the vault's stable source
	// identity stamped on every reported event; seqAlloc hands out the
	// per-source never-reused sequence. Both nil/empty until SetDeliveryIntegrity
	// wires them (offline-only or pre-seqalloc builds report v1-shaped events).
	sourceID           string
	seqAlloc           *events.SeqAllocator
	clientVersion      string // build version for audit metadata in usage events
	proxyConfigVersion string // generation ID or config revision
	loadedControlSeq   int64  // vault change_seq loaded at generation build time
	loggedInAccountID  string // current platform_account.account_id (for personal key events)

	// quota is the Phase 2 enterprise token-quota gate (Stage 3). nil-safe +
	// flag-gated: when nil or disabled it is a pure no-op, so the request path is
	// never blocked by quota machinery — only by an actual confirmed over-limit.
	// Wired via SetQuotaEnforcer from the supervisor's snapshot+counter.
	quota *quota.Enforcer

	requests atomic.Int64
	errors   atomic.Int64

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

	// Configurable slow-request thresholds (milliseconds).
	SlowRequestMs     int64
	VerySlowRequestMs int64

	// UpstreamTimeout caps how long a detached upstream call may run after
	// the client disconnects. Default: defaultUpstreamTimeout (10 min).
	UpstreamTimeout time.Duration

	// appHealthCache records the most recent app-pipeline call per slug,
	// in process memory only (no persistence). Powers the Web "Connected
	// Apps" list Health column via the admin /admin/apps/health endpoint.
	// Always non-nil after New(); the cache itself is safe for concurrent
	// readers/writers (sync.RWMutex internal). See
	// apppipe/health.go for the rationale on why this isn't a DWD-side
	// projection.
	appHealthCache *apppipe.HealthCache
}

// SetTransport sets a custom RoundTripper for outbound requests to AI providers.
// Must be called before serving requests. A nil value restores the default
// behavior (http.DefaultTransport, which honors HTTP_PROXY / HTTPS_PROXY env vars).
func (p *Proxy) SetTransport(t http.RoundTripper) {
	p.transport = t
	if t != nil {
		slog.Info("proxy: custom transport set")
	}
}

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
	return p
}

// SetBroker injects the OAuth broker for credential resolution.
// Must be called before the proxy handles any OAuth-credential requests.
func (p *Proxy) SetBroker(b OAuthBroker) {
	p.broker = b
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

// SetQuotaEnforcer injects the Phase 2 token-quota gate (Stage 3). Wired by the
// supervisor from the per-process snapshot+counter. Safe to leave unset — a nil
// enforcer is a no-op (no enforcement), which is the correct behavior for
// editions/tests that don't run quota.
func (p *Proxy) SetQuotaEnforcer(e *quota.Enforcer) {
	p.quota = e
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
