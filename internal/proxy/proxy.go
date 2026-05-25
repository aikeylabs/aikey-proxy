package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/apppipe"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/probepipe"
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
	vault        VaultGetter
	activeReader ActiveKeyReader   // non-nil when vault implements ActiveKeyReader
	appVault     apppipe.VaultReader // non-nil when vault implements the App pipeline read surface (Phase 4)
	probeVault   probepipe.VaultReader // non-nil when vault implements the Probe pipeline read surface (mode C, SPEC 2026-05-23)
	broker       OAuthBroker       // OAuth credential provider (nil = OAuth not available)
	registry     *vkeys.Registry
	providers    *provider.Registry
	collector    *events.Collector
	reporter     *events.Reporter // usage reporting to collector-service (nil = disabled)
	wal          *events.WALWriter // local JSONL WAL (shared with reporter when both set; sole writer when reporter is nil)
	transport    http.RoundTripper // nil → http.DefaultTransport (reads env vars)
	proxyCtx     context.Context   // cancelled when the proxy shuts down
	proxyInstanceID    string
	clientVersion      string // build version for audit metadata in usage events
	proxyConfigVersion string // generation ID or config revision
	loadedControlSeq   int64  // vault change_seq loaded at generation build time
	loggedInAccountID  string // current platform_account.account_id (for personal key events)
	requests     atomic.Int64
	errors       atomic.Int64

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
	// vault contains any app_records row with filter_stages != NULL. While
	// active, ALL data-plane traffic returns 501 FILTER_NOT_IMPLEMENTED —
	// SPEC §1.5.7 / §6.6 anti-example F mandate that an unimplemented
	// filter chain must NOT silently let traffic through (would be
	// "pseudo-security": looks configured, actually inert). Set during
	// supervisor.buildGeneration; not flipped at runtime.
	filterStub501Active bool

	// Configurable slow-request thresholds (milliseconds).
	SlowRequestMs     int64
	VerySlowRequestMs int64

	// UpstreamTimeout caps how long a detached upstream call may run after
	// the client disconnects. Default: defaultUpstreamTimeout (10 min).
	UpstreamTimeout time.Duration
}

// SetTransport sets a custom RoundTripper for outbound requests to AI providers.
// Must be called before serving requests. A nil value restores the default
// behaviour (http.DefaultTransport, which honours HTTP_PROXY / HTTPS_PROXY env vars).
func (p *Proxy) SetTransport(t http.RoundTripper) {
	p.transport = t
	if t != nil {
		slog.Info("proxy: custom transport set")
	}
}

// New creates a new Proxy. ctx is the proxy lifecycle context; cancelling it
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

// SetFilterStub501Active is the supervisor wiring entry for the SPEC
// §1.5.7 P3 stub: when the vault has any app declaring filter_stages
// but the real filter dispatcher is not yet shipped, the proxy must
// fail-loud rather than silent-allow. Called once at generation build;
// must not be flipped at runtime (the filterpipe implementation will
// land in P4 alongside its own runtime wiring).
func (p *Proxy) SetFilterStub501Active(active bool) {
	p.filterStub501Active = active
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

// TotalRequests returns the total number of proxied requests.
func (p *Proxy) TotalRequests() int64 { return p.requests.Load() }

// TotalErrors returns the total number of error responses.
func (p *Proxy) TotalErrors() int64 { return p.errors.Load() }

// Handle is the main HTTP handler for data plane requests.
func (p *Proxy) Handle(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	p.requests.Add(1)

	// Extract or create W3C trace context from the incoming request.
	tc := observability.ExtractOrCreate(r)
	logger := slog.With(
		"trace_id", tc.TraceID,
		"span_id", tc.SpanID,
		"request_id", tc.RequestID,
	)

	// 0-pre. SPEC §1.5.7 / §6.6 E-mode fail-loud stub.
	//
	// If vault has any app_records row declaring filter_stages but the
	// filterpipe dispatcher is not implemented (always true in P3 — real
	// impl lands in P4), reject ALL data-plane requests with 501. This
	// is the explicit fix for anti-example F: an unimplemented filter
	// MUST NOT silently let traffic through, otherwise an operator who
	// configured filter_stages believes they have compliance enforcement
	// while actually the chain is inert.
	//
	// Lives BEFORE all routing branches so probe / app / user_chat all
	// return uniformly. supervisor.buildGeneration warns the operator at
	// startup so they see this state in logs, not just in client 501s.
	if p.filterStub501Active {
		p.errors.Add(1)
		writeJSONError(w, http.StatusNotImplemented, "server_error",
			"FILTER_NOT_IMPLEMENTED",
			"This proxy build has vault rows declaring filter_stages but the "+
				"filterpipe dispatcher is not implemented yet (SPEC §1.5.7 P3 stub). "+
				"All traffic is being rejected to avoid silent-allow. Either clear "+
				"the filter declaration in vault or wait for the proxy build that "+
				"includes the filter dispatcher.")
		return
	}

	// 0a-prime. Probe pipeline path: /probe/<alias>/v1/... (mode C, SPEC
	// 2026-05-23-credential-mode-architecture §1.3).
	//
	// MUST be checked BEFORE both /apps/ and the legacy provider-prefix
	// parser — same prefix-collision reason as the App routing below: a
	// URL like /probe/X/v1 must not be misread as a provider-prefix route
	// or app slug. The ordering invariant is enforced by a regression
	// test in proxy_test.go.
	//
	// Probe pipeline differs from App pipeline in three ways: URL alias
	// (instead of vault-registered slug) is the credential source, the
	// constant first-party Bearer (instead of issued app key) is the
	// auth, and follow_user_active is ALWAYS ignored. See SPEC §1.3 for
	// the full contract.
	if probeCtx := probepipe.ExtractProbePath(r.URL.Path); probeCtx != nil {
		p.handleProbePipeline(w, r, probeCtx, startTime, logger, tc.TraceID)
		return
	}

	// 0a. App pipeline path: /apps/<slug>/v1/... (Phase 4).
	//
	// MUST be checked BEFORE extractProviderFromPath — otherwise
	// /apps/X/openai/v1 would be misread by the legacy parser as
	// provider="apps" with a meaningless stripped path, producing a
	// confusing 404 instead of a precise App pipeline error. This
	// ordering is the wiring invariant called out in apppipe/router.go's
	// ExtractAppPath docstring; verified by TestHandle_AppPathTakesPrecedenceOverProviderPrefix.
	//
	// Today the App pipeline handler returns 501 with diagnostic detail
	// (slug + protocol parsed correctly, vault → Registry plumbing
	// confirmed working if the bearer is recognized) — the authn /
	// resolve / egress / forward stages land in subsequent AKL-204..207
	// sub-tasks.
	if appCtx := apppipe.ExtractAppPath(r.URL.Path); appCtx != nil {
		p.handleAppPipeline(w, r, appCtx, startTime, logger, tc.TraceID)
		return
	}

	// 0. Path-prefix routing: /anthropic/v1/... or /openai/v1/...
	// Takes precedence over token-based routing when the path starts with a
	// known provider prefix. Uses the active key config from the vault.
	if providerCode, strippedPath := extractProviderFromPath(r.URL.Path); providerCode != "" {
		p.handlePathPrefixRoute(w, r, providerCode, strippedPath, startTime, logger, tc.TraceID)
		return
	}

	// 1. Extract virtual key.
	token := extractVirtualKey(r)
	if token == "" {
		p.errors.Add(1)
		logger.Warn("authentication failed: missing virtual key",
			"event.name", observability.EventProxyRequestAuthFailed,
			"error.code", observability.ErrCodeTokenMissing,
		)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_MISSING",
			"Missing virtual key. Expected token with 'aikey_team_' or 'aikey_personal_' prefix in Authorization or x-api-key header.")
		return
	}

	// 2. Namespace-authority gate (2026-04-29). Legacy /v1/... entry has no
	// path prefix, so only Tier1 (registry-bound) tokens make sense here.
	// Tier2 probe / Tier3 active sentinel both need a path-derived canonical
	// provider — explicitly reject with a hint to use path-prefix routing.
	// TokenInvalid (malformed / reserved aikey_route_* / unknown) hard-fails.
	// Closes legacy-entry namespace bypass: see review #1, 2026-04-29.
	switch ClassifyToken(token) {
	case Tier1Team, Tier1Personal:
		// fall through to registry resolve
	case Tier1App:
		// App bearers route through /apps/<slug>/v1/... — they
		// MUST NOT be presented at the legacy /v1/... entry because that
		// would leak the app's binding scope into the user's default
		// profile. Reject with a precise hint pointing at the env line
		// `aikey app authorize` printed for this token.
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "APP_TOKEN_WRONG_PATH",
			"App bearer tokens must be sent to /apps/<slug>/v1/... URLs, "+
				"not the legacy /v1/... entry. Use the OPENAI_BASE_URL value printed "+
				"by `aikey app authorize <slug>` for the correct URL.")
		return
	case Tier2Probe:
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Probe sentinel requires path-prefix routing (use /<provider>/v1/... URL).")
		return
	case Tier2ProbeRaw:
		// Same gating reason as Tier2Probe — probe_raw needs path-derived
		// canonical provider to construct upstream URL; legacy /v1/... entry
		// has no path prefix. Reject precisely so caller (CLI/web) gets a
		// clear hint rather than a silent upstream-URL-empty failure.
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Pre-save probe (aikey_probe_raw_*) requires path-prefix routing (use /<provider>/v1/... URL).")
		return
	case Tier3ActiveSentinel:
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Active sentinel requires path-prefix routing (use /<provider>/v1/... URL). "+
				"This entry is for static team/personal tokens only.")
		return
	case TokenInvalid:
		p.errors.Add(1)
		logger.Warn("aikey_* token form invalid (namespace authority)",
			"event.name", observability.EventProxyRequestAuthFailed,
		)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Token is in the aikey_ namespace but doesn't match any recognized form. "+
				"Run 'aikey route' to see valid tokens.")
		return
	default: // Tier3Native — extractVirtualKey only returns aikey_* tokens, so this is unreachable
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Unexpected token classification at legacy entry.")
		return
	}

	// 3. Resolve virtual key → route.
	route := p.registry.Resolve(token)
	if route == nil {
		p.errors.Add(1)
		logger.Warn("authentication failed: invalid virtual key",
			"event.name", observability.EventProxyRequestAuthFailed,
			"error.code", observability.ErrCodeTokenInvalid,
		)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Invalid virtual key. Token not found in registry.")
		return
	}

	// Enrich logger with route context (no secrets).
	logger = logger.With(
		"virtual_key_id", route.VirtualKeyID,
		"provider", route.Provider,
	)

	// 3. Check model allowlist (if applicable).
	if len(route.AllowedModels) > 0 {
		model := extractModel(r)
		if model != "" && !route.IsModelAllowed(model) {
			p.errors.Add(1)
			logger.Warn("policy denied: model not allowed",
				"event.name", observability.EventProxyRequestPolicyDenied,
				"error.code", observability.ErrCodePolicyModelForbidden,
				"model", model,
			)
			writeJSONError(w, http.StatusForbidden, "permission_error", "POLICY_MODEL_FORBIDDEN",
				"Model '"+model+"' is not allowed for this virtual key.")
			return
		}
	}

	// 4. Get real key — either from the pre-decrypted managed cache or from vault.
	var realKey string
	if route.PlaintextKey != "" {
		// Team-managed virtual key: provider key was decrypted from
		// managed_virtual_keys_cache at proxy startup. Use it directly.
		realKey = route.PlaintextKey
	} else {
		var err error
		realKey, err = p.vault.GetSecret(route.KeyAlias)
		if err != nil {
			p.errors.Add(1)
			logger.Error("vault lookup failed",
				"event.name", observability.EventProxyRequestVaultFailed,
				"error.code", observability.ErrCodeSecretNotConfigured,
				"error.message", err.Error(),
				"key_alias", route.KeyAlias,
			)
			writeJSONError(w, http.StatusServiceUnavailable, "server_error", "SECRET_NOT_CONFIGURED",
				"Provider API Key '"+route.KeyAlias+"' is not in the vault. Run: aikey add "+route.KeyAlias)
			return
		}
	}

	// 5. Get provider adapter — use protocol type (e.g. "openai_compatible"),
	// not the provider_code (e.g. "kimi_code"). 2026-05-08 Kimi 双平台拆分:
	// pre-split route.Provider 同时是 provider_code 又是 adapter registry key
	// (因 "kimi"/"openai" 字面值刚好相同),post-split 新 provider_codes
	// ("kimi_code" / "moonshot") **不是** adapter registry key —— adapter 是
	// 按 protocol 注册 (openai_compatible / anthropic / kimi / generic)。
	// 与 handlePathPrefixRoute 对齐用 protocol 查找,避免 502 PROVIDER_ERROR。
	// route.ProtocolType 兜底退回 route.Provider 防 pre-2026-05-08 fixture。
	adapterKey := route.ProtocolType
	if adapterKey == "" {
		adapterKey = route.Provider
	}
	prov, err := p.providers.Get(adapterKey)
	if err != nil {
		p.errors.Add(1)
		logger.Error("unknown provider",
			"event.name", observability.EventProxyRequestUpstreamError,
			"error.code", observability.ErrCodeProviderError,
			"error.message", err.Error(),
		)
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
			"Unknown provider protocol: "+adapterKey)
		return
	}

	// SPEC §1.4.1: legacy /v1/... entry serves user-chat traffic; wire
	// observer through helper so ndjson-fanout subscribers see this stream.
	p.serveRouteWithObserver(w, r, route, prov, realKey, token, startTime, logger,
		observer.StreamUserChat, tc.TraceID)
}

// serveRouteWithObserver wraps p.serveRoute with NotifyStart/End for the
// given SPEC §1.4.1 stream. Used by user_chat callers (Handle's legacy
// /v1/ branch + handlePathPrefixRoute's 4 sub-branches) so the
// observer wiring lives in one place rather than 5 copy-pastes.
//
// Why not also use this from handleAppPipeline / handleProbePipeline:
// those handlers build a richer RequestContext (AppKeyID / AppSlug /
// AppMode for the App pipeline, alias_kind logging for Probe) inline
// at call site. Funneling them through here would either lose those
// fields or balloon the helper's signature. Two-handler-specific +
// one-shared-helper is the right granularity — DRY where the pipelines
// agree, explicit where they diverge.
//
// requestedModel intentionally empty for user_chat — extracting body.model
// here would require parsing + restoring r.Body, with risk of breaking
// the byte-identical forward semantics path-prefix routing relies on.
// Event.Model has json:omitempty so the downstream NDJSON consumer
// survives the absence.
func (p *Proxy) serveRouteWithObserver(
	w http.ResponseWriter, r *http.Request,
	route *vkeys.ResolvedRoute, prov provider.Provider,
	realKey, inboundBearer string,
	startTime time.Time, logger *slog.Logger,
	stream string, traceID string,
) {
	var obsReqCtx *observer.RequestContext
	if p.observerRegistry != nil && p.observerRegistry.Active() > 0 {
		// User_chat-side ProtocolFamily fallback (2026-05-23): the legacy
		// /v1/... route resolution doesn't fill `route.ProtocolFamily`
		// (it's only populated in handleAppPipeline — see
		// ResolvedRoute.ProtocolFamily doc-comment). Without this, the
		// rhythm observer's protocol gate trips on every user_chat event
		// (`unknown_protocol` WARN) and D-rule scoring never runs. We
		// re-derive from the same provider_fingerprint yaml the app
		// pipeline uses so user_chat observers see the same shape app
		// observers do. No change for paths that already filled the
		// field (route.ProtocolFamily != "" wins).
		pf := route.ProtocolFamily
		if pf == "" && route.ProviderCode != "" {
			if pr, ok := provider.Routes().ByProvider(route.ProviderCode); ok {
				pf = pr.Protocol
			}
		}
		obsReqCtx = &observer.RequestContext{
			KeyAlias:       route.KeyAlias,
			ProviderID:     route.ProviderCode,
			ProtocolFamily: pf,
			SessionID:      resolveSessionID(r.Header, route.ProviderCode),
			TraceID:        traceID,
			StartedAt:      startTime,
		}
		route.ObserverContext = obsReqCtx
		route.ObserverRegistry = p.observerRegistry
		p.observerRegistry.NotifyStart(r.Context(), stream, obsReqCtx)
	}

	p.serveRoute(w, r, route, prov, realKey, inboundBearer, startTime, logger)

	if obsReqCtx != nil {
		latency := int(time.Since(startTime).Milliseconds())
		p.observerRegistry.NotifyEnd(r.Context(), obsReqCtx, latency)
	}
}

// ResolveBindingCredential resolves the upstream credential for the
// given `binding`. Behavior depends on `binding.KeySourceType`:
//
//   - "personal_oauth_account" → broker.EnsureFresh + ResolveCredential,
//     mutate `r` headers via oauthInject, apply Codex BaseURL override
//     for canonicalCode=openai. On broker failure (broker nil, refresh
//     failed, resolve failed) returns *BindingResolveError that the
//     caller passes to writeJSONError.
//
//   - "team" → activeReader.GetTeamKeyByID; populates ManagedKey,
//     KeyAlias (LocalAlias), BaseURL (ProviderBaseURLs lookup with
//     canonicalCode → providerCode → mk.BaseURL fallback). Soft-fails
//     (logger.Warn + empty RealKey) so caller falls back to legacy.
//
//   - default (personal) → activeReader.GetPersonalKeyByAlias;
//     populates RealKey, KeyAlias (== binding.KeySourceRef), BaseURL
//     (entry-specified or providerDefaultBaseURL). Soft-fails like team.
//
// Refactored from the inline code at handlePathPrefixRoute's binding
// branch (AKL-207, 2026-05-20). Fence tests in oauth_binding_fence_test.go
// pin the OAuth path's exact pre-refactor behavior.
func (p *Proxy) ResolveBindingCredential(
	r *http.Request,
	binding *vault.ProviderBinding,
	providerCode, canonicalCode string,
	logger *slog.Logger,
) (*apppipe.BindingCredential, *apppipe.BindingResolveError) {
	out := &apppipe.BindingCredential{}

	switch binding.KeySourceType {
	case "personal_oauth_account":
		// OAuth account — resolve via broker, not vault.
		if p.broker == nil {
			return nil, &apppipe.BindingResolveError{
				StatusCode: http.StatusServiceUnavailable,
				ErrorType:  "server_error",
				ErrorCode:  "OAUTH_NOT_AVAILABLE",
				Message:    "OAuth is not configured. Restart proxy or use API Key instead.",
			}
		}

		// EnsureFresh: broker handles token refresh internally.
		if err := p.broker.EnsureFresh(r.Context(), binding.KeySourceRef); err != nil {
			logger.Warn("oauth: EnsureFresh failed", "account_id", binding.KeySourceRef, "error", err)
			return nil, &apppipe.BindingResolveError{
				StatusCode: http.StatusUnauthorized,
				ErrorType:  "auth_error",
				ErrorCode:  "OAUTH_TOKEN_EXPIRED",
				Message:    err.Error() + "\n  Run: aikey auth login " + providerCode,
			}
		}

		// Resolve decrypted credential.
		cred, err := p.broker.ResolveCredential(r.Context(), binding.KeySourceRef)
		if err != nil {
			logger.Error("oauth: ResolveCredential failed", "account_id", binding.KeySourceRef, "error", err)
			return nil, &apppipe.BindingResolveError{
				StatusCode: http.StatusServiceUnavailable,
				ErrorType:  "server_error",
				ErrorCode:  "OAUTH_RESOLVE_FAILED",
				Message:    err.Error(),
			}
		}

		// Codex BaseURL override pinned by TestFence_OAuthBinding_OpenAICodexBaseURLOverride.
		// Why: Codex OAuth uses chatgpt.com/backend-api/codex (Responses API),
		// NOT api.openai.com/v1 (Chat Completions API). API key users hit
		// api.openai.com; OAuth users hit chatgpt.com.
		// Ref: workflow/CI/researchs/oauth-codex-test/main.go
		if canonicalCode == "openai" {
			out.BaseURL = "https://chatgpt.com/backend-api/codex"
		} else {
			out.BaseURL = providerDefaultBaseURL(canonicalCode)
		}
		oauthInject(r, cred, canonicalCode)

		identityTag := cred.Identity
		if identityTag == "" {
			identityTag = binding.KeySourceRef
		}
		logger.Info("oauth: forwarding request",
			"provider", canonicalCode,
			"identity", identityTag,
			"account_id", binding.KeySourceRef,
		)

		out.RealKey = "__oauth__" // sentinel — not used for header injection (injector did it)
		out.VirtualKeyID = "oauth:" + binding.KeySourceRef
		out.OAuthIdentity = identityTag
		out.OAuthAccountID = binding.KeySourceRef
		return out, nil

	case "team":
		mk, err := p.activeReader.GetTeamKeyByID(binding.KeySourceRef)
		if err != nil {
			logger.Warn("vault: team key lookup via binding failed", "vk_id", binding.KeySourceRef, "error", err)
			return out, nil // soft fail — caller will try legacy fallback
		}
		if mk == nil {
			return out, nil // not found, soft fail
		}
		out.ManagedKey = mk
		out.RealKey = mk.PlaintextKey
		out.VirtualKeyID = mk.VirtualKeyID
		// 2026-05-09: surface the team key's user-facing alias so the
		// receipt / WAL `key_label` shows e.g. `key-335923591-0011-1`
		// instead of the vk_id tail.
		out.KeyAlias = mk.LocalAlias
		if url, ok := mk.ProviderBaseURLs[canonicalCode]; ok && url != "" {
			out.BaseURL = url
		} else if url, ok := mk.ProviderBaseURLs[providerCode]; ok && url != "" {
			out.BaseURL = url
		} else {
			out.BaseURL = mk.BaseURL
		}
		return out, nil

	default:
		// Personal key path. binding.KeySourceType is typically "personal"
		// (legacy) or "personal_api_key" (canonical post-CredentialType
		// enum). Both are accepted via the default branch — strict-match
		// would have been a regression if the writer side ever emits the
		// other.
		plaintext, _, entryBaseURL, err := p.activeReader.GetPersonalKeyByAlias(binding.KeySourceRef)
		if err != nil {
			logger.Warn("vault: personal key lookup via binding failed", "alias", binding.KeySourceRef, "error", err)
			return out, nil // soft fail
		}
		out.RealKey = plaintext
		out.VirtualKeyID = "personal:" + binding.KeySourceRef
		out.KeyAlias = binding.KeySourceRef
		if entryBaseURL != "" {
			out.BaseURL = entryBaseURL
		} else {
			out.BaseURL = providerDefaultBaseURL(canonicalCode)
		}
		return out, nil
	}
}

// handleAppPipeline is the entry into the Phase 4 App pipeline for requests
// matching /apps/<slug>/v1/... (Tier 0a in proxy.Handle's
// routing order). Today it's a structural stub returning 501 with the
// parsed AppContext for diagnosability — Sprint 2 remaining tasks
// (AKL-204 authn, AKL-205 resolve, AKL-206 egress sanitizer, AKL-207
// pipeline editorial) replace this body with the full pipeline.
//
// Until those land, this handler proves the wiring works end-to-end:
//   1. Tier 0a routing fires (URL parsing — AKL-203)
//   2. The user sees confirmation that slug + protocol parsed correctly
//   3. Counters + logger context include app_slug + app_protocol for
//      operator visibility while the pipeline is being filled in
//
// The 501 is intentional vs 503: per RFC 9110, 501 says "the server does
// not support the functionality required to fulfil the request" which
// matches "this endpoint exists in routing but its handler is not yet
// wired", whereas 503 implies temporary unavailability of a working
// service. Clients (test scripts, integration probes) can distinguish
// "deploy in progress" (501) from "transient downstream failure" (503).
func (p *Proxy) handleAppPipeline(w http.ResponseWriter, r *http.Request, appCtx *apppipe.AppContext, startTime time.Time, logger *slog.Logger, traceID string) {
	_ = startTime
	logger = logger.With("app_slug", appCtx.Slug)

	// 2026-05-25 防呆 (double-v1 base_url misconfiguration):
	//
	// Real-world bug seen with Anthropic Python SDK + claude-mem-style
	// plugin: the SDK appends "/v1/messages" to the configured base_url
	// unconditionally. If the user set base_url to
	// "http://127.0.0.1:27200/apps/<slug>/v1" (the form that works for
	// openai-python, which appends "/chat/completions" without "/v1"),
	// the Anthropic SDK produces
	// "http://127.0.0.1:27200/apps/<slug>/v1/v1/messages" — double v1.
	//
	// ExtractAppPath happily parses this as
	// {Slug:<slug>, StrippedPath:"/v1/messages"}, then the handler
	// prepends "/v1" again on line 921 → outbound URL becomes
	// "https://api.anthropic.com/v1/v1/messages" which Anthropic 404s
	// with "Not Found". The user sees an opaque 404 with no clue that
	// it's a base_url config error on their side.
	//
	// Detection: strippedPath starting with "/v1/" means the inbound URL
	// was /apps/<slug>/v1/v1/... (only the second v1 ends up in
	// strippedPath after the first one was stripped). No legitimate
	// upstream path starts with /v1 (Anthropic uses /messages,
	// /complete; OpenAI uses /chat/completions, /embeddings; none start
	// with another "v1" segment). Safe to reject.
	//
	// Emit a precise, actionable error so the user fixes it in their
	// SDK config rather than blaming AiKey for "404 from upstream".
	if strings.HasPrefix(appCtx.StrippedPath, "/v1/") || appCtx.StrippedPath == "/v1" {
		p.errors.Add(1)
		logger.Warn("app pipeline base_url misconfigured (double /v1)",
			"event.name", "proxy.app.base_url_misconfigured",
			"inbound_path", r.URL.Path,
			"stripped_path", appCtx.StrippedPath,
			"hint", "client base_url likely ends with /v1 AND SDK appends another /v1/<endpoint>",
		)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "BASE_URL_MISCONFIGURED",
			fmt.Sprintf(
				"Your client's base_url has a double /v1/ — received URL %q after stripping "+
					"the app prefix becomes %q, which means the original URL was "+
					"/apps/%s/v1/v1/... — that 'second v1' was added by your SDK on top of the /v1 "+
					"already in your base_url. Fix: drop /v1 from base_url. "+
					"For Anthropic SDK: base_url=\"http://127.0.0.1:27200/apps/%s\" (no trailing /v1). "+
					"For OpenAI SDK: base_url=\"http://127.0.0.1:27200/apps/%s/v1\" (keep /v1 — OpenAI SDK appends /chat/completions without /v1).",
				r.URL.Path, appCtx.StrippedPath, appCtx.Slug, appCtx.Slug, appCtx.Slug,
			))
		return
	}

	// Stage 1: authn — extract bearer, verify Registry membership, check
	// the URL slug matches the token's vault-recorded AppSlug.
	route, authErr := apppipe.Authenticate(r.Header, p.registry, appCtx)
	if authErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline authn failed",
			"error.code", authErr.ErrorCode,
			"event.name", observability.EventProxyRequestAuthFailed,
		)
		writeJSONError(w, authErr.StatusCode, "authentication_error", authErr.ErrorCode, authErr.Message)
		return
	}

	// Stage 2: resolve metadata-only — pick profile scope + load app_records.
	// Binding lookup is deferred to Stage 4 (after body sanitize + model
	// inference); the inferred upstream is the lookup key.
	resolved, resolveErr := apppipe.Resolve(p.appVault, route, appCtx)
	if resolveErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline resolve failed",
			"error.code", resolveErr.ErrorCode,
			"app_key_id", route.AppKeyID,
			"app_kind", route.AppKind,
		)
		writeJSONError(w, resolveErr.StatusCode, "server_error", resolveErr.ErrorCode, resolveErr.Message)
		return
	}

	// Stage 3: sanitize — strip aikey/metadata fields, reject n>1, silent-drop
	// logprobs/seed with warnings. response_format is passed through to the
	// protocol translator (Phase 2 Day 5).
	//
	// Capture the genuine inbound User-Agent BEFORE Stage 5 (which calls
	// oauthInject → forces UA to "claude-cli/2.1.22 (external, cli)" for
	// non-CLI clients). The post-translation WAF re-rewrite below needs
	// to know if the original client was real Claude CLI (skip rewrite)
	// vs a third-party SDK (apply rewrite). Without this snapshot the
	// post-translation check always sees the masked UA.
	inboundUAWasClaudeCode := clientIsClaudeCode(r)

	bodyBytes, bodyErr := io.ReadAll(r.Body)
	if bodyErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline body read failed", "error", bodyErr)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "BODY_READ_FAILED",
			"Could not read request body: "+bodyErr.Error())
		return
	}
	_ = r.Body.Close()

	sanitized, sanitizeCtx, sanitizeErr := apppipe.SanitizeRequestBody(bodyBytes)
	if sanitizeErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline body sanitize failed",
			"error.code", sanitizeErr.ErrorCode,
			"app_key_id", route.AppKeyID,
		)
		writeJSONError(w, sanitizeErr.StatusCode, "invalid_request_error", sanitizeErr.ErrorCode, sanitizeErr.Message)
		return
	}
	for _, w := range sanitizeCtx.Warnings {
		logger.Warn("app pipeline field degraded", "degradation", w, "app_key_id", route.AppKeyID)
	}

	// Stage 4 (Phase 2 Day 7): infer upstream from body.model and look up
	// the binding for (profile, upstream). This replaces the URL-protocol-
	// based binding lookup of Phase 1. The Agent's body.model field is the
	// single routing signal — LangChain-aligned per industry consensus.
	inboundModel := extractModelLazy(sanitized)
	inferredUpstream := provider.InferUpstreamFromModel(inboundModel)
	binding, bindResolveErr := apppipe.ResolveUpstreamBinding(p.appVault, resolved, inferredUpstream)
	if bindResolveErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline upstream-binding resolve failed",
			"error.code", bindResolveErr.ErrorCode,
			"app_key_id", route.AppKeyID,
			"model", inboundModel,
			"inferred_upstream", inferredUpstream,
		)
		writeJSONError(w, bindResolveErr.StatusCode, "invalid_request_error",
			bindResolveErr.ErrorCode, bindResolveErr.Message)
		return
	}

	// B mode normalization (2026-05-23, credential-mode-architecture SPEC §1.1.B):
	// When the binding came from a bound_alias dereference, its ProviderCode
	// may be a brand alias from the vault row (e.g., OAuth provider="claude")
	// rather than the canonical code body.model resolves to ("anthropic").
	// Normalize both sides via providerCanonicalCode — same lockstep
	// canonicalization handleProbePipeline applies for mode C — so downstream
	// stages (provider adapter, WAF inject) see a single canonical value.
	// Mismatch is a caller-side bug (e.g., bound_alias=oauth(anthropic) but
	// body.model=gpt-4); fail loud rather than letting the upstream reject
	// the wrong-provider credential.
	if resolved.AppRecord != nil && resolved.AppRecord.BoundAlias != "" {
		canonicalBound := providerCanonicalCode(binding.ProviderCode)
		canonicalUpstream := providerCanonicalCode(inferredUpstream)
		if canonicalBound != "" && canonicalBound != canonicalUpstream {
			p.errors.Add(1)
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				"BOUND_ALIAS_PROVIDER_MISMATCH",
				"App \""+appCtx.Slug+"\" is bound to alias \""+resolved.AppRecord.BoundAlias+
					"\" (provider=\""+binding.ProviderCode+"\") but body.model resolves to upstream \""+
					inferredUpstream+"\". Use a body.model matching the bound alias's provider, "+
					"or `aikey app update "+appCtx.Slug+" --bound-alias <name>` to re-bind.")
			return
		}
		binding.ProviderCode = canonicalUpstream
	}

	// Capture inbound bearer BEFORE Stage 5 — ResolveBindingCredential calls
	// oauthInject which overwrites r.Header.Authorization with the upstream
	// OAuth access token. If we read it AFTER, `extractRawAuthValue(r)` returns
	// the upstream secret instead of the client-presented token, breaking the
	// audit anchor (virtual_key_hash) AND the first-party probe attribution
	// branch in BuildReportableEvent (BR-rc.5-60 fix relies on the client
	// bearer to reverse-lookup the app slug). Bug surfaced via BR-rc.5-60
	// follow-up 2026-05-25 when manual Trust Check probes kept landing in ODS
	// with app_slug=NULL despite the attribution code being in place.
	inboundBearer := extractRawAuthValue(r)

	// Stage 5: resolve credential from binding (shared with legacy path).
	// p.ResolveBindingCredential walks the same OAuth/team/personal branches
	// used by handlePathPrefixRoute — pinned by oauth_binding_fence_test.go.
	// Mutates r headers via oauthInject on the OAuth path.
	cred, bindErr := p.ResolveBindingCredential(r, binding, inferredUpstream, inferredUpstream, logger)
	if bindErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline credential resolution failed",
			"error.code", bindErr.ErrorCode,
			"app_key_id", route.AppKeyID,
		)
		writeJSONError(w, bindErr.StatusCode, bindErr.ErrorType, bindErr.ErrorCode, bindErr.Message)
		return
	}
	if cred.RealKey == "" {
		p.errors.Add(1)
		writeJSONError(w, http.StatusServiceUnavailable, "server_error", "BINDING_CREDENTIAL_UNRESOLVED",
			"App's binding (profile=\""+resolved.ProfileID+"\", upstream=\""+inferredUpstream+
				"\", source="+binding.KeySourceType+":"+binding.KeySourceRef+
				") could not be resolved to a usable credential. The referenced "+
				"alias or virtual-key may have been deleted. Re-run `aikey app route "+appCtx.Slug+
				"` to repair.")
		return
	}

	// Stage 6: build the ResolvedRoute for serveRoute. Provider /
	// ProviderCode / ProtocolType reflect the BINDING's upstream provider
	// (the inferred-from-model value, equal to binding.ProviderCode by
	// construction in this branch). ProtocolFamily resolves the provider
	// to its wire family via pkg/providerroutes yaml (single source of
	// truth, see ResolvedRoute.ProtocolFamily doc-comment).
	protocolFamily := ""
	if pr, ok := provider.Routes().ByProvider(binding.ProviderCode); ok {
		protocolFamily = pr.Protocol
	}
	appResolvedRoute := &vkeys.ResolvedRoute{
		VirtualKeyID:     route.VirtualKeyID, // "app:<slug>"
		Provider:         binding.ProviderCode,
		BaseURL:          cred.BaseURL,
		KeyAlias:         cred.KeyAlias,
		PlaintextKey:     cred.RealKey,
		OAuthIdentity:    cred.OAuthIdentity,
		AccountID:        cred.OAuthAccountID,
		ProviderCode:     binding.ProviderCode,
		ProtocolType:     binding.ProviderCode,
		ProtocolFamily:   protocolFamily,
		RouteSource:      "app",
		AppSlug:          route.AppSlug,
		AppKind:          route.AppKind,
		AppKeyID:         route.AppKeyID,
		FollowUserActive: route.FollowUserActive,
	}
	if cred.ManagedKey != nil {
		appResolvedRoute.OrgID = cred.ManagedKey.OrgID
		appResolvedRoute.SeatID = cred.ManagedKey.SeatID
		appResolvedRoute.CredentialID = cred.ManagedKey.CredentialID
		appResolvedRoute.CredentialRevision = cred.ManagedKey.CredentialRevision
		appResolvedRoute.VirtualKeyRevision = cred.ManagedKey.VirtualKeyRevision
	}

	// Stage 7: provider adapter selected by the BINDING's upstream protocol.
	prov, err := p.providers.Get(binding.ProviderCode)
	if err != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
			"Unknown upstream provider protocol: "+binding.ProviderCode)
		return
	}

	// Strip /apps/<slug>/v1 prefix → leave only the upstream path part
	// (e.g., "/chat/completions"). serveRoute prepends BaseURL.
	r.URL.Path = "/v1" + appCtx.StrippedPath
	if r.URL.RawPath != "" {
		r.URL.RawPath = r.URL.Path
	}

	// Stage 8 (Phase 2 protocol translation, optional): if inbound wire
	// differs from upstream wire (binding.ProviderCode), translate the
	// request body + arm a response-side closure on the ResolvedRoute.
	// No-op when from == to. Phase 2 中方案 (2026-05-21): inbound wire
	// is inferred from URL path — `/v1/messages` ≡ Anthropic, else
	// OpenAI (see apppipe.InferInboundWire).
	inboundFmt := apppipe.InferInboundWire(appCtx.StrippedPath)
	translateOut, translateErr := apppipe.MaybeTranslateRequest(
		r.Context(),
		p.translatorRegistry,
		appResolvedRoute,
		binding,
		inboundFmt,
		r,
		sanitized,
		inboundModel,
	)
	if translateErr != nil {
		p.errors.Add(1)
		logger.Warn("app pipeline protocol translation failed",
			"error.code", translateErr.ErrorCode,
			"app_key_id", route.AppKeyID,
			"upstream", binding.ProviderCode,
		)
		writeJSONError(w, translateErr.StatusCode, "invalid_request_error", translateErr.ErrorCode, translateErr.Message)
		return
	}
	if translateOut.Engaged {
		logger.Info("app pipeline translation engaged",
			"upstream_format", string(translateOut.UpstreamFormat),
			"app_key_id", route.AppKeyID,
		)
		// Rewrite the upstream path for the target format (e.g.
		// /v1/chat/completions → /v1/messages for Anthropic).
		if canonical := apppipe.CanonicalUpstreamPath(translateOut.UpstreamFormat); canonical != "" {
			r.URL.Path = canonical
			if r.URL.RawPath != "" {
				r.URL.RawPath = canonical
			}
		}
	}

	// Replace request body with the post-translation bytes (or sanitized
	// if no translation engaged — TranslateOutcome.Body is always the
	// final bytes to forward).
	r.Body = io.NopCloser(bytes.NewReader(translateOut.Body))
	r.ContentLength = int64(len(translateOut.Body))

	// Phase 4 fix (2026-05-22, Stage 7 smoke): when OAuth → Anthropic, the
	// WAF body fingerprint must be present in body.system[0]. The body
	// rewriter ran inside ResolveBindingCredential's oauthInject() call
	// above, but at that point r.Body had already been consumed by Stage 3
	// (line 606 io.ReadAll); the rewriter saw an empty body, no-oped, and
	// returned without injecting. Now that r.Body carries the post-
	// translation bytes, re-run the WAF rewriter so the body that actually
	// goes upstream gets the magic-intro + billing-header fingerprint.
	// Without this, Anthropic returns 429 "rate_limit_error" with no
	// anthropic-ratelimit-* headers (business rejection signature, ref
	// workflow/CI/research/oauth-token-response-identity/2026-04-15-oauth-token-response-identity.md).
	if binding.KeySourceType == "personal_oauth_account" &&
		binding.ProviderCode == "anthropic" &&
		!inboundUAWasClaudeCode {
		injectClaudeWAFFingerprintFull(r)
		// injectClaudeWAFFingerprintFull may have rewritten r.Body; sync
		// ContentLength so the reverse proxy reports the correct length
		// to the upstream.
		if r.Body != nil {
			if newBytes, err := io.ReadAll(r.Body); err == nil {
				r.Body = io.NopCloser(bytes.NewReader(newBytes))
				r.ContentLength = int64(len(newBytes))
			}
		}
	}

	// inboundBearer is captured pre-Stage-5 above (moved 2026-05-25 to
	// survive oauthInject's Authorization rewrite — see comment near
	// Stage 5).

	// app_mode tags the credential-resolution path so log readers can tell
	// A vs B mode without re-deriving from follow_user_active + bound_alias
	// fields. SPEC §1.1 / §6.1 anti-example "label deception" was rooted in
	// log fields that didn't distinguish modes; this is the explicit fix.
	appMode := "a"
	if resolved.AppRecord != nil && resolved.AppRecord.BoundAlias != "" {
		appMode = "b"
	}
	logger.Info("app pipeline forwarding upstream",
		"app_key_id", route.AppKeyID,
		"app_kind", route.AppKind,
		"app_mode", appMode,
		"bound_alias", resolved.AppRecord.BoundAlias, // empty in A mode
		"profile_id", resolved.ProfileID,
		"binding_source_type", binding.KeySourceType,
		"upstream_base", cred.BaseURL,
		"upstream", binding.ProviderCode,
		"protocol_family", appResolvedRoute.ProtocolFamily,
	)

	// Phase 4 M2 plugin observer — NotifyStart at App pipeline entry +
	// NotifyEnd at exit. The per-frame NotifySSEEvent dispatch lives
	// inside streamDrainer (gated on the observer registry being
	// attached + ProtocolFamily known) so it sees the byte-identical
	// upstream SSE before ResponseTransform reshapes the chunks.
	//
	// Why we build the RequestContext here (not inside serveRoute):
	// app-specific fields (AppSlug / AppKeyID / AppMode / ProviderID /
	// ProtocolFamily) are only meaningful for the App pipeline branch.
	// serveRoute is shared with the legacy /v1/... + /<provider>/v1/...
	// paths which never need a RequestContext. Wiring here keeps the
	// observer surface contained to the App pipeline by construction.
	//
	// nil observerRegistry ⇒ the Notify* helpers below short-circuit;
	// see Proxy.observerRegistry doc-comment for zero-cost rationale.
	var obsReqCtx *observer.RequestContext
	if p.observerRegistry != nil && p.observerRegistry.Active() > 0 {
		appMode := "isolated"
		if route.FollowUserActive {
			appMode = "follow-active"
		}
		obsReqCtx = &observer.RequestContext{
			AppKeyID:       route.AppKeyID,
			AppSlug:        route.AppSlug,
			AppMode:        appMode,
			// KeyAlias is the vault-side credential alias resolved at this
			// step (e.g. user's "claude" for follow-user-active). trust-local
			// uses it as the alias_name primary aggregation key — without it
			// the report falls back to a synthetic "app:<slug>:<keyid>"
			// alias and PerAliasTrust queries can't surface real-user trust
			// per provider key.
			KeyAlias:       appResolvedRoute.KeyAlias,
			ProviderID:     binding.ProviderCode,
			ProtocolFamily: appResolvedRoute.ProtocolFamily,
			RequestedModel: inboundModel,
			SessionID:      resolveSessionID(r.Header, binding.ProviderCode),
			TraceID:        traceID,
			StartedAt:      startTime,
		}
		// Stash on the route so streamDrainer can pull it out without
		// needing a parallel parameter channel. Tier 1 / Tier 2 routes
		// never set ObserverContext, so the drainer's nil-check
		// short-circuits for legacy paths.
		appResolvedRoute.ObserverContext = obsReqCtx
		appResolvedRoute.ObserverRegistry = p.observerRegistry
		// SPEC §1.4.1: this handler serves the /apps/<slug>/v1/... pipeline
		// so emit under the StreamAppPipeline name. Observers that didn't
		// declare interest in this stream are filtered at Registry level.
		p.observerRegistry.NotifyStart(r.Context(), observer.StreamAppPipeline, obsReqCtx)
	}

	p.serveRoute(w, r, appResolvedRoute, prov, cred.RealKey, inboundBearer, startTime, logger)

	if obsReqCtx != nil {
		latency := int(time.Since(startTime).Milliseconds())
		p.observerRegistry.NotifyEnd(r.Context(), obsReqCtx, latency)
	}
}

// handleProbePipeline is the entry into the Probe pipeline (mode C) for
// requests matching /probe/<alias>/v1/... See SPEC
// `workflow/CI/requirements/2026-05-23-credential-mode-architecture.md` §1.3.
//
// Pipeline stages (parallel to handleAppPipeline but simpler — no
// app_records / follow_user_active / provider-binding indirection):
//
//	1. authn          — first-party constant Bearer check (probepipe.Authenticate)
//	2. resolve alias  — vault.GetAliasCredential → synthetic ProviderBinding
//	3. sanitize body  — strip aikey/* fields, reject n>1 (reuses apppipe)
//	4. infer upstream — body.model → provider; sanity-check matches alias's provider
//	5. resolve cred   — reuses ResolveBindingCredential (shared with App pipeline)
//	6. build route    — synthesize ResolvedRoute with RouteSource="probe"
//	7. translate      — reuses apppipe.MaybeTranslateRequest (no-op when wire matches)
//	8. forward        — same serveRoute as App / legacy pipelines
//
// Why we reuse so much from apppipe: sanitize / translate / ResolveBindingCredential
// don't depend on app concepts (slug / follow_user_active); they operate on
// (ProviderBinding, request) inputs. Sharing them avoids divergence on the
// shared upstream-injection paths (OAuth WAF fingerprint, model translation,
// SSE drain). Probe-specific differences live entirely in stages 1-2 + 6.
func (p *Proxy) handleProbePipeline(w http.ResponseWriter, r *http.Request, probeCtx *probepipe.ProbeContext, startTime time.Time, logger *slog.Logger, traceID string) {
	_ = traceID
	logger = logger.With("probe_alias", probeCtx.AliasName, "routing", "probe")

	// Stage 1: authn — first-party constant Bearer.
	if authErr := probepipe.Authenticate(r.Header); authErr != nil {
		p.errors.Add(1)
		logger.Warn("probe pipeline authn failed",
			"error.code", authErr.ErrorCode,
			"event.name", observability.EventProxyRequestAuthFailed,
		)
		writeJSONError(w, authErr.StatusCode, "authentication_error", authErr.ErrorCode, authErr.Message)
		return
	}

	// Stage 2: resolve alias → synthetic ProviderBinding.
	aliasCred, resolveErr := probepipe.Resolve(p.probeVault, probeCtx)
	if resolveErr != nil {
		p.errors.Add(1)
		logger.Warn("probe pipeline alias resolve failed",
			"error.code", resolveErr.ErrorCode,
		)
		writeJSONError(w, resolveErr.StatusCode, "server_error", resolveErr.ErrorCode, resolveErr.Message)
		return
	}
	binding := aliasCred.Binding

	// Capture the genuine inbound User-Agent BEFORE the credential resolve
	// step (which may call oauthInject and mask the UA). Mirrors the
	// handleAppPipeline pattern; needed for the post-translation WAF rewrite
	// decision below.
	inboundUAWasClaudeCode := clientIsClaudeCode(r)

	// Stage 3: sanitize body (reuses apppipe — same egress rules apply).
	bodyBytes, bodyErr := io.ReadAll(r.Body)
	if bodyErr != nil {
		p.errors.Add(1)
		logger.Warn("probe pipeline body read failed", "error", bodyErr)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "BODY_READ_FAILED",
			"Could not read request body: "+bodyErr.Error())
		return
	}
	_ = r.Body.Close()

	sanitized, sanitizeCtx, sanitizeErr := apppipe.SanitizeRequestBody(bodyBytes)
	if sanitizeErr != nil {
		p.errors.Add(1)
		logger.Warn("probe pipeline body sanitize failed",
			"error.code", sanitizeErr.ErrorCode,
		)
		writeJSONError(w, sanitizeErr.StatusCode, "invalid_request_error", sanitizeErr.ErrorCode, sanitizeErr.Message)
		return
	}
	for _, warning := range sanitizeCtx.Warnings {
		logger.Warn("probe pipeline field degraded", "degradation", warning)
	}

	// Stage 4: infer upstream from body.model and sanity-check it matches the
	// alias's recorded provider. Probing FreySilvaqzs@... (Anthropic OAuth)
	// with a body that says "gpt-4o" is a caller-side bug — fail loud.
	//
	// Compare via canonical codes so brand aliases agree:
	// vault may store "claude" (OAuth) while InferUpstreamFromModel returns
	// "anthropic"; both must reconcile. providerCanonicalCode is the same
	// helper apppipe + path-prefix routing use, so the probe pipeline
	// inherits identical alias semantics with no drift.
	inboundModel := extractModelLazy(sanitized)
	inferredUpstream := provider.InferUpstreamFromModel(inboundModel)
	if inferredUpstream == "" {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "UPSTREAM_UNINFERRABLE",
			"Could not infer upstream provider from body.model. Expected a "+
				"recognized model id (claude-*, gpt-*, kimi-*, ...) so AiKey "+
				"can confirm the alias's provider matches the request.")
		return
	}
	canonicalUpstream := providerCanonicalCode(inferredUpstream)
	canonicalBound := providerCanonicalCode(binding.ProviderCode)
	if canonicalBound != "" && canonicalBound != canonicalUpstream {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "PROBE_PROVIDER_MISMATCH",
			"Alias \""+probeCtx.AliasName+"\" is bound to provider \""+binding.ProviderCode+
				"\" but body.model resolves to upstream \""+inferredUpstream+
				"\". Use a body.model that matches the alias's provider.")
		return
	}
	// Normalize binding's ProviderCode to canonical form so downstream
	// stages (provider adapter lookup, ResolveBindingCredential, translate)
	// see the same code regardless of vault storage convention.
	binding.ProviderCode = canonicalUpstream

	// Capture inbound bearer BEFORE Stage 5 — same reason as handleAppPipeline:
	// ResolveBindingCredential → oauthInject overwrites r.Header.Authorization
	// with the upstream OAuth access token. Reading AFTER returns the upstream
	// secret instead of the client's constant first-party bearer, breaking
	// BR-rc.5-60's probe → app_slug attribution (firstPartyAppSlugForBearer
	// lookup fails because the bearer is no longer the whitelisted constant).
	inboundBearer := extractRawAuthValue(r)

	// Stage 5: resolve credential via the shared App/legacy machinery.
	upstream := binding.ProviderCode
	cred, bindErr := p.ResolveBindingCredential(r, binding, upstream, upstream, logger)
	if bindErr != nil {
		p.errors.Add(1)
		logger.Warn("probe pipeline credential resolution failed",
			"error.code", bindErr.ErrorCode,
			"binding_source_type", binding.KeySourceType,
		)
		writeJSONError(w, bindErr.StatusCode, bindErr.ErrorType, bindErr.ErrorCode, bindErr.Message)
		return
	}
	if cred.RealKey == "" {
		p.errors.Add(1)
		writeJSONError(w, http.StatusServiceUnavailable, "server_error", "BINDING_CREDENTIAL_UNRESOLVED",
			"Alias \""+probeCtx.AliasName+"\" (source="+binding.KeySourceType+":"+
				binding.KeySourceRef+") could not be resolved to a usable credential. "+
				"The referenced personal entry or OAuth account may have been deleted.")
		return
	}

	// Stage 6: build the ResolvedRoute for serveRoute. RouteSource="probe"
	// distinguishes probe traffic from app/legacy in usage_event records;
	// trust-local reads this to attribute probe events to the right pipeline.
	protocolFamily := ""
	if pr, ok := provider.Routes().ByProvider(binding.ProviderCode); ok {
		protocolFamily = pr.Protocol
	}
	probeResolvedRoute := &vkeys.ResolvedRoute{
		VirtualKeyID:     "probe:" + probeCtx.AliasName,
		Provider:         binding.ProviderCode,
		BaseURL:          cred.BaseURL,
		KeyAlias:         cred.KeyAlias,
		PlaintextKey:     cred.RealKey,
		OAuthIdentity:    cred.OAuthIdentity,
		AccountID:        cred.OAuthAccountID,
		ProviderCode:     binding.ProviderCode,
		ProtocolType:     binding.ProviderCode,
		ProtocolFamily:   protocolFamily,
		RouteSource:      "probe",
		FollowUserActive: false, // Probe NEVER follows active — that's the whole point of mode C.
	}
	if cred.ManagedKey != nil {
		probeResolvedRoute.OrgID = cred.ManagedKey.OrgID
		probeResolvedRoute.SeatID = cred.ManagedKey.SeatID
		probeResolvedRoute.CredentialID = cred.ManagedKey.CredentialID
		probeResolvedRoute.CredentialRevision = cred.ManagedKey.CredentialRevision
		probeResolvedRoute.VirtualKeyRevision = cred.ManagedKey.VirtualKeyRevision
	}

	// Stage 7: provider adapter.
	prov, err := p.providers.Get(binding.ProviderCode)
	if err != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
			"Unknown upstream provider: "+binding.ProviderCode)
		return
	}

	// Strip /probe/<alias>/v1 prefix → leave only upstream path.
	r.URL.Path = "/v1" + probeCtx.StrippedPath
	if r.URL.RawPath != "" {
		r.URL.RawPath = r.URL.Path
	}

	// Stage 8: protocol translation (reuses apppipe — no-op when inbound and
	// upstream wire formats already match, which is the common case for
	// first-party degrade-detector calling Anthropic /messages).
	inboundFmt := apppipe.InferInboundWire(probeCtx.StrippedPath)
	translateOut, translateErr := apppipe.MaybeTranslateRequest(
		r.Context(),
		p.translatorRegistry,
		probeResolvedRoute,
		binding,
		inboundFmt,
		r,
		sanitized,
		inboundModel,
	)
	if translateErr != nil {
		p.errors.Add(1)
		logger.Warn("probe pipeline protocol translation failed",
			"error.code", translateErr.ErrorCode,
			"upstream", binding.ProviderCode,
		)
		writeJSONError(w, translateErr.StatusCode, "invalid_request_error", translateErr.ErrorCode, translateErr.Message)
		return
	}
	if translateOut.Engaged {
		logger.Info("probe pipeline translation engaged",
			"upstream_format", string(translateOut.UpstreamFormat),
		)
		if canonical := apppipe.CanonicalUpstreamPath(translateOut.UpstreamFormat); canonical != "" {
			r.URL.Path = canonical
			if r.URL.RawPath != "" {
				r.URL.RawPath = canonical
			}
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(translateOut.Body))
	r.ContentLength = int64(len(translateOut.Body))

	// OAuth → Anthropic WAF fingerprint rewrite (same rationale as App pipeline
	// — body had been consumed at sanitize stage, oauthInject saw empty body
	// and no-oped; re-run on the final post-translation body).
	if binding.KeySourceType == "personal_oauth_account" &&
		binding.ProviderCode == "anthropic" &&
		!inboundUAWasClaudeCode {
		injectClaudeWAFFingerprintFull(r)
		if r.Body != nil {
			if newBytes, err := io.ReadAll(r.Body); err == nil {
				r.Body = io.NopCloser(bytes.NewReader(newBytes))
				r.ContentLength = int64(len(newBytes))
			}
		}
	}

	// inboundBearer captured pre-Stage-5 above (must precede oauthInject).

	logger.Info("probe pipeline forwarding upstream",
		"binding_source_type", binding.KeySourceType,
		"upstream_base", cred.BaseURL,
		"upstream", binding.ProviderCode,
		"protocol_family", probeResolvedRoute.ProtocolFamily,
		"alias_kind", aliasCred.AliasKind,
	)

	// Observer wiring (SPEC §1.4 stream = probe). Same pattern as
	// handleAppPipeline — Registry filters per-observer by Streams
	// declaration, so observers that didn't subscribe to probe (e.g.
	// rhythm with Streams=[app_pipeline]) get nothing; ndjson-fanout
	// (Streams=AllStreams()) writes the event to subscribers' files.
	var obsReqCtx *observer.RequestContext
	if p.observerRegistry != nil && p.observerRegistry.Active() > 0 {
		obsReqCtx = &observer.RequestContext{
			KeyAlias:       probeResolvedRoute.KeyAlias,
			ProviderID:     binding.ProviderCode,
			ProtocolFamily: probeResolvedRoute.ProtocolFamily,
			RequestedModel: inboundModel,
			SessionID:      resolveSessionID(r.Header, binding.ProviderCode),
			TraceID:        traceID,
			StartedAt:      startTime,
		}
		probeResolvedRoute.ObserverContext = obsReqCtx
		probeResolvedRoute.ObserverRegistry = p.observerRegistry
		p.observerRegistry.NotifyStart(r.Context(), observer.StreamProbe, obsReqCtx)
	}

	p.serveRoute(w, r, probeResolvedRoute, prov, cred.RealKey, inboundBearer, startTime, logger)

	if obsReqCtx != nil {
		latency := int(time.Since(startTime).Milliseconds())
		p.observerRegistry.NotifyEnd(r.Context(), obsReqCtx, latency)
	}
}

// handlePathPrefixRoute resolves the active key for providerCode and forwards
// the request with the provider prefix stripped from the path.
// Called when the request path starts with a known provider prefix
// (e.g., /anthropic/v1/messages → strip /anthropic → forward to Anthropic API).
func (p *Proxy) handlePathPrefixRoute(w http.ResponseWriter, r *http.Request, providerCode, strippedPath string, startTime time.Time, logger *slog.Logger, traceID string) {
	logger = logger.With("provider", providerCode, "routing", "path-prefix")

	// 2026-04-29 namespace-authority early hard-fail. Run BEFORE the
	// activeReader nil check so malformed `aikey_*` tokens always fail
	// loud with TOKEN_INVALID — independent of vault wiring state. This
	// also keeps the proxy's behavior consistent across editions (Personal
	// without active vault still rejects clearly-bad aikey tokens).
	if rawAuth := extractRawAuthValue(r); rawAuth != "" {
		switch ClassifyToken(rawAuth) {
		case TokenInvalid:
			p.errors.Add(1)
			logger.Warn("aikey_* token form invalid (namespace authority)",
				"event.name", observability.EventProxyRequestAuthFailed,
			)
			writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
				"Token is in the aikey_ namespace but doesn't match any recognized form. "+
					"Run 'aikey route' to see valid tokens.")
			return
		case Tier1App:
			// 2026-05-20 AKL-208: App bearer at provider-prefix URL is the
			// wrong path. Reject precisely BEFORE the activeReader nil check
			// so the user-actionable hint surfaces consistently across
			// editions (including Personal without active vault). The
			// downstream Tier1App branch in this function would otherwise
			// be unreachable in editions without activeReader.
			p.errors.Add(1)
			writeJSONError(w, http.StatusUnauthorized, "authentication_error", "APP_TOKEN_WRONG_PATH",
				"App bearer tokens must be sent to /apps/<slug>/v1/... URLs, "+
					"not /"+providerCode+"/v1/... Use the OPENAI_BASE_URL value printed "+
					"by `aikey app authorize <slug>` for the correct URL.")
			return
		}
	}

	if p.activeReader == nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusServiceUnavailable, "server_error", "ACTIVE_KEY_NOT_SUPPORTED",
			"Path-prefix routing is not available (vault does not support active key config).")
		return
	}

	var realKey, baseURL, protocolType, virtualKeyID string
	var mk *vault.ManagedKey      // populated when resolved via team key (for org metadata)
	var oauthIdentity, oauthAccountID string // populated when resolved via OAuth account
	// keyAlias carries the vault-entry alias for personal / BYOK routes so the
	// reporter's deriveKeyLabel shows "my-kimi-key" instead of a truncated
	// virtual_key_id like "personal:my-…". Team keys have no per-binary alias
	// (ManagedKey stores VK id, not label); OAuth uses OAuthIdentity instead.
	var keyAlias string

	// Normalise brand aliases ("claude" → "anthropic") before vault lookup so
	// the query matches the provider_code stored by the server.
	canonicalCode := providerCanonicalCode(providerCode)

	// Protocol type is determined by the URL path provider code — the user's
	// intent is explicit (e.g. /anthropic/v1/messages → Anthropic protocol).
	// This is authoritative for both team and personal keys.
	protocolType = providerToProtocol(canonicalCode)

	// ── 2026-04-29 prefix rename: namespace-authority dispatch ─────────────
	// `aikey_*` tokens are AiKey's routing namespace; proxy is the
	// authoritative decision point. Only specific subforms (team, personal,
	// probe, active) are valid; anything else in the namespace returns
	// TOKEN_INVALID immediately. Non-`aikey_*` tokens (native provider
	// tokens from Claude CLI / Cursor) fall through to the default binding.
	// See dispatch.go ClassifyToken for the full namespace rules.
	rawAuthValue := extractRawAuthValue(r)
	dispatchAction := ClassifyToken(rawAuthValue)

	// Hard-fail any `aikey_*` token whose subform we don't recognize. This
	// catches: aikey_route_* (reserved namespace, not implemented), unknown
	// aikey_* prefixes (typos / future-extension residue), legacy aikey_vk_*
	// (fully removed post-migration), malformed aikey_personal_<non-64-hex>.
	// Falling through silently would mask config bugs — exactly what the
	// namespace-authority principle forbids.
	if dispatchAction == TokenInvalid {
		p.errors.Add(1)
		logger.Warn("aikey_* token form invalid (namespace authority)",
			"event.name", observability.EventProxyRequestAuthFailed,
		)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Token is in the aikey_ namespace but doesn't match any recognized form. "+
				"Run 'aikey route' to see valid tokens.")
		return
	}

	// Tier2ProbeRaw — pre-save proxy probe (2026-05-26, see probe_raw.go +
	// roadmap20260320/技术实现/update/20260526-pre-save-proxy-probe-raw.md).
	// MUST be dispatched BEFORE Tier1 / Tier3 paths because handleProbeRaw
	// short-circuits all vault binding lookups — caller's plaintext bearer
	// in X-Aikey-Probe-Bearer is the auth source. Self-contained pipeline:
	// no reporter / WAL / GetProviderBinding involvement (audit-able as one
	// file in probe_raw.go).
	if dispatchAction == Tier2ProbeRaw {
		// Strip provider prefix so handleProbeRaw forwards using the path
		// the caller actually requested (e.g. /anthropic/v1/messages →
		// /v1/messages joined onto upstream base URL).
		p.handleProbeRaw(w, r, canonicalCode, strippedPath, logger)
		return
	}

	// Tier 1: aikey_team_<vk_id> or aikey_personal_<64-hex> — resolve via Registry.
	// (Tier1App was handled early-fail above per AKL-208 for edition consistency.)
	if dispatchAction == Tier1Team || dispatchAction == Tier1Personal {
		route := p.registry.Resolve(rawAuthValue)
		if route == nil {
			p.errors.Add(1)
			logger.Warn("tier-1 bearer not in registry",
				"event.name", observability.EventProxyRequestAuthFailed,
			)
			writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
				"Route token not found in registry. Run 'aikey route' to see available tokens.")
			return
		}

		// Provider compatibility check: token's provider must match path's provider.
		if !isProviderCompatible(route, canonicalCode) {
			p.errors.Add(1)
			writeJSONError(w, http.StatusForbidden, "permission_error", "PROVIDER_MISMATCH",
				"Route token is bound to provider '"+route.ProviderCode+
					"', but request path indicates '"+canonicalCode+
					"'. Use the correct path prefix or a different token.")
			return
		}

		// Strip provider prefix from path.
		r.URL.Path = strippedPath
		if r.URL.RawPath != "" {
			r.URL.RawPath = strippedPath
		}

		// Resolve real key.
		var tokenRealKey string
		if route.PlaintextKey != "" {
			tokenRealKey = route.PlaintextKey
		} else if route.KeyAlias == "__oauth__" {
			// OAuth route token — broker handles credential injection in serveRoute.
			tokenRealKey = "__oauth__"
			oauthIdentity = route.OAuthIdentity
			oauthAccountID = route.AccountID
		} else {
			var err error
			tokenRealKey, err = p.vault.GetSecret(route.KeyAlias)
			if err != nil {
				p.errors.Add(1)
				writeJSONError(w, http.StatusServiceUnavailable, "server_error", "SECRET_NOT_CONFIGURED",
					"Provider API Key '"+route.KeyAlias+"' is not in the vault. Run: aikey add "+route.KeyAlias)
				return
			}
		}

		// Override baseURL from path's provider default if route doesn't specify one.
		tokenBaseURL := route.BaseURL
		if tokenBaseURL == "" {
			tokenBaseURL = providerDefaultBaseURL(canonicalCode)
		}

		prov, err := p.providers.Get(protocolType)
		if err != nil {
			p.errors.Add(1)
			writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
				"Unknown provider protocol: "+protocolType)
			return
		}

		tokenRoute := &vkeys.ResolvedRoute{
			VirtualKeyID:  route.VirtualKeyID,
			Provider:      providerCode,
			BaseURL:       tokenBaseURL,
			PlaintextKey:  tokenRealKey,
			ProviderCode:  canonicalCode,
			ProtocolType:  protocolType,
			OrgID:         route.OrgID,
			AccountID:     route.AccountID,
			SeatID:        route.SeatID,
			OAuthIdentity: oauthIdentity,
			AllowedModels: route.AllowedModels, // Why: serveRoute checks this field for model allowlist enforcement
			// Why: KeyAlias is the user-facing label for team/personal/BYOK
			// routes (see deriveKeyLabel in reportable.go). Without copying
			// it through, path-prefix receipts degrade to a truncated
			// virtual_key_id like `vk_abc…` instead of the key's alias.
			// OAuth uses OAuthIdentity instead so we skip KeyAlias for the
			// sentinel __oauth__ value.
			KeyAlias: func() string {
				if route.KeyAlias == "__oauth__" {
					return ""
				}
				return route.KeyAlias
			}(),
			// Why: route_source drives deriveKeyLabel's classification — OAuth
			// routes pick OAuthIdentity (user's email), personal/team pick
			// KeyAlias. Without this copy, reportable.go's OrgID-based fallback
			// mis-classifies OAuth as "personal" and the UI shows a truncated
			// VK id like `oauth:sessio` instead of the user's email.
			RouteSource: route.RouteSource,
		}

		// Handle OAuth credential injection if this is an OAuth route token.
		if tokenRealKey == "__oauth__" && oauthAccountID != "" && p.broker != nil {
			if err := p.broker.EnsureFresh(r.Context(), oauthAccountID); err != nil {
				p.errors.Add(1)
				writeJSONError(w, http.StatusUnauthorized, "auth_error", "OAUTH_TOKEN_EXPIRED",
					err.Error()+"\n  Run: aikey auth login "+providerCode)
				return
			}
			cred, err := p.broker.ResolveCredential(r.Context(), oauthAccountID)
			if err != nil {
				p.errors.Add(1)
				writeJSONError(w, http.StatusServiceUnavailable, "server_error", "OAUTH_RESOLVE_FAILED", err.Error())
				return
			}
			// Why override for openai: Codex OAuth uses chatgpt.com/backend-api/codex
			// (Responses API), NOT api.openai.com/v1 (Chat Completions API).
			if canonicalCode == "openai" {
				tokenRoute.BaseURL = "https://chatgpt.com/backend-api/codex"
			}
			oauthInject(r, cred, canonicalCode)
		}

		// SPEC §1.4.1 user_chat — see serveRouteWithObserver docstring.
		p.serveRouteWithObserver(w, r, tokenRoute, prov, tokenRealKey, rawAuthValue, startTime, logger,
			observer.StreamUserChat, traceID)
		return
	}

	// ── aikey_probe_<alias> sentinel ────────────────────────────────────
	//
	// Introduced 2026-04-22 (Stage 3 of connectivity-probe-through-proxy).
	// Renamed in the 2026-04-29 prefix rename refactor — was previously a
	// dedicated `_alias_` suffix form, now `aikey_probe_<alias>`.
	//
	// Why: `aikey test <alias>` and the shell wrapper preflight (called
	// before every `claude` / `codex`) must probe a specific personal API
	// key without the CLI touching the vault. The CLI cannot ask for the
	// master password on every invocation — that's terrible UX for a
	// wrapper that runs on every command. Proxy already holds the vault
	// derived key in memory from its own startup password prompt, so it
	// can decrypt any personal alias on demand.
	//
	// Unlike the no-bearer fallback below — which resolves whichever
	// personal/team/OAuth binding is ACTIVE for canonicalCode — this
	// sentinel tests EXACTLY the alias the caller named. That fixes the
	// 2026-04-22 caveat where probing an inactive personal key silently
	// exercised the active one.
	//
	// Security: proxy is bound to 127.0.0.1, so any caller already has
	// local-host equivalence — this is the same trust boundary that lets
	// `claude` runtime hit `127.0.0.1:<port>/anthropic/v1/...` without
	// presenting credentials. No new attack surface.
	if dispatchAction == Tier2Probe {
		alias := strings.TrimPrefix(rawAuthValue, "aikey_probe_")
		if alias == "" {
			p.errors.Add(1)
			writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
				"aikey_probe_ sentinel missing alias suffix")
			return
		}

		// ── OAuth probe path (2026-04-29 fix A — bugfix/2026-04-29-oauth-probe-tier2-503.md) ──
		//
		// CLI sends `aikey_probe_<account_id>` for OAuth credentials too
		// (connectivity/mod.rs:243 oauth_target builds bearer this way).
		// account_id looks like `session_*`. Without this branch the code
		// below tries GetPersonalKeyByAlias("session_xxx"), fails, returns
		// 503 — the user-facing "claude → ... 503" red row in `aikey doctor`.
		//
		// Try OAuth account lookup first (cheap status check via broker);
		// only fall through to personal-key lookup if it's not a known
		// OAuth account. This preserves Tier3 active-OAuth's documented
		// flow (proxy refreshes token, attaches persona headers, forwards)
		// for the probe path too — connectivity/mod.rs:84 explicitly
		// promises this behavior.
		if p.broker != nil {
			if _, statusErr := p.broker.GetAccountStatus(r.Context(), alias); statusErr == nil {
				// OAuth account recognized — refresh + forward
				if err := p.broker.EnsureFresh(r.Context(), alias); err != nil {
					p.errors.Add(1)
					logger.Warn("oauth probe: EnsureFresh failed",
						"account_id", alias, "error", err,
						"event.name", observability.EventProxyRequestVaultFailed,
					)
					writeJSONError(w, http.StatusUnauthorized, "auth_error", "OAUTH_TOKEN_EXPIRED",
						err.Error()+"\n  Run: aikey auth login "+providerCode)
					return
				}
				cred, err := p.broker.ResolveCredential(r.Context(), alias)
				if err != nil {
					p.errors.Add(1)
					logger.Error("oauth probe: ResolveCredential failed",
						"account_id", alias, "error", err)
					writeJSONError(w, http.StatusServiceUnavailable, "server_error",
						"OAUTH_RESOLVE_FAILED", err.Error())
					return
				}

				// BaseURL: same rule as Tier3 active-OAuth path (proxy.go:629).
				// openai OAuth uses chatgpt.com/backend-api/codex (Codex API),
				// not api.openai.com (API-key path).
				var oauthBase string
				if canonicalCode == "openai" {
					oauthBase = "https://chatgpt.com/backend-api/codex"
				} else {
					oauthBase = providerDefaultBaseURL(canonicalCode)
				}
				oauthInject(r, cred, canonicalCode)

				identityTag := cred.Identity
				if identityTag == "" {
					identityTag = alias
				}
				logger.Info("oauth probe: forwarding request",
					"provider", canonicalCode,
					"identity", identityTag,
					"account_id", alias,
					"routing", "tier2-probe",
				)

				// Strip provider prefix (e.g. /anthropic/v1/messages →
				// /v1/messages) before forwarding — same as personal-probe
				// fallback below.
				r.URL.Path = strippedPath
				if r.URL.RawPath != "" {
					r.URL.RawPath = strippedPath
				}

				prov, err := p.providers.Get(protocolType)
				if err != nil {
					p.errors.Add(1)
					writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
						"Unknown provider protocol: "+protocolType)
					return
				}

				oauthRoute := &vkeys.ResolvedRoute{
					VirtualKeyID:  "oauth:" + alias,
					Provider:      providerCode,
					BaseURL:       oauthBase,
					PlaintextKey:  "__oauth__", // sentinel — header injection done by oauthInject above
					ProviderCode:  canonicalCode,
					ProtocolType:  protocolType,
					KeyAlias:      "", // OAuth uses Identity, not alias
					RouteSource:   "oauth",
					OAuthIdentity: identityTag,
					AccountID:     alias, // OAuth account_id; correct field name (not OAuthAccountID)
				}
				// SPEC §1.4.1 user_chat — see serveRouteWithObserver docstring.
				p.serveRouteWithObserver(w, r, oauthRoute, prov, "__oauth__", rawAuthValue, startTime, logger,
					observer.StreamUserChat, traceID)
				return
			}
			// not an OAuth account — fall through to personal-key lookup below
		}

		plaintext, entryProviderCode, entryBaseURL, err := p.activeReader.GetPersonalKeyByAlias(alias)
		if err != nil {
			p.errors.Add(1)
			logger.Warn("personal-alias sentinel: vault lookup failed",
				"alias", alias, "error", err,
				"event.name", observability.EventProxyRequestVaultFailed,
			)
			writeJSONError(w, http.StatusServiceUnavailable, "server_error", "SECRET_NOT_CONFIGURED",
				"Personal key '"+alias+"' not found or could not be decrypted. Run: aikey list")
			return
		}

		// Derive baseURL: entry's custom URL > entry's stored provider default >
		// path-prefix canonical default. The last rung matters for personal
		// keys that are bound to multiple providers (one alias, several
		// provider_code rows via the bindings table) — path prefix
		// disambiguates at probe time.
		resolvedBase := entryBaseURL
		if resolvedBase == "" && entryProviderCode != "" {
			resolvedBase = providerDefaultBaseURL(entryProviderCode)
		}
		if resolvedBase == "" {
			resolvedBase = providerDefaultBaseURL(canonicalCode)
		}

		prov, err := p.providers.Get(protocolType)
		if err != nil {
			p.errors.Add(1)
			writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
				"Unknown provider protocol: "+protocolType)
			return
		}

		// Strip provider prefix (e.g. /anthropic/v1/messages → /v1/messages)
		// before forwarding, matching the tier-1 (Registry) branch behaviour.
		r.URL.Path = strippedPath
		if r.URL.RawPath != "" {
			r.URL.RawPath = strippedPath
		}

		aliasRoute := &vkeys.ResolvedRoute{
			VirtualKeyID: "personal:" + alias,
			Provider:     providerCode,
			BaseURL:      resolvedBase,
			PlaintextKey: plaintext,
			ProviderCode: canonicalCode,
			ProtocolType: protocolType,
			KeyAlias:     alias,
			// RouteSource = "personal" matches what personalTokenToRoute uses
			// so reportable.go's label classification stays consistent
			// regardless of which path produced the route.
			RouteSource: "personal",
		}
		// SPEC §1.4.1 user_chat — see serveRouteWithObserver docstring.
		p.serveRouteWithObserver(w, r, aliasRoute, prov, plaintext, rawAuthValue, startTime, logger,
			observer.StreamUserChat, traceID)
		return
	}

	// ── No auth header: fall through to default binding ────────────────────

	// ── v1.0.2: try provider binding first ─────────────────────────────────
	// The new model stores per-provider primary key selection in
	// user_profile_provider_bindings. If a binding exists, resolve directly
	// via the shared resolveBindingCredential helper (AKL-207). The helper
	// also serves the App pipeline so both paths produce identical
	// credential records — see helper docstring for per-KeySourceType semantics.
	binding, _ := p.activeReader.GetProviderBinding(canonicalCode)
	if binding != nil {
		cred, bindErr := p.ResolveBindingCredential(r, binding, providerCode, canonicalCode, logger)
		if bindErr != nil {
			// OAuth path: writeJSONError + return (helper does NOT increment
			// p.errors because the caller's view of "what's an error" may
			// differ — we increment here to keep the metric semantics
			// identical to the pre-refactor inline code).
			p.errors.Add(1)
			writeJSONError(w, bindErr.StatusCode, bindErr.ErrorType, bindErr.ErrorCode, bindErr.Message)
			return
		}
		// Soft-fail path (team / personal with empty cred): RealKey="" leaves
		// the variables blank below and the legacy fallback block fires.
		// OAuth-success path: cred fields populated, RealKey="__oauth__".
		realKey = cred.RealKey
		virtualKeyID = cred.VirtualKeyID
		keyAlias = cred.KeyAlias
		baseURL = cred.BaseURL
		oauthIdentity = cred.OAuthIdentity
		oauthAccountID = cred.OAuthAccountID
		if cred.ManagedKey != nil {
			mk = cred.ManagedKey
		}
	}

	// ── Legacy fallback: active team key → active personal key ─────────────
	// For backward compatibility with pre-v1.0.2 vaults that don't have the
	// user_profile_provider_bindings table.
	if realKey == "" {
		var err error
		mk, err = p.activeReader.GetActiveTeamKeyByProvider(canonicalCode)
		if err != nil {
			p.errors.Add(1)
			logger.Error("vault: active team key lookup failed", "error", err)
			writeJSONError(w, http.StatusServiceUnavailable, "server_error", "VAULT_ERROR", err.Error())
			return
		}

		if mk != nil {
			realKey = mk.PlaintextKey
			virtualKeyID = mk.VirtualKeyID
			// 2026-05-09: same alias surfacing as the binding-driven team
			// branch above, for the legacy fallback (pre-v1.0.2 vaults
			// without user_profile_provider_bindings).
			keyAlias = mk.LocalAlias
			if url, ok := mk.ProviderBaseURLs[canonicalCode]; ok && url != "" {
				baseURL = url
			} else if url, ok := mk.ProviderBaseURLs[providerCode]; ok && url != "" {
				baseURL = url
			} else {
				baseURL = mk.BaseURL
			}
		} else {
			cfg, err := p.activeReader.GetActiveKeyConfig()
			if err != nil {
				p.errors.Add(1)
				logger.Error("vault: active key config read failed", "error", err)
				writeJSONError(w, http.StatusServiceUnavailable, "server_error", "VAULT_ERROR", err.Error())
				return
			}
			if cfg != nil && cfg.KeyType == "personal" {
				supported := len(cfg.Providers) == 0
				for _, code := range cfg.Providers {
					if strings.EqualFold(providerCanonicalCode(code), canonicalCode) {
						supported = true
						break
					}
				}
				if supported {
					plaintext, pcode, entryBaseURL, err := p.activeReader.GetPersonalKeyByAlias(cfg.KeyRef)
					if err != nil {
						p.errors.Add(1)
						logger.Error("vault: personal key read failed", "alias", cfg.KeyRef, "error", err)
						writeJSONError(w, http.StatusServiceUnavailable, "server_error", "VAULT_ERROR", err.Error())
						return
					}
					realKey = plaintext
					virtualKeyID = "personal:" + cfg.KeyRef
					keyAlias = cfg.KeyRef
					if entryBaseURL != "" {
						baseURL = entryBaseURL
					} else if pcode != "" {
						baseURL = providerDefaultBaseURL(pcode)
					} else {
						baseURL = providerDefaultBaseURL(canonicalCode)
					}
				}
			}
		}
	}

	if realKey == "" {
		p.errors.Add(1)
		logger.Warn("no active key for provider")
		writeJSONError(w, http.StatusServiceUnavailable, "server_error", "NO_ACTIVE_KEY",
			"No active key for '"+providerCode+"'. Run 'aikey use <key>'.")
		return
	}

	// Resolve provider adapter by protocol type (derived from URL path).
	prov, err := p.providers.Get(protocolType)
	if err != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
			"Unknown provider protocol: "+protocolType+" (from path: "+providerCode+")")
		return
	}

	// Strip provider prefix from path before forwarding.
	r.URL.Path = strippedPath
	if r.URL.RawPath != "" {
		r.URL.RawPath = strippedPath
	}

	route := &vkeys.ResolvedRoute{
		VirtualKeyID: virtualKeyID,
		Provider:     providerCode,
		BaseURL:      baseURL,
		PlaintextKey: realKey,
		ProviderCode: canonicalCode,
		ProtocolType: protocolType,
		// Why: for personal/BYOK path-prefix routes, keyAlias was captured
		// above at vault-lookup time. Without this field, reportable.go's
		// deriveKeyLabel falls back to truncating VirtualKeyID (e.g.
		// "personal:my-kimi-…" instead of "my-kimi-key"). Team & OAuth
		// paths leave this empty because they label via different fields
		// (ManagedKey has no alias; OAuth uses OAuthIdentity).
		KeyAlias: keyAlias,
	}
	// Populate org/account/seat from managed key so usage events carry the correct org_id.
	if mk != nil {
		route.OrgID = mk.OrgID
		route.AccountID = mk.OwnerAccountID
		route.SeatID = mk.SeatID
	}
	// OAuth: carry identity + account_id so usage events can identify the account.
	if oauthAccountID != "" {
		route.AccountID = oauthAccountID
		route.OAuthIdentity = oauthIdentity
	}
	// Why: classify so reportable.go's deriveKeyLabel picks the right label
	// field (OAuthIdentity for oauth, KeyAlias for team/personal). Without
	// this, the OrgID fallback in reportable.go mis-classifies OAuth personal
	// requests as "personal" and produces truncated labels like `oauth:sessio`
	// instead of the user's email. Order matters: OAuth wins even when a team
	// managed-key lookup happens to side-populate mk for the same account.
	switch {
	case oauthAccountID != "":
		route.RouteSource = "oauth"
	case mk != nil:
		route.RouteSource = "team"
	default:
		route.RouteSource = "personal"
	}

	// 2026-04-29 prefix rename: receipt token rebuilt from virtualKeyID for
	// usage reporting only (not auth). At this code path virtualKeyID has
	// already been resolved/normalized upstream (via the registry which
	// itself goes through supervisor.NormalizeTeamToken at load time), so
	// simple concat is safe — the registry guarantees no historical-prefix
	// residue. Avoid importing supervisor here to prevent a package cycle.
	// SPEC §1.4.1 user_chat — see serveRouteWithObserver docstring.
	p.serveRouteWithObserver(w, r, route, prov, realKey, "aikey_team_"+virtualKeyID, startTime, logger,
		observer.StreamUserChat, traceID)
}

// serveRoute executes the forwarding pipeline (streaming detection, transport
// selection, reverse proxy) shared by token-based and path-prefix routing.
func (p *Proxy) serveRoute(w http.ResponseWriter, r *http.Request, route *vkeys.ResolvedRoute, prov provider.Provider, realKey string, bearerToken string, startTime time.Time, logger *slog.Logger) {
	// Why: extractModel also stashes the parsed model into the `x-aikey-model`
	// request header, which buildBaseEvent later reads to populate ev.Model.
	// Historically this was only called inside the allowlist check (`len(route.AllowedModels) > 0`),
	// so OAuth / personal routes without an allowlist left `ev.Model` empty
	// and the UI showed `model: null`. Call unconditionally — it's cheap
	// (single JSON decode of an already-buffered body).
	_ = extractModel(r)

	// 6. Detect streaming.
	streaming := isStreamingRequest(r)

	// 6b. Optional: stash raw request body for the 4xx debug-capture path
	// (gated by AIKEY_PROXY_DEBUG_4XX_BODIES). No-op when flag is off, so
	// hot path stays untouched. Must run AFTER extractModel — extractModel
	// has already re-buffered r.Body once, our stash reads from the buffer
	// and re-buffers again.
	stashRequestBodyForDebug(r)

	// 6a. Inject stream_options.include_usage=true for /chat/completions only.
	// Why: OpenAI-compatible streaming responses only include token usage in the
	// final SSE chunk when this option is set. Without it, all token counts are 0.
	// Only /chat/completions supports this; newer endpoints like /responses
	// (used by Codex) reject it as unknown_parameter.
	if streaming && prov.Name() != "anthropic" && strings.HasSuffix(r.URL.Path, "/chat/completions") {
		injectStreamUsageOption(r)
	}

	// 7. Store metadata in context for post-processing.
	// For streaming requests, bridge the HTTP/1.1 close-notifier to a context
	// so the streamDrainer can abort the upstream call when the client
	// disconnects mid-stream (HTTP/1.1 does not cancel r.Context() until
	// ServeHTTP returns, which is too late to interrupt upstream.Read).
	reqBase := r.Context()
	if streaming {
		//nolint:staticcheck // CloseNotifier is the only reliable HTTP/1.1 disconnect signal
		if cn, ok := w.(http.CloseNotifier); ok {
			cancelCtx, cancel := context.WithCancel(reqBase)
			defer cancel()
			// Isolated: per-request disconnect watcher. A panic here only
			// breaks one streaming request's mid-stream cancel behavior.
			observability.GoSafe("proxy.request.close_notifier", observability.Isolated, func() {
				select {
				case <-cn.CloseNotify(): //nolint:staticcheck
					cancel()
				case <-cancelCtx.Done():
				}
			})
			reqBase = cancelCtx
		}
	}
	ctx := context.WithValue(reqBase, ctxKeyRoute, route)
	ctx = context.WithValue(ctx, ctxKeyStartTime, startTime)
	ctx = context.WithValue(ctx, ctxKeyIsStreaming, streaming)
	r = r.WithContext(ctx)

	// 8. Build inner transport.
	// Non-streaming: detach from the client context so the upstream call
	// completes even if the client disconnects — the provider has already
	// started generating and will charge for it regardless.
	// Streaming: keep the client context. When the client disconnects the
	// upstream TCP connection is released so the provider stops generation
	// and stops billing. Partial token usage is still recorded by the drainer.
	inner := p.transport
	if inner == nil {
		inner = http.DefaultTransport
		logger.Debug("using default transport (no custom transport set)")
	} else {
		logger.Debug("using custom transport (upstream proxy)")
	}
	var transport http.RoundTripper = inner
	if !streaming {
		transport = &detachedTransport{
			inner:      inner,
			proxyCtx:   p.proxyCtx,
			maxTimeout: p.UpstreamTimeout,
		}
	}

	logger.Debug("forwarding request", "base_url", route.BaseURL, "path", r.URL.Path, "provider_code", route.ProviderCode)

	// 9. Build and execute reverse proxy.
	rp := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			if realKey == "__oauth__" {
				// OAuth: headers already injected by oauthInject() — only set upstream URL.
				// BaseURL may contain a path prefix (e.g. https://api.kimi.com/coding)
				// that must be prepended to the request path.
				if u, err := url.Parse(route.BaseURL); err == nil {
					req.URL.Scheme = u.Scheme
					req.URL.Host = u.Host
					req.Host = u.Host
					if u.Path != "" && u.Path != "/" {
						req.URL.Path = strings.TrimRight(u.Path, "/") + req.URL.Path
					}
				}
			} else {
				if err := prov.RewriteRequest(req, realKey, route.BaseURL); err != nil {
					logger.Error("rewrite request failed", "error", err)
				}
			}
			// Remove hop-by-hop headers the proxy shouldn't forward.
			req.Header.Del("X-Forwarded-For")

			// Strip AiKey-internal annotations before forwarding. These are
			// stashed onto the incoming request by extractModel() /
			// stashExtractedFields() for downstream usage-event recording
			// (see stashExtractedFields, proxy.go:1436). They must NOT
			// reach the upstream provider — Anthropic's OAuth WAF, in
			// particular, treats unrecognised headers as a persona signal
			// that the request isn't a real Claude Code session, returning
			// 429 with no X-RateLimit-Reset (business rejection signature).
			// Strip the whole `x-aikey-*` namespace so future internal
			// annotations don't repeat this leak.
			for k := range req.Header {
				if len(k) >= 8 && strings.EqualFold(k[:8], "X-Aikey-") {
					req.Header.Del(k)
				}
			}
			// Why: tell upstream we only accept identity (uncompressed) so the
			// drainer and non-streaming token extractor can parse the body
			// directly. Anthropic's OAuth endpoint in particular returns
			// Content-Encoding: gzip for SSE streams, which made
			// ExtractTokens see gzip magic bytes (1f8b08...) and return 0/0.
			// Trade-off: slightly more bandwidth on the proxy-upstream hop,
			// but we're usually local loopback or a fast VPC so this is fine,
			// and unambiguous token counting is more valuable than saving a
			// few KB per request.
			req.Header.Set("Accept-Encoding", "identity")

			// Optional upstream-headers diagnostic capture. The toggle is
			// resolved through three layers (API > env > compile); see
			// debug_upstream.go for semantics. Logs the final method, URL,
			// and headers — the snapshot AFTER all rewrites (path strip,
			// OAuth Bearer + persona, Accept-Encoding override), so what
			// you see is what goes on the wire. Authorization / x-api-key
			// are masked.
			if debugUpstreamHeadersEnabled() {
				logger.Info("upstream request snapshot",
					"event.name", "proxy.request.upstream_headers",
					"method", req.Method,
					"url", req.URL.String(),
					"headers", maskAuthHeaders(req.Header),
					"request_body", truncateBodyForLog(debugRequestBodyFromContext(r.Context())),
				)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			// Upstream-headers debug toggle: log a "response snapshot" with
			// status + body + selected response headers (rate-limit + retry
			// hints) for ANY status code. Why every status, not just 4xx:
			// the user-facing failure mode "opencode shows error" can be
			// 200-with-empty-content, 200-with-error-body, 4xx, or 5xx; a
			// snapshot scoped to 4xx misses the first two. Truncated to
			// debug4xxBodyCap so log lines stay bounded.
			if debugUpstreamHeadersEnabled() {
				respBody, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				resp.Body = io.NopCloser(bytes.NewReader(respBody))
				resp.ContentLength = int64(len(respBody))
				rateLimitHeaders := map[string]string{}
				for k, v := range resp.Header {
					kl := strings.ToLower(k)
					if strings.Contains(kl, "ratelimit") || kl == "x-should-retry" || kl == "retry-after" || kl == "request-id" || kl == "anthropic-organization-id" {
						rateLimitHeaders[k] = strings.Join(v, ", ")
					}
				}
				logger.Info("upstream response snapshot",
					"event.name", "proxy.response.upstream_snapshot",
					"status_code", resp.StatusCode,
					"upstream_request_id", extractUpstreamRequestID(resp),
					"response_signal_headers", rateLimitHeaders,
					"response_body", truncateBodyForLog(respBody),
				)
			}
			if resp.StatusCode >= 400 {
				// 2026-05-25 — default-on app-pipeline 4xx/5xx forensic
				// WARN log. Symptom that motivated this: a third-party
				// APP's OAuth call returned 8 × 404 from Anthropic, and
				// neither the WAL nor the proxy log captured the
				// outbound URL or upstream error envelope — we couldn't
				// distinguish "wrong URL" / "wrong model" / "WAF body
				// rejection" without that data. The opt-in
				// AIKEY_PROXY_DEBUG_4XX_BODIES capture below is verbose
				// (full request/response body), but that's gated
				// because bodies contain user prompts (PII). This new
				// log stays default-on by limiting to non-PII fields:
				// status + outbound URL + response envelope error
				// metadata + route shape. No body contents.
				//
				// Scoped to RouteSource == "app" because the legacy
				// /v1/... and provider-prefix paths already have their
				// own observability surfaces; this fills the third-
				// party app gap specifically.
				if route.RouteSource == "app" {
					p.logAppUpstreamErrorForensic(logger, r, resp, route, realKey)
				}
				// Optional debug capture: when AIKEY_PROXY_DEBUG_4XX_BODIES
				// is set, drain the upstream body, log it together with the
				// stashed request body, and re-buffer so the client still
				// gets the original payload. Truncated to debug4xxBodyCap
				// to keep the jsonl line bounded.
				//
				// Why log only for 4xx (not 5xx): 5xx is usually upstream
				// infrastructure (timeouts, gateway errors); the response
				// body is rarely informative. 4xx is where provider-side
				// validation rejects something specific in the request,
				// which is exactly what this capture exists to inspect.
				if debug4xxEnabled() && resp.StatusCode < 500 {
					respBody, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					resp.Body = io.NopCloser(bytes.NewReader(respBody))
					resp.ContentLength = int64(len(respBody))
					reqBody := debugRequestBodyFromContext(r.Context())
					logger.Warn("upstream 4xx body capture",
						"event.name", "proxy.request.4xx_body_capture",
						"status_code", resp.StatusCode,
						"upstream_request_id", extractUpstreamRequestID(resp),
						"provider", route.ProviderCode,
						"request_path", r.URL.Path,
						"request_content_type", r.Header.Get("Content-Type"),
						"response_content_type", resp.Header.Get("Content-Type"),
						"request_body", truncateBodyForLog(reqBody),
						"response_body", truncateBodyForLog(respBody),
					)
				}
				// Error response: record immediately without token counts.
				p.recordEvent(r, resp, startTime, route, bearerToken, streaming)
				return nil
			}
			// Reverse tool-name rewrite — runs only when forward (in oauth_inject)
			// stored a mapping on the request context. Real Claude CLI traffic
			// has no mapping → no-op. See oauth_tool_rewrite.go.
			toolNameRevMapping := toolNameMappingFrom(r.Context())

			if !streaming {
				// Non-streaming success: read body, extract tokens, re-buffer.
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					return nil
				}
				body = rewriteToolNamesReverseJSON(body, toolNameRevMapping)

				// Token extraction runs on the upstream-NATIVE body shape
				// (e.g. Anthropic for an App pipeline binding pointed at
				// Claude). The optional ResponseTransform below runs AFTER
				// this so the translation step doesn't affect usage events.
				breakdown := prov.ExtractTokenBreakdown(body, false, logger)

				// Phase 2 (App pipeline only): if a ResponseTransform is
				// armed on the ResolvedRoute, translate the upstream body
				// to the inbound protocol shape (e.g. Anthropic → OpenAI).
				// Tier 1 / Tier 2 routes leave this field nil → block is
				// a single nil-check no-op. On failure: rewrite status to
				// 502 + emit a synthetic OpenAI-style error envelope so
				// the client gets a precise, structured error instead of
				// the upstream's body or a generic httputil 502.
				if route.ResponseTransform != nil {
					translated, terr := route.ResponseTransform(r.Context(), body)
					if terr != nil {
						logger.Error("app pipeline response translation failed",
							"event.name", "proxy.response.translation_failed",
							"error", terr,
							"provider", route.ProviderCode,
							"app_slug", route.AppSlug,
						)
						resp.StatusCode = http.StatusBadGateway
						resp.Status = "502 Bad Gateway"
						// Drop transfer/content encoding headers that
						// referred to the upstream body we're discarding.
						resp.Header.Del("Content-Length")
						resp.Header.Del("Content-Encoding")
						resp.Header.Del("Transfer-Encoding")
						resp.Header.Set("Content-Type", "application/json")
						errBody := []byte(`{"error":{"type":"server_error","code":"RESPONSE_TRANSLATION_FAILED","message":"Upstream response could not be translated back to the inbound protocol shape: ` +
							jsonEscapeForError(terr.Error()) + `"}}`)
						resp.Body = io.NopCloser(bytes.NewReader(errBody))
						resp.ContentLength = int64(len(errBody))
						// Still record the event with the upstream-native
						// breakdown so usage isn't lost on translation
						// failures.
						p.recordEvent(r, resp, startTime, route, bearerToken, streaming)
						return nil
					}
					body = translated
					// Translator changed the body size — drop the upstream's
					// Content-Length header so Go's net/http server recomputes
					// it from the new body length. Without this, the client
					// sees `transfer closed with N bytes remaining` because
					// the header still advertises the upstream-side size.
					resp.Header.Del("Content-Length")
					resp.Header.Del("Content-Encoding")
					resp.Header.Del("Transfer-Encoding")
				}

				// Rebuffer with the FINAL body (post-translation if engaged,
				// otherwise unchanged from upstream).
				resp.Body = io.NopCloser(bytes.NewReader(body))
				resp.ContentLength = int64(len(body))

				// Caller-side double defense per principles/logging-conventions.md:
				// extractor may have logged a WARN for a known shape mismatch, but if
				// it returned (0, 0) on a non-empty 2xx body without WARN'ing (new
				// wire format the extractor wasn't updated for), this catches it.
				// Note: `body` may be post-translation here, but breakdown was
				// computed from the upstream-native body above so the WARN
				// condition is unchanged in semantics.
				if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
					len(body) > 100 &&
					breakdown.InputTokens == 0 && breakdown.OutputTokens == 0 {
					logger.Warn("non-streaming: 2xx response with non-empty body but extractor produced zero tokens",
						"event.name", observability.EventProxyExtractionEmpty,
						"error.code", observability.ErrCodeUsageExtractionFailed,
						"provider", route.ProviderCode,
						"path", r.URL.Path,
						"body_len", len(body),
					)
				}
				ev := p.buildBaseEvent(r, resp, startTime, route, false)
				ev.InputTokens = breakdown.InputTokens
				ev.OutputTokens = breakdown.OutputTokens
				// 2026-05-09 response-first model: prefer the
				// upstream-resolved model id from the JSON response
				// (often a dated pin like claude-opus-4-7-20251015)
				// over the request-body model (alias the client sent)
				// captured by extractModel(). Fall back to the
				// request-side value when the body was malformed or
				// the extractor returned an empty Model.
				if breakdown.Model != "" {
					ev.Model = breakdown.Model
				}
				// Probe traffic is forwarded normally so the CLI gets a truthful
				// status code, but must not inflate usage counters or trigger
				// reporter uploads (it'd be double-counting our own self-tests).
				if !isAikeyProbe(r) {
					p.collector.Record(ev)
					// Non-streaming always terminates atomically — the response is
					// either the full JSON or it's an error we surface elsewhere.
					sessionID := resolveSessionID(r.Header, route.ProviderCode)
					upstreamReqID := extractUpstreamRequestID(resp)
					p.reportUsage(route, bearerToken, ev.Model, startTime, resp.StatusCode, breakdown, "", realKey, sessionID, "complete", upstreamReqID)
				}
			} else {
				// Streaming success: wrap body — background goroutine drains the
				// full SSE stream and records token usage when it ends, regardless
				// of whether the client stays connected.
				baseEvent := p.buildBaseEvent(r, resp, startTime, route, true)
				// Capture probe flag + session_id from the request now; by
				// callback time the request's header map may have been recycled.
				probe := isAikeyProbe(r)
				sessionID := resolveSessionID(r.Header, route.ProviderCode)
				// Capture upstreamReqID NOW (response headers are stable from
				// here onward; the streaming body keeps draining in a goroutine
				// but headers are already finalised by upstream).
				upstreamReqID := extractUpstreamRequestID(resp)
				var cb reporterCallback
				if p.reporter != nil && !probe {
					cb = func(br provider.TokenBreakdown, completion string) {
						// 2026-05-09 response-first: prefer the upstream-resolved
						// model id from the SSE first frame (br.Model) over the
						// request-body model captured into baseEvent. Same logic
						// as in stream_drainer.go where ev.Model gets overridden
						// for the SQLite collector path. Without this fix, the
						// JSONL WAL written via reportUsage would carry the
						// request-side undated alias even when extractor saw a
						// dated upstream response — observed via DEBUG log
						// "DEBUG response-first".
						model := baseEvent.Model
						if br.Model != "" {
							model = br.Model
						}
						p.reportUsage(route, bearerToken, model, startTime, resp.StatusCode, br, "", realKey, sessionID, completion, upstreamReqID)
					}
				}
				// For probe traffic skip the collector entirely by passing nil.
				collector := p.collector
				if probe {
					collector = nil
				}
				// Wrap upstream BEFORE streamDrainer so SSE chunks are line-
				// buffered + tool_use.name rewritten before the drainer reads
				// them. newSSEToolNameRewriter is a no-op pass-through when
				// the mapping is empty (real CLI traffic).
				upstream := newSSEToolNameRewriter(resp.Body, toolNameRevMapping)
				// Phase 4 M2 plugin observer dispatch: pluck the observer
				// context + registry that handleAppPipeline stashed on the
				// route (App pipeline branch only — legacy /v1/... routes
				// leave both nil, the drainer short-circuits). Type-assert
				// here because vkeys/types.go declares both fields as `any`
				// to keep vkeys at the bottom of the dep graph.
				var obsRegistry *observer.Registry
				var obsReqCtx *observer.RequestContext
				if route.ObserverRegistry != nil {
					obsRegistry, _ = route.ObserverRegistry.(*observer.Registry)
				}
				if route.ObserverContext != nil {
					obsReqCtx, _ = route.ObserverContext.(*observer.RequestContext)
				}
				resp.Body = newStreamDrainer(upstream, baseEvent, prov, collector, p.proxyCtx, r.Context(), logger, cb, obsRegistry, obsReqCtx)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.errors.Add(1)
			latencyMs := time.Since(startTime).Milliseconds()
			logger.Error("upstream error",
				"event.name", observability.EventProxyRequestUpstreamError,
				"error.code", observability.ErrCodeUpstreamError,
				"error.message", err.Error(),
				"latency_ms", latencyMs,
			)
			writeJSONError(w, http.StatusBadGateway, "server_error", "UPSTREAM_ERROR",
				"Failed to connect to upstream provider.")
		},
		FlushInterval: -1, // Flush immediately for SSE streaming.
	}

	rp.ServeHTTP(w, r)

	// 10. Slow request detection (after the full response is sent).
	latencyMs := time.Since(startTime).Milliseconds()
	if latencyMs >= p.VerySlowRequestMs {
		logger.Warn("very slow request",
			"event.name", observability.EventProxyRequestSlow,
			"latency_ms", latencyMs,
			"threshold_ms", p.VerySlowRequestMs,
		)
	} else if latencyMs >= p.SlowRequestMs {
		logger.Info("slow request",
			"event.name", observability.EventProxyRequestSlow,
			"latency_ms", latencyMs,
			"threshold_ms", p.SlowRequestMs,
		)
	}
}

// buildBaseEvent constructs a UsageEvent from the request/response metadata,
// without token counts (filled in by callers that have the response body).
//
// 2026-05-08 Kimi 双平台拆分: Provider 字段优先用 canonical ProviderCode (e.g.
// "kimi_code"),不用 URL-prefix 的 Provider (e.g. "kimi" deprecated alias) ——
// 否则同一 vault entry 经 deprecated /kimi/v1 路径请求时 events.provider 写入
// "kimi",而经 /kimi_code/v1 路径请求时写入 "kimi_code",计费 / 用量聚合时
// 会被算成两个 provider,造成数据分裂。canonical ProviderCode 是 single source。
// route.Provider 仍保留 URL-prefix 形式给其他 (调试 / RequestPath 关联) 用途。
func (p *Proxy) buildBaseEvent(req *http.Request, resp *http.Response, startTime time.Time, route *vkeys.ResolvedRoute, streaming bool) events.UsageEvent {
	provider := route.ProviderCode
	if provider == "" {
		// 极端兜底:ResolvedRoute 没填 ProviderCode 时退回 URL-form,避免空字符串
		provider = route.Provider
	}
	ev := events.UsageEvent{
		Timestamp:    startTime,
		VirtualKeyID: route.VirtualKeyID,
		Provider:     provider,
		DurationMs:   time.Since(startTime).Milliseconds(),
		StatusCode:   resp.StatusCode,
		IsStreaming:  streaming,
		RequestPath:  req.URL.Path,
	}
	if model := req.Header.Get("x-aikey-model"); model != "" {
		ev.Model = model
		ev.RequestedModel = model // Phase 4 §5.3 — captured at request entry, may differ from upstream `Model` after translator remaps
	}
	// Phase 4 (AKL-207) — App pipeline audit fields. Empty for legacy paths
	// (route.RouteSource != "app").
	if route.RouteSource == "app" {
		ev.AppSlug = route.AppSlug
		ev.AppKeyID = route.AppKeyID
		if route.FollowUserActive {
			ev.AppMode = "follow-active"
			ev.BoundVia = "default" // follow-active path uses the user's default profile binding
		} else {
			ev.AppMode = "isolated"
			ev.BoundVia = "app:" + route.AppSlug
		}
		ev.ResolvedProvider = provider
	}
	return ev
}

// recordEvent records a usage event for error responses (no token counts).
func (p *Proxy) recordEvent(req *http.Request, resp *http.Response, startTime time.Time, route *vkeys.ResolvedRoute, bearerToken string, streaming bool) {
	ev := p.buildBaseEvent(req, resp, startTime, route, streaming)
	if resp.StatusCode >= 400 {
		p.errors.Add(1)
		ev.ErrorType = http.StatusText(resp.StatusCode)
	}
	// Probe traffic bypasses all sinks — see isAikeyProbe rationale in
	// middleware.go. Keep p.errors.Add(1) above so the /metrics view still
	// shows "N requests returned 4xx/5xx" even for self-tests.
	if isAikeyProbe(req) {
		return
	}
	p.collector.Record(ev)
	// Error responses are treated as interrupted — the client never got a
	// usable result even though the request finished "fast" from our POV.
	sessionID := resolveSessionID(req.Header, route.ProviderCode)
	upstreamReqID := extractUpstreamRequestID(resp)
	p.reportUsage(route, bearerToken, ev.Model, startTime, resp.StatusCode, provider.TokenBreakdown{}, ev.ErrorType, "", sessionID, "interrupted", upstreamReqID)
}

// debug4xxEnabled reports whether AIKEY_PROXY_DEBUG_4XX_BODIES is set to a
// truthy value. Read on every request — getenv is cheap and lets operators
// flip the flag at runtime via an EnvironmentFile reload (no proxy restart
// required) when chasing a sporadic 4xx in production.
//
// Why opt-in (not always on): the request body for chat completions is
// often a few KB of conversation history; logging it for every 4xx adds
// disk pressure and surfaces user prompts into developer-facing logs. The
// flag scopes that exposure to deliberate diagnostic windows.
func debug4xxEnabled() bool {
	v := os.Getenv("AIKEY_PROXY_DEBUG_4XX_BODIES")
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// debug4xxBodyCap caps how many bytes of each side we log. 4 KB is enough
// for typical provider error envelopes (anthropic Bad Request bodies are
// usually <500 bytes; Claude Code request bodies that trigger them sit
// around 1-3 KB). Larger payloads get a `...<truncated>` marker so the
// reader knows there was more.
//
// AIKEY_PROXY_DEBUG_BODY_CAP_BYTES env override: third-party clients
// (opencode/Cline/Cursor) routinely send 30-80 KB request bodies (tool
// definitions + message history); the default 4 KB cap is too small to
// see metadata.user_id / tools / late messages when chasing identity-
// gating bugs. Setting the env to e.g. 65536 lets a focused diagnostic
// session capture full bodies. Hard-capped at 1 MB so a misconfigured
// value can't OOM the log writer.
const (
	debug4xxBodyCap        = 4 * 1024
	debugBodyCapHardCeil   = 1024 * 1024
	debugBodyCapEnvOverride = "AIKEY_PROXY_DEBUG_BODY_CAP_BYTES"
)

// resolvedBodyLogCap returns the active body-log cap, env override winning
// over the compile-time default. Invalid env values fall back silently.
func resolvedBodyLogCap() int {
	if v := os.Getenv(debugBodyCapEnvOverride); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > debugBodyCapHardCeil {
				return debugBodyCapHardCeil
			}
			return n
		}
	}
	return debug4xxBodyCap
}

// stashRequestBodyForDebug reads r.Body fully, stores the bytes in request
// context for ModifyResponse to retrieve later, and re-buffers r.Body for
// the actual upstream call. No-op when no debug flag is active, the body
// is empty, or the body exceeds extractBodyHardLimit.
//
// Why two flags drive this: AIKEY_PROXY_DEBUG_4XX_BODIES historically gated
// 4xx-only body capture; debugUpstreamHeadersEnabled() also drives request-
// body capture so the broader upstream-snapshot toggle can include body
// alongside headers (otherwise body diagnostics needs a separate restart
// with the legacy env).
//
// Why context (not a header): bodies can be megabytes of conversation; cramming
// them into headers would break upstream forwarding (header size limits,
// inadvertent leaks via mirrored response headers).
func stashRequestBodyForDebug(r *http.Request) {
	if (!debug4xxEnabled() && !debugUpstreamHeadersEnabled()) || r.Body == nil {
		return
	}
	if r.ContentLength > extractBodyHardLimit {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	*r = *r.WithContext(context.WithValue(r.Context(), ctxKeyDebugReqBody, body))
}

// debugRequestBodyFromContext fetches the stashed request body. Returns nil
// when the flag was off or the request was too large to stash.
func debugRequestBodyFromContext(ctx context.Context) []byte {
	b, _ := ctx.Value(ctxKeyDebugReqBody).([]byte)
	return b
}

// logAppUpstreamErrorForensic emits a default-on WARN log whenever an
// app-pipeline request returns 4xx/5xx from the upstream. The goal is
// to make third-party APP integration failures debuggable WITHOUT
// requiring the operator to flip AIKEY_PROXY_DEBUG_4XX_BODIES first —
// that flag dumps full bodies (PII) and is rightly opt-in, but the
// resulting "off by default" leaves users staring at a generic 404 in
// the dashboard with no way to ask "what URL? what error message?
// what model? OAuth or API key?".
//
// PII safety contract:
//   - Logs: status, outbound URL (host + path + query), upstream
//     request_id, route shape (slug / kind / route_source), credential
//     family (oauth vs personal-or-team — never the actual secret),
//     upstream error envelope's `type` + `message` (truncated to
//     errorMessageLogCap chars).
//   - Does NOT log: Authorization header, x-api-key, OAuth bearer,
//     full request body (may contain user prompts), full response body
//     (may contain provider's PII echo).
//
// Body handling: drains the response body so the envelope parser can
// run, then re-buffers so the client still gets the original payload
// — same pattern as the existing debug4xx capture below. The drain is
// hard-capped at errorBodyParseCap to keep memory pressure bounded
// even when the upstream returns a giant 4xx response.
//
// When the body parses as a known provider error envelope (Anthropic /
// OpenAI shape) the parsed `type` + `message` are surfaced as
// dedicated fields so log consumers (jq filters, alert rules) can
// pivot without string-matching the whole envelope.
func (p *Proxy) logAppUpstreamErrorForensic(
	logger *slog.Logger,
	r *http.Request,
	resp *http.Response,
	route *vkeys.ResolvedRoute,
	realKey string,
) {
	// Drain the response body — capped — so we can parse the error
	// envelope. Re-buffer immediately so the downstream client still
	// gets the original payload byte-for-byte.
	const errorBodyParseCap = 8 * 1024
	var bodyBytes []byte
	if resp.Body != nil {
		buf, err := io.ReadAll(io.LimitReader(resp.Body, errorBodyParseCap+1))
		if err == nil {
			bodyBytes = buf
		}
		_ = resp.Body.Close()
		// Re-buffer for the client. If reading hit the cap, we lose
		// the tail — accept that trade-off (the alternative is two
		// passes / a TeeReader, both add complexity without proving
		// useful in practice; provider errors fit well under 8 KB).
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		resp.ContentLength = int64(len(bodyBytes))
	}

	// Outbound URL — reconstruct host from route.BaseURL since
	// ReverseProxy.Director set req.URL.Scheme/Host on a different
	// request object (the one passed to Director, not `r`). r.URL.Path
	// + r.URL.RawQuery at this point ARE the outbound versions (the
	// path mutation in handleAppPipeline + the ?beta=true added by
	// oauthInject all happened before the Director ran).
	outboundURL := route.BaseURL + r.URL.Path
	if r.URL.RawQuery != "" {
		outboundURL += "?" + r.URL.RawQuery
	}

	// Credential family — never the secret. realKey is one of:
	//   "__oauth__" sentinel (oauth path; actual token in header set by oauthInject)
	//   personal key plaintext / team virtual key plaintext (set by ResolveBindingCredential)
	// Logging the family alone is enough for diagnosis without leaking
	// the secret. realKey could in theory contain a real key, so the
	// switch is a positive-match-or-redact pattern.
	credFamily := "personal-or-team"
	if realKey == "__oauth__" {
		credFamily = "oauth"
	}

	// Parse the response envelope for provider-side error metadata.
	// Both Anthropic and OpenAI wrap errors in:
	//   {"type":"error","error":{"type":"...","message":"..."}}     (Anthropic)
	//   {"error":{"type":"...","message":"...","code":"..."}}        (OpenAI)
	// A single struct with optional fields covers both shapes.
	errType, errMessage := parseUpstreamErrorEnvelope(bodyBytes)

	const errorMessageLogCap = 500
	if len(errMessage) > errorMessageLogCap {
		errMessage = errMessage[:errorMessageLogCap] + "...<truncated>"
	}

	logger.Warn("app pipeline upstream error",
		"event.name", "proxy.app.upstream_error",
		"status_code", resp.StatusCode,
		"upstream_request_id", extractUpstreamRequestID(resp),
		"outbound_url", outboundURL,
		"outbound_method", r.Method,
		"route_source", route.RouteSource,
		"app_slug", route.AppSlug,
		"app_kind", route.AppKind,
		"provider", route.ProviderCode,
		"credential_family", credFamily,
		"upstream_error_type", errType,
		"upstream_error_message", errMessage,
		// Hint for verbose follow-up — only one place to point operators
		// at when this log isn't sufficient for diagnosis.
		"hint", "set AIKEY_PROXY_DEBUG_4XX_BODIES=1 for full request/response body capture (PII risk: contains user prompts)",
	)
}

// parseUpstreamErrorEnvelope extracts (type, message) from a provider
// error response body. Returns ("", "") when the body isn't parseable
// JSON or doesn't match a known envelope shape — both cases are
// signal-free, not a bug.
//
// Anthropic shape:  {"type":"error","error":{"type":"not_found_error","message":"..."}}
// OpenAI shape:     {"error":{"type":"invalid_request","message":"...","code":"..."}}
// Both share the `error.{type,message}` nested path, so one parse covers them.
func parseUpstreamErrorEnvelope(body []byte) (errType, errMessage string) {
	if len(body) == 0 {
		return "", ""
	}
	var env struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", ""
	}
	return env.Error.Type, env.Error.Message
}

// truncateBodyForLog renders body bytes as a string, capping at the
// resolved body-log cap (env override or compile default) and appending
// an explicit truncation marker so the reader knows the captured snippet
// is incomplete.
func truncateBodyForLog(b []byte) string {
	cap := resolvedBodyLogCap()
	if len(b) <= cap {
		return string(b)
	}
	return string(b[:cap]) + "...<truncated>"
}

// extractUpstreamRequestID pulls the provider's own request id out of the
// response headers. Anthropic uses `request-id` (their docs explicitly call
// it out as the audit-log pivot), OpenAI / Codex / Azure-OpenAI use
// `x-request-id` or the legacy `openai-request-id`, and most other gateways
// follow one of those two conventions. Returns the first non-empty value;
// callers treat empty as "upstream did not surface one".
func extractUpstreamRequestID(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	for _, h := range []string{"request-id", "x-request-id", "openai-request-id"} {
		if v := resp.Header.Get(h); v != "" {
			return v
		}
	}
	return ""
}

// reportUsage builds a ReportableEvent and emits it to whichever sinks are
// configured:
//   - reporter present → Report() handles WAL append + async upload
//   - reporter nil but WAL present → append directly (offline standalone mode)
//   - neither → no-op
// sessionID is the value of X-Claude-Code-Session-Id (empty for non-Claude-Code clients).
// completion is the transport-level outcome: "complete" | "partial" | "interrupted".
// breakdown carries the optional cache split (zeroed for providers that don't
// surface it, e.g. OpenAI/Kimi).
// upstreamReqID is the provider-side request id (anthropic `req_xxx` / openai
// `req_xxx`) extracted from response headers; empty when upstream omitted it.
func (p *Proxy) reportUsage(route *vkeys.ResolvedRoute, bearerToken, model string, startTime time.Time, statusCode int, breakdown provider.TokenBreakdown, errorType, realKey, sessionID, completion, upstreamReqID string) {
	if p.reporter == nil && p.wal == nil {
		return
	}
	ev := events.BuildReportableEvent(events.ReportOpts{
		EventID:         observability.NewID(),
		ProxyInstanceID: p.proxyInstanceID,
		Route:           route,
		BearerToken:     bearerToken,
		Model:           model,
		StartTime:       startTime,
		FinishedAt:      time.Now(),
		StatusCode:      statusCode,
		InputTokens:     breakdown.InputTokens,
		OutputTokens:    breakdown.OutputTokens,
		CacheReadInputTokens:     breakdown.CacheReadInputTokens,
		CacheCreationInputTokens: breakdown.CacheCreationInputTokens,
		StopReason:               breakdown.StopReason,
		ErrorType:       errorType,
		RealKey:         realKey,
		ClientVersion:      p.clientVersion,
		SourceVersion:      p.clientVersion,
		ProxyConfigVersion: p.proxyConfigVersion,
		LoadedControlSeq:   p.loadedControlSeq,
		LoggedInAccountID:  p.loggedInAccountID,
		SessionID:          sessionID,
		Completion:         completion,
		UpstreamRequestID:  upstreamReqID,
	})
	if p.reporter != nil {
		// Reporter writes WAL + enqueues upload; when wal is the shared
		// instance no duplicate append happens.
		p.reporter.Report(ev)
		return
	}
	// Offline path: no collector_url, but WAL is still desired so local
	// statusline / watch can consume it.
	p.wal.Append(ev)
}

// resolveSessionID picks the request's session identifier from whichever
// source the upstream client populated:
//   - `X-Claude-Code-Session-Id` header (Claude Code native)
//   - `x-aikey-kimi-session` header (we stash it from body `prompt_cache_key`
//     in extractModel; only Kimi's kimi-cli populates that field)
//
// Header order is "Claude first" so Claude's current behaviour is unchanged
// when both happen to be set (which shouldn't occur in practice since one
// vk corresponds to one provider).
// resolveSessionID returns the session id to stamp into the WAL event.
//
// Priority:
//  1. `X-Claude-Code-Session-Id` request header (authoritative — set by
//     Claude Code client for every turn). Wins unconditionally, across
//     any provider — the header is Claude-specific and can't be forged
//     by other upstream SDKs.
//  2. `x-aikey-kimi-session` (stashed by extractModel from body
//     `prompt_cache_key`). Only consulted when `providerCode == "kimi"`,
//     so a non-Kimi client that happens to put a `prompt_cache_key` in
//     its body CANNOT inject a session_id into our WAL (review finding
//     2026-04-20 #3). `prompt_cache_key` is a first-class Kimi concept;
//     other SDKs may repurpose that field for unrelated things and we
//     must not conflate them.
//
// `providerCode` should be the route's canonical provider code (e.g.
// "kimi_code", "moonshot", "anthropic"), not a URL-derived alias.
//
// 2026-05-08 Kimi 双平台拆分: provider_code 'kimi' 拆为 'kimi_code' (Kimi Code)
// + 'moonshot' (Moonshot)。两个平台都基于 Kimi 上游协议,都使用
// `prompt_cache_key` 作为 session id 字段,所以都需要从 stash header 提取。
// 'kimi' 保留为 deprecated alias 兜底 (老 vault 数据 / 手工构造场景)。
func resolveSessionID(h http.Header, providerCode string) string {
	if v := h.Get("X-Claude-Code-Session-Id"); v != "" {
		return v
	}
	switch providerCode {
	case "kimi_code", "moonshot", "kimi":
		return h.Get("x-aikey-kimi-session")
	}
	return ""
}

// extractModel reads the request body to find the top-level `model` field
// and Kimi's `prompt_cache_key` (= session id). It stashes both into
// custom x-aikey-* request headers so buildBaseEvent / reportUsage can
// read them later without re-parsing the body.
//
// Why both in one pass: once ReverseProxy forwards the request the body
// stream is consumed — ModifyResponse can't reach back into it. Parsing
// here is the only correct timing.
//
// Memory model (simplified 2026-04-21 from the prior streaming-prefix
// design):
//
//	Body ≤ extractBodyHardLimit (4 MB): full io.ReadAll + json.Unmarshal.
//	  Typical Claude/Kimi/OpenAI text bodies sit at 10 KB – 500 KB, well
//	  within this budget. Concurrency on a single-user local proxy is
//	  low, so the instantaneous memory cost is tiny.
//	Body > extractBodyHardLimit: skip parsing entirely. ev.Model stays
//	  empty (UI handles the empty case via fallback paths). This fence
//	  protects against OOM on multimodal payloads with base64 images
//	  (legitimately 10+ MB).
//
// Earlier a 16 KB streaming-prefix scan was added to reduce memory for
// mid-size bodies, but it turned out to break real Kimi CLI 1.36.0
// traffic: kosong's Python SDK serialises `messages` (huge array) as the
// first top-level key and spreads `prompt_cache_key` via `**kwargs` AFTER
// it. The prefix scan never reached the session id field, so Kimi WAL
// events landed with empty session_id and the receipt hook did not fire.
// The fence alone preserves the OOM protection that review finding #1
// asked for, without the field-order fragility.
const extractBodyHardLimit = 4 * 1024 * 1024 // 4 MB

// jsonEscapeForError escapes a string for safe embedding in a JSON
// error-body literal. Only escapes the JSON-syntax-critical characters
// (`\`, `"`, control bytes); higher-byte sequences pass through, which
// is fine for UTF-8 since none of them collide with structural JSON.
// Used by the App-pipeline ResponseTransform failure path to embed
// an upstream error message into a synthetic error envelope without
// pulling json.Marshal on a known-tiny string.
func jsonEscapeForError(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				// Other control chars get the \u00XX form. Rare in error
				// messages; covered for safety.
				const hex = "0123456789abcdef"
				b.WriteString(`\u00`)
				b.WriteByte(hex[(c>>4)&0xf])
				b.WriteByte(hex[c&0xf])
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

// extractModelLazy parses the `model` field out of an already-buffered
// JSON body without touching the http.Request — used by App pipeline's
// translation step, which has the sanitized bytes in-hand and doesn't
// want to consume/re-buffer r.Body. Returns empty string on parse
// failure or absent field (caller treats empty as "let translator
// decide / pass through").
func extractModelLazy(body []byte) string {
	if len(body) == 0 || len(body) > extractBodyHardLimit {
		return ""
	}
	var partial struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &partial); err != nil {
		return ""
	}
	return partial.Model
}

func extractModel(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	if r.ContentLength > extractBodyHardLimit {
		return ""
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	var partial struct {
		Model          string `json:"model"`
		PromptCacheKey string `json:"prompt_cache_key"`
	}
	if err := json.Unmarshal(bodyBytes, &partial); err != nil {
		// Body isn't JSON we understand — leave both headers unset.
		return ""
	}

	stashExtractedFields(r, partial.Model, partial.PromptCacheKey)
	return partial.Model
}

func stashExtractedFields(r *http.Request, model, promptCacheKey string) {
	if model != "" {
		r.Header.Set("x-aikey-model", model)
	}
	if promptCacheKey != "" {
		// Kimi-specific; resolveSessionID gates by provider_code so a
		// non-Kimi client that happens to send prompt_cache_key cannot
		// accidentally inject a session_id into WAL (review finding #3).
		r.Header.Set("x-aikey-kimi-session", promptCacheKey)
	}
}
