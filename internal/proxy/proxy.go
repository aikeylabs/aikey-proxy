package proxy

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
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
	activeReader ActiveKeyReader // non-nil when vault implements ActiveKeyReader
	broker       OAuthBroker     // OAuth credential provider (nil = OAuth not available)
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
		vault:             v,
		registry:          reg,
		providers:         prov,
		collector:         coll,
		proxyCtx:          ctx,
		SlowRequestMs:     2000,
		VerySlowRequestMs: 10000,
		UpstreamTimeout:   defaultUpstreamTimeout,
	}
	if ar, ok := v.(ActiveKeyReader); ok {
		p.activeReader = ar
	}
	return p
}

// SetBroker injects the OAuth broker for credential resolution.
// Must be called before the proxy handles any OAuth-credential requests.
func (p *Proxy) SetBroker(b OAuthBroker) {
	p.broker = b
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

	// 0. Path-prefix routing: /anthropic/v1/... or /openai/v1/...
	// Takes precedence over token-based routing when the path starts with a
	// known provider prefix. Uses the active key config from the vault.
	if providerCode, strippedPath := extractProviderFromPath(r.URL.Path); providerCode != "" {
		p.handlePathPrefixRoute(w, r, providerCode, strippedPath, startTime, logger)
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
	case Tier2Probe:
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Probe sentinel requires path-prefix routing (use /<provider>/v1/... URL).")
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

	p.serveRoute(w, r, route, prov, realKey, token, startTime, logger)
}

// handlePathPrefixRoute resolves the active key for providerCode and forwards
// the request with the provider prefix stripped from the path.
// Called when the request path starts with a known provider prefix
// (e.g., /anthropic/v1/messages → strip /anthropic → forward to Anthropic API).
func (p *Proxy) handlePathPrefixRoute(w http.ResponseWriter, r *http.Request, providerCode, strippedPath string, startTime time.Time, logger *slog.Logger) {
	logger = logger.With("provider", providerCode, "routing", "path-prefix")

	// 2026-04-29 namespace-authority early hard-fail. Run BEFORE the
	// activeReader nil check so malformed `aikey_*` tokens always fail
	// loud with TOKEN_INVALID — independent of vault wiring state. This
	// also keeps the proxy's behavior consistent across editions (Personal
	// without active vault still rejects clearly-bad aikey tokens).
	if rawAuth := extractRawAuthValue(r); rawAuth != "" && ClassifyToken(rawAuth) == TokenInvalid {
		p.errors.Add(1)
		logger.Warn("aikey_* token form invalid (namespace authority)",
			"event.name", observability.EventProxyRequestAuthFailed,
		)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Token is in the aikey_ namespace but doesn't match any recognized form. "+
				"Run 'aikey route' to see valid tokens.")
		return
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

	// Tier 1: aikey_team_<vk_id> or aikey_personal_<64-hex> — resolve via Registry.
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

		p.serveRoute(w, r, tokenRoute, prov, tokenRealKey, rawAuthValue, startTime, logger)
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
				p.serveRoute(w, r, oauthRoute, prov, "__oauth__", rawAuthValue, startTime, logger)
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
		p.serveRoute(w, r, aliasRoute, prov, plaintext, rawAuthValue, startTime, logger)
		return
	}

	// ── No auth header: fall through to default binding ────────────────────

	// ── v1.0.2: try provider binding first ─────────────────────────────────
	// The new model stores per-provider primary key selection in
	// user_profile_provider_bindings.  If a binding exists, resolve directly.
	binding, _ := p.activeReader.GetProviderBinding(canonicalCode)
	if binding != nil {
		if binding.KeySourceType == "personal_oauth_account" {
			// OAuth account — resolve via broker, not vault
			if p.broker == nil {
				p.errors.Add(1)
				writeJSONError(w, http.StatusServiceUnavailable, "server_error", "OAUTH_NOT_AVAILABLE",
					"OAuth is not configured. Restart proxy or use API Key instead.")
				return
			}

			// EnsureFresh: broker handles token refresh internally
			if err := p.broker.EnsureFresh(r.Context(), binding.KeySourceRef); err != nil {
				logger.Warn("oauth: EnsureFresh failed", "account_id", binding.KeySourceRef, "error", err)
				p.errors.Add(1)
				writeJSONError(w, http.StatusUnauthorized, "auth_error", "OAUTH_TOKEN_EXPIRED",
					err.Error()+"\n  Run: aikey auth login "+providerCode)
				return
			}

			// Resolve decrypted credential
			cred, err := p.broker.ResolveCredential(r.Context(), binding.KeySourceRef)
			if err != nil {
				logger.Error("oauth: ResolveCredential failed", "account_id", binding.KeySourceRef, "error", err)
				p.errors.Add(1)
				writeJSONError(w, http.StatusServiceUnavailable, "server_error", "OAUTH_RESOLVE_FAILED", err.Error())
				return
			}

			// Inject OAuth credential via provider-specific injector.
			// Why override for openai: Codex OAuth uses chatgpt.com/backend-api/codex
			// (Responses API), NOT api.openai.com/v1 (Chat Completions API).
			// API key users hit api.openai.com; OAuth users hit chatgpt.com.
			// Ref: workflow/CI/researchs/oauth-codex-test/main.go
			if canonicalCode == "openai" {
				baseURL = "https://chatgpt.com/backend-api/codex"
			} else {
				baseURL = providerDefaultBaseURL(canonicalCode)
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

			realKey = "__oauth__" // sentinel — not used for header injection (injector handles it)
			virtualKeyID = "oauth:" + binding.KeySourceRef
			oauthIdentity = identityTag
			oauthAccountID = binding.KeySourceRef

		} else if binding.KeySourceType == "team" {
			var err error
			mk, err = p.activeReader.GetTeamKeyByID(binding.KeySourceRef)
			if err != nil {
				logger.Warn("vault: team key lookup via binding failed", "vk_id", binding.KeySourceRef, "error", err)
			}
			if mk != nil {
				realKey = mk.PlaintextKey
				virtualKeyID = mk.VirtualKeyID
				// 2026-05-09: surface the team key's user-facing alias so the
				// receipt / WAL `key_label` shows e.g. `key-335923591-0011-1`
				// instead of the vk_id tail. mk.LocalAlias is COALESCEd with
				// the canonical `alias` column in vault.GetTeamKeyByID, so it
				// is non-empty for any normal team key.
				keyAlias = mk.LocalAlias
				if url, ok := mk.ProviderBaseURLs[canonicalCode]; ok && url != "" {
					baseURL = url
				} else if url, ok := mk.ProviderBaseURLs[providerCode]; ok && url != "" {
					baseURL = url
				} else {
					baseURL = mk.BaseURL
				}
			}
		} else {
			// personal key
			plaintext, _, entryBaseURL, err := p.activeReader.GetPersonalKeyByAlias(binding.KeySourceRef)
			if err != nil {
				logger.Warn("vault: personal key lookup via binding failed", "alias", binding.KeySourceRef, "error", err)
			} else {
				realKey = plaintext
				virtualKeyID = "personal:" + binding.KeySourceRef
				keyAlias = binding.KeySourceRef
				if entryBaseURL != "" {
					baseURL = entryBaseURL
				} else {
					baseURL = providerDefaultBaseURL(canonicalCode)
				}
			}
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
	p.serveRoute(w, r, route, prov, realKey, "aikey_team_"+virtualKeyID, startTime, logger)
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
				resp.Body = io.NopCloser(bytes.NewReader(body))
				resp.ContentLength = int64(len(body))

				breakdown := prov.ExtractTokenBreakdown(body, false, logger)
				// Caller-side double defense per principles/logging-conventions.md:
				// extractor may have logged a WARN for a known shape mismatch, but if
				// it returned (0, 0) on a non-empty 2xx body without WARN'ing (new
				// wire format the extractor wasn't updated for), this catches it.
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
				resp.Body = newStreamDrainer(upstream, baseEvent, prov, collector, p.proxyCtx, r.Context(), logger, cb)
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
