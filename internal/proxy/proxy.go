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
			"Missing virtual key. Expected token with 'aikey_vk_' prefix in Authorization or x-api-key header.")
		return
	}

	// 2. Resolve virtual key → route.
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

	// 5. Get provider adapter.
	prov, err := p.providers.Get(route.Provider)
	if err != nil {
		p.errors.Add(1)
		logger.Error("unknown provider",
			"event.name", observability.EventProxyRequestUpstreamError,
			"error.code", observability.ErrCodeProviderError,
			"error.message", err.Error(),
		)
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
			"Unknown provider: "+route.Provider)
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

	// ── v1.0.4: Per-request route token resolution ─────────────────────────
	// If the client sends an aikey_vk_ token, resolve it via Registry.
	// Non-aikey_vk_ auth headers (e.g. native provider tokens from Claude CLI,
	// Cursor, etc.) fall through to the default binding — the proxy replaces
	// them with the real key from the vault binding.
	rawAuthValue := extractRawAuthValue(r)
	if rawAuthValue != "" && strings.HasPrefix(rawAuthValue, "aikey_vk_") {
		route := p.registry.Resolve(rawAuthValue)
		if route == nil {
			p.errors.Add(1)
			logger.Warn("aikey_vk_ token not in registry",
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

	p.serveRoute(w, r, route, prov, realKey, "aikey_vk_"+virtualKeyID, startTime, logger)
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
			go func() {
				select {
				case <-cn.CloseNotify(): //nolint:staticcheck
					cancel()
				case <-cancelCtx.Done():
				}
			}()
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
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode >= 400 {
				// Error response: record immediately without token counts.
				p.recordEvent(r, resp, startTime, route, bearerToken, streaming)
				return nil
			}
			if !streaming {
				// Non-streaming success: read body, extract tokens, re-buffer.
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					return nil
				}
				resp.Body = io.NopCloser(bytes.NewReader(body))
				resp.ContentLength = int64(len(body))

				breakdown := prov.ExtractTokenBreakdown(body, false)
				ev := p.buildBaseEvent(r, resp, startTime, route, false)
				ev.InputTokens = breakdown.InputTokens
				ev.OutputTokens = breakdown.OutputTokens
				p.collector.Record(ev)
				// Non-streaming always terminates atomically — the response is
				// either the full JSON or it's an error we surface elsewhere.
				sessionID := resolveSessionID(r.Header)
				p.reportUsage(route, bearerToken, ev.Model, startTime, resp.StatusCode, breakdown, "", realKey, sessionID, "complete")
			} else {
				// Streaming success: wrap body — background goroutine drains the
				// full SSE stream and records token usage when it ends, regardless
				// of whether the client stays connected.
				baseEvent := p.buildBaseEvent(r, resp, startTime, route, true)
				// Capture session_id from the request now; by callback time
				// the request's header map may have been recycled.
				sessionID := resolveSessionID(r.Header)
				var cb reporterCallback
				if p.reporter != nil {
					cb = func(br provider.TokenBreakdown, completion string) {
						p.reportUsage(route, bearerToken, baseEvent.Model, startTime, resp.StatusCode, br, "", realKey, sessionID, completion)
					}
				}
				resp.Body = newStreamDrainer(resp.Body, baseEvent, prov, p.collector, p.proxyCtx, r.Context(), cb)
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
func (p *Proxy) buildBaseEvent(req *http.Request, resp *http.Response, startTime time.Time, route *vkeys.ResolvedRoute, streaming bool) events.UsageEvent {
	ev := events.UsageEvent{
		Timestamp:    startTime,
		VirtualKeyID: route.VirtualKeyID,
		Provider:     route.Provider,
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
	p.collector.Record(ev)
	// Error responses are treated as interrupted — the client never got a
	// usable result even though the request finished "fast" from our POV.
	sessionID := resolveSessionID(req.Header)
	p.reportUsage(route, bearerToken, ev.Model, startTime, resp.StatusCode, provider.TokenBreakdown{}, ev.ErrorType, "", sessionID, "interrupted")
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
func (p *Proxy) reportUsage(route *vkeys.ResolvedRoute, bearerToken, model string, startTime time.Time, statusCode int, breakdown provider.TokenBreakdown, errorType, realKey, sessionID, completion string) {
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
func resolveSessionID(h http.Header) string {
	if v := h.Get("X-Claude-Code-Session-Id"); v != "" {
		return v
	}
	return h.Get("x-aikey-kimi-session")
}

// extractModel reads the request body to find the "model" field.
// It re-buffers the body for upstream forwarding and stores the model
// in a custom header for later use.
//
// This also extracts `prompt_cache_key` in the same body-parse pass —
// Kimi's kimi-cli stashes its session_id in that field (see the Kimi
// receipt integration design doc). Doing both extractions here is the
// only correct spot: once the ReverseProxy forwards the request, the
// body stream has been consumed and downstream code (including the
// streaming drainer's ModifyResponse branch) can't re-read it.
//
// The extracted Kimi session is stored in the `x-aikey-kimi-session`
// request header; buildBaseEvent/reportUsage prefer the Claude header
// `X-Claude-Code-Session-Id` and fall back to this one.
func extractModel(r *http.Request) string {
	if r.Body == nil {
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
	if partial.Model != "" {
		// Store in a custom header so we can read it later without re-parsing.
		r.Header.Set("x-aikey-model", partial.Model)
	}
	if partial.PromptCacheKey != "" {
		// Kimi-only, but harmless if other providers ever set it:
		// session_id wiring is gated on provider_code == "kimi" downstream.
		r.Header.Set("x-aikey-kimi-session", partial.PromptCacheKey)
	}
	return partial.Model
}
