package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
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
}

// Proxy is the core reverse proxy that handles virtual key resolution
// and request forwarding.
type Proxy struct {
	vault        VaultGetter
	activeReader ActiveKeyReader // non-nil when vault implements ActiveKeyReader
	registry     *vkeys.Registry
	providers    *provider.Registry
	collector    *events.Collector
	reporter     *events.Reporter // usage reporting to collector-service (nil = disabled)
	transport    http.RoundTripper // nil → http.DefaultTransport (reads env vars)
	proxyCtx     context.Context   // cancelled when the proxy shuts down
	proxyInstanceID string
	clientVersion   string // build version for audit metadata in usage events
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
func (p *Proxy) SetTransport(t http.RoundTripper) { p.transport = t }

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

// SetReporter sets the usage reporter for collector-service upload.
// clientVersion is the proxy build version (e.g. "0.1.0"), used as audit metadata.
func (p *Proxy) SetReporter(r *events.Reporter, instanceID, clientVersion string) {
	p.reporter = r
	p.proxyInstanceID = instanceID
	p.clientVersion = clientVersion
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
				"Provider secret '"+route.KeyAlias+"' is not in the vault. Run: aikey secret set "+route.KeyAlias+" --from-stdin")
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

	// Normalise brand aliases ("claude" → "anthropic") before vault lookup so
	// the query matches the provider_code stored by the server.
	canonicalCode := providerCanonicalCode(providerCode)

	// Try active team key first.
	mk, err := p.activeReader.GetActiveTeamKeyByProvider(canonicalCode)
	if err != nil {
		p.errors.Add(1)
		logger.Error("vault: active team key lookup failed", "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "server_error", "VAULT_ERROR", err.Error())
		return
	}

	if mk != nil {
		realKey = mk.PlaintextKey
		protocolType = mk.ProtocolType
		virtualKeyID = mk.VirtualKeyID
		// Use provider-specific base URL if available; fall back to primary slot's base_url.
		// ProviderBaseURLs is keyed by provider_code as stored in the vault
		// (may be "Claude", "claude", or "anthropic") — try canonical first.
		if url, ok := mk.ProviderBaseURLs[canonicalCode]; ok && url != "" {
			baseURL = url
		} else if url, ok := mk.ProviderBaseURLs[providerCode]; ok && url != "" {
			baseURL = url
		} else {
			baseURL = mk.BaseURL
		}
	} else {
		// Fall back to active personal key if its provider matches.
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
				// Match by canonical code so "claude" matches "anthropic" and vice-versa.
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
				protocolType = providerToProtocol(pcode)
				// Use user-set base_url if available; fall back to provider default.
				if entryBaseURL != "" {
					baseURL = entryBaseURL
				} else {
					baseURL = providerDefaultBaseURL(pcode)
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

	// Resolve provider adapter by protocol type, falling back to provider code.
	prov, err := p.providers.Get(protocolType)
	if err != nil {
		prov, err = p.providers.Get(providerCode)
		if err != nil {
			p.errors.Add(1)
			writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
				"Unknown provider: "+providerCode)
			return
		}
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
	}

	p.serveRoute(w, r, route, prov, realKey, "aikey_vk_"+virtualKeyID, startTime, logger)
}

// serveRoute executes the forwarding pipeline (streaming detection, transport
// selection, reverse proxy) shared by token-based and path-prefix routing.
func (p *Proxy) serveRoute(w http.ResponseWriter, r *http.Request, route *vkeys.ResolvedRoute, prov provider.Provider, realKey string, bearerToken string, startTime time.Time, logger *slog.Logger) {
	// 6. Detect streaming.
	streaming := isStreamingRequest(r)

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
	}
	var transport http.RoundTripper = inner
	if !streaming {
		transport = &detachedTransport{
			inner:      inner,
			proxyCtx:   p.proxyCtx,
			maxTimeout: p.UpstreamTimeout,
		}
	}

	// 9. Build and execute reverse proxy.
	rp := &httputil.ReverseProxy{
		Transport: transport,
		Director: func(req *http.Request) {
			if err := prov.RewriteRequest(req, realKey, route.BaseURL); err != nil {
				logger.Error("rewrite request failed", "error", err)
			}
			// Remove hop-by-hop headers the proxy shouldn't forward.
			req.Header.Del("X-Forwarded-For")
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

				in, out := prov.ExtractTokens(body, false)
				ev := p.buildBaseEvent(r, resp, startTime, route, false)
				ev.InputTokens = in
				ev.OutputTokens = out
				p.collector.Record(ev)
				p.reportUsage(route, bearerToken, ev.Model, startTime, resp.StatusCode, in, out, "", realKey)
			} else {
				// Streaming success: wrap body — background goroutine drains the
				// full SSE stream and records token usage when it ends, regardless
				// of whether the client stays connected.
				baseEvent := p.buildBaseEvent(r, resp, startTime, route, true)
				var cb reporterCallback
				if p.reporter != nil && route.OrgID != "" {
					cb = func(inTok, outTok int) {
						p.reportUsage(route, bearerToken, baseEvent.Model, startTime, resp.StatusCode, inTok, outTok, "", realKey)
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
	p.reportUsage(route, bearerToken, ev.Model, startTime, resp.StatusCode, 0, 0, ev.ErrorType, "")
}

// reportUsage sends a usage event to the collector-service reporter (if configured).
func (p *Proxy) reportUsage(route *vkeys.ResolvedRoute, bearerToken, model string, startTime time.Time, statusCode, inTokens, outTokens int, errorType, realKey string) {
	if p.reporter == nil {
		return
	}
	// Only report team-managed keys (with org_id)
	if route.OrgID == "" {
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
		InputTokens:     inTokens,
		OutputTokens:    outTokens,
		ErrorType:       errorType,
		RealKey:         realKey,
		ClientVersion:   p.clientVersion,
		SourceVersion:   p.clientVersion,
	})
	p.reporter.Report(ev)
}

// extractModel reads the request body to find the "model" field.
// It re-buffers the body for upstream forwarding and stores the model
// in a custom header for later use.
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
		Model string `json:"model"`
	}
	if json.Unmarshal(bodyBytes, &partial) == nil && partial.Model != "" {
		// Store in a custom header so we can read it later without re-parsing.
		r.Header.Set("x-aikey-model", partial.Model)
		return partial.Model
	}
	return ""
}
