package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"sync/atomic"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// VaultGetter retrieves decrypted secrets by alias.
type VaultGetter interface {
	GetSecret(alias string) (string, error)
}

// Proxy is the core reverse proxy that handles virtual key resolution
// and request forwarding.
type Proxy struct {
	vault     VaultGetter
	registry  *vkeys.Registry
	providers *provider.Registry
	collector *events.Collector
	requests  atomic.Int64
	errors    atomic.Int64
}

// New creates a new Proxy.
func New(v VaultGetter, reg *vkeys.Registry, prov *provider.Registry, coll *events.Collector) *Proxy {
	return &Proxy{
		vault:     v,
		registry:  reg,
		providers: prov,
		collector: coll,
	}
}

// TotalRequests returns the total number of proxied requests.
func (p *Proxy) TotalRequests() int64 { return p.requests.Load() }

// TotalErrors returns the total number of error responses.
func (p *Proxy) TotalErrors() int64 { return p.errors.Load() }

// Handle is the main HTTP handler for data plane requests.
func (p *Proxy) Handle(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	p.requests.Add(1)

	// 1. Extract virtual key.
	token := extractVirtualKey(r)
	if token == "" {
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_MISSING",
			"Missing virtual key. Expected token with 'aikey_vk_' prefix in Authorization or x-api-key header.")
		return
	}

	// 2. Resolve virtual key → route.
	route := p.registry.Resolve(token)
	if route == nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Invalid virtual key. Token not found in registry.")
		return
	}

	// 3. Check model allowlist (if applicable).
	if len(route.AllowedModels) > 0 {
		model := extractModel(r)
		if model != "" && !route.IsModelAllowed(model) {
			p.errors.Add(1)
			writeJSONError(w, http.StatusForbidden, "permission_error", "POLICY_MODEL_FORBIDDEN",
				"Model '"+model+"' is not allowed for this virtual key.")
			return
		}
	}

	// 4. Get real key from vault.
	realKey, err := p.vault.GetSecret(route.KeyAlias)
	if err != nil {
		p.errors.Add(1)
		slog.Error("vault lookup failed", "alias", route.KeyAlias, "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "server_error", "SECRET_NOT_CONFIGURED",
			"Provider secret '"+route.KeyAlias+"' is not in the vault. Run: aikey secret set "+route.KeyAlias+" --from-stdin")
		return
	}

	// 5. Get provider adapter.
	prov, err := p.providers.Get(route.Provider)
	if err != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
			"Unknown provider: "+route.Provider)
		return
	}

	// 6. Detect streaming.
	streaming := isStreamingRequest(r)

	// 7. Store metadata in context for post-processing.
	ctx := context.WithValue(r.Context(), ctxKeyRoute, route)
	ctx = context.WithValue(ctx, ctxKeyStartTime, startTime)
	ctx = context.WithValue(ctx, ctxKeyIsStreaming, streaming)
	r = r.WithContext(ctx)

	// 8. Build and execute reverse proxy.
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			if err := prov.RewriteRequest(req, realKey, route.BaseURL); err != nil {
				slog.Error("rewrite request failed", "error", err)
			}
			// Remove hop-by-hop headers the proxy shouldn't forward.
			req.Header.Del("X-Forwarded-For")
		},
		ModifyResponse: func(resp *http.Response) error {
			p.recordEvent(r, resp, startTime, route, streaming)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.errors.Add(1)
			slog.Error("upstream error", "provider", route.Provider, "error", err)
			writeJSONError(w, http.StatusBadGateway, "server_error", "UPSTREAM_ERROR",
				"Failed to connect to upstream provider.")
		},
		FlushInterval: -1, // Flush immediately for SSE streaming.
	}

	rp.ServeHTTP(w, r)
}

// recordEvent sends a usage event to the async collector.
func (p *Proxy) recordEvent(req *http.Request, resp *http.Response, startTime time.Time, route *vkeys.ResolvedRoute, streaming bool) {
	duration := time.Since(startTime)

	event := events.UsageEvent{
		Timestamp:    startTime,
		VirtualKeyID: route.VirtualKeyID,
		Provider:     route.Provider,
		DurationMs:   duration.Milliseconds(),
		StatusCode:   resp.StatusCode,
		IsStreaming:   streaming,
		RequestPath:  req.URL.Path,
	}

	// Try to extract model from request context (already parsed in extractModel).
	if model := req.Header.Get("x-aikey-model"); model != "" {
		event.Model = model
	}

	if resp.StatusCode >= 400 {
		p.errors.Add(1)
		event.ErrorType = http.StatusText(resp.StatusCode)
	}

	p.collector.Record(event)
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
