package proxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"log/slog"

	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/probepipe"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// Model discovery for the Probe pipeline: GET /probe/<alias>/v1/models.
//
// 🔴 WHY THIS EXISTS: WE WERE GUESSING A MODEL AND BLAMING THE USER'S RELAY
// FOR THE GUESS.
//
// trust-check has to name a model before it can check a credential, and for
// an alias that has never been checked it fell back to the provider's default
// (`gpt-4o` for openai). That is a fair guess for a key pointing at
// api.openai.com and an unfounded one for a relay, which serves whatever its
// operator configured. Measured on a real newapi gateway on 2026-08-15: the
// token was scoped to `gpt-5.6-sol` alone, so the check went out asking for
// gpt-4o and came back
//
//	UPSTREAM_4XX: 403 该令牌无权访问模型 gpt-4o
//
// which reads as "your relay is broken" when the truth is "AiKey asked for a
// model your relay never claimed to serve". Relays are the primary thing this
// product checks, so the first click failing is not an edge case.
//
// Asking the endpoint what it serves is the only answer that needs no user
// input (交互简洁性优先) and no second source of truth to drift.
//
// 🔴 WHY IT GOES THROUGH THE PROXY AT ALL: trust-local must never hold a
// provider key. The whole credential model is that the proxy owns secrets and
// trust-local presents a first-party bearer. Discovery therefore has to be a
// proxy capability, or it would force the key into a process built not to
// have one.
//
// 🔴 WHY NOT serveRoute: that path exists for chat traffic — usage
// accounting, observers, model translation, SSE draining. A model listing has
// no tokens to account and nothing to observe; routing it through serveRoute
// would write usage events for a request that consumed nothing and put
// chat-shaped machinery on a path that is a plain GET.
//
// 🚫 DELIBERATELY NARROW, AND IT MUST STAY THAT WAY. GET only, the exact
// suffix `/models` only, no request body forwarded, a capped response, and a
// short timeout. This is not a general pass-through: widening it to arbitrary
// paths would turn the probe pipeline into an open relay for anything the
// credential can reach, authenticated by a bearer that is a compile-time
// constant.

// probeModelsSuffix is the only StrippedPath this handler will serve.
const probeModelsSuffix = "/models"

// probeModelsTimeout bounds the whole discovery round-trip. Short on purpose:
// discovery runs while a user is looking at a page, and a slow answer is worth
// less than a fast "we could not tell".
const probeModelsTimeout = 10 * time.Second

// probeModelsMaxBytes caps what we copy back. Some aggregator gateways list
// thousands of models; the caller only needs enough to pick one, and an
// unbounded copy makes the response size an upstream's choice.
const probeModelsMaxBytes = 512 * 1024

// isProbeModelsRequest reports whether this probe request is the read-only
// model-discovery call.
//
// 🔴 Method AND path, not path alone. A POST to /v1/models is not discovery,
// and letting one through would forward an unexamined body upstream on a path
// that skips the sanitizer.
func isProbeModelsRequest(r *http.Request, probeCtx *probepipe.ProbeContext) bool {
	return r != nil && probeCtx != nil &&
		r.Method == http.MethodGet &&
		probeCtx.StrippedPath == probeModelsSuffix
}

// handleProbeModelsDiscovery forwards a model listing for one alias.
//
// Stages 1 (authn) and 2 (alias resolve) have already run in
// handleProbePipeline; this takes over from there and deliberately skips
// stage 3 (body sanitize) and stage 4 (infer upstream from body.model), both
// of which assume a chat request. Stage 4 is precisely what cannot run here:
// there is no model in the request — finding one out is the point.
func (p *Proxy) handleProbeModelsDiscovery(
	w http.ResponseWriter,
	r *http.Request,
	probeCtx *probepipe.ProbeContext,
	binding *vault.ProviderBinding,
	logger *slog.Logger,
) {
	logger = logger.With("probe_stage", "models_discovery")

	// The upstream-facing path, set before credential resolution for the same
	// reason the chat path does it: provider setup reads it.
	r.URL.Path = "/v1" + probeModelsSuffix
	if r.URL.RawPath != "" {
		r.URL.RawPath = r.URL.Path
	}
	r.Body = http.NoBody
	r.ContentLength = 0

	cred, resolvedReq, bindErr := p.ResolveBindingCredential(r, binding, logger)
	if bindErr != nil {
		p.errors.Add(1)
		logger.Warn("probe models discovery credential resolution failed",
			"error.code", bindErr.ErrorCode)
		writeJSONError(w, bindErr.StatusCode, bindErr.ErrorType, bindErr.ErrorCode, bindErr.Message)
		return
	}
	r = resolvedReq
	if cred.RealKey == "" {
		p.errors.Add(1)
		writeJSONError(w, http.StatusServiceUnavailable, "server_error", "BINDING_CREDENTIAL_UNRESOLVED",
			"Alias \""+probeCtx.AliasName+"\" could not be resolved to a usable credential.")
		return
	}

	// Same protocol resolution as the chat path's stage 6, so discovery and
	// the check that follows it speak to the same adapter. A relay resolved
	// as openai_compatible for chat must not be asked for its models through
	// the anthropic adapter.
	protocolType := binding.ProtocolType
	if protocolType == "" && cred.ManagedKey != nil && cred.ManagedKey.ProtocolType != "" {
		protocolType = cred.ManagedKey.ProtocolType
	}
	if protocolType == "" {
		if pr, ok := provider.Routes().LookupByBaseURL(cred.BaseURL); ok {
			protocolType = pr.Protocol
		} else if pf, ok := provider.ProtocolFamily(binding.ProviderCode, protocolType); ok {
			protocolType = pf
		}
	}
	prov, provErr := p.providers.Get(protocolType)
	if provErr != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
			"Unknown upstream provider protocol: "+protocolType)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), probeModelsTimeout)
	defer cancel()

	out, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, "http://placeholder/v1"+probeModelsSuffix, nil)
	if reqErr != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusInternalServerError, "server_error", "PROBE_MODELS_REQUEST_BUILD_FAILED",
			"Could not build the model-discovery request: "+reqErr.Error())
		return
	}
	// 🔴 The adapter sets the auth header and stitches the base URL. Doing
	// either by hand here would be a second implementation of credential
	// carriage, and the two would drift on exactly the endpoints that need
	// them most (the `/v1/v1` stitching case is why Routes().Stitch exists).
	if rewriteErr := prov.RewriteRequest(out, cred.RealKey, cred.BaseURL); rewriteErr != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROBE_MODELS_REWRITE_FAILED",
			"Could not target the upstream for model discovery: "+rewriteErr.Error())
		return
	}
	// Carry the inbound UA so a gateway that filters on it behaves the same
	// way here as it does for the check that follows. The relay measured on
	// 2026-08-15 answers 1010 (Cloudflare UA ban) to a default Go/urllib UA
	// and 200 to a client UA — discovery that got banned while the check
	// succeeded would report "no models" about a perfectly reachable endpoint.
	if ua := r.Header.Get("User-Agent"); ua != "" {
		out.Header.Set("User-Agent", ua)
	}
	out.Header.Set("Accept", "application/json")

	transport := p.currentTransport()
	if transport == nil {
		transport = http.DefaultTransport
	}
	client := &http.Client{Transport: transport, Timeout: probeModelsTimeout}

	resp, doErr := client.Do(out)
	if doErr != nil {
		p.errors.Add(1)
		logger.Warn("probe models discovery upstream call failed",
			"error", doErr, "error.code", "PROBE_MODELS_UPSTREAM_UNREACHABLE")
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROBE_MODELS_UPSTREAM_UNREACHABLE",
			"Could not reach the endpoint to list its models: "+doErr.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// 🔴 Status and body are passed through rather than interpreted. A 404
	// from an endpoint with no /v1/models is a real answer ("this endpoint
	// does not tell you"), and the caller has to be able to tell it apart
	// from a 401 or a network failure to word its own abstention correctly.
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(resp.StatusCode)
	if _, copyErr := io.Copy(w, io.LimitReader(resp.Body, probeModelsMaxBytes)); copyErr != nil {
		logger.Warn("probe models discovery response copy failed", "error", copyErr)
		return
	}
	logger.Info("probe models discovery completed",
		"event.name", "proxy.probe.models_discovered",
		"upstream_status", resp.StatusCode,
		"upstream_host", strings.TrimPrefix(strings.TrimPrefix(cred.BaseURL, "https://"), "http://"),
	)
}
