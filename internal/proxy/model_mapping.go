package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/providerroutes"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// restoreResponseModel rewrites a non-streaming response body's top-level
// `model` field back to the client's original name when the request leg mapped
// it (design D-5 / P3.1-3.2). Returns the body unchanged when no mapping
// happened or the field already matches. 🚫 Never substitutes a hardcoded
// constant — only the exact client string carried in context (cc-switch #3600
// anti-pattern). Streaming SSE restoration is a separate, larger change (the
// stream drainer forwards frames verbatim) — see tasks P3.3.
func restoreResponseModel(ctx context.Context, body []byte) []byte {
	clientModel, ok := ctx.Value(ctxKeyMappedClientModel).(string)
	if !ok || clientModel == "" {
		return body
	}
	if gjson.GetBytes(body, "model").String() == clientModel {
		return body
	}
	if patched, err := sjson.SetBytes(body, "model", clientModel); err == nil {
		return patched
	}
	return body
}

// modelMappingResult is the outcome of applying a provider's model_map to a
// request (P2 / design D-1). RequestedModel is the client口径, EffectiveModel
// the upstream口径 — the audit 双口径 (I2). When Reject is set the caller must
// return MODEL_MAPPING_NOT_FOUND (unmatched policy=reject). NewBody is non-nil
// only when the body's `model` field actually changed; passthrough leaves the
// body byte-identical so non-mapped providers have zero blast radius.
type modelMappingResult struct {
	Mapped         bool
	RequestedModel string
	EffectiveModel string
	Reject         bool
	HadMap         bool // the resolved provider has a model_map (for passthrough WARN)
	Provider       string
	NewBody        []byte
}

// applyModelMapping resolves the model_map for a request's REAL upstream
// provider — determined path-awarely from the resolved base_url (GLM's
// /api/anthropic → zhipu), not the URL-path prefix — and rewrites the body's
// top-level `model` field to the upstream model name.
//
// Design D-1: this is an independent mapping layer, run AFTER route resolution
// and BEFORE the adapter's RewriteRequest — it never lives inside an adapter
// (which would drift per-adapter and pollute the narrow Key/Host/URL contract).
//
// Match order (exact → role → wildcard, 歧义不猜) and unmatched policy live in
// providerroutes.ResolveModel — the single source of truth shared byte-for-byte
// with the Rust CLI (P1c golden fixture). This function only decides WHEN to
// apply and rewrites the body.
func applyModelMapping(baseURL, requestedModel string, body []byte) modelMappingResult {
	res := modelMappingResult{RequestedModel: requestedModel, EffectiveModel: requestedModel}
	if requestedModel == "" {
		return res // no client model → nothing to map (e.g. non-chat endpoints)
	}
	tbl := provider.Routes()

	// Resolve the real upstream provider from the base_url path-awarely. This
	// is the safe P1d primitive (LookupByBaseURL) — it affects only which
	// model_map we consult, not adapter selection or event attribution.
	pr, ok := tbl.LookupByBaseURL(baseURL)
	if !ok || pr.Provider == "" {
		return res // host not in table → no mapping (P1j owns base_url fail-loud)
	}
	res.Provider = pr.Provider
	_, res.HadMap = tbl.ModelMapFor(pr.Provider)

	effective, matched, policy := tbl.ResolveModel(pr.Provider, requestedModel)
	if !matched {
		// unmatched + reject policy → caller emits MODEL_MAPPING_NOT_FOUND.
		// ResolveModel only returns a non-default policy when a map exists.
		if policy == providerroutes.UnmatchedReject {
			res.Reject = true
		}
		return res // passthrough: body untouched (byte-identical)
	}

	res.EffectiveModel = effective
	if effective == requestedModel {
		res.Mapped = true
		return res // matched but same name → no body change
	}
	newBody, err := sjson.SetBytes(body, "model", effective)
	if err != nil {
		// Rewrite failed (malformed body). Leave body unchanged; report the
		// intended effective model for audit but don't corrupt the request.
		return res
	}
	res.Mapped = true
	res.NewBody = newBody
	return res
}

// truthfulProviderCode resolves a binding's REAL upstream vendor from its
// base_url (P1d / design D-10 refined). GLM's .../api/anthropic endpoint →
// "zhipu" even when the binding was declared as "anthropic". Returns the
// declared code unchanged when the base_url is empty or its host isn't in the
// route table (third-party gateways), so the fix is a no-op for everything
// except genuine cross-provider endpoints.
func truthfulProviderCode(baseURL, declared string) string {
	if baseURL == "" {
		return declared
	}
	if pr, ok := provider.Routes().LookupByBaseURL(baseURL); ok && pr.Provider != "" {
		return pr.Provider
	}
	return declared
}

// applyModelMappingToRequest wires the mapping layer into the path-prefix
// request path (P2 / design D-1). It runs AFTER route resolution + the client-
// model allowlist (D-4: whitelist validated the CLIENT model first) and BEFORE
// the reverse proxy — an independent layer, never inside an adapter.
//
// Behaviour:
//   - mapped provider (currently only zhipu/GLM): rewrites the outbound
//     body.model to the upstream name; emits proxy.request.model_mapped.
//   - unmatched + reject policy: answers MODEL_MAPPING_NOT_FOUND, returns false.
//   - unmatched + passthrough policy (provider HAS a map): forwards unchanged +
//     WARN proxy.request.model_mapping_missing (禁止 #32: 回落必配 WARN).
//   - provider without any map (all non-GLM traffic today): fully inert — body
//     byte-identical, no log — so blast radius is scoped to mapped providers.
//
// Audit 双口径 (I2) falls out naturally: extractModel already stashed the CLIENT
// model as ev.RequestedModel before this runs, and the upstream echoes the
// rewritten (effective) model into ev.Model.
func (p *Proxy) applyModelMappingToRequest(w http.ResponseWriter, r *http.Request, route *vkeys.ResolvedRoute, logger *slog.Logger) (proceed bool) {
	if r.Body == nil || route == nil {
		return true
	}
	requested := extractModel(r)
	if requested == "" {
		return true
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, extractBodyHardLimit+1))
	if err != nil || len(bodyBytes) > extractBodyHardLimit {
		// Can't (or shouldn't) rewrite an unreadable/oversized body — restore
		// and pass through unchanged (same fence extractModel uses).
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return true
	}

	res := applyModelMapping(route.BaseURL, requested, bodyBytes)

	if res.Reject {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		p.errors.Add(1)
		p.mapRejected.Add(1)                          // 7.9/3.5: configured-but-missing (reject)
		p.recordMappingMiss(res.Provider, requested) // 7.9/3.5: stash last miss
		logger.Warn("model mapping: unmatched model rejected",
			"event.name", "proxy.request.model_mapping_missing",
			"provider", res.Provider, "requested_model", requested)
		// Terse, single action, no internal structure; 🚫 must NOT point at a
		// console switch (rev3: no such switch exists).
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "MODEL_MAPPING_NOT_FOUND",
			"Model '"+requested+"' isn't available on this upstream. Use a supported model name.")
		return false
	}

	if res.NewBody != nil {
		r.Body = io.NopCloser(bytes.NewReader(res.NewBody))
		r.ContentLength = int64(len(res.NewBody))
		r.Header.Set("Content-Length", itoaInt64(int64(len(res.NewBody))))
		// Stash the client's ORIGINAL model (response restoration, D-5) and the
		// EFFECTIVE upstream model (audit 双口径 / pricing, I2). *r mutation via
		// WithContext mirrors extractModelLazy's stash pattern.
		ctx := context.WithValue(r.Context(), ctxKeyMappedClientModel, requested)
		ctx = context.WithValue(ctx, ctxKeyMappedEffectiveModel, res.EffectiveModel)
		*r = *r.WithContext(ctx)
		p.mapApplied.Add(1) // 7.9/3.5: healthy — a rule rewrote the model
		logger.Debug("model mapped",
			"event.name", "proxy.request.model_mapped",
			"provider", res.Provider, "requested_model", requested, "effective_model", res.EffectiveModel)
		return true
	}

	// No rewrite. Restore the body byte-for-byte.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	if res.HadMap && !res.Mapped {
		// passthrough policy, no rule matched — surface it (禁止 #32).
		p.mapPassthrough.Add(1) // 7.9/3.5: configured-but-missing (passthrough)
		p.recordMappingMiss(res.Provider, requested)
		logger.Warn("model mapping: passthrough, no rule matched",
			"event.name", "proxy.request.model_mapping_missing",
			"provider", res.Provider, "requested_model", requested)
	}
	return true
}

// recordMappingMiss stamps the most-recent "configured but not effective"
// occurrence for the diagnostics endpoint (7.9). Also bumps mapRejected when the
// caller is on the reject path (Reject sets it before this via the counter add
// below — here we only stash the last record + the reject counter for the reject
// branch). Kept tiny + lock-free (atomic pointer swap) so it stays off the hot
// path's critical section.
func (p *Proxy) recordMappingMiss(provider, requested string) {
	if provider == "" {
		provider = "unknown"
	}
	p.lastMapMiss.Store(&mapMissRecord{
		Provider:  provider,
		Requested: requested,
		AtUnix:    time.Now().Unix(),
	})
}

// mapMissRecord is the last "model configured but no rule matched" occurrence,
// surfaced read-only by /v1/diagnostics/pipeline so the four surfaces (3.5) can
// tell the user a mapping isn't taking effect (vs. "no data").
type mapMissRecord struct {
	Provider  string `json:"provider"`
	Requested string `json:"requested_model"`
	AtUnix    int64  `json:"at_unix"`
}
