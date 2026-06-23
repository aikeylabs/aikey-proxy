package apppipe

// egress.go — request body sanitizer + response header strip for the App
// pipeline. Implements the "Ingress Parse, Egress Strip" contract from
// 主方案 §5.2:
//
//   - X-AiKey-*  headers MUST NOT leave AiKey.
//   - body.aikey field MUST NOT leave AiKey (custom user-supplied metadata).
//   - body.metadata MUST NOT leave AiKey by default (agent-supplied;
//     provider adapter is the only party allowed to inject upstream
//     metadata — e.g. Claude OAuth's metadata.user_id — but the inbound
//     value is stripped here).
//   - n>1 MUST hard-fail with UNSUPPORTED_PARAMETER (Anthropic upstream
//     can't honor it, "silently drop" would deceive the caller).
//   - logprobs / top_logprobs / seed silently drop + warn (per
//     trace_id dedupe is the caller's responsibility; sanitizer just
//     returns a flag in SanitizeContext.Warnings).
//   - response_format is PASSED THROUGH untouched — Phase 2's
//     protocol-translator handles json_object / json_schema via the
//     forced tool-call workaround (LiteLLM-aligned). Pre-Phase-2 this
//     sanitizer hard-rejected it; Day 5 of Phase 2 removed the reject
//     because the translator now does the real work.
//
// What this layer is NOT:
//   - It does NOT do OpenAI ↔ Anthropic field mapping; that's the
//     protocol-translator's job (Phase 2, separate gomod).
//   - It does NOT enforce per-provider header allowlists; that's a
//     provider adapter concern (Phase 2).
//
// Performance budget (per 主方案 §5.2 sanitizer table): < 2ms for 100KB
// body, < 20ms for 1MB body. JSON full parse + re-marshal is the
// approach because gjson/sjson can't strip nested `metadata` recursively
// without per-path code and we want one parse pass.

import (
	"encoding/json"
	"net/http"
	"strings"
)

// SanitizeContext carries data the sanitizer extracted from the request
// body that downstream pipeline stages (usage event emitter, audit log)
// need but the upstream must NOT see.
type SanitizeContext struct {
	// AikeyField is the verbatim value of body.aikey before strip.
	// nil if the field was absent. Used by pipeline.go to emit a
	// metadata-rich usage event without re-parsing the body.
	AikeyField map[string]interface{}
	// Metadata is the verbatim value of body.metadata before strip.
	// nil if absent. Same usage as AikeyField; the two fields are
	// independent so an agent could populate either or both.
	Metadata map[string]interface{}
	// Warnings holds non-fatal degradation notices for ops visibility.
	// One entry per degraded field (e.g., "logprobs_dropped", "seed_dropped").
	// Caller is responsible for trace_id-based dedupe before emitting
	// to logs (主方案 §4.4 says "单次 WARN per trace_id").
	Warnings []string
}

// SanitizeError represents a request that cannot proceed because its
// body is malformed or contains a hard-rejected field. Same shape as
// AuthError / ResolveError; once a 3rd similar struct appears these
// will be factored to a shared PipelineError type.
type SanitizeError struct {
	ErrorCode  string
	Message    string
	StatusCode int
}

func (e *SanitizeError) Error() string { return e.ErrorCode + ": " + e.Message }

// SanitizeRequestBody parses, sanitizes, and re-marshals an inbound
// OpenAI-style chat completion / messages request body.
//
// Returns:
//   - sanitized: the re-marshaled body safe to forward upstream
//   - ctx: extracted aikey + metadata + degradation warnings
//   - err: SanitizeError when the body is malformed or contains a
//     hard-rejected field; sanitized + ctx are nil in that case
//
// JSON-parse failures are converted to 400 MALFORMED_REQUEST_BODY so
// the user sees a clean error rather than a confusing upstream 4xx.
//
// Why full-parse-and-re-marshal vs gjson surgical edits: spec requires
// stripping body.metadata which may contain arbitrary nested data
// (including the agent's own metadata.aikey if any); a gjson-based
// stripper would need bespoke code per known nested path, while
// map[string]interface{} round-trip handles arbitrary depth cleanly.
// Performance is within the spec budget at typical sizes.
func SanitizeRequestBody(body []byte) ([]byte, *SanitizeContext, *SanitizeError) {
	if len(body) == 0 {
		// Empty body is structurally invalid for chat/completions
		// (model + messages are required). Surface as a precise error
		// so the user sees "your client sent no body" rather than a
		// vague upstream 400.
		return nil, nil, &SanitizeError{
			StatusCode: http.StatusBadRequest,
			ErrorCode:  "MALFORMED_REQUEST_BODY",
			Message:    "Request body is empty. Send a JSON object with at least `model` and `messages`.",
		}
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil, &SanitizeError{
			StatusCode: http.StatusBadRequest,
			ErrorCode:  "MALFORMED_REQUEST_BODY",
			Message:    "Request body is not valid JSON: " + err.Error(),
		}
	}

	ctx := &SanitizeContext{}

	// ── Hard rejects (errors that stop the pipeline) ──────────────────
	//
	// Order: check rejects BEFORE doing strips. If the request is going
	// to fail, we don't waste cycles re-marshaling a body that won't be
	// forwarded.

	// n>1 is a hard reject because silent-drop would return 1 completion
	// while the caller thought they asked for multiple — masking the
	// limitation and breaking caller assumptions about the response shape.
	if nRaw, ok := parsed["n"]; ok {
		if n, isNumber := asInt(nRaw); isNumber && n > 1 {
			return nil, nil, &SanitizeError{
				StatusCode: http.StatusBadRequest,
				ErrorCode:  "UNSUPPORTED_PARAMETER",
				Message:    "n must be 1; multiple completions are not supported (Anthropic upstream has no multi-completion mode, and silent drop would mislead the caller about response shape).",
			}
		}
	}

	// response_format is intentionally pass-through here — Phase 2's
	// protocol-translator (pairs/openai_anthropic/response_format.go)
	// converts json_object / json_schema into a forced tool-call against
	// a synthetic "respond_in_json" tool. Sanitizer is the
	// protocol-agnostic security layer; structured-output translation
	// is provider-specific compatibility work and belongs downstream
	// (主方案 §6).

	// ── Silent drops with warning (logprobs / top_logprobs / seed) ────
	//
	// Per 主方案 §4.4, these are silent-dropped because Anthropic
	// upstream silently ignores them anyway — rejecting them would be
	// stricter than the upstream itself. We DO emit a single warning
	// per trace_id (caller-side dedupe via ctx.Warnings) so ops can see
	// when an Agent expects these to work.
	if _, ok := parsed["logprobs"]; ok {
		delete(parsed, "logprobs")
		ctx.Warnings = append(ctx.Warnings, "logprobs_dropped")
	}
	// top_logprobs is meaningful only with logprobs, so the single
	// "logprobs_dropped" warning covers it; silently drop the orphan field.
	delete(parsed, "top_logprobs")
	if _, ok := parsed["seed"]; ok {
		delete(parsed, "seed")
		ctx.Warnings = append(ctx.Warnings, "seed_dropped")
	}

	// ── Strips (agent control-plane fields that must not reach upstream) ──
	//
	// Extract into SanitizeContext BEFORE deleting so the pipeline can
	// emit a usage event carrying these values (audit + per-app
	// telemetry — they're the whole reason agents send them).
	if v, ok := parsed["aikey"]; ok {
		// Coerce to map; if the agent sent a non-object (e.g., string),
		// we still strip it but don't try to interpret. Future: emit
		// a warning for non-map aikey since it's spec-violating.
		if m, isMap := v.(map[string]interface{}); isMap {
			ctx.AikeyField = m
		}
		delete(parsed, "aikey")
	}
	if v, ok := parsed["metadata"]; ok {
		if m, isMap := v.(map[string]interface{}); isMap {
			ctx.Metadata = m
		}
		delete(parsed, "metadata")
	}

	// ── Re-marshal ─────────────────────────────────────────────────────
	//
	// json.Marshal sorts map keys alphabetically; the upstream doesn't
	// care about key order so this is fine. We deliberately do NOT
	// preserve the inbound key order — that would require a manual
	// streaming rewrite (gjson/sjson style) which we rejected up front
	// for the metadata-arbitrary-depth reason.
	sanitized, err := json.Marshal(parsed)
	if err != nil {
		// Shouldn't happen — we just parsed from JSON. Defensive.
		return nil, nil, &SanitizeError{
			StatusCode: http.StatusInternalServerError,
			ErrorCode:  "SANITIZE_REMARSHAL_FAILED",
			Message:    "Failed to re-marshal sanitized request body: " + err.Error(),
		}
	}

	return sanitized, ctx, nil
}

// StripResponseHeaders removes the X-AiKey-* family from an outbound
// response so internal control-plane headers don't leak to the
// third-party Agent process.
//
// Why not also strip from inbound: the existing proxy already strips
// X-AiKey-* on the request path in proxy/proxy.go:1053 (independent
// concern). This function is the App-pipeline-specific RESPONSE
// counterpart — when the upstream replies, if anything in the chain
// injected an X-AiKey-* header (legacy proxy middleware, etc.) we
// strip it before handing the response to the Agent.
func StripResponseHeaders(h http.Header) {
	if h == nil {
		return
	}
	// Collect keys first because deleting while ranging mutates the map.
	var toDelete []string
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-aikey-") {
			toDelete = append(toDelete, k)
		}
	}
	for _, k := range toDelete {
		h.Del(k)
	}
}

// asInt coerces a JSON number (which Go decodes as float64) to int with
// a hint flag. Floating-point n values like 1.5 return (1, true); they
// fail the n>1 check at 1.5 < 2 but that's fine — the upstream would
// reject 1.5 anyway as a non-integer.
func asInt(v interface{}) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	case int64:
		return int(x), true
	case json.Number:
		i, err := x.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	}
	return 0, false
}
