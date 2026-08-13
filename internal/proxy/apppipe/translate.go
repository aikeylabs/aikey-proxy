package apppipe

import (
	"context"
	"net/http"

	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/sjson"
)

// translate.go — App pipeline protocol translation.
//
// 2026-05-21 Phase 2 Day 7 redesign:
//
//   - Inbound wire format is ALWAYS OpenAI Chat Completions (the URL is
//     `/apps/<slug>/v1/chat/completions`; no protocol segment in the URL).
//   - Upstream wire format is determined by the BINDING's protocol_type.
//     provider_code remains the physical vendor identity and is used only
//     for provider-scoped model normalization.
//   - When fromFmt == toFmt (e.g. OpenAI → OpenAI), no translation is
//     needed; this is a fast-path zero-cost short-circuit.
//   - Streaming requests requiring translation are hard-rejected with
//     501 STREAM_TRANSLATION_NOT_SUPPORTED (Phase 2 阶段 0 limit; see
//     `workflow/Docs/Production/streaming-translation-limitation.md`).
//
// Isolation: this file lives in apppipe. Tier 1 / Tier 2 routes NEVER
// reach this code. Translation engagement writes to a per-request
// ResolvedRoute.ResponseTransform closure — the field stays nil on
// non-app routes so serveRoute's ModifyResponse is byte-identical for
// them. The provider adapter layer (`internal/provider/*.go`) is NOT
// touched.

// TranslateOutcome reports what MaybeTranslateRequest did so callers can
// log accurately and tests can assert end-state. Zero value means "no
// translation applied for this request" (fast path).
type TranslateOutcome struct {
	// UpstreamFormat is the target wire format we translated TO (or
	// would have, if Engaged=true). Surfaced for structured logging.
	UpstreamFormat translator.Format
	// Body is what serveRoute should forward. When Engaged is true this
	// is the translated bytes; when false it's the sanitized bytes
	// echoed back unchanged (so callers can use one statement).
	Body []byte
	// Engaged is true iff translation was performed.
	Engaged bool
}

// MaybeTranslateRequest decides whether protocol translation is needed
// for this app-pipeline request and, if so, runs the request-side half +
// arms the response-side half on the ResolvedRoute.
//
// Inputs:
//   - registry: protocol-translator Registry (translator.DefaultRegistry()
//     in production)
//   - route: per-request ResolvedRoute; mutated to install
//     ResponseTransform when translation engages
//   - binding: the upstream binding resolved earlier; ProviderCode and
//     ProtocolType are independent axes
//   - inboundFmt: inferred from URL path (FormatOpenAI for /chat/completions,
//     FormatAnthropic for /v1/messages) — see InferInboundWire in router.go
//   - r: inbound *http.Request, only used for query-string stream check
//   - sanitized: already-sanitized inbound body bytes
//   - model: parsed model id (used to fill the translated request's
//     model field; passed as-is to upstream — Anthropic/OpenAI handle
//     model id validation on their end)
//
// Returns:
//   - Outcome describing what happened
//   - *SanitizeError on hard-fail (matching the existing error envelope
//     pipeline used by sanitize/resolve callers in proxy.go)
//
// Phase 2 中方案 supported matrix (2026-05-21):
//   - OpenAI    → OpenAI    : fast path (same wire)
//   - OpenAI    → Anthropic : translate via openai_anthropic pair
//   - Anthropic → Anthropic : fast path (passthrough, Cursor / Claude Code)
//   - Anthropic → OpenAI    : REJECT (no pair registered, loud 501)
//   - other     → other     : REJECT (no pair registered)
func MaybeTranslateRequest(
	ctx context.Context,
	registry *translator.Registry,
	route *vkeys.ResolvedRoute,
	binding *vault.ProviderBinding,
	inboundFmt translator.Format,
	r *http.Request,
	sanitized []byte,
	model string,
) (TranslateOutcome, *SanitizeError) {
	fromFmt := inboundFmt
	if fromFmt == "" {
		// Defensive: should never happen because InferInboundWire always
		// returns a non-empty Format. Fall back to OpenAI default.
		fromFmt = translator.FormatOpenAI
	}
	toFmt := bindingProtocolFormat(binding)

	// G1 fix (2026-05-21): strip `<upstream>/` prefix from body.model
	// before forwarding to upstream. Affects both translate path (passes
	// normalized model to TranslateRequest) and passthrough path (rewrites
	// the body.model field in `sanitized` via sjson).
	//
	// Why before the matrix dispatch: normalization is a pre-condition
	// for both translate and passthrough paths — neither would work
	// correctly with a raw `anthropic/claude-...` value (direct upstream
	// rejects, aggregator handles).
	//
	// See provider.NormalizeModelForUpstream for the rule.
	normalizedModel := provider.NormalizeModelForUpstream(model, binding.ProviderCode)
	if normalizedModel != model {
		// Patch the sanitized body so passthrough (fast path) also sees
		// the normalized model. For translate paths this is harmless
		// (translator reads `model` arg first; body's model field is
		// rebuilt anyway).
		if patched, err := sjson.SetBytes(sanitized, "model", normalizedModel); err == nil {
			sanitized = patched
		}
		model = normalizedModel
	}

	// Fast path: same wire family. No translator round-trip; saves ~50µs/req
	// (one JSON parse + rebuild). Cases covered:
	//
	//   (a) Identical Format strings (e.g. OpenAI → OpenAI, Anthropic → Anthropic).
	//   (b) OpenAI wire family — fromFmt is FormatOpenAI AND toFmt is an
	//       OpenAI-wire-compatible upstream code (Kimi / DeepSeek / Qwen /
	//       OpenRouter / SiliconFlow / Groq / Together / ...). The body shape
	//       matches; the per-provider adapter handles BaseURL + auth header
	//       differences. See provider.IsOpenAIWireCompatible for the catalog.
	//
	// Without case (b), client sending body.model="kimi-k2-turbo" with a
	// Kimi-bound app would hit TRANSLATION_PAIR_NOT_REGISTERED (501) because
	// no openai→kimi translator pair exists — wrong, since nothing needs
	// to be translated.
	if fromFmt == toFmt ||
		(fromFmt == translator.FormatOpenAI && provider.IsOpenAIWireCompatible(string(toFmt))) {
		return TranslateOutcome{Engaged: false, Body: sanitized, UpstreamFormat: toFmt}, nil
	}

	// Pair availability gate. Loud failure rather than silent passthrough.
	if !registry.HasPair(fromFmt, toFmt) {
		return TranslateOutcome{}, &SanitizeError{
			StatusCode: http.StatusNotImplemented,
			ErrorCode:  "TRANSLATION_PAIR_NOT_REGISTERED",
			Message: "App binding requires protocol translation from " + string(fromFmt) +
				" to " + string(toFmt) + " but no translator pair is registered for that " +
				"combination. Only the openai → anthropic direction is implemented in Phase 2 阶段 0.",
		}
	}

	// Phase 2 阶段 0 hard limit: streaming requires SSE chunk transform
	// which is阶段 1 work. Reject explicitly so SDKs see a precise 501
	// rather than mysterious broken-shape responses. See
	// workflow/Docs/Production/streaming-translation-limitation.md.
	if requestIsStreaming(r, sanitized) {
		return TranslateOutcome{}, &SanitizeError{
			StatusCode: http.StatusNotImplemented,
			ErrorCode:  "STREAM_TRANSLATION_NOT_SUPPORTED",
			Message: "Streaming requests through the App pipeline's protocol translator " +
				"are not yet supported in Phase 2 阶段 0 (the SSE chunk reshaper lands " +
				"in 阶段 1). Workaround: set `stream=false` in your request body " +
				"and re-issue. The non-stream response shape is fully translated.",
		}
	}

	// Run the request-side transform.
	translated, tErr := registry.TranslateRequest(ctx, fromFmt, toFmt, model, sanitized, false)
	if tErr != nil {
		return TranslateOutcome{}, translateErrorToSanitizeError(tErr)
	}

	// Arm the response-side transform. Wrapping *TranslateError as plain
	// error keeps vkeys decoupled from pkg/protocol-translator.
	route.ResponseTransform = func(rctx context.Context, body []byte) ([]byte, error) {
		out, terr := registry.TranslateNonStream(rctx, fromFmt, toFmt, body)
		if terr != nil {
			return nil, terr
		}
		return out, nil
	}

	return TranslateOutcome{Engaged: true, Body: translated, UpstreamFormat: toFmt}, nil
}

// bindingProtocolFormat converts the route-table protocol vocabulary to the
// translator registry vocabulary. Legacy bindings without protocol_type retain
// the old provider-derived behavior only when the provider has a unique
// protocol; normalized current bindings always take this path explicitly.
func bindingProtocolFormat(binding *vault.ProviderBinding) translator.Format {
	protocolType := provider.CanonicalProtocol(binding.ProtocolType)
	if protocolType == "" {
		protocolType, _ = provider.ProtocolFamily(binding.ProviderCode, "")
	}
	switch protocolType {
	case "openai_compatible":
		return translator.FormatOpenAI
	case "anthropic":
		return translator.FormatAnthropic
	case "gemini":
		return translator.FormatGemini
	default:
		return translator.Format(protocolType)
	}
}

// requestIsStreaming detects "stream":true in the sanitized request body.
// Also checks `?stream=true` query param as a defensive fallback (some
// clients use both). String scan over the sanitized JSON to avoid an
// extra parse — at MVP we only need a yes/no.
//
// Sanitizer's json round-trip canonicalizes keys to lowercase + double-quoted
// form, so `"stream":true` reliably appears as that literal substring
// when the field is set. A false positive is acceptable (cost = 501,
// user retries); false negative is more expensive (silently translated
// stream broken shape).
func requestIsStreaming(r *http.Request, sanitizedBody []byte) bool {
	if r != nil {
		if q := r.URL.Query().Get("stream"); q == "true" || q == "1" {
			return true
		}
	}
	if len(sanitizedBody) == 0 {
		return false
	}
	s := string(sanitizedBody)
	return containsCI(s, `"stream":true`) || containsCI(s, `"stream": true`)
}

func containsCI(haystack, needle string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	hl := len(haystack)
	nl := len(needle)
	for i := 0; i <= hl-nl; i++ {
		match := true
		for j := 0; j < nl; j++ {
			hc := haystack[i+j]
			nc := needle[j]
			if hc >= 'A' && hc <= 'Z' {
				hc += 'a' - 'A'
			}
			if nc >= 'A' && nc <= 'Z' {
				nc += 'a' - 'A'
			}
			if hc != nc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// translateErrorToSanitizeError adapts a *translator.TranslateError into
// the SanitizeError shape the app-pipeline error pipeline already knows
// how to render. We don't add a new envelope per "expose conflicts, don't
// average" — SanitizeError is the existing error contract for app-pipeline
// 4xx/5xx, and translator errors fit cleanly.
func translateErrorToSanitizeError(tErr *translator.TranslateError) *SanitizeError {
	return &SanitizeError{
		StatusCode: tErr.HTTPStatus,
		ErrorCode:  tErr.Code,
		Message:    tErr.Message,
	}
}

// /apps/<slug>/v1/chat/completions is the standard inbound path. After
// translator engagement to Anthropic, we need to rewrite it to
// /v1/messages for the upstream. This function returns the canonical
// upstream path for a given target Format. Empty string means "no
// rewrite needed" (e.g. OpenAI→OpenAI keeps /v1/chat/completions).
//
// Why a separate function (vs hardcoded in handleAppPipeline): the path
// is a PROTOCOL-level convention, not a provider-instance convention,
// and there's no reason to scatter the openai→anthropic mapping in
// multiple places. Add new entries here when new pairs land.
func CanonicalUpstreamPath(to translator.Format) string {
	switch to {
	case translator.FormatAnthropic:
		return "/v1/messages"
	case translator.FormatOpenAI:
		return "/v1/chat/completions"
	case translator.FormatOpenAIResponses, translator.FormatGemini, translator.FormatBedrock:
		// No path rewrite — these formats are not translated to Anthropic here.
		return ""
	default:
		return ""
	}
}
