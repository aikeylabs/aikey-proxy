package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/pkg/providerroutes"
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const (
	ctxKeyRoute contextKey = iota
	ctxKeyStartTime
	ctxKeyIsStreaming
	// ctxKeyDebugReqBody stores the raw request body bytes for the 4xx
	// debug-capture path. Populated only when AIKEY_PROXY_DEBUG_4XX_BODIES
	// is enabled (see proxy.go); absent on the hot path so we don't pay
	// the read+stash cost for every successful request.
	ctxKeyDebugReqBody
	// ctxKeyTrace stores the request's W3C TraceContext (created at the HTTP
	// entry in Handle) so deep code paths — notably buildBaseEvent feeding the
	// async collector — can correlate logs without re-extracting from headers.
	ctxKeyTrace
	// ctxKeyCodexCandidateModel stages a Codex-OAuth request body's `model`
	// field for deferred persistence. Populated on the request leg by
	// `captureCodexModel`; read on the response leg by `ModifyResponse`,
	// which only writes the state file when upstream returned 2xx. This
	// gates out poisoning scenarios (bug 2026-06-09): a single bad request
	// — e.g. `model: gpt-4o` against the ChatGPT-account Codex endpoint —
	// otherwise wrote a permanent stale value that all later connectivity
	// probes inherited.
	ctxKeyCodexCandidateModel
	// ctxKeyExtractedModel caches the body.model parsed by the FIRST
	// extractModel call this request, so the 2-3 later calls (model allowlist
	// check, inbound filter, usage stash) reuse it instead of re-reading +
	// re-unmarshaling r.Body. Keyed on the context — NOT the x-aikey-model
	// header — on purpose: the header is client-spoofable, and short-circuiting
	// on a client-injected value would bypass the model allowlist. The first
	// call always parses the real body (overwriting any injected header via
	// stashExtractedFields), so the security-critical first read is never
	// skipped; only repeat calls hit this cache.
	ctxKeyExtractedModel
	// ctxKeyPoolWindowCap carries the chosen pool account's window_max_util_pct
	// (int, N11's randomized pre-cut cap), stashed at resolution and read in
	// serveRoute's ModifyResponse to pre-cut the account when the upstream's
	// unified-utilization header crosses the cap (N10 防封). Absent → no pre-cut.
	ctxKeyPoolWindowCap
	// ctxKeyMappedClientModel carries the client's ORIGINAL model name when the
	// P2 model-mapping layer rewrote the request body to a different upstream
	// model (design D-5). The response leg reads it to write the model name
	// back to what the client sent, so the client recognizes its own model.
	// 🚫 Never a hardcoded constant (cc-switch #3600 anti-pattern) — always the
	// exact string the client requested. Absent → no restoration (no mapping).
	ctxKeyMappedClientModel
	// ctxKeyMappedEffectiveModel carries the UPSTREAM (effective) model the
	// request was mapped to (e.g. glm-4.6). buildBaseEvent reads it so the
	// usage event / pricing use the effective model (audit 双口径 I2 / P4.1),
	// while RequestedModel keeps the client model. Absent → no mapping.
	ctxKeyMappedEffectiveModel
	// ctxKeyMaskRestore carries the per-request *maskRestore state (numbered
	// placeholder → original text) built by applyInboundFilter when the inbound
	// filter applied a RESTORABLE mask (v4 apphook contract, B3 2026-08-08).
	// The response leg (non-streaming body + SSE restorer) reads it to swap
	// placeholders back to the user's original text — the ONLY sanctioned
	// response-direction rewrite (spec 2026-06-04 合规过滤方向 规则 2 唯一例外).
	// 🚫 The mapping lives in THIS context value only: never persisted, never
	// logged, dies with the request (B3 拍板 2026-08-06). Absent → response
	// passes through untouched (zero cost).
	ctxKeyMaskRestore
	// ctxKeyProviderPathDecision pins the exact OAuth-group outbound path and
	// override decision admitted by the path breaker. A concurrent Settings
	// change may affect the next request, but must not make one in-flight request
	// report success/failure against a different path than it actually used.
	ctxKeyProviderPathDecision
)

// traceFromContext retrieves the request's TraceContext. Returns the zero value
// (empty ids) when absent, so callers can log unconditionally.
func traceFromContext(ctx context.Context) observability.TraceContext {
	tc, _ := ctx.Value(ctxKeyTrace).(observability.TraceContext)
	return tc
}

// isAikeyProbe returns true when the caller (typically `aikey test` / doctor /
// add) has marked the request as a connectivity probe via `X-Aikey-Probe: 1`.
//
// Probe traffic flows through the regular data plane for credential injection
// + forwarding, but must NOT be recorded into reporter / WAL / collector —
// otherwise pre-flight tests inflate usage counters and (for OAuth/team keys
// with upstream billing) look like real work to the provider.
//
// Keep this helper next to the other header extractors so every emission site
// in proxy.go / recordEvent / streaming callback shares one definition.
const headerAikeyProbe = "X-Aikey-Probe"

func isAikeyProbe(r *http.Request) bool {
	return r != nil && r.Header.Get(headerAikeyProbe) == "1"
}

// routeSourceProbe is the ResolvedRoute.RouteSource stamped by
// handleProbePipeline (mode C, /probe/<alias>/v1/...). It is the ONE name for
// "this request came out of the Probe pipeline"; before it existed the concept
// was a bare "probe" literal repeated at the producer and re-derived by hand at
// every consumer, which is how the compliance exclusion below got lost.
const routeSourceProbe = "probe"

// isProbePipelineRoute reports whether a resolved route came from the Probe
// pipeline. THE single exit for that question — consumers must call this rather
// than compare RouteSource to a literal.
//
// Why it is not the same predicate as isAikeyProbe: the two describe different
// trust levels and must not be merged.
//
//   - isProbePipelineRoute is derived SERVER-SIDE from the path the request
//     arrived on (/probe/<alias>/...), after probepipe.Authenticate. The payload
//     on that path is aikey's own fixed degrade-detection probe, and the pipeline
//     can only resolve the caller's own PERSONAL aliases — it cannot reach a team
//     virtual key at all.
//   - isAikeyProbe is a CLIENT-SET header (X-Aikey-Probe: 1) that rides on any
//     route including team virtual keys. It already suppresses usage accounting
//     and quota; extending it to compliance would hand every employee a one-header
//     DLP bypass on the team lane. Deliberately NOT done — 安全 > UX.
func isProbePipelineRoute(routeSource string) bool {
	return routeSource == routeSourceProbe
}

// extractVirtualKey extracts a token from the request that belongs to the
// `aikey_*` namespace. Returns "" if the header is missing or the token is
// not in the aikey namespace (native tokens like sk-... handled separately).
//
// IMPORTANT (2026-04-29 prefix rename): this extractor is purely a
// "is this an aikey-namespace token at all?" filter — it does NOT validate
// whether the suffix matches a known prefix subform. All form/legitimacy
// checks live in dispatch (proxy.go) per the namespace-authority principle:
// any token starting with `aikey_` is authoritatively decided here, including
// returning TOKEN_INVALID for unknown / malformed forms. If middleware
// pre-filtered to a narrow whitelist (e.g. only aikey_team_ + aikey_personal_)
// then unknown shapes like `aikey_route_*` would slip back to the
// native-token / missing-token path and silently work — exactly the pitfall
// the namespace-authority design forbids.
//
// Headers checked (in order):
//  1. Authorization: Bearer <token>
//  2. x-api-key: <token>
func extractVirtualKey(req *http.Request) string {
	// Check Authorization: Bearer <token> (OpenAI-style)
	if auth := req.Header.Get("Authorization"); auth != "" {
		if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
			token = strings.TrimSpace(token)
			if strings.HasPrefix(token, "aikey_") {
				return token
			}
		}
	}

	// Check x-api-key header (Anthropic-style)
	if apiKey := req.Header.Get("x-api-key"); apiKey != "" {
		apiKey = strings.TrimSpace(apiKey)
		if strings.HasPrefix(apiKey, "aikey_") {
			return apiKey
		}
	}

	return ""
}

// extractRawAuthValue extracts the raw API key/token value from request headers,
// regardless of prefix.  Returns "" if no auth header is present.
// Used by path-prefix routing for two-phase auth handling:
//  1. Any aikey_* prefix → namespace-authority dispatch (see ClassifyToken)
//  2. Anything else (incl. native provider tokens from CLI tools) → fallback to default binding
//
// Why non-aikey_-namespace tokens are NOT rejected: CLI tools (claude, cursor, openai) send their own
// auth headers through the proxy; the binding logic replaces them with the real key.
func extractRawAuthValue(req *http.Request) string {
	// Check x-api-key first (Anthropic-style, most common for path-prefix)
	if apiKey := req.Header.Get("x-api-key"); apiKey != "" {
		return strings.TrimSpace(apiKey)
	}
	// Check Authorization: Bearer <token> (OpenAI-style)
	if auth := req.Header.Get("Authorization"); auth != "" {
		if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return strings.TrimSpace(token)
		}
	}
	return ""
}

// isProviderCompatible checks if a route token's provider matches the request path's provider.
// Compares canonical codes so broker aliases (claude→anthropic, codex→openai) match correctly.
func isProviderCompatible(route *vkeys.ResolvedRoute, canonicalCode, requestedProtocol string) bool {
	routeCanonical := providerCanonicalCode(route.ProviderCode)
	if routeCanonical == canonicalCode {
		return true
	}
	if route.ProtocolType != "" && requestedProtocol != "" &&
		strings.EqualFold(route.ProtocolType, requestedProtocol) {
		return true
	}
	// P1d (R-C, design D-10 refined): cross-provider SAME-protocol. A binding
	// whose real upstream endpoint speaks the same wire protocol the path
	// prefix implies is compatible — e.g. a zhipu binding with base_url
	// .../api/anthropic accessed via the /anthropic path (GLM's anthropic
	// endpoint). The route row for the binding's base_url is the truth source
	// for the endpoint's protocol; requestedProtocol comes from the request
	// endpoint/client route, never from the upstream Provider identity. Same
	// protocol → adapter/wire are compatible,
	// and the credential + base_url stay fixed by the binding (no upstream
	// escalation), so this is a routing allowance, not a permission bypass.
	if route.BaseURL != "" {
		if pr, ok := provider.Routes().LookupByBaseURL(route.BaseURL); ok && pr.Protocol == requestedProtocol {
			return true
		}
	}
	return false
}

func requestProtocolFromPath(path string) string {
	switch {
	case strings.HasSuffix(path, "/messages"):
		return "anthropic"
	case strings.HasSuffix(path, "/responses"), strings.HasSuffix(path, "/chat/completions"):
		return "openai_compatible"
	default:
		return ""
	}
}

// extractProviderFromPath checks if path starts with a client path-prefix the
// registry declares (e.g. "/anthropic/v1/messages", "/groq/v1/chat/completions")
// and returns the canonical provider code plus the path with that prefix
// removed (e.g. "anthropic", "/v1/messages"). Returns ("", "") if nothing
// matched — the caller then falls through to token-based routing.
//
// The prefix table is DERIVED from provider_registry.yaml; see
// clientPathPrefixes in pathprefix_table.go for the derivation and for why a
// hand-written list here was a production defect (bugfix
// workflow/CI/bugfix/20260808-provider-path-prefix-routing-registry-drift.md).
func extractProviderFromPath(path string) (providerCode, strippedPath string) {
	if len(path) < 2 || path[0] != '/' {
		return "", ""
	}
	// Bucket by first path segment so the hot path is one map lookup plus a
	// 1-4 element scan, regardless of how many providers the registry grows to.
	seg := path[1:]
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	// Candidates are pre-sorted LONGEST FIRST. Longest-prefix-wins is load
	// bearing, not a tidiness preference: "/groq/v1/..." must be matched by the
	// full proxy_path "groq/v1" and stripped whole. If the bare "groq" candidate
	// won instead, the surplus "/v1" would be handed to providerroutes.Stitch as
	// if the client had sent it — that is exactly defect D-2, where the vendor
	// received its own base path twice and answered 404.
	for _, c := range clientPathPrefixes().candidatesFor(seg) {
		p := "/" + c.prefix
		if path == p || strings.HasPrefix(path, p+"/") {
			return c.code, path[len(p):]
		}
	}
	return "", ""
}

// providerDefaultBaseURL returns the default upstream base URL for a provider.
// Accepts both canonical codes ("anthropic") and brand aliases ("claude").
//
// ⚠️  CROSS-LANGUAGE DRIFT RISK — MUST STAY IN SYNC WITH Rust registry.
//
// This table mirrors `aikey-cli/data/provider_registry.yaml`. Any new
// provider added there MUST get a matching branch here (and in
// providerCanonicalCode below). See the YAML's top-of-file comment for the
// long-term codegen plan; until that lands, adding a provider is a
// two-language change.
//
// Last synced (2026-04-24): added P0 (groq / xai / openrouter / perplexity)
// + P1 (zhipu / qwen / doubao / siliconflow) alongside the original 6.
// codexUpstreamBaseURL is the Codex OAuth upstream — chatgpt.com/backend-api/codex
// (Responses API), NOT api.openai.com/v1 (that's the API-key path). Both OAuth
// dispatch sites hardcoded this string; centralized here (single source) so they
// can't drift AND so an E2E can redirect it to a local mock.
//
// Test-only hook (loopback-gated, same posture as providerDefaultBaseURL's
// AIKEY_PROXY_TEST_ANTHROPIC_BASE_URL): Codex OAuth carries no configurable
// base_url, so the codex-account routing E2E can't exercise the inject path
// against a mock without this. The loopback guard means a prod misconfig can
// never reroute real traffic. See aikey-test/oauthgroup/codex_account_routing_test.go.
func codexUpstreamBaseURL() string {
	if o := os.Getenv("AIKEY_PROXY_TEST_CODEX_BASE_URL"); o != "" &&
		(strings.HasPrefix(o, "http://127.0.0.1:") || strings.HasPrefix(o, "http://localhost:")) {
		return o
	}
	return "https://chatgpt.com/backend-api/codex"
}

// resolveOAuthUpstream selects the upstream base URL for an OAuth-credential
// request AND applies any provider-specific request setup, returning the
// (possibly re-wrapped) request. Every OAuth dispatch lane calls this function;
// provider-specific setup must not be copied into an individual pipeline.
//
// existingBase is the route/account's already-resolved endpoint. It is a valid
// input, not an error: supervisor routes intentionally store effective URLs and
// custom gateways may carry their own prefix. The provider table is only the
// fallback when no endpoint has already been selected. OpenAI OAuth remains the
// deliberate exception because it targets the ChatGPT Codex backend rather
// than the API-key endpoint.
//
// codex is the one provider whose OAuth base ≠ its API-key base: OAuth hits
// chatgpt.com/backend-api/codex (Responses API), API keys hit api.openai.com/v1.
// It also needs deferred model capture (captureCodexModel returns a NEW request
// carrying the model in context; the caller must use the returned request).
// Other providers keep an already-resolved route/account base when present and
// otherwise fall back to the provider table; they need no request mutation.
func resolveOAuthUpstream(canonicalCode, protocolType, existingBase string, r *http.Request) (baseURL string, req *http.Request) {
	switch canonicalCode {
	case "openai":
		req = captureCodexModel(r)
		// Version-prefix normalization (bugfix 2026-07-19): the codex OAuth
		// upstream serves /responses — no /v1 segment. But OpenAI-convention
		// clients carry base_urls ENDING in /v1 (the group-lane agent base_url
		// must, to clear the ingress allowlist), so the path arrives here as
		// /v1/responses; verbatim append then produced
		// backend-api/codex/v1/responses → upstream FastAPI 404
		// {"detail":"Not Found"} (live codex repro, cf-ray …-LAX). The dialect
		// gate (oauthUpstreamRejectsPath) already accepts BOTH shapes — this
		// makes the forwarded shape match the upstream too. Mirrors the
		// version-segment re-normalization providerroutes.Stitch does for
		// table-known API-key hosts.
		if strings.HasPrefix(req.URL.Path, "/v1/") {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, "/v1")
			req.URL.RawPath = ""
		}
		return codexUpstreamBaseURL(), req
	default:
		// A configured test-only override is the final upstream for hermetic
		// Anthropic E2Es, even when the member runtime carries the provider's
		// non-empty default URL. runtimeDeps began delivering that default in
		// 2026-07-23; checking only in providerBaseURLForProtocol then silently
		// bypassed the hook and sent test traffic to the real provider edge.
		// Production is unchanged: this branch is inert unless the explicit env
		// value also passes the loopback / RFC 6761 .test safety gate.
		if testBase, ok := oauthTestBaseURL(canonicalCode, protocolType); ok {
			return testBase, r
		}
		if strings.TrimSpace(existingBase) != "" {
			return existingBase, r
		}
		if protocolType != "" {
			return providerBaseURLForProtocol(canonicalCode, protocolType), r
		}
		return providerDefaultBaseURL(canonicalCode), r
	}
}

// oauthUpstreamRejectsPath reports whether an OAuth-credential request can NOT
// be served by that provider's OAuth upstream, and why (2026-07-13, user report:
// codex works, opencode dies with a bogus "invalid x-api-key").
//
// Why this exists: codex is the one provider whose OAuth upstream differs from
// its API-key upstream (see resolveOAuthUpstream) — ChatGPT accounts are served
// by chatgpt.com/backend-api/codex, which speaks ONLY the Responses API. The
// request path is appended verbatim to that base, so a /chat/completions client
// (opencode, ai-sdk, LangChain, …) ended up calling a route that doesn't exist
// there; ChatGPT's edge answered with its own 4xx whose body says "invalid
// x-api-key". Nothing was wrong with the key — but the message sent users
// debugging credentials for hours. The honest failure is: this credential's
// upstream doesn't serve this dialect.
//
// Deliberately narrow: only the openai-OAuth lane is constrained. Every other
// provider's OAuth upstream == its API-key upstream, so their clients are free
// to speak whatever the provider serves. API-key credentials of ANY provider are
// untouched (they route to api.openai.com/v1 & friends, which do serve
// /chat/completions) — this guard is only reached from the OAuth branches.
//
// Empty reason = allowed.
func oauthUpstreamRejectsPath(canonicalCode, urlPath string) string {
	if canonicalCode != "openai" {
		return ""
	}
	// The Responses API is the only dialect chatgpt.com/backend-api/codex serves.
	// Match on suffix so both /v1/responses (legacy lane) and /responses (group
	// lane, already stripped) pass.
	if strings.HasSuffix(strings.TrimSuffix(urlPath, "/"), "/responses") {
		return ""
	}
	return "This key is backed by a ChatGPT OAuth account, whose upstream only serves the Responses API (/responses). " +
		"The client called " + urlPath + " (Chat Completions). Use an API-key credential for this client, " +
		"or use a Responses-API client such as codex."
}

// testOnlyBaseURLAllowed gates the AIKEY_PROXY_TEST_* base-url hooks. Allowed:
// plain-http loopback, or a plain-http hostname under the RFC 6761 reserved
// ".test" TLD — public DNS can never resolve ".test", so a prod misconfig still
// cannot reroute real traffic anywhere routable. Why ".test" is needed at all:
// the egress-coexistence E2E must send OAuth traffic THROUGH a per-account
// egress, and the always-on loopback egress bypass (egress_engine.go, 2026-07-16
// security fix) would short-circuit a 127.0.0.1 mock — so the mock is addressed
// by a fake ".test" hostname the test's socks5 exit resolves back to loopback.
// See aikey-test/oauthgroup/egress_coexist_e2e_test.go.
func testOnlyBaseURLAllowed(raw string) bool {
	if raw == "" {
		return false
	}
	if strings.HasPrefix(raw, "http://127.0.0.1:") || strings.HasPrefix(raw, "http://localhost:") {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "http" && strings.HasSuffix(u.Hostname(), ".test")
}

// anthropicTestBaseURL is the single reader for the Anthropic real-binary E2E
// override. The bool means a valid, safety-gated override is configured. Keep
// this separate from the production registry/runtime order: test code needs an
// absolute final target, while production must continue honoring custom runtime
// gateways before provider defaults.
func anthropicTestBaseURL(canonicalCode, protocolType string) (string, bool) {
	if canonicalCode != "anthropic" || protocolType != "anthropic" {
		return "", false
	}
	o := os.Getenv("AIKEY_PROXY_TEST_ANTHROPIC_BASE_URL")
	if !testOnlyBaseURLAllowed(o) {
		return "", false
	}
	return o, true
}

// oauthTestBaseURL is the single test-only upstream override used by real
// binary OAuth E2Es. Every value is rejected unless it is plain HTTP on
// loopback or the reserved .test TLD, so production traffic cannot be diverted
// by an arbitrary environment value. Anthropic keeps its historical variable;
// Kimi needs a separate endpoint because its OAuth wire contract is Chat
// Completions rather than Codex Responses.
func oauthTestBaseURL(canonicalCode, protocolType string) (string, bool) {
	if base, ok := anthropicTestBaseURL(canonicalCode, protocolType); ok {
		return base, true
	}
	if provider.CanonicalCode(canonicalCode) != "kimi_code" || provider.CanonicalProtocol(protocolType) != "openai_compatible" {
		return "", false
	}
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("AIKEY_PROXY_TEST_KIMI_BASE_URL")), "/")
	if !testOnlyBaseURLAllowed(base) {
		return "", false
	}
	return base, true
}

func providerDefaultBaseURL(providerCode string) string {
	canonical := providerCanonicalCode(providerCode)
	protocol, ok := provider.ProtocolFamily(canonical, "")
	if !ok {
		return ""
	}
	route, ok := provider.Routes().ByProviderProtocol(canonical, protocol)
	if !ok {
		return ""
	}
	// This legacy helper returns the root because its callers append an
	// incoming path that already carries the version segment. Exact routing
	// paths that need the effective endpoint use providerBaseURLForProtocol.
	return route.BaseURL
}

// testDialOverrideBaseURL returns a loopback / .test address to DIAL INSTEAD of
// baseURL, for the provider that baseURL resolves to.
//
// # Why this is a DIAL-time override and not a resolution-time one
//
// The three older hooks (ANTHROPIC / KIMI / CODEX) are read inside
// providerBaseURLForProtocol, i.e. they replace the base URL *before* anything
// else looks at it. That is fine for those lanes but useless for model mapping:
// `applyModelMapping` selects the provider's map FROM route.BaseURL, so a hook
// that rewrote the base URL first would make the map unselectable and the test
// would assert on a mapping that never ran.
//
// This one is therefore applied AFTER mapping and attribution have consumed the
// real base URL, and only swaps the address actually dialed. It is what lets a
// hermetic test exercise `provider_model_maps` at all: every base URL that
// selects a mapped provider is, by construction, a real vendor edge (route rows
// do not match once a port is present, so a loopback address can never resolve
// to one).
//
// 🚫 Every value is rejected unless testOnlyBaseURLAllowed accepts it — plain
// HTTP on loopback or the reserved .test TLD — so a production deployment cannot
// be diverted by an arbitrary environment value.
func testDialOverrideBaseURL(baseURL string) (string, bool) {
	if strings.TrimSpace(baseURL) == "" {
		return "", false
	}
	route, ok := provider.Routes().LookupByBaseURL(baseURL)
	if !ok {
		return "", false
	}
	name := "AIKEY_PROXY_TEST_" + strings.ToUpper(strings.TrimSpace(route.Provider)) + "_BASE_URL"
	o := strings.TrimRight(strings.TrimSpace(os.Getenv(name)), "/")
	if !testOnlyBaseURLAllowed(o) {
		return "", false
	}
	return o, true
}

func providerBaseURLForProtocol(providerCode, protocolType string) string {
	canonical := providerCanonicalCode(providerCode)
	// Test-only hook (gated to loopback / .test): the cross-component
	// OAuth-account routing E2E points the otherwise-hardcoded Anthropic
	// upstream at a local mock. This shared reader is also consulted BEFORE a
	// non-empty runtime BaseURL in resolveOAuthUpstream; otherwise delivery of a
	// provider default would bypass the same hook.
	if o, ok := anthropicTestBaseURL(canonical, protocolType); ok {
		return o
	}
	route, ok := provider.Routes().ByProviderProtocol(canonical, protocolType)
	if !ok {
		return ""
	}
	return providerroutes.EffectiveUpstream(route)
}

// providerCanonicalCode maps a brand alias back to the canonical provider code
// used in vault queries (e.g. "claude" → "anthropic").
//
// ⚠️ Same cross-language drift warning as providerDefaultBaseURL — keep in
// sync with Rust's `provider_registry::canonical()` / the YAML oauth_aliases.
func providerCanonicalCode(providerCode string) string {
	return provider.CanonicalCode(providerCode)
}

// activeEntryServesProvider answers "does this active_key_providers entry
// cover the provider this request needs?" across BOTH axes (bugfix
// 2026-08-20 NO_ACTIVE_KEY-for-moonshot).
//
// The list is meant to hold SUPPLIER codes, and the CLI now writes them — but
// vaults written before that fix hold CLIENT ROUTE names, and requiring a
// re-run of `aikey use` to keep routing would strand every existing machine.
//
// Why an exact-or-family test rather than canonicalising both sides: the
// registry aliases `kimi → kimi_code`, so canonical equality silently accepts
// the route name as ONE supplier of its family and rejects the others. That
// is exactly how a moonshot key served /kimi/v1 while refusing /moonshot/v1.
// Family membership is the honest question for a route-shaped entry, and the
// registry owns family — no second table here.
func activeEntryServesProvider(entry, requestProviderCode string) bool {
	e := strings.ToLower(strings.TrimSpace(entry))
	want := strings.ToLower(strings.TrimSpace(requestProviderCode))
	if e == "" || want == "" {
		return false
	}
	// Which axis is this entry on? The registry answers it: a FAMILY name is
	// its own family ("kimi" → family "kimi"), while a supplier code belongs
	// to a family other than itself ("moonshot" → family "kimi"). That single
	// test separates a legacy route-shaped entry from a supplier entry
	// without a second table — and it matters, because family membership is
	// NOT interchangeability: a moonshot key cannot authenticate against
	// kimi_code's endpoint, so a supplier entry must stay exact.
	entryFamily, entryKnown := provider.FamilyOf(e)
	if entryKnown && entryFamily == e {
		// Route axis (legacy vaults): any supplier of this family serves it.
		wantFamily, wantKnown := provider.FamilyOf(want)
		return wantKnown && wantFamily == entryFamily
	}
	// Supplier axis: exact provider, aliases folded.
	return e == want || providerCanonicalCode(e) == providerCanonicalCode(want)
}

// HeaderAikeyErrorSource marks a response as GENERATED BY the aikey proxy (auth /
// quota / policy / upstream-wrapper errors) rather than passed through from the
// upstream provider. It carries the aikey error `code` (e.g. QUOTA_EXCEEDED_USD,
// TOKEN_INVALID). Why a header: writeJSONError deliberately shapes the BODY like a
// provider error (Anthropic/OpenAI `type`) so SDKs parse it, which makes the body
// alone ambiguous — so e.g. a quota 429 looks like a provider rate-limit 429. A
// client tells them apart by this header: 429 WITH it = aikey (quota/policy);
// 429 WITHOUT it = a real upstream rate limit (passed through the ReverseProxy,
// which never sets it; providers don't emit the X-Aikey-* namespace).
const HeaderAikeyErrorSource = "X-Aikey-Error-Source"

// Error-origin traceability headers (P1, 20260719-错误产地标签方案). These are
// RESPONSE-direction only — they ride the response back to the client and NEVER
// go to the upstream (the request-direction X-Aikey-* strip in forward Director
// removes anything before the LLM; see §6 floor-invariant 6). They let a user
// tell WHO produced an error without SSH-grepping every hop:
//
//	X-Aikey-Error-Origin: <component>.<code>  — the ORIGIN of the error.
//	    First-writer-wins: whoever GENERATES the error sets it; a component
//	    RELAYING a deeper error must NOT overwrite it (the deepest producer is
//	    the root cause, Java caused-by style). component ∈ {local-proxy,
//	    worker-proxy, oauth-ingress, upstream:<provider>}.
//	X-Aikey-Error-Path: <component>              — the HOP CHAIN. Each aikey hop
//	    APPENDS itself (multi-value header) so the client sees the route the
//	    error traversed, e.g. "local-proxy, oauth-ingress".
const (
	HeaderAikeyErrorOrigin = "X-Aikey-Error-Origin"
	HeaderAikeyErrorPath   = "X-Aikey-Error-Path"
	// HeaderAikeyUpstreamRequestID re-exposes the provider's own request id under
	// ONE consistent aikey-namespaced RESPONSE header (P3, 20260719). WHY: cross-
	// request correlation must NOT propagate a trace header to the upstream
	// (WAF/撞墙 risk — §6 floor-invariant 6). Instead we surface the provider's
	// request id (the natural anchor that already crosses the aikey↔provider
	// boundary) so a user can JOIN it across the proxy log / usage store / the
	// provider's support — without needing to know each provider's own header
	// name (request-id vs openai-request-id vs x-request-id). RESPONSE direction
	// only; the request-side strip removes any X-Aikey-* before the upstream.
	HeaderAikeyUpstreamRequestID = "X-Aikey-Upstream-Request-Id"
)

// stripAikeyRequestHeaders removes the ENTIRE X-Aikey-* namespace from an
// OUTBOUND request before it reaches the upstream provider. This is the floor
// invariant (§6) that keeps error-origin / trace annotations from ever polluting
// the LLM request — Anthropic's OAuth WAF treats unrecognized headers as a
// non-Claude-Code persona signal and returns a business 429 with no
// X-RateLimit-Reset (撞墙 signature). Extracted from the forward Director so a
// fence test can assert the invariant directly.
func stripAikeyRequestHeaders(h http.Header) {
	for k := range h {
		if len(k) >= 8 && strings.EqualFold(k[:8], "X-Aikey-") {
			// delete(), not h.Del(): Del canonicalizes its argument before
			// deleting, so for a key written straight into the map in
			// non-canonical form ("x-aikey-…", as a verbatim copy from another
			// hop can be) it deletes a DIFFERENT, absent key and the real entry
			// survives the strip — the case-insensitive match above then reads
			// as protection that isn't there. Found 2026-07-21 by the probe/
			// forward convergence fence. net/http canonicalizes inbound server
			// headers, so this was not a live leak; it was a live blind spot.
			delete(h, k)
		}
	}
}

// upstreamRequestIDFromHeader reads the provider's own request id from a header
// set (the http.Header form of extractUpstreamRequestID, for the response-
// capturing middleware which has headers but no *http.Response).
func upstreamRequestIDFromHeader(h http.Header) string {
	for _, name := range []string{"request-id", "x-request-id", "openai-request-id"} {
		if v := h.Get(name); v != "" {
			return v
		}
	}
	return ""
}

// errorOriginComponent is THIS process's component label for the origin header —
// "local-proxy" (personal/no cluster.node_id) or "worker-proxy" (cluster node).
// Set once at startup via SetErrorOriginComponent before serving; read-only
// thereafter (no lock needed). Default "local-proxy" so tests / older wiring
// still produce a sensible origin.
var errorOriginComponent = "local-proxy"

// SetErrorOriginComponent fixes this process's component label from the cluster
// node id (empty → local-proxy, set → worker-proxy). Single source: the SAME
// cluster.node_id existence check the rest of the proxy uses to tell editions
// apart. Call once at startup (app.Run) before the server accepts traffic.
func SetErrorOriginComponent(clusterNodeID string) {
	if strings.TrimSpace(clusterNodeID) != "" {
		errorOriginComponent = "worker-proxy"
	} else {
		errorOriginComponent = "local-proxy"
	}
}

// setErrorOrigin stamps the error-origin traceability headers on a response THIS
// component is generating. First-writer-wins on Origin (defensive: a fresh
// self-generated response has none, so we set it); always append this component
// to the path. code is the aikey error code (origin value = component.code).
func setErrorOrigin(h http.Header, code string) {
	if h.Get(HeaderAikeyErrorOrigin) == "" {
		h.Set(HeaderAikeyErrorOrigin, errorOriginComponent+"."+code)
	}
	h.Add(HeaderAikeyErrorPath, errorOriginComponent)
}

// writeJSONError writes a JSON error response in OpenAI-compatible format.
func writeJSONError(w http.ResponseWriter, statusCode int, errType, code, message string) {
	writeJSONErrorDetails(w, statusCode, errType, code, message, nil)
}

// writeJSONErrorDetails extends the standard AiKey error object with optional,
// display-safe machine fields. It is used only when the component that owns the
// error also owns the facts (for example the pool cooldown deadline); callers
// must not estimate runtime state from a database snapshot.
func writeJSONErrorDetails(w http.ResponseWriter, statusCode int, errType, code, message string, details map[string]any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	// Mark every aikey-GENERATED error so callers can distinguish it from an
	// upstream pass-through (esp. quota 429 vs provider rate-limit 429). Value =
	// the aikey error code (presence alone is the discriminator; the code adds detail).
	h.Set(HeaderAikeyErrorSource, code)
	// P1 error-origin: this component GENERATED the error → stamp origin + path.
	setErrorOrigin(h, code)
	w.WriteHeader(statusCode)
	// 拍板 2026-08-18 #4: every aikey-GENERATED message carries the "AiKey: "
	// prefix so a human reading the CLI output tells aikey's own errors from a
	// provider's verbatim passthrough at a glance (the headers/origin field
	// already give machines the same discriminator). Idempotent — messages
	// already leading with "AiKey" are left alone.
	if !strings.HasPrefix(message, "AiKey") {
		message = "AiKey: " + message
	}
	errObj := map[string]any{"message": message, "type": errType, "code": code}
	for key, value := range details {
		errObj[key] = value
	}
	// origin (top-level) mirrors the header so a client that reads only the body
	// still learns who produced the error. json.Marshal keeps future detail values
	// correctly escaped instead of growing a second hand-written JSON encoder.
	body, _ := json.Marshal(map[string]any{
		"error":  errObj,
		"origin": h.Get(HeaderAikeyErrorOrigin),
	})
	_, _ = w.Write(body)
}
