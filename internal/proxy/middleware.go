package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
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

// selectTokenBinding resolves a multi-binding managed token before any route
// field is consumed. The active client-route binding is authoritative when it
// points at this VK; otherwise a unique requested-protocol candidate is safe.
func (p *Proxy) selectTokenBinding(route *vkeys.ResolvedRoute, clientRoute, requestedProtocol string) (*vkeys.ResolvedRoute, error) {
	if route == nil || len(route.Bindings) == 0 {
		return route, nil
	}
	if p.activeReader != nil && clientRoute != "" {
		if binding, err := p.activeReader.GetProviderBinding(clientRoute); err == nil && binding != nil &&
			(binding.KeySourceType == "team" || binding.KeySourceType == "managed_virtual_key") &&
			binding.KeySourceRef == route.VirtualKeyID {
			for _, candidate := range route.Bindings {
				if strings.EqualFold(candidate.ProviderCode, binding.ProviderCode) &&
					(binding.ProtocolType == "" || strings.EqualFold(candidate.ProtocolType, binding.ProtocolType)) {
					copy := *candidate
					return &copy, nil
				}
			}
		}
	}
	var candidates []*vkeys.ResolvedRoute
	for _, candidate := range route.Bindings {
		if requestedProtocol == "" || strings.EqualFold(candidate.ProtocolType, requestedProtocol) {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 1 {
		copy := *candidates[0]
		return &copy, nil
	}
	return nil, fmt.Errorf("managed token has %d bindings for protocol %q; select an exact client-route binding with `aikey use`", len(candidates), requestedProtocol)
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

// extractProviderFromPath checks if path starts with a known provider prefix
// (e.g., "/anthropic/v1/messages") and returns the provider code and the
// stripped path (e.g., "anthropic", "/v1/messages"). Returns ("", "") if no
// prefix matched.
func extractProviderFromPath(path string) (providerCode, strippedPath string) {
	// This is a client-route list, not a Provider list. In particular `mock`
	// must never become a URL/client namespace: Mock credentials enter through
	// `/anthropic` or `/openai` according to their exact stored protocol.
	// Aliases remain for old active.env files.
	// 2026-05-08 Kimi 双平台拆分: 加 'kimi_code' 作为 path-prefix 候选。'kimi' 保留
	// 作为 deprecated path-prefix(老 shell hook 已写到用户 env,不能断流)。
	known := []string{"anthropic", "claude", "openai", "google", "kimi_code", "kimi", "deepseek", "moonshot", "groq", "xai", "openrouter", "perplexity", "zhipu", "qwen", "doubao", "siliconflow"}
	for _, code := range known {
		prefix := "/" + code
		if strings.HasPrefix(path, prefix+"/") || path == prefix {
			return code, strings.TrimPrefix(path, prefix)
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
// (possibly re-wrapped) request. Centralizes the per-provider OAuth-upstream
// policy so the two dispatch sites (legacy /v1 forward_and_resolve + the group
// route in group_serve) share ONE source instead of each carrying its own
// `if canonicalCode == "openai"` branch — a new provider whose OAuth upstream
// differs from its API-key default (like codex) adds one case here, not two.
//
// codex is the one provider whose OAuth base ≠ its API-key base: OAuth hits
// chatgpt.com/backend-api/codex (Responses API), API keys hit api.openai.com/v1.
// It also needs deferred model capture (captureCodexModel returns a NEW request
// carrying the model in context; the caller must use the returned request).
// Every other provider's OAuth base is the (provider, protocol) row's ROOT
// base_url and needs no setup.
//
// CONTRACT: the returned base URL is always a ROOT — scheme, host, and any
// non-version path prefix, never a trailing version segment. Its sole consumer
// is applyOAuthUpstreamURL, which concatenates it with a request path that
// already carries the version. Returning the base_url+version form here is the
// 2026-07-24 all-models-404 regression; see
// TestResolveOAuthUpstream_NoDoubleVersionSegment.
func resolveOAuthUpstream(canonicalCode, protocolType string, r *http.Request) (baseURL string, req *http.Request) {
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
		if protocolType != "" {
			// ROOT form, not EffectiveUpstream: applyOAuthUpstreamURL prepends
			// this path onto a request path that already carries the version
			// segment. Returning base_url+version here produced
			// /v1/v1/messages → a bare upstream 404 for every model
			// (2026-07-24 onsite incident). The protocol axis still selects the
			// right row, so GLM's .../api/anthropic endpoint keeps working.
			if root := providerRootBaseURLForProtocol(canonicalCode, protocolType); root != "" {
				return root, r
			}
			// Unknown (provider, protocol) pair — fall through to the
			// protocol-agnostic default rather than forwarding to "".
		}
		return providerDefaultBaseURL(canonicalCode), r
	}
}

// applyOAuthUpstreamURL points req at an OAuth upstream base URL. It is the
// consuming half of resolveOAuthUpstream's contract: the base URL carries the
// ROOT (scheme, host and any non-version path prefix such as
// https://api.kimi.com/coding), and the inbound request path already carries
// the version segment (/v1/messages), so the two are concatenated verbatim.
//
// ⚠️ The contract is why resolveOAuthUpstream must NOT return
// providerroutes.EffectiveUpstream (base_url + version): that form is for UI
// display, and prepending it here double-counts the version — an anthropic
// OAuth request became /v1/v1/messages, which api.anthropic.com answers with a
// bare 404 for EVERY model. Pinned by
// TestResolveOAuthUpstream_NoDoubleVersionSegment.
func applyOAuthUpstreamURL(req *http.Request, baseURL string) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	req.Host = u.Host
	if u.Path != "" && u.Path != "/" {
		req.URL.Path = strings.TrimRight(u.Path, "/") + req.URL.Path
	}
}

// looksLikeVersionSegment reports whether a single path segment (with its
// leading slash, e.g. "/v1", "/v1beta", "/v4") is an API version segment.
// Deliberately shape-based rather than a fixed list: the fingerprint table
// already carries /v1, /v1beta, /v3 and /v4, and a new provider must not need a
// code change here to be fenced.
func looksLikeVersionSegment(seg string) bool {
	if len(seg) < 3 || seg[0] != '/' {
		return false
	}
	if seg[1] != 'v' && seg[1] != 'V' {
		return false
	}
	return seg[2] >= '0' && seg[2] <= '9'
}

// oauthBaseURLFault reports why an OAuth upstream base URL cannot serve reqPath,
// or "" when the join is sound. It is the guard for applyOAuthUpstreamURL's
// literal-prepend contract, and its message is written to be read by the person
// who has to fix the configuration.
//
// Why this exists (2026-07-24): when the base URL and the request path BOTH
// carry the version segment, the join silently produces /v1/v1/messages and
// api.anthropic.com answers 404 for every model. `aikey doctor --last-errors`
// showed only `404 ← upstream:anthropic — not an aikey fault`, so a config fault
// on our side was rendered as a provider fault, and the operator's next move was
// to blame model names and account entitlements. Failing loud here converts a
// half-day misdiagnosis into one actionable line.
//
// Scope: OAuth routes only. API-key routes join through providerroutes.Stitch,
// which is version-aware AND row-selects on the path prefix — a stored base_url
// ending in /v1 is normalized there, not broken, so fencing it would reject
// configurations that work today.
func oauthBaseURLFault(baseURL, reqPath string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "Upstream base URL " + strconv.Quote(baseURL) + " is not a valid URL. Fix the credential's base URL in the console."
	}
	if u.Scheme == "" || u.Host == "" {
		return "Upstream base URL " + strconv.Quote(baseURL) + " is missing a scheme or host. Fix the credential's base URL in the console."
	}
	basePath := strings.TrimRight(u.Path, "/")
	if basePath == "" {
		return ""
	}
	last := basePath[strings.LastIndex(basePath, "/"):]
	if !looksLikeVersionSegment(last) {
		return "" // e.g. https://api.kimi.com/coding — a real prefix, not a version
	}
	if !strings.HasPrefix(reqPath, last+"/") && reqPath != last {
		return ""
	}
	return "Upstream base URL " + strconv.Quote(baseURL) + " already ends with the API version segment " +
		strconv.Quote(last) + ", and the incoming request path " + strconv.Quote(reqPath) +
		" carries it too. Forwarding would request " + strconv.Quote(basePath+reqPath) +
		", which the provider answers with 404 for EVERY model. Fix: remove " + strconv.Quote(last) +
		" from this credential's base URL — AiKey takes the version from the request path."
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

func providerBaseURLForProtocol(providerCode, protocolType string) string {
	canonical := providerCanonicalCode(providerCode)
	if canonical == "anthropic" && protocolType == "anthropic" {
		// Test-only hook (gated to loopback / .test): the cross-component
		// OAuth-account routing E2E points the otherwise-hardcoded Anthropic
		// upstream at a local mock. OAuth accounts carry no configurable base_url
		// (unlike api_key material), so without this the OAuth inject path can't
		// be exercised against a mock. The guard means a prod misconfig can never
		// reroute real traffic. See aikey-test/oauthgroup/oauth_account_routing_test.go.
		if o := os.Getenv("AIKEY_PROXY_TEST_ANTHROPIC_BASE_URL"); testOnlyBaseURLAllowed(o) {
			return o
		}
	}
	route, ok := provider.Routes().ByProviderProtocol(canonical, protocolType)
	if !ok {
		return ""
	}
	return providerroutes.EffectiveUpstream(route)
}

// providerRootBaseURLForProtocol is the ROOT-form counterpart of
// providerBaseURLForProtocol: same (provider, protocol) row selection — so a
// protocol-specific endpoint like GLM's .../api/anthropic is still honoured —
// but it returns the row's base_url WITHOUT the version segment appended.
//
// Callers that hand the result to a literal-prepend join (applyOAuthUpstreamURL,
// whose inbound path already carries /v1) MUST use this. Callers that want the
// user-facing "where does this actually route" string, or that feed a
// version-aware stitch, want providerBaseURLForProtocol.
//
// Splitting the two is the fix for the 2026-07-24 all-models-404 incident; see
// TestResolveOAuthUpstream_NoDoubleVersionSegment.
func providerRootBaseURLForProtocol(providerCode, protocolType string) string {
	canonical := providerCanonicalCode(providerCode)
	if canonical == "anthropic" && protocolType == "anthropic" {
		// Same loopback/.test-gated E2E hook as providerBaseURLForProtocol, and
		// deliberately verbatim: the mock's base URL is already a root, and the
		// OAuth Director prepends its path the same way it does in production.
		if o := os.Getenv("AIKEY_PROXY_TEST_ANTHROPIC_BASE_URL"); testOnlyBaseURLAllowed(o) {
			return o
		}
	}
	route, ok := provider.Routes().ByProviderProtocol(canonical, protocolType)
	if !ok {
		return ""
	}
	return route.BaseURL
}

// providerCanonicalCode maps a brand alias back to the canonical provider code
// used in vault queries (e.g. "claude" → "anthropic").
//
// ⚠️ Same cross-language drift warning as providerDefaultBaseURL — keep in
// sync with Rust's `provider_registry::canonical()` / the YAML oauth_aliases.
func providerCanonicalCode(providerCode string) string {
	switch strings.ToLower(providerCode) {
	case "claude":
		return "anthropic"
	case "gpt", "chatgpt", "codex":
		return "openai"
	case "gemini":
		return "google"
	// 2026-05-08 Kimi 双平台拆分: 'kimi' 是 deprecated alias,canonical 形态是
	// 'kimi_code'。这样 vault 查询 (GetProviderBinding) + isProviderCompatible
	// 在新旧 path-prefix / vault 数据之间都能正确匹配。详见
	// roadmap20260320/技术实现/update/20260508-Kimi双平台拆分-moonshot与kimi-code.md
	case "kimi":
		return "kimi_code"

	// ── P0/P1 additions (2026-04-24) ──
	case "grok", "xai_grok":
		return "xai"
	case "pplx":
		return "perplexity"
	case "glm", "zhipuai":
		return "zhipu"
	case "dashscope", "tongyi":
		return "qwen"
	case "ark", "volcengine":
		return "doubao"

	default:
		return strings.ToLower(providerCode)
	}
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
	h := w.Header()
	h.Set("Content-Type", "application/json")
	// Mark every aikey-GENERATED error so callers can distinguish it from an
	// upstream pass-through (esp. quota 429 vs provider rate-limit 429). Value =
	// the aikey error code (presence alone is the discriminator; the code adds detail).
	h.Set(HeaderAikeyErrorSource, code)
	// P1 error-origin: this component GENERATED the error → stamp origin + path.
	setErrorOrigin(h, code)
	w.WriteHeader(statusCode)
	// Write error JSON inline to avoid encoding/json import for this simple case.
	// origin (top-level) mirrors the header so a client that reads only the body
	// still learns who produced the error.
	origin := escapeJSON(h.Get(HeaderAikeyErrorOrigin))
	_, _ = w.Write([]byte(`{"error":{"message":"` + escapeJSON(message) + `","type":"` + errType + `","code":"` + code + `"},"origin":"` + origin + `"}`))
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
