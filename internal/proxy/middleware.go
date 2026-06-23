package proxy

import (
	"context"
	"net/http"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
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
func isProviderCompatible(route *vkeys.ResolvedRoute, canonicalCode string) bool {
	routeCanonical := providerCanonicalCode(route.ProviderCode)
	if routeCanonical == canonicalCode {
		return true
	}
	// Team managed keys with ProviderBaseURLs support multiple providers.
	// TODO: when ProviderBaseURLs is added to ResolvedRoute, check it here.
	return false
}

// extractProviderFromPath checks if path starts with a known provider prefix
// (e.g., "/anthropic/v1/messages") and returns the provider code and the
// stripped path (e.g., "anthropic", "/v1/messages"). Returns ("", "") if no
// prefix matched.
func extractProviderFromPath(path string) (providerCode, strippedPath string) {
	// List covers both canonical codes and common brand-name aliases that may
	// appear in base URLs written by older CLI versions or non-normalised keys.
	// 2026-05-08 Kimi 双平台拆分: 加 'kimi_code' 作为 path-prefix 候选。'kimi' 保留
	// 作为 deprecated path-prefix(老 shell hook 已写到用户 env,不能断流)。
	known := []string{"anthropic", "claude", "openai", "google", "kimi_code", "kimi", "deepseek", "moonshot"}
	for _, code := range known {
		prefix := "/" + code
		if strings.HasPrefix(path, prefix+"/") || path == prefix {
			return code, strings.TrimPrefix(path, prefix)
		}
	}
	return "", ""
}

// providerToProtocol maps a provider code (or brand alias) to its proxy protocol name.
func providerToProtocol(providerCode string) string {
	switch strings.ToLower(providerCode) {
	case "anthropic", "claude":
		return "anthropic"
	default:
		return "openai_compatible"
	}
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
func providerDefaultBaseURL(providerCode string) string {
	switch strings.ToLower(providerCode) {
	case "anthropic", "claude":
		return "https://api.anthropic.com"
	case "openai", "gpt", "chatgpt", "codex":
		// Why: OpenAI SDK clients (including Codex) treat base_url as already
		// containing /v1, sending paths like /responses or /chat/completions
		// without the /v1 prefix. Without /v1 here, requests hit wrong endpoints.
		// Ref: bugfix/20260406-ux-feedback-p0-p1-fixes.md
		return "https://api.openai.com/v1"
	case "google", "gemini":
		return "https://generativelanguage.googleapis.com"
	case "kimi_code", "kimi":
		// 2026-05-08 Kimi 双平台拆分:
		//   - 'kimi_code' = canonical 新码 (Kimi Code 平台 https://api.kimi.com/coding)
		//   - 'kimi'      = deprecated alias, mirrors kimi_code (vault 升级残留 / 手工
		//                   构造数据兜底; provider_registry.yaml 同样把 'kimi' 留作 alias)
		// Why no /v1: path-prefix routing strips "/kimi_code" / "/kimi" leaving
		// "/v1/chat/completions". applyBaseURL prepends the base path, so /coding +
		// /v1/... = /coding/v1/... If we used /coding/v1 here, it would become
		// /coding/v1/v1/... (double v1).
		return "https://api.kimi.com/coding"
	case "moonshot":
		// 2026-05-08 Kimi 双平台拆分: Moonshot 平台真实 upstream (api.moonshot.cn);
		// pre-split 这里和 'kimi' 共用同一 case 错误地路由到 Kimi Code endpoint。
		// Why no /v1: 同 kimi_code,path-prefix routing 已剥掉 /moonshot,留下 /v1/...
		return "https://api.moonshot.cn"
	case "deepseek":
		// Why: same reason as openai — deepseek SDK expects /v1 in base_url.
		return "https://api.deepseek.com/v1"

	// ── P0 (2026-04-24) ── OpenAI-compatible Western providers ──
	case "groq":
		return "https://api.groq.com/openai/v1"
	case "xai", "grok", "xai_grok":
		return "https://api.x.ai/v1"
	case "openrouter":
		return "https://openrouter.ai/api/v1"
	case "perplexity", "pplx":
		return "https://api.perplexity.ai/v1"

	// ── P1 (2026-04-24) ── China-market providers ──
	case "zhipu", "glm", "zhipuai":
		return "https://open.bigmodel.cn/api/paas/v4"
	case "qwen", "dashscope", "tongyi":
		return "https://dashscope.aliyuncs.com/compatible-mode/v1"
	case "doubao", "ark", "volcengine":
		return "https://ark.cn-beijing.volces.com/api/v3"
	case "siliconflow":
		return "https://api.siliconflow.cn/v1"

	default:
		return ""
	}
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

// writeJSONError writes a JSON error response in OpenAI-compatible format.
func writeJSONError(w http.ResponseWriter, statusCode int, errType, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	// Mark every aikey-GENERATED error so callers can distinguish it from an
	// upstream pass-through (esp. quota 429 vs provider rate-limit 429). Value =
	// the aikey error code (presence alone is the discriminator; the code adds detail).
	w.Header().Set(HeaderAikeyErrorSource, code)
	w.WriteHeader(statusCode)
	// Write error JSON inline to avoid encoding/json import for this simple case.
	_, _ = w.Write([]byte(`{"error":{"message":"` + escapeJSON(message) + `","type":"` + errType + `","code":"` + code + `"}}`))
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
