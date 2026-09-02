// handle_dispatch.go — central HTTP request router for the proxy package.
//
// Holds *Proxy.Handle, the entry point for every inbound request to
// aikey-proxy. Handle classifies the bearer token + URL via
// dispatch.go's ClassifyToken and routes to one of the three pipeline
// handlers in pipelines.go (handleAppPipeline / handleProbePipeline /
// handlePathPrefixRoute). The actual forwarding logic that those
// handlers share lives in forward_and_resolve.go.
//
// Split out of proxy.go on 2026-05-26 — see
// workflow/CI/refactor/2026-05-26-proxy-go-split.md for the file map.
package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/apppipe"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/probepipe"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// Handle is the main HTTP handler for data plane requests.
func (p *Proxy) Handle(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	p.requests.Add(1)

	// Extract or create W3C trace context from the incoming request.
	tc := observability.ExtractOrCreate(r)
	// Stash on the request context so deep paths (buildBaseEvent → the async
	// collector's drop WARN) can correlate without re-parsing headers.
	r = r.WithContext(context.WithValue(r.Context(), ctxKeyTrace, tc))
	logger := slog.With(
		"trace_id", tc.TraceID,
		"span_id", tc.SpanID,
		"request_id", tc.RequestID,
	)

	// 0-pre. SPEC §1.5.7 / §6.6 E-mode fail-loud guard.
	//
	// If a compliance filter is REQUIRED (vault filter_stages declaration or
	// org mandate) but no working dispatcher could be built, reject ALL
	// data-plane requests with 501. This is the explicit fix for
	// anti-example F: a broken filter MUST NOT silently let traffic through,
	// otherwise an operator who configured filter_stages believes they have
	// compliance enforcement while actually the chain is inert.
	//
	// Lives BEFORE all routing branches so probe / app / user_chat all
	// return uniformly. The body message renders the CAUSE the supervisor
	// recorded — same facts, same fix path as the startup logs (bugfix
	// 2026-08-19: the P3-era static string here contradicted the logs for
	// two months and sent users chasing "server-side/temporary" ghosts).
	if cause := p.filterStub501; cause != nil {
		p.errors.Add(1)
		writeJSONErrorDetails(w, http.StatusNotImplemented, "server_error",
			"FILTER_NOT_IMPLEMENTED", filterStub501Message(cause),
			map[string]any{
				"reason_code":   cause.Reason,
				"filter_slug":   cause.Slug,
				"expected_path": cause.ExpectedPath,
				"org_mandated":  cause.Mandated,
			})
		return
	}

	// 0-diag. Read-only pipeline diagnostics (task 7.9). GET-only, no auth, no
	// mutation — exposes the embedded registry provenance + model-mapping runtime
	// health so the four surfaces (3.5) can show "configured but not effective".
	// Checked before any routing branch so it never collides with a provider prefix.
	if r.URL.Path == "/v1/diagnostics/pipeline" {
		p.handleDiagnosticsPipeline(w, r)
		return
	}

	// 0-license. The deployment's license forwarding gate.
	//
	// 🔴 WHY THIS IS HERE AT ALL (2026-08-27,
	// workflow/CI/bugfix/20260827-forwarding-gate-was-never-wired.md). The control
	// plane has always computed this verdict — licstate gives `expired`,
	// `grace_exhausted`, `revoked` and `stale` a `Forwarding: deny`, and serves the
	// projection on /v1/license/plane under a comment naming the proxy as its
	// reader. Nothing read it. An expired deployment's console correctly went
	// read-only while every virtual key it had already issued kept forwarding, for
	// ever. This line is the consumer that was missing.
	//
	// 🔴 WHY AFTER 0-diag AND BEFORE EVERY ROUTING BRANCH. After, because
	// read-only diagnostics must survive a refusal — R8 makes read/export `allow`
	// on every row of the plane table, including the ones that deny forwarding, so
	// an operator diagnosing the refusal must not be locked out by it. Before,
	// because Handle is the single per-request entry the supervisor calls, and
	// putting the gate above probe / app / path-prefix / token routing is what
	// makes one placement cover all four rather than four placements covering
	// three. hotpath_license_gate_fence_test.go asserts this position by
	// reachability rather than trusting the comment.
	//
	// Cost: one atomic load. No file read, no database query, no signature check,
	// no synchronous control call — specs/edition-entitlement requires all five of
	// those absences on the forwarding path, and the cache exists to provide them.
	if !licenseForwardingAllowed(p.licensePlane) {
		p.errors.Add(1)
		// Logged per REQUEST would be a mistake: a denied deployment is denied for
		// every call, and a per-request line is how a developer machine once
		// accumulated a 466 MB log. The transition is logged by the rail instead.
		writeJSONErrorDetails(w, http.StatusPaymentRequired, "license_error",
			observability.ErrCodeLicenseForwardingDenied, licenseForwardingDeniedMessage,
			map[string]any{
				// 🔴 Stated in the refusal itself, because the first thing anyone asks
				// is whether their data is stuck. It is not: R10 takes nothing back and
				// read/export stay available on every plane row.
				"read_and_export_unaffected": true,
				"next_step": map[string]any{
					"code":     "check_license",
					"summary":  licenseForwardingDeniedNextStep,
					"surfaces": []string{"console:/master/license", "cli:aikey license status"},
				},
			})
		return
	}

	// 0a-prime. Probe pipeline path: /probe/<alias>/v1/... (mode C, SPEC
	// 2026-05-23-credential-mode-architecture §1.3).
	//
	// MUST be checked BEFORE both /apps/ and the legacy provider-prefix
	// parser — same prefix-collision reason as the App routing below: a
	// URL like /probe/X/v1 must not be misread as a provider-prefix route
	// or app slug. The ordering invariant is enforced by a regression
	// test in proxy_test.go.
	//
	// Probe pipeline differs from App pipeline in three ways: URL alias
	// (instead of vault-registered slug) is the credential source, the
	// constant first-party Bearer (instead of issued app key) is the
	// auth, and follow_user_active is ALWAYS ignored. See SPEC §1.3 for
	// the full contract.
	if probeCtx := probepipe.ExtractProbePath(r.URL.Path); probeCtx != nil {
		p.handleProbePipeline(w, r, probeCtx, startTime, logger, tc.TraceID)
		return
	}

	// 0a. App pipeline path: /apps/<slug>/v1/... (Phase 4).
	//
	// MUST be checked BEFORE extractProviderFromPath — otherwise
	// /apps/X/openai/v1 would be misread by the legacy parser as
	// provider="apps" with a meaningless stripped path, producing a
	// confusing 404 instead of a precise App pipeline error. This
	// ordering is the wiring invariant called out in apppipe/router.go's
	// ExtractAppPath docstring; verified by TestHandle_AppPathTakesPrecedenceOverProviderPrefix.
	//
	// Today the App pipeline handler returns 501 with diagnostic detail
	// (slug + protocol parsed correctly, vault → Registry plumbing
	// confirmed working if the bearer is recognized) — the authn /
	// resolve / egress / forward stages land in subsequent AKL-204..207
	// sub-tasks.
	if appCtx := apppipe.ExtractAppPath(r.URL.Path); appCtx != nil {
		p.handleAppPipeline(w, r, appCtx, startTime, logger, tc.TraceID)
		return
	}

	// 0. Path-prefix routing: /anthropic/v1/... or /openai/v1/...
	// Takes precedence over token-based routing when the path starts with a
	// known provider prefix. Uses the active key config from the vault.
	if providerCode, strippedPath := extractProviderFromPath(r.URL.Path); providerCode != "" {
		p.handlePathPrefixRoute(w, r, providerCode, strippedPath, startTime, logger, tc.TraceID)
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
			"Missing virtual key. Expected token with 'aikey_team_' or 'aikey_personal_' prefix in Authorization or x-api-key header.")
		return
	}

	// 2. Namespace-authority gate (2026-04-29). Legacy /v1/... entry has no
	// path prefix, so only Tier1 (registry-bound) tokens make sense here.
	// Tier2 probe / Tier3 active sentinel both need a path-derived canonical
	// provider — explicitly reject with a hint to use path-prefix routing.
	// TokenInvalid (malformed / reserved aikey_route_* / unknown) hard-fails.
	// Closes legacy-entry namespace bypass: see review #1, 2026-04-29.
	switch ClassifyToken(token) {
	case Tier1Team, Tier1Personal:
		// fall through to registry resolve
	case Tier1App:
		// App bearers route through /apps/<slug>/v1/... — they
		// MUST NOT be presented at the legacy /v1/... entry because that
		// would leak the app's binding scope into the user's default
		// profile. Reject with a precise hint pointing at the env line
		// `aikey app authorize` printed for this token.
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "APP_TOKEN_WRONG_PATH",
			"App bearer tokens must be sent to /apps/<slug>/v1/... URLs, "+
				"not the legacy /v1/... entry. Use the OPENAI_BASE_URL value printed "+
				"by `aikey app authorize <slug>` for the correct URL.")
		return
	case Tier2Probe:
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Probe sentinel requires path-prefix routing (use /<provider>/v1/... URL).")
		return
	case Tier2ProbeRaw:
		// Same gating reason as Tier2Probe — probe_raw needs path-derived
		// canonical provider to construct upstream URL; legacy /v1/... entry
		// has no path prefix. Reject precisely so caller (CLI/web) gets a
		// clear hint rather than a silent upstream-URL-empty failure.
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Pre-save probe (aikey_probe_raw_*) requires path-prefix routing (use /<provider>/v1/... URL).")
		return
	case Tier3ActiveSentinel:
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Active sentinel requires path-prefix routing (use /<provider>/v1/... URL). "+
				"This entry is for static team/personal tokens only.")
		return
	case TokenInvalid:
		p.errors.Add(1)
		logger.Warn("aikey_* token form invalid (namespace authority)",
			"event.name", observability.EventProxyRequestAuthFailed,
		)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Token is in the aikey_ namespace but doesn't match any recognized form. "+
				"Run 'aikey route' to see valid tokens.")
		return
	case Tier3Native: // extractVirtualKey only returns aikey_* tokens, so this is unreachable (kept explicit for exhaustiveness)
		p.errors.Add(1)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "TOKEN_INVALID",
			"Unexpected token classification at legacy entry.")
		return
	}

	// 3. Resolve virtual key → route.
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
	requestedProtocol := requestProtocolFromPath(r.URL.Path)
	clientRoute := ""
	if requestedProtocol == "anthropic" {
		clientRoute = "anthropic"
	} else if requestedProtocol == "openai_compatible" {
		clientRoute = "openai"
	}
	// 🔴 Task 2.28: multiple bindings under one (virtual key, protocol) is the
	// SHAPE OF A CHAIN, not an error. This used to 409 PROVIDER_ROUTE_AMBIGUOUS —
	// on a correctly configured path — so an administrator who set up a
	// primary/fallback pair got a conflict on their employee's very first
	// request, and the word "ambiguous" sent them back to re-check configuration
	// that was right all along.
	chain, selectErr := p.selectTokenChain(route, clientRoute, requestedProtocol, logger)
	if selectErr != nil {
		p.errors.Add(1)
		writeJSONError(w, http.StatusConflict, "invalid_request_error", "PROVIDER_ROUTE_AMBIGUOUS", selectErr.Error())
		return
	}
	route = chain.primary()

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

	// 3b. Enterprise token-quota gate (Phase 2 Stage 3). Pre-route, in-memory;
	// blocks an over-limit seat with 429 before any vault/upstream work. No-op
	// when quota is disabled or the seat has no quota.
	if p.enforceQuota(w, route, logger) {
		return
	}

	// 3c. Oauth-group routing (N8). A group VK carries no static key — its
	// per-account material is in route.GroupRuntime; pick a candidate account +
	// inject its credential via the dedicated handler. Gated on the field, not a
	// re-read of the feature flag: group VKs are only ever registered when the
	// flag is on (N7c-1), so route.OauthGroupID is empty in the flag-off build and
	// the direct-bind path below stays byte-identical. A registered group VK MUST
	// be served as a group — never fall through to the static-key path (that
	// misroute is exactly what the registration gate prevents).
	if route.OauthGroupID != "" {
		p.handleOauthGroupRoute(w, r, route, token, startTime, logger, tc.TraceID)
		return
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
			// Distinguish "key truly missing" from a transient vault infra
			// error (SQLITE_BUSY / IO / decrypt). Without this split, a
			// momentary lock — on Trial the cli+proxy+server share one SQLite
			// — would tell the user to re-add an already-existing key (GAP 5,
			// 2026-06-09 proxy architecture review). Both stay 503 to preserve
			// the existing soft-fail contract; only the code + message differ.
			if errors.Is(err, vault.ErrSecretNotFound) {
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
			logger.Error("vault lookup failed",
				"event.name", observability.EventProxyRequestVaultFailed,
				"error.code", "VAULT_UNAVAILABLE",
				"error.message", err.Error(),
				"key_alias", route.KeyAlias,
			)
			writeJSONError(w, http.StatusServiceUnavailable, "server_error", "VAULT_UNAVAILABLE",
				"Vault temporarily unavailable, please retry.")
			return
		}
	}

	// 5. Get provider adapter — use protocol type (e.g. "openai_compatible"),
	// not the provider_code (e.g. "kimi_code"). 2026-05-08 Kimi 双平台拆分:
	// pre-split route.Provider 同时是 provider_code 又是 adapter registry key
	// (因 "kimi"/"openai" 字面值刚好相同),post-split 新 provider_codes
	// ("kimi_code" / "moonshot") **不是** adapter registry key —— adapter 是
	// 按 protocol 注册 (openai_compatible / anthropic / kimi / generic)。
	// 与 handlePathPrefixRoute 对齐用 protocol 查找,避免 502 PROVIDER_ERROR。
	// route.ProtocolType 兜底退回 route.Provider 防 pre-2026-05-08 fixture。
	adapterKey := route.ProtocolType
	if adapterKey == "" {
		adapterKey = route.Provider
	}
	prov, err := p.providers.Get(adapterKey)
	if err != nil {
		p.errors.Add(1)
		logger.Error("unknown provider",
			"event.name", observability.EventProxyRequestUpstreamError,
			"error.code", observability.ErrCodeProviderError,
			"error.message", err.Error(),
		)
		writeJSONError(w, http.StatusBadGateway, "server_error", "PROVIDER_ERROR",
			"Unknown provider protocol: "+adapterKey)
		return
	}

	// 🔴 Task 2.0b: the candidate loop hangs HERE and on handlePathPrefixRoute —
	// the two entries that serve a team VK's direct-bind credential. Wiring only
	// one of them would make failover depend on the URL SHAPE the client happens
	// to use (`/v1/messages` vs `/anthropic/v1/messages`), and nobody debugging
	// "it failed over for me but not for them" would think to suspect the path
	// prefix.
	//
	// A chain that cannot fail over falls through to the single-shot call below,
	// byte-identical to the pre-upgrade behavior. That is what keeps this change
	// inert for every installation that never configured a route group.
	if chain.canFailover() || (chain.grouped && len(chain.candidates) == 1) {
		p.serveManagedChain(w, r, chain, token, startTime, logger, tc.TraceID, observer.StreamUserChat)
		return
	}

	// SPEC §1.4.1: legacy /v1/... entry serves user-chat traffic; wire
	// observer through helper so ndjson-fanout subscribers see this stream.
	p.serveRouteWithObserver(w, r, route, prov, realKey, token, startTime, logger,
		observer.StreamUserChat, tc.TraceID)
}

// The refusal text for the license forwarding gate.
//
// 🔴 It names the CAUSE and a step the reader can take, because the reader is a
// developer whose `claude` command just stopped working and who has no idea their
// company's deployment has a license at all. "Forbidden" or "unauthorized" would
// send them to check their API key, which is fine — that is the whole reason this
// is a 402 and not a 403.
//
// 🚫 No expiry date, no company name, no state name. The person seeing this is a
// member, and PRD §6.4 keeps the deployment's commercial standing off member
// surfaces; the administrator gets the full story on the console page named
// below. It is also why the wire projection this gate reads carries one word.
const (
	licenseForwardingDeniedMessage = "This deployment's AiKey license does not currently permit " +
		"AI request forwarding. Your existing keys and data are untouched, and reading and " +
		"exporting still work."
	licenseForwardingDeniedNextStep = "Ask an administrator to open the license page in the AiKey " +
		"console, or run `aikey license status` to see this deployment's license state."
)

// filterStub501Message renders the fail-loud 501 body for one FilterStubCause.
// Contract (bugfix 2026-08-19 filterpipe-501-stale-copy): every branch states
// the REAL cause and a step the user can actually execute — never "wait for a
// build", never "server-side", never "temporary". The org-mandate branch must
// not suggest clearing local settings (that path cannot lift a mandate block).
func filterStub501Message(cause *FilterStubCause) string {
	slug := cause.Slug
	if slug == "" {
		slug = "ai-compliance-detector"
	}
	where := ""
	if cause.ExpectedPath != "" {
		where = " (expected at " + cause.ExpectedPath + ")"
	}
	switch cause.Reason {
	case FilterStubReasonMandateNotInstalled:
		return "Your organization requires the AiKey compliance detector, but it is " +
			"not installed on this machine" + where + ". Run `aikey app install " + slug +
			"` to install it; traffic is blocked until then (fail-closed by org policy — " +
			"clearing local filter settings will not lift this block)."
	case FilterStubReasonSpawnFailed:
		return "The compliance filter '" + slug + "' is installed but failed to start" +
			where + ". Check the proxy logs for the spawn error, then reinstall it with " +
			"`aikey app install " + slug + "`. Traffic is blocked to avoid forwarding unfiltered."
	default: // FilterStubReasonBinaryMissing and any future unclassified cause
		// The disable hint must reference a command that actually ships (the
		// P3-era text told users to "clear the filter declaration" with no
		// public verb for it): the compliance detector has `aikey compliance
		// off`; any other filter app is removed with `aikey app uninstall`.
		off := "`aikey app uninstall " + slug + "` to remove it"
		if slug == "ai-compliance-detector" {
			off = "`aikey compliance off` to disable compliance scanning"
		}
		return "This machine declares the compliance filter '" + slug + "' but its " +
			"binary was not found" + where + ". Run `aikey app install " + slug + "` to " +
			"install it, or " + off + ". Traffic is blocked to avoid forwarding unfiltered."
	}
}
