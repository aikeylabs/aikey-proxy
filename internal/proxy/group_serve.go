// group_serve.go — N8b: serve a oauth-group virtual key on the legacy /v1 entry.
//
// A group VK carries no static key (route.PlaintextKey == ""); its per-account
// material was pulled into route.GroupRuntime by N7c-2. handleOauthGroupRoute
// picks a candidate account (N8a resolver), injects its credential exactly the
// way the personal-OAuth / team-key paths do, and forwards through the shared
// serveRouteWithObserver. The direct-bind path in handle_dispatch is untouched —
// this whole branch is reached only when route.OauthGroupID != "" AND the feature
// flag is on, and group VKs aren't even registered when the flag is off (N7c-1).
//
// SECURITY / CORRECTNESS:
//   - registry.Resolve hands out a SHARED *ResolvedRoute pointer. We mutate a
//     per-request COPY (rc := *route) so concurrent requests on the same group VK
//     never race on BaseURL/AccountID or corrupt the registry entry.
//   - OAuth injection mirrors ResolveBindingCredential's branch byte-for-byte
//     (Codex chatgpt.com base + captureCodexModel; others provider-default;
//     headers via oauthInject; "__oauth__" sentinel realKey so the Director only
//     rewrites the URL). refresh_token never reaches here (not in the material).
package proxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// handleOauthGroupRoute resolves + serves a group VK request. Called from Handle
// after route resolution, model-allowlist, and quota gating, in place of the
// static-key step-4 path. Always writes a response (success forward or a 503
// degrade) — the caller returns immediately after.
func (p *Proxy) handleOauthGroupRoute(
	w http.ResponseWriter, r *http.Request,
	route *vkeys.ResolvedRoute, inboundBearer string,
	startTime time.Time, logger *slog.Logger, traceID string,
) {
	// Need the vault key to decrypt the at-rest material. nil only when the
	// injected vault doesn't expose DerivedKey() (tests) — degrade, never panic.
	if p.groupKey == nil {
		p.degradeGroup(w, logger, route, observability.ErrCodeGroupKeyUnavailable,
			"Group routing is temporarily unavailable. Please retry shortly.")
		return
	}

	// §5.5 hard cap: the engine left this seat UNBOUND — every account in its
	// pool/segment is at the ≤3-人/号 cap. 429 here; do NOT fall through to the
	// local pick, which is cap-blind and would route a 4th user onto a full account.
	// (Distinct from the 503 degrade: an actionable "pool full" state, not a
	// transient failure.)
	if p.routingOverrides.Blocked(route.SeatID, route.OauthGroupID) {
		logger.Warn("oauth-group seat blocked: pool at per-account user cap",
			"event.name", observability.EventProxyGroupSeatBlocked,
			"oauth_group_id", route.OauthGroupID,
			"seat_id", route.SeatID)
		writeJSONError(w, http.StatusTooManyRequests, "rate_limit_error", observability.ErrCodeGroupPoolFull,
			"No available account: every account in your pool is at the per-account user limit. Ask your admin to add accounts.")
		return
	}
	// Skip accounts cooling down from a recent upstream failure (N8c reactive
	// fallback) so this request routes around them. The allocation engine's
	// routing override for this seat (§6.5; "" when off / no redirect) is applied
	// inside the resolver ONLY if it's still a valid candidate — fault-isolated,
	// falls back to the local pick on any miss.
	override := p.routingOverrides.lookup(route.SeatID, route.OauthGroupID)
	res, err := resolveGroupCredential(route, p.groupKey.DerivedKey(), time.Now().Unix(), p.poolCooldown.skipSet(), override)
	if err != nil {
		code := observability.ErrCodeGroupKeyUnavailable
		if ge, ok := err.(*groupResolveError); ok {
			// RW2/D2: the routed account has no token for this member — return a
			// structured login prompt (not a 503 degrade) so the client triggers the
			// local OAuth login for THAT account.
			if ge.Code == groupErrLoginRequired {
				p.respondLoginRequired(w, logger, route, ge.Account)
				return
			}
			code = ge.Code
		}
		p.degradeGroup(w, logger, route, code, groupDegradeMessage(code))
		return
	}

	// Member has a token for the routed account ⇒ any earlier "login required"
	// statusline hint is now stale — clear it (no-op unless one was written;
	// see groupLoginStateStore.dirty).
	p.groupLoginState.Clear(logger)

	// Per-request copy — DO NOT mutate the shared registry route (see file doc).
	rc := *route
	rc.AccountID = res.AccountID       // usage attribution → the account actually used
	rc.CredentialID = res.CredentialID // I5 signal reporting keyed by credential_id (T2 uplink; empty group route.CredentialID was dropping all signals)
	// Point-in-time audit identity (2026-07-01, usage-audit "selected account" display):
	// the SELECTED pool account's email rides the usage event as oauth_identity
	// (reportable.go reads route.OAuthIdentity → ODS → DWD → the master usage-audit
	// page). Denormalized ON PURPOSE: routing changes over time, so joining live
	// tables later would misattribute history — the event must carry who served it.
	rc.OAuthIdentity = res.Identity
	// Per-account egress proxy (§11.7, P7): pin this account's outbound to its own
	// exit IP. serveRoute reads rc.EgressProxyURL to select a per-account egress
	// transport (single-hop, or 2-hop chained through the node socks5 front proxy).
	rc.EgressProxyURL = res.EgressProxyURL

	// A group VK is bound to a oauth_group, NOT a single provider, so the VK-level
	// ProviderCode is EMPTY — the provider lives per-account in group_accounts.
	// Use the RESOLVED account's provider_code (the candidate ref the resolver
	// picked); fall back to the route's only for safety. Using rc.ProviderCode
	// here yielded canonicalCode="" → empty upstream base URL → 502 (found by the
	// live full-pipeline E2E 2026-06-25; hermetic tests set route.ProviderCode so
	// never hit the empty case).
	provCode := res.ProviderCode
	if provCode == "" {
		provCode = rc.ProviderCode
	}
	canonicalCode := providerCanonicalCode(provCode)
	var realKey string
	switch res.CredentialType {
	case credTypeKey:
		realKey = res.PlaintextKey
		if res.BaseURL != "" {
			rc.BaseURL = res.BaseURL
		}
	default: // oauth_account
		// Dialect gate (2026-07-13): codex OAuth serves ONLY the Responses API.
		// Without this, a /chat/completions client's path got appended to
		// chatgpt.com/backend-api/codex and ChatGPT's edge answered with a
		// misleading "invalid x-api-key". Fail fast with the real reason.
		if reason := oauthUpstreamRejectsPath(canonicalCode, r.URL.Path); reason != "" {
			logger.Warn("group route: OAuth upstream does not serve this endpoint",
				"event.name", observability.EventProxyRequestDialectUnsupported,
				"error.code", observability.ErrCodeOAuthResponsesOnly,
				"error.message", reason,
				"url.path", r.URL.Path,
			)
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				observability.ErrCodeOAuthResponsesOnly, reason)
			return
		}
		// Per-provider OAuth upstream (base URL + any provider setup like codex's
		// deferred model capture) via the shared resolver — same source as the
		// legacy /v1 path. Headers injected here; the Director sees the sentinel
		// and only rewrites the upstream URL.
		rc.BaseURL, r = resolveOAuthUpstream(canonicalCode, r)
		oauthInject(r, res.OAuth, canonicalCode)
		// Stash the window cap so ModifyResponse can pre-cut this account when the
		// upstream's unified-utilization crosses it (N10 防封).
		if res.WindowMaxUtilPct != nil {
			r = stashWindowCap(r, *res.WindowMaxUtilPct)
		}
		realKey = oauthSentinelKey
	}

	adapterKey := rc.ProtocolType
	if adapterKey == "" {
		adapterKey = rc.Provider
	}
	prov, perr := p.providers.Get(adapterKey)
	if perr != nil {
		p.errors.Add(1)
		logger.Error("group route: unknown provider",
			"event.name", observability.EventProxyRequestUpstreamError,
			"error.code", observability.ErrCodeProviderError,
			"error.message", perr.Error(),
		)
		writeJSONError(w, http.StatusBadGateway, "server_error", observability.ErrCodeProviderError,
			"Unknown provider protocol: "+adapterKey)
		return
	}

	// N9 #8: audit a fallback — the seat's primary account was unusable (cooled /
	// exhausted / expired / no material) so we routed to a different candidate.
	if res.Primary != "" && res.Primary != res.AccountID {
		logger.Info("oauth-group account switched (primary unusable)",
			"event.name", observability.EventProxyGroupAccountSwitched,
			"oauth_group_id", rc.OauthGroupID,
			"from_account_id", res.Primary,
			"to_account_id", res.AccountID,
		)
	}

	logger.Info("group route resolved",
		"event.name", observability.EventProxyGroupRouteResolved,
		"oauth_group_id", rc.OauthGroupID,
		"account_id", res.AccountID,
		"credential_type", res.CredentialType,
		"provider", canonicalCode,
	)

	// Group VKs leave rc.ProviderCode empty by design (the provider is per-account
	// in group_accounts; the base URL above already used the resolved canonicalCode,
	// NOT rc.ProviderCode — see the 502 note earlier). But the conversation-audit
	// observer's protocol-specific extractor needs the provider to parse the turn:
	// without it serveRouteWithObserver leaves ProtocolFamily="" → the extractor
	// can't decode the messages/SSE → CONTENT_EMPTY_EXTRACT drops the turn while
	// usage (protocol-agnostic) still reports. Found by the OAuth-pool E2E
	// (2026-06-26). Set it to the resolved canonical provider now that the base URL
	// is fixed, so the observer's ProtocolFamily fallback fires.
	rc.ProviderCode = canonicalCode

	p.serveRouteWithObserver(w, r, &rc, prov, realKey, inboundBearer, startTime, logger,
		observer.StreamUserChat, traceID)
}

// groupDegradeMessage maps a resolver failure code to an actionable, end-user
// (Claude Code) message. The three modes mean very different things and need
// different guidance — collapsing them into one "retry shortly" misleads a member
// whose access is permanently gone (unbound) into retrying forever.
func groupDegradeMessage(code string) string {
	switch code {
	case groupErrNoCandidates:
		// Permanent until an admin acts: the seat has NO account available in the
		// group — either it was removed from the seat group, or the group has no
		// active accounts. Covers both the empty candidate snapshot AND an empty
		// channel-③ delivery ("{}", 2026-06-30). Retrying will NOT help.
		return "Your seat has no available account in this credential-sharing group " +
			"(it may have been removed from the group, or the group has no active accounts). " +
			"Contact your administrator — this will not resolve on its own."
	case groupErrNoMaterial:
		// Transient: candidates exist but the proxy hasn't pulled their material
		// yet (channel ③ poll in flight). Retrying shortly is the right action.
		return "This group's credentials are still syncing to the proxy. Please retry shortly."
	case groupErrAllUnusable:
		// Every candidate is expired / quota-exhausted / undecryptable right now.
		return "All accounts in this credential-sharing group are currently unavailable " +
			"(rate-limited or expired). Contact your administrator if this persists."
	default:
		return "Group routing is temporarily unavailable. Please retry shortly."
	}
}

// groupLoginConsolePath is the local-console page where a member completes the
// pool-account sign-in (C19 rename: /user/oauth-contribute → /user/team-oauth).
// Appended to the configured console base to form login_url. The page route is
// owned by aikey-control's local web router — a rename there must update this
// constant (cross-repo contract, same as the JSON body shape below).
const groupLoginConsolePath = "/user/team-oauth"

// respondLoginRequired returns the RW2/D2 structured login prompt: the member has
// no token for the HRW-routed account, so the client must run the local OAuth
// login for THAT account (proxy did NOT skip to a later logged-in candidate).
// Status 401: the member must authenticate to the account before the request can
// proceed.
//
// Display contract (20260703 update, spike-verified in dev2):
//   - error.type is "authentication_error" — the Anthropic-standard type — NOT a
//     custom string. claude/codex only render error.message verbatim for types
//     they recognize; the previous custom "login_required" type fell into the
//     generic "API error · Retrying" path and the user never saw the prompt.
//     Machine consumers keep the precise signal via error.code and the
//     X-Aikey-Error-Source header (both stay OAUTH_GROUP_MEMBER_LOGIN_REQUIRED).
//   - login_url is assembled HERE from Config.ConsoleURL (决策2: single assembly
//     point — the statusline state file below reuses the same URL). Empty
//     ConsoleURL (cluster node / server-side proxy) degrades to URL-less wording.
func (p *Proxy) respondLoginRequired(w http.ResponseWriter, logger *slog.Logger, route *vkeys.ResolvedRoute, accountID string) {
	loginURL := p.groupLoginURL()
	logger.Info("group route requires member login",
		"event.name", observability.EventProxyGroupLoginRequired,
		"oauth_group_id", route.OauthGroupID,
		"virtual_key_id", route.VirtualKeyID,
		"account_id", accountID,
		"login_url", loginURL,
	)
	// Bypass statusline hint (决策3): best-effort, never blocks the response.
	p.groupLoginState.Write(logger, route.ProviderCode, accountID, loginURL)

	message := "AiKey: log in to this shared account before use. " +
		"Open your local AiKey console (" + groupLoginConsolePath + " page), complete sign-in, then retry."
	if loginURL != "" {
		message = "AiKey: log in to this shared account before use. " +
			"Open " + loginURL + " and complete sign-in, then retry."
	}

	// SyncRail truthful wording (§5.4, 2026-07-03 incident): when the engine's
	// assignment rail is stale/offline, THIS pick came from the local ranked
	// fallback and may contradict what the team-oauth page shows (the engine may
	// have routed the seat to an account the member already signed into). Saying
	// "go log in" then sends the member on a wild-goose chase — say what is
	// actually wrong instead. reason stays machine-readable; error.code and the
	// header keep the precise signal unchanged (additive contract only).
	reason := ""
	if p.routingRailHealth != nil {
		if st, downSecs := p.routingRailHealth(); st == "stale" || st == "offline" {
			reason = "routing_sync_unavailable"
			message = "AiKey: account routing sync with your team server has been unreachable for " +
				humanDuration(downSecs) + ", so this sign-in request may be misdirected. " +
				"Check the connection to your team server (aikey status), or contact your admin. " +
				"If the account shown on your console is already signed in, this error should clear once sync recovers."
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(HeaderAikeyErrorSource, groupErrLoginRequired)
	w.WriteHeader(http.StatusUnauthorized)
	errObj := map[string]string{
		"message": message,
		"type":    "authentication_error",
		"code":    groupErrLoginRequired,
	}
	if reason != "" {
		errObj["reason"] = reason
	}
	// json.Marshal (not string concat) so account ids / future fields can't break
	// the JSON or inject — correct escaping for free.
	body, _ := json.Marshal(map[string]any{
		"error":     errObj,
		"account":   accountID,
		"login_url": loginURL,
	})
	_, _ = w.Write(body)
}

// humanDuration renders seconds as a coarse "N min" / "N h" for user-facing
// error text (en-US wording per the code-and-ui-language rule).
func humanDuration(secs int64) string {
	switch {
	case secs >= 3600:
		return fmt.Sprintf("%d h", secs/3600)
	case secs >= 60:
		return fmt.Sprintf("%d min", secs/60)
	default:
		return fmt.Sprintf("%d s", secs)
	}
}

// groupLoginURL assembles the member-login page URL from the configured local
// console base. "" when no console is co-installed (empty console_url).
func (p *Proxy) groupLoginURL() string {
	base := strings.TrimRight(p.consoleURL, "/")
	if base == "" {
		return ""
	}
	return base + groupLoginConsolePath
}

// groupDegradeStatus maps a resolver failure code to the HTTP status that gives the
// client the RIGHT retry behavior (2026-07-01). The Anthropic SDK retries 5xx (and
// 429) with exponential backoff — so a PERMANENT failure returned as 503 makes
// `claude` HANG for minutes retrying something that can never succeed, and renders a
// misleading "server-side issue, usually temporary — try again" suffix that
// contradicts our own "will not resolve on its own" message. Rule: permanent → 4xx
// (fail fast); genuinely transient → 503.
func groupDegradeStatus(code string) (status int, errType string) {
	switch code {
	case groupErrNoCandidates:
		// Permanent until an admin acts: the seat has no account in the group
		// (removed / empty group). Retrying never helps → 403 so the client fails
		// FAST — no backoff hang, no "try again" framing. THIS fixes the reported
		// "no available oauth → claude hangs for minutes" bug.
		return http.StatusForbidden, "permission_error"
	case groupErrAllUnusable:
		// Every candidate is rate-limited / expired — a genuine rate-limit that
		// recovers when the upstream window resets. 429 is the honest code (the
		// client MAY back off and retry, which is legitimate here).
		return http.StatusTooManyRequests, "rate_limit_error"
	default:
		// NO_MATERIAL (channel-③ poll in flight) / group key unavailable (vault
		// reload) → genuinely transient; retrying shortly IS the right action → 503.
		return http.StatusServiceUnavailable, "server_error"
	}
}

// degradeGroup fails a group request loudly (never silently routes it to a wrong
// key). Emits a WARN with trace context + the degrade reason code, then the status
// groupDegradeStatus picks for that code (permanent → 4xx fail-fast, transient →
// 503). N8c extends this with per-candidate fallback before giving up; today a
// resolver failure means every candidate was already unusable.
func (p *Proxy) degradeGroup(w http.ResponseWriter, logger *slog.Logger, route *vkeys.ResolvedRoute, code, clientMsg string) {
	p.errors.Add(1)
	status, errType := groupDegradeStatus(code)
	logger.Warn("group route degraded",
		"event.name", observability.EventProxyGroupRouteDegraded,
		"error.code", code,
		"http.status", status,
		"oauth_group_id", route.OauthGroupID,
		"virtual_key_id", route.VirtualKeyID,
	)
	writeJSONError(w, status, errType, code, clientMsg)
}
