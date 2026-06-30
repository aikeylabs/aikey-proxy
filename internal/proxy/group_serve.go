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
	"log/slog"
	"net/http"
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
	if p.routingOverrides.Blocked(route.SeatID) {
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
	override := p.routingOverrides.lookup(route.SeatID)
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

	// Per-request copy — DO NOT mutate the shared registry route (see file doc).
	rc := *route
	rc.AccountID = res.AccountID // usage attribution → the account actually used

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
		// Mirror ResolveBindingCredential's OAuth branch: Codex uses the
		// chatgpt.com Responses API base (+ deferred model capture); other
		// providers use their default base. Headers injected here; the Director
		// sees the sentinel and only rewrites the upstream URL.
		if canonicalCode == "openai" {
			rc.BaseURL = "https://chatgpt.com/backend-api/codex"
			r = captureCodexModel(r)
		} else {
			rc.BaseURL = providerDefaultBaseURL(canonicalCode)
		}
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
		// Permanent until an admin acts: the seat isn't (or is no longer) a member
		// of the group, so it has no candidate accounts. Retrying will not help.
		return "Your seat is not a member of this credential-sharing group (it may have been removed). " +
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

// respondLoginRequired returns the RW2/D2 structured login prompt: the member has
// no token for the HRW-routed account, so the client must run the local OAuth
// login for THAT account (proxy did NOT skip to a later logged-in candidate). The
// body carries the account id so the client opens the right login; login_url is
// assembled client-side from its local contribute page (the proxy is not wired to
// the local web base — tracked as carry-over). Status 401: the member must
// authenticate to the account before the request can proceed.
func (p *Proxy) respondLoginRequired(w http.ResponseWriter, logger *slog.Logger, route *vkeys.ResolvedRoute, accountID string) {
	logger.Info("group route requires member login",
		"event.name", observability.EventProxyGroupLoginRequired,
		"oauth_group_id", route.OauthGroupID,
		"virtual_key_id", route.VirtualKeyID,
		"account_id", accountID,
	)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(HeaderAikeyErrorSource, groupErrLoginRequired)
	w.WriteHeader(http.StatusUnauthorized)
	msg := "Log in to this account to use it: open your local AiKey console and complete sign-in."
	_, _ = w.Write([]byte(`{"error":{"message":"` + escapeJSON(msg) +
		`","type":"login_required","code":"` + groupErrLoginRequired +
		`"},"account":"` + escapeJSON(accountID) + `","login_url":""}`))
}

// degradeGroup fails a group request loudly (never silently routes it to a wrong
// key). Emits a WARN with trace context + the degrade reason code, then a 503 so
// the client retries. N8c extends this with per-candidate fallback before giving
// up; today a resolver failure means every candidate was already unusable.
func (p *Proxy) degradeGroup(w http.ResponseWriter, logger *slog.Logger, route *vkeys.ResolvedRoute, code, clientMsg string) {
	p.errors.Add(1)
	logger.Warn("group route degraded",
		"event.name", observability.EventProxyGroupRouteDegraded,
		"error.code", code,
		"oauth_group_id", route.OauthGroupID,
		"virtual_key_id", route.VirtualKeyID,
	)
	writeJSONError(w, http.StatusServiceUnavailable, "server_error", code, clientMsg)
}
