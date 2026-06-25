// group_serve.go — N8b: serve a seat-group virtual key on the legacy /v1 entry.
//
// A group VK carries no static key (route.PlaintextKey == ""); its per-account
// material was pulled into route.GroupRuntime by N7c-2. handleSeatGroupRoute
// picks a candidate account (N8a resolver), injects its credential exactly the
// way the personal-OAuth / team-key paths do, and forwards through the shared
// serveRouteWithObserver. The direct-bind path in handle_dispatch is untouched —
// this whole branch is reached only when route.SeatGroupID != "" AND the feature
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

// handleSeatGroupRoute resolves + serves a group VK request. Called from Handle
// after route resolution, model-allowlist, and quota gating, in place of the
// static-key step-4 path. Always writes a response (success forward or a 503
// degrade) — the caller returns immediately after.
func (p *Proxy) handleSeatGroupRoute(
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

	res, err := resolveGroupCredential(route, p.groupKey.DerivedKey(), time.Now().Unix(), nil)
	if err != nil {
		code := observability.ErrCodeGroupKeyUnavailable
		if ge, ok := err.(*groupResolveError); ok {
			code = ge.Code
		}
		p.degradeGroup(w, logger, route, code,
			"No usable account is available in this credential-sharing group right now. "+
				"Please retry shortly or contact your administrator.")
		return
	}

	// Per-request copy — DO NOT mutate the shared registry route (see file doc).
	rc := *route
	rc.AccountID = res.AccountID // usage attribution → the account actually used

	canonicalCode := providerCanonicalCode(rc.ProviderCode)
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

	logger.Info("group route resolved",
		"event.name", observability.EventProxyGroupRouteResolved,
		"seat_group_id", rc.SeatGroupID,
		"account_id", res.AccountID,
		"credential_type", res.CredentialType,
		"provider", canonicalCode,
	)

	p.serveRouteWithObserver(w, r, &rc, prov, realKey, inboundBearer, startTime, logger,
		observer.StreamUserChat, traceID)
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
		"seat_group_id", route.SeatGroupID,
		"virtual_key_id", route.VirtualKeyID,
	)
	writeJSONError(w, http.StatusServiceUnavailable, "server_error", code, clientMsg)
}
