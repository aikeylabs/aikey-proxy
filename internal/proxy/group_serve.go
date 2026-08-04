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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
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

	// A deleted group has an explicit access tombstone. Runtime material is
	// keep-last-known for availability and may still list usable accounts, so it
	// must never be allowed to reconstruct serving authorization after deletion.
	// Unknown routes remain backward-compatible local picks; only Removed fails
	// closed with the established permanent no-candidates response.
	if p.routingOverrides.Removed(route.SeatID, route.OauthGroupID) {
		p.degradeGroup(w, logger, route, groupErrNoCandidates,
			groupDegradeMessage(groupErrNoCandidates))
		return
	}

	// §5.5: the engine left this seat UNBOUND (every pool account at the ≤3-人/号
	// cap, or no usable account at all). 429 here; do NOT fall through to the
	// local pick, which is cap-blind and would route a 4th user onto a full
	// account. Neutral wording that doesn't guess the cause — the original "add
	// accounts" phrasing misdirected admins when the real cause was a transient
	// unbind (2026-07-17 customer incident; the actual root cause was fixed in the
	// binding pass, so this 429 is now rare — genuine cap-full or all-dead pool).
	if p.routingOverrides.Blocked(route.SeatID, route.OauthGroupID) {
		logger.Warn("oauth-group seat blocked by the allocation engine",
			"event.name", observability.EventProxyGroupSeatBlocked,
			"error.code", observability.ErrCodeGroupPoolFull,
			"oauth_group_id", route.OauthGroupID,
			"seat_id", route.SeatID)
		writeJSONError(w, http.StatusTooManyRequests, "rate_limit_error", observability.ErrCodeGroupPoolFull,
			"No available account in your pool right now. Contact your administrator if this persists.")
		return
	}
	// N9 in-request failover (2026-07-19, sub2api blueprint — see group_failover.go):
	// buffer the request body ONCE so every attempt can replay a pristine clone;
	// per-attempt header/context mutations (oauthInject persona, URL rewrite,
	// window-cap stash) live on that attempt's clone only.
	reqBody, rerr := io.ReadAll(r.Body)
	if rerr != nil {
		p.degradeGroup(w, logger, route, observability.ErrCodeGroupKeyUnavailable,
			"Failed to read the request body. Please retry.")
		return
	}
	_ = r.Body.Close()
	baseReq := r

	// failed accounts of THIS request (merged into the resolver skip set): the
	// shared cooldown store already learns 401/evidence-429 via ModifyResponse,
	// but a 529/5xx attempt must also never be re-picked within this request.
	failed := map[string]bool{}
	failedPaths := map[string]bool{}
	var lastCaptured *groupFailoverWriter
	var lastBlockedPath *ProviderPathHealth
	upstreamAttempts := 0

	// P1-C: the skip set is MODEL-AWARE — an account cooled only for a premium
	// tier (Fable weekly window) is skipped for that tier's requests and stays
	// fully available to everything else.
	reqModel := extractModelLazy(reqBody)

	override := p.routingOverrides.lookup(route.SeatID, route.OauthGroupID)
	for {
		// baseSkip is durable routing state (whole-account/model-tier cooldown).
		// Keep it separate from this request's failed attempts: a needs_login account
		// selected after baseSkip is actionable and must become the visible route;
		// one reached only because of a transient request-local 5xx is not.
		baseSkip := p.poolCooldown.skipSetFor(reqModel)
		skip := baseSkip
		if len(failed) > 0 {
			merged := make(map[string]bool, len(skip)+len(failed))
			for id := range skip {
				merged[id] = true
			}
			for id := range failed {
				merged[id] = true
			}
			skip = merged
		}
		nowUnix := time.Now().Unix()
		res, err := resolveGroupCredential(route, p.groupKey.DerivedKey(), nowUnix, skip, override)
		if err != nil {
			ge, isGE := err.(*groupResolveError)
			// 1. RW2/D2: a needs_login destination is actionable when no upstream
			//    attempt preceded it, or when the same destination is selected from the
			//    durable cooldown set alone. If it appears only after merging a transient
			//    request-local failure, preserve that captured upstream error instead.
			if isGE && ge.Code == groupErrLoginRequired {
				actionable := lastCaptured == nil && lastBlockedPath == nil
				if !actionable {
					_, baseErr := resolveGroupCredential(route, p.groupKey.DerivedKey(), nowUnix, baseSkip, override)
					if baseGE, ok := baseErr.(*groupResolveError); ok && baseGE.Code == groupErrLoginRequired && baseGE.Account == ge.Account {
						actionable = true
					}
				}
				if actionable {
					p.respondLoginRequired(w, logger, route, ge.Account)
				} else if lastCaptured != nil {
					lastCaptured.flushCaptured()
				} else if lastBlockedPath != nil {
					p.respondProviderPathUnavailable(w, logger, route, *lastBlockedPath)
				} else {
					p.degradeGroup(w, logger, route, ge.Code, groupDegradeMessage(ge.Code))
				}
				return
			}
			// 2. P1-C Phase 2 guidance (用户拍板 2026-07-19): when the REQUESTED
			//    model's premium tier is what emptied the candidate set, say so —
			//    and say it EVEN on the request that DISCOVERED the exhaustion via
			//    failover (guidance beats flushing the raw upstream 429, which lacks
			//    the switch-model hint). The generic "all accounts unavailable"
			//    wording implies the whole pool is down; this tells the user that
			//    switching model unblocks them right now.
			if isGE && ge.Code == groupErrAllUnusable {
				if tier := tierForModel(reqModel); tier != nil {
					if until, cooled := p.poolCooldown.tierCooldownUntil(tier.Key); cooled {
						p.respondModelTierExhausted(w, logger, route, reqModel, tier.Key, until)
						return
					}
				}
			}
			// 3. Mid-failover candidate exhaustion (non-tier): the last upstream
			//    error IS the final answer — flush it verbatim (transparent, never
			//    invent a shape).
			if lastCaptured != nil {
				lastCaptured.flushCaptured()
				return
			}
			if lastBlockedPath != nil {
				p.respondProviderPathUnavailable(w, logger, route, *lastBlockedPath)
				return
			}
			// A durable HTTP 5xx cooldown (or legacy persisted transport cooldown)
			// is not quota exhaustion. The
			// resolver intentionally consumes a bool skip set, so recover the
			// reason from the cooldown store before the generic 429 mapping. Do
			// this only when this request has no concrete upstream response to
			// preserve verbatim.
			if isGE && ge.Code == groupErrAllUnusable {
				p.setGroupCooldownRetryAfter(w, route, baseSkip)
				if code := p.groupUnavailableCooldownCode(route, baseSkip); code != "" {
					p.degradeGroup(w, logger, route, code, groupDegradeMessage(code))
					return
				}
			}
			// 4. Resolve-time degrade (nothing served this request at all).
			code := observability.ErrCodeGroupKeyUnavailable
			if isGE {
				code = ge.Code
			}
			p.degradeGroup(w, logger, route, code, groupDegradeMessage(code))
			return
		}
		result := p.serveGroupAttempt(w, baseReq, reqBody, route, res, inboundBearer, startTime, logger, traceID,
			upstreamAttempts, failed, failedPaths, &lastCaptured)
		if result.attempted {
			upstreamAttempts++
		}
		if result.blockedPath != nil {
			lastBlockedPath = result.blockedPath
		}
		if result.done {
			return
		}
	}
}

type groupAttemptResult struct {
	done        bool
	attempted   bool
	blockedPath *ProviderPathHealth
}

// serveGroupAttempt evaluates ONE candidate and reports whether it reached the
// upstream, completed the client response, or was blocked by path health. A
// captured upstream failure adds the account/path to the request-local skip set
// so the caller can resolve the next useful candidate.
func (p *Proxy) serveGroupAttempt(
	w http.ResponseWriter, baseReq *http.Request, reqBody []byte,
	route *vkeys.ResolvedRoute, res *groupResolution, inboundBearer string,
	startTime time.Time, logger *slog.Logger, traceID string,
	attempt int, failed map[string]bool, failedPaths map[string]bool, lastCaptured **groupFailoverWriter,
) groupAttemptResult {
	// fresh clone per attempt: pristine headers + replayed body + inherited
	// context stashes (route/model extraction ride the context, not the body).
	r := baseReq.Clone(baseReq.Context())
	if len(reqBody) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
		r.ContentLength = int64(len(reqBody))
	} else {
		r.Body = http.NoBody
		r.ContentLength = 0
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
	protocolType := res.ProtocolType
	if protocolType == "" {
		protocolType = rc.ProtocolType
	}
	if protocolType != "" {
		rc.ProtocolType = protocolType
	}
	var realKey string
	switch res.CredentialType {
	case credTypeKey:
		realKey = res.PlaintextKey
		if res.BaseURL != "" {
			rc.BaseURL = res.BaseURL
		}
	default: // oauth_account
		oauthCode, oauthCodeOK := oauthInjectionProvider(canonicalCode, protocolType)
		if !oauthCodeOK {
			writeJSONError(w, http.StatusBadGateway, "server_error", observability.ErrCodeProviderError,
				"OAuth account has no supported provider persona for provider="+canonicalCode+" protocol_type="+protocolType)
			return groupAttemptResult{done: true}
		}
		// Dialect gate (2026-07-13): codex OAuth serves ONLY the Responses API.
		// Without this, a /chat/completions client's path got appended to
		// chatgpt.com/backend-api/codex and ChatGPT's edge answered with a
		// misleading "invalid x-api-key". Fail fast with the real reason.
		if reason := oauthUpstreamRejectsPath(oauthCode, r.URL.Path); reason != "" {
			logger.Warn("group route: OAuth upstream does not serve this endpoint",
				"event.name", observability.EventProxyRequestDialectUnsupported,
				"error.code", observability.ErrCodeOAuthResponsesOnly,
				"error.message", reason,
				"url.path", r.URL.Path,
			)
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				observability.ErrCodeOAuthResponsesOnly, reason)
			return groupAttemptResult{done: true}
		}
		// B2 guard (2026-07-17, verify-first 红灯实证 group_serve_verify_b2_test.go):
		// an anthropic OAuth account whose material lacks ExternalID (the OAuth
		// account UUID) must NOT be served — the injected metadata.user_id would
		// carry an EMPTY uuid ("…_account__session_…"), which Anthropic's OAuth WAF
		// rejects with a business 429 (no rate-limit signal → never cooled → sticky
		// re-pick → permanent 429 dead loop; 引擎方案 §2.2 audit + research/
		// oauth-token-exchange-test). Reachable via the RW7 admin-enroll window:
		// external_id is backfilled on first member login, and the material rail
		// lags ≤60s behind. Respond login-required for THIS account: the member's
		// sign-in IS the backfill action (SetExternalIDIfEmpty), and if already
		// backfilled the prompt self-heals on the next material pull (§6.3:
		// incomplete material = 不可选). Codex keys off AccountID and Kimi doesn't
		// use it — only the anthropic family needs the uuid.
		if oauthCode == "anthropic" && res.OAuth != nil && res.OAuth.ExternalID == "" {
			p.respondLoginRequired(w, logger, route, res.AccountID)
			return groupAttemptResult{done: true}
		}
		// Per-provider OAuth upstream (base URL + any provider setup like codex's
		// deferred model capture) via the shared resolver — same source as the
		// legacy /v1 path. Headers injected here; the Director sees the sentinel
		// and only rewrites the upstream URL.
		if canonicalCode == "mock" && strings.TrimSpace(res.BaseURL) == "" {
			logger.Error("Mock Provider OAuth account has no runtime base URL",
				"event.name", observability.EventProxyRequestUpstreamError,
				"error.code", observability.ErrCodeProviderError,
				"account_id", res.AccountID,
				"protocol_type", protocolType,
			)
			writeJSONError(w, http.StatusBadGateway, "server_error", observability.ErrCodeProviderError,
				"Mock Provider account has no runtime base URL")
			return groupAttemptResult{done: true}
		}
		resolvedBase := res.BaseURL
		if strings.TrimSpace(resolvedBase) == "" {
			resolvedBase = rc.BaseURL
		}
		rc.BaseURL, r = resolveOAuthUpstream(canonicalCode, protocolType, resolvedBase, r)
		oauthInject(r, res.OAuth, oauthCode)
		// Stash the window cap so ModifyResponse can pre-cut this account when the
		// upstream's unified-utilization crosses it (N10 防封).
		if res.WindowMaxUtilPct != nil || res.Window7dMaxUtilPct != nil {
			r = stashWindowCaps(r, intValue(res.WindowMaxUtilPct), intValue(res.Window7dMaxUtilPct))
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
		return groupAttemptResult{done: true}
	}

	// The group-level route intentionally leaves ProviderCode empty; path health
	// needs the resolved account provider before deriving its non-secret key.
	rc.ProviderCode = canonicalCode
	overrideOn := p.oauthEgressOverride.Load()
	path := providerPathForRoute(&rc, overrideOn)
	if failedPaths[path.Key] {
		failed[res.AccountID] = true
		return groupAttemptResult{}
	}
	if permit := p.pathHealth.Permit(path); !permit.Allowed {
		failed[res.AccountID] = true
		failedPaths[path.Key] = true
		health := permit.Health
		logger.Warn("oauth-group provider path is backing off",
			"event.name", observability.EventProxyGroupProviderPathState,
			"oauth_group_id", rc.OauthGroupID,
			"path_id", health.PathID,
			"provider", health.Provider,
			"transport", health.Transport,
			"state", health.State,
			"retry_after_seconds", health.RetryAfterSeconds,
		)
		return groupAttemptResult{blockedPath: &health}
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxKeyProviderPathDecision, providerPathDecision{
		path: path, overrideOn: overrideOn,
	}))

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
	// N9 first-byte gate: forward through the capture writer. A failover-eligible
	// upstream failure (401 / evidence-429 / >=500 incl. the ReverseProxy-
	// synthesized 503 for group transport errors) is DEFERRED — nothing reaches the
	// client — and we signal the caller to retry on the next candidate. Capture is
	// disabled on the last permitted attempt so its outcome streams straight
	// through (no pointless buffering when no retry can follow).
	fw := newGroupFailoverWriter(w, attempt < groupFailoverMaxSwitches)
	p.serveRouteWithObserver(fw, r, &rc, prov, realKey, inboundBearer, startTime, logger,
		observer.StreamUserChat, traceID)
	// No-op after an HTTP response (the entry is already closed) or transport
	// failure (it is suspect/open). This only releases a half-open slot when a
	// local pre-forward guard answered without testing the network path.
	p.pathHealth.NoteProbeCanceled(path)
	if !fw.capturedResponse() {
		return groupAttemptResult{done: true, attempted: true} // streamed to the client
	}
	failed[res.AccountID] = true
	if fw.failedPathKey != "" {
		failedPaths[fw.failedPathKey] = true
	}
	*lastCaptured = fw
	logger.Warn("oauth-group in-request failover: retrying on next candidate",
		"event.name", observability.EventProxyGroupRequestFailover,
		"oauth_group_id", rc.OauthGroupID,
		"from_account_id", res.AccountID,
		"failed_status", fw.status,
		"attempt", attempt+1,
	)
	return groupAttemptResult{attempted: true}
}

func (p *Proxy) respondProviderPathUnavailable(
	w http.ResponseWriter, logger *slog.Logger, route *vkeys.ResolvedRoute, health ProviderPathHealth,
) {
	code := observability.ErrCodeGroupUpstreamUnavailable
	if health.Transport != "node" || health.FailureClass == pathFailureEgressDial {
		code = observability.ErrCodeAccountEgressProxy
	}
	if health.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", health.RetryAfterSeconds))
	}
	p.degradeGroup(w, logger, route, code, groupDegradeMessage(code))
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
	case observability.ErrCodeAccountEgressProxy:
		return "The credential-sharing group's configured account egress is unavailable. " +
			"Run `aikey doctor` and ask your administrator to check the account egress credentials and connectivity."
	case observability.ErrCodeGroupUpstreamUnavailable:
		return "All currently routable accounts in this credential-sharing group have an upstream connection failure. " +
			"Please retry shortly; if it persists, ask your administrator to check account egress and upstream connectivity."
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
	// P1 error-origin: this component GENERATED the login-required error.
	setErrorOrigin(w.Header(), groupErrLoginRequired)
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
		"origin":    w.Header().Get(HeaderAikeyErrorOrigin),
	})
	_, _ = w.Write(body)
}

// respondModelTierExhausted is the P1-C Phase 2 guidance response: the
// REQUESTED model's premium weekly window (e.g. Fable's) is exhausted on every
// usable pool account, but the pool itself is healthy for other models. The
// message must say BOTH facts — which budget ran out (with its reset horizon)
// and that switching model unblocks the user right now. Standard
// "rate_limit_error" type so claude/codex render the message verbatim (the same
// display contract the login-required prompt verified); machine consumers get
// the precise signal via error.code + the error-source header.
func (p *Proxy) respondModelTierExhausted(w http.ResponseWriter, logger *slog.Logger,
	route *vkeys.ResolvedRoute, reqModel, tierKey string, until time.Time) {
	resetIn := humanDuration(int64(time.Until(until).Seconds()))
	logger.Warn("group route: requested model's tier window exhausted pool-wide",
		"event.name", observability.EventProxyGroupModelTierCooldown,
		"error.code", observability.ErrCodeModelTierExhausted,
		"oauth_group_id", route.OauthGroupID,
		"model", reqModel,
		"tier", tierKey,
		"reset_in", resetIn,
	)
	w.Header().Set(HeaderAikeyErrorSource, observability.ErrCodeModelTierExhausted)
	writeJSONError(w, http.StatusTooManyRequests, "rate_limit_error", observability.ErrCodeModelTierExhausted,
		"The weekly limit for "+reqModel+" (premium-tier models) is used up on all pool accounts; it resets in about "+resetIn+". "+
			"Other models are still available — switch your model to continue working.")
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
	case observability.ErrCodeAccountEgressProxy, observability.ErrCodeGroupUpstreamUnavailable:
		return http.StatusServiceUnavailable, "server_error"
	default:
		// NO_MATERIAL (channel-③ poll in flight) / group key unavailable (vault
		// reload) → genuinely transient; retrying shortly IS the right action → 503.
		return http.StatusServiceUnavailable, "server_error"
	}
}

// groupUnavailableCooldownCode preserves the reason when every route candidate
// was skipped by durable cooldown state. A precise egress failure wins over a
// generic upstream failure; either wins over the generic all-unusable 429,
// because a mixed pool is not truthfully "all quota exhausted".
func (p *Proxy) groupUnavailableCooldownCode(route *vkeys.ResolvedRoute, skip map[string]bool) string {
	if route == nil || len(skip) == 0 {
		return ""
	}
	ids := groupRouteAccountIDs(route)

	states := p.poolCooldown.routeStateSnapshot()
	hasUpstreamFailure := false
	for id := range ids {
		if !skip[id] {
			continue
		}
		state, ok := states[id]
		if !ok || state.Status != poolRouteUpstreamUnavailable {
			continue
		}
		if state.ErrorCode == observability.ErrCodeAccountEgressProxy {
			return observability.ErrCodeAccountEgressProxy
		}
		hasUpstreamFailure = true
	}
	if hasUpstreamFailure {
		return observability.ErrCodeGroupUpstreamUnavailable
	}
	return ""
}

func groupRouteAccountIDs(route *vkeys.ResolvedRoute) map[string]bool {
	ids := make(map[string]bool)
	if route == nil {
		return ids
	}
	var refs []vkeys.GroupAccountRef
	if json.Unmarshal([]byte(route.GroupAccounts), &refs) == nil {
		for _, ref := range refs {
			if ref.AccountID != "" {
				ids[ref.AccountID] = true
			}
		}
	}
	var material map[string]vkeys.GroupRuntimeAccount
	if json.Unmarshal([]byte(route.GroupRuntime), &material) == nil {
		for id := range material {
			ids[id] = true
		}
	}
	return ids
}

// setGroupCooldownRetryAfter exposes the earliest route-account recovery to the
// client when resolution is blocked by durable cooldown state. It is advisory:
// routing still relies exclusively on the cooldown store and its clock-based
// lazy re-entry, so a missing/malformed route payload never blocks the response.
func (p *Proxy) setGroupCooldownRetryAfter(w http.ResponseWriter, route *vkeys.ResolvedRoute, skip map[string]bool) {
	if route == nil || len(skip) == 0 {
		return
	}
	if seconds, ok := p.poolCooldown.earliestRetryAfterSeconds(groupRouteAccountIDs(route), skip); ok {
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
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
