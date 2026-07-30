package proxy

// chain_app.go — the App pipeline's candidate chain (openspec change
// `aliyun-aigw-p0-upstream-fallback`, task 2.0b / decision F-19 · D-5).
//
// # 🔴 The decision this file implements
//
// F-19 asked whether the App pipeline gets upstream failover, and flagged that
// the App pipeline "走 app 作用域的钉选、不完全等同 VK 链" — app-scoped pinning is
// not identical to a virtual-key chain — so the App line owner had to confirm
// rather than the change author picking a side.
//
// Confirmed 2026-07-30: **yes, and it needs no App-specific failover rule.**
//
// The reason the concern dissolves is that the App pipeline's "app-scoped pin"
// IS a row in `user_profile_provider_bindings` — the same table `aikey use`
// writes, just at `profile_id = 'app:<slug>'` instead of `'default'`
// (apppipe.Resolve picks the profile; vault.GetProviderBindingWithScope reads
// it). That table already carries `route_group_id` (task 1.2b), so the
// three-state derivation frozen in 0b.8c —
//
//	route_group_id empty              → legacy row, pre-upgrade behavior
//	route_group_id set, provider empty → pinned to the GROUP  (failover applies)
//	route_group_id set, provider set   → pinned to one MEMBER (failover does not)
//
// — applies to an app's row verbatim. So the App surface gets the SAME rule as
// the CLI, evaluated against its OWN pin row. That is one rule at two call
// sites, not a third behavior invented for a third surface.
//
// 🚫 What was rejected: leaving the App pipeline single-shot. An App-routed team
// VK with a route group configured would show 「配了但没生效」 on the App surface —
// the exact disease this change exists to treat — and it would do so on a
// correctly configured path, which is the expensive kind of wrong.
//
// 🚫 Also rejected: hooking the loop unconditionally, ignoring the app's pin
// row. That would let failover override an explicit pin on one surface while
// honouring it on the other, and D-1③/F-16④ already decided that an explicit
// pin means "only this one, and say so out loud".
//
// # 🔴 Why the hop overlay exists instead of walking the team route directly
//
// The registry's candidate routes describe a team virtual key. An App request's
// ResolvedRoute additionally carries state that only the App pipeline builds:
// the synthetic `app:<slug>` virtual-key id that App attribution is keyed on,
// the plugin observer context, the response-transform closure armed by protocol
// translation, and AppSlug / AppKeyID / ProtocolFamily.
//
// Handing the registry's routes to the chain walker directly would drop all of
// it — the App's usage events would start attributing to the team VK, and the
// translated response would stop being un-translated on the way back. Both
// failures produce a 200. So each hop is the APP's route with only the
// per-upstream fields replaced.
//
// 🔴 `VirtualKeyID` deliberately stays `app:<slug>`. This change adds a retry
// loop; it does not renegotiate App attribution. Two consequences worth naming
// because they look like bugs otherwise:
//
//   - stickiness / switch-back (2.19) is keyed per APP, so an app and its user's
//     CLI keep independent idle-gap state. That is the behavior 2.22 argues for
//     — a long conversation lives inside ONE client, and that is what must not
//     have its upstream swapped mid-way.
//   - cooldown (2.15) is keyed by `binding_id` and therefore SHARED across every
//     surface on the machine. That is also right: a cooldown records "this
//     machine cannot reach that upstream", which is not app-specific.
//
// # 🔴 Consent is not widened by failing over
//
// An app declares `upstreams[]` and cannot use an undeclared one without
// re-consent (`UPSTREAM_NOT_DECLARED`). That check is on the CLIENT-ROUTE axis —
// it is derived from `body.model` — and every hop of a chain shares one
// protocol by construction (the group key is `(virtual_key, protocol)`), so no
// hop can move the request onto an upstream the app did not declare. What DOES
// vary per hop is the physical vendor, which is exactly what the administrator
// configured the chain to do, and is no different from the direct-connect path.
// 🚫 Do not "helpfully" re-run the declared-upstream check per hop: it would
// compare a provider code against a list of client routes and reject every
// chain.

import (
	"log/slog"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// appChainSourceTypes names the binding sources that have a chain at all.
//
// 🔴 Only a team / managed virtual key does. The other sources the App pipeline
// can resolve have no chain by construction, and the 2.0b entry table already
// says so for their direct-connect equivalents:
//
//	personal alias / local key   → 没有链 (Personal's natural state)
//	personal_oauth_account       → the ACCOUNT axis owns failover here, and it
//	                               already has it; wrapping a second loop around
//	                               it is the multiplicative nesting 2.1 forbids
//
// Returning "no chain" for those is not a gap — it routes them down the
// byte-identical single-shot path they use today.
var appChainSourceTypes = map[string]bool{
	"team":                true,
	"managed_virtual_key": true,
}

// appChain builds the ordered candidate sequence for one App-pipeline request,
// or nil when this request has no chain and must keep single-shot behavior.
//
// appRoute is the fully built App ResolvedRoute (the one that would have gone
// straight to serveRoute); appBinding is the app-scoped pin row that produced
// it; protocolType is the upstream protocol already resolved for the request.
//
// 🔴 Returns nil rather than an error for "no chain". A missing chain is the
// normal resting state for most installations, and turning it into an error
// would make the App pipeline fail for everyone who never configured failover.
func (p *Proxy) appChain(
	appRoute *vkeys.ResolvedRoute,
	appBinding *vault.ProviderBinding,
	protocolType string,
	logger *slog.Logger,
) *candidateChain {
	if appRoute == nil || appBinding == nil || p.registry == nil {
		return nil
	}
	if !appChainSourceTypes[appBinding.KeySourceType] {
		return nil
	}
	if appBinding.KeySourceRef == "" {
		return nil
	}
	// The app's binding points at the team virtual key by id; the registry is
	// keyed by the bearer token built from that id.
	//
	// 🔴 Plain concat, matching the sibling lookup in pipelines.go (the
	// follow-active group-VK branch) which resolves the SAME input the same way.
	// 🚫 Do not import supervisor.NormalizeTeamToken for this: supervisor imports
	// proxy, so the reference is an import cycle — the reason is already written
	// down at the receipt-token site in pipelines.go. 🚫 And do not hand-roll a
	// third prefix normalizer in this package either; that is the second source
	// of truth the shared helper exists to prevent.
	//
	// If a vault row somehow carries historical prefix residue, Resolve misses
	// and we return nil → the request is served single-shot, exactly as it is
	// today. Degrading to current behavior is the correct failure here.
	teamRoute := p.registry.Resolve("aikey_team_" + appBinding.KeySourceRef)
	if teamRoute == nil {
		// The app references a virtual key the registry does not have. Nothing to
		// walk — hop 1 is already resolved and will be served single-shot, which
		// surfaces the real problem (a stale app binding) at the upstream rather
		// than as a chain error the operator cannot act on.
		return nil
	}

	chain, chainErr := p.chainFrom(teamRoute, appBinding, protocolType, logger)
	if chainErr != nil || chain == nil || len(chain.candidates) == 0 {
		// 🔴 A selection error (today: two members at the same priority) is NOT
		// promoted to a client error here. The direct-connect entries answer that
		// with 409 PROVIDER_ROUTE_AMBIGUOUS because selection is their only way to
		// get a route; the App pipeline has ALREADY resolved a usable hop, so
		// refusing to serve it would turn a data-consistency warning into an
		// outage. chainFrom has already logged the inconsistency.
		if chainErr != nil && logger != nil {
			logger.Warn("app pipeline: upstream chain could not be ordered; serving the resolved hop single-shot",
				"app_slug", appRoute.AppSlug,
				"virtual_key_id", appBinding.KeySourceRef,
				"error.message", chainErr.Error(),
			)
		}
		return nil
	}

	overlaid := make([]*vkeys.ResolvedRoute, 0, len(chain.candidates))
	for _, cand := range chain.candidates {
		hop := *appRoute
		applyHopToAppRoute(&hop, cand)
		overlaid = append(overlaid, &hop)
	}
	chain.candidates = overlaid
	return chain
}

// applyHopToAppRoute replaces the per-upstream fields of an App route with one
// candidate binding's, leaving every app-scoped field intact.
//
// 🔴 The field list is explicit on purpose. A struct copy or a
// `*dst = *src`-style assignment would silently take the team route's whole
// shape, dropping the observer context and the response transform — and the
// request would still return 200, so no test that only checks status codes
// would notice.
func applyHopToAppRoute(dst, hop *vkeys.ResolvedRoute) {
	// Identity of the upstream for this hop.
	dst.Provider = hop.Provider
	dst.ProviderCode = hop.ProviderCode
	dst.ProtocolType = hop.ProtocolType
	dst.BaseURL = hop.BaseURL

	// Credential for this hop. 🔴 Each binding row carries its own decrypted key
	// and its own address (2.3 / I5) — 🚫 never reuse hop 1's key against hop 2's
	// address, and 🚫 never fall back to the provider's default address when the
	// row has one, or the administrator's gateway is quietly bypassed.
	dst.PlaintextKey = hop.PlaintextKey
	dst.KeyAlias = hop.KeyAlias
	dst.CredentialID = hop.CredentialID
	dst.CredentialRevision = hop.CredentialRevision
	dst.VirtualKeyRevision = hop.VirtualKeyRevision
	dst.BindingID = hop.BindingID

	// Chain position, so attribution and the response header describe THIS hop.
	dst.Priority = hop.Priority
	dst.FallbackRole = hop.FallbackRole
	dst.RouteGroupID = hop.RouteGroupID
	dst.RouteGroupName = hop.RouteGroupName

	// Cost attribution follows the hop that actually served (F-3): the org and
	// seat that own the credential being spent, not the ones on hop 1.
	if hop.OrgID != "" {
		dst.OrgID = hop.OrgID
	}
	if hop.SeatID != "" {
		dst.SeatID = hop.SeatID
	}

	// 🚫 NOT copied, and each omission is load-bearing:
	//   VirtualKeyID     — stays `app:<slug>`; App attribution is unchanged.
	//   RouteSource      — stays "app".
	//   AppSlug/AppKind/AppKeyID/FollowUserActive — identify the app.
	//   ObserverContext / ObserverRegistry        — the plugin fan-out.
	//   ProtocolFamily   — resolved by the App pipeline from the path-aware
	//                      base_url row; the team route's copy is not
	//                      app-aware.
}
