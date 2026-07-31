package proxy

// candidate_chain.go — the ordered set of upstreams one request may try
// (openspec change `aliyun-aigw-p0-upstream-fallback`, tasks 2.0 / 2.26 / 2.27b /
// 2.27c / 2.28).
//
// # 🔴 Why this file replaces "unique binding, otherwise 409"
//
// `selectTokenBinding` used to demand that exactly ONE binding match the
// requested protocol and return `PROVIDER_ROUTE_AMBIGUOUS` otherwise. But "more
// than one binding under the same (virtual key, protocol)" is the literal
// definition of a primary/fallback chain — so the control plane has been letting
// administrators configure chains that the data plane answers with 409.
//
// That failure lands on a CORRECTLY configured path, which is what makes it
// expensive: the first thing anyone does with a 409 saying "ambiguous" is go back
// and re-check the configuration that was right all along.
//
// So multiple bindings are now a legal, ordered candidate sequence.
// `PROVIDER_ROUTE_AMBIGUOUS` is kept but NARROWED to the case that really cannot
// be ordered — two members sharing a priority. 🚫 It is not deleted: an older
// client may be switching on the code.
//
// # 🔴 Three empty-ish states that must stay distinguishable (2.0)
//
//	no bindings at all      → single-shot, byte-identical to pre-upgrade behavior.
//	                          This is Personal's natural resting state.
//	a chain with ONE member → an administrator built a chain and very likely
//	                          believes it is redundant. Its failure is
//	                          UPSTREAM_FALLBACK_UNCONFIGURED, which points at the
//	                          thing they need to change.
//	a chain with N members  → real failover.
//
// Collapsing the first two into one answer would send half of the people who hit
// it in the wrong direction, which is exactly the split §1 of the contract freeze
// spends three paragraphs protecting.
//
// # 🔴 Same virtual key only (2.26 / I15)
//
// Candidates are drawn from ONE ResolvedRoute's `Bindings`, which the registry
// groups per bearer token. Crossing virtual keys would break two things at once —
// the call is billed to somebody else, and the user reaches a channel they were
// never granted — and it would do so on a request that SUCCEEDS, so nobody would
// report it. The fence in candidate_chain_test.go exists because "it is true
// today by construction" is not the same as "it will stay true".

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// candidateChain is one request's ordered try-list.
type candidateChain struct {
	// candidates in the administrator's configured order (priority ascending).
	// Never empty when err is nil.
	candidates []*vkeys.ResolvedRoute
	// pinned is true when `aikey use` fixed routing to a single hop. 🔴 Failover
	// is DISABLED in that state by decision D-1③/F-16④, and the CLI is required
	// to say so at the moment the user pins — a pin that silently removes
	// failover is the trap that decision exists to close.
	pinned bool
	// grouped reports whether these bindings came from a route group at all.
	// false = a legacy row with no group, which keeps single-shot behavior even
	// if it somehow has siblings.
	grouped   bool
	groupID   string
	groupName string
}

// primary is the first candidate — the route every existing single-shot caller
// consumes. Never nil for a chain built without error.
func (c *candidateChain) primary() *vkeys.ResolvedRoute { return c.candidates[0] }

// canFailover reports whether this request may try a second upstream.
func (c *candidateChain) canFailover() bool { return !c.pinned && len(c.candidates) > 1 }

// exhaustedCode names the terminal error for a chain whose candidates all failed.
//
// 🔴 The one-member case is NOT "we ran out of candidates" — there was never more
// than one. `UNCONFIGURED` is a PERMANENT state whose text must never suggest
// retrying: retrying cannot succeed until an administrator adds a second upstream,
// so telling the user to retry both wastes their time and hides the only action
// that would work.
func (c *candidateChain) exhaustedCode() string {
	if c.grouped && len(c.candidates) == 1 {
		return observability.ErrCodeUpstreamFallbackUnconfigured
	}
	return observability.ErrCodeUpstreamFallbackExhausted
}

// selectTokenChain resolves a managed token into the ordered candidate sequence.
//
// It supersedes selectTokenBinding, which returned "the one binding" and errored
// on anything else. Callers that only want the primary keep working by taking
// chain.primary().
//
// The pin it honors is the one in the DEFAULT profile — the row `aikey use`
// writes. Entries serving a NON-default profile (the App pipeline, whose profile
// is `app:<slug>`) must not read this row, so they resolve their own and call
// chainFrom directly. See chain_app.go.
func (p *Proxy) selectTokenChain(route *vkeys.ResolvedRoute, clientRoute, requestedProtocol string, logger *slog.Logger) (*candidateChain, error) {
	var pin *vault.ProviderBinding
	if p.activeReader != nil && clientRoute != "" {
		if binding, err := p.activeReader.GetProviderBinding(clientRoute); err == nil {
			pin = binding
		}
	}
	return p.chainFrom(route, pin, requestedProtocol, logger)
}

// chainFrom is the ONE chain-selection implementation. `pin` is the local
// pin row that applies to this request's profile, or nil when the caller's
// profile has none.
//
// 🔴 Why the pin arrives as a parameter instead of being looked up in here: the
// App pipeline routes under profile `app:<slug>`, and reading the default
// profile's row for it would apply one user's `aikey use` decision to every app
// on the machine. Making the caller supply its own pin row keeps a SINGLE
// selection engine — 🚫 the alternative (a second, app-flavored copy of this
// function) is how the two would come to disagree about what a pin means, and
// the disagreement would surface as "failover works on one surface and not the
// other" with nothing in the logs to explain it.
func (p *Proxy) chainFrom(route *vkeys.ResolvedRoute, pin *vault.ProviderBinding, requestedProtocol string, logger *slog.Logger) (*candidateChain, error) {
	if route == nil {
		return nil, fmt.Errorf("no route")
	}
	// No sibling bindings: single-shot, exactly as before. `grouped` follows the
	// route's own group id so a one-member group is still recognized as a chain
	// the administrator built.
	if len(route.Bindings) == 0 {
		return &candidateChain{
			candidates: []*vkeys.ResolvedRoute{route},
			grouped:    route.RouteGroupID != "",
			groupID:    route.RouteGroupID,
			groupName:  route.RouteGroupName,
		}, nil
	}

	// ── The local pin (`aikey use`) ────────────────────────────────────────
	//
	// 🔴 Pinning does NOT reorder the chain. Letting a developer's local action
	// promote a vendor to the front would let the data plane rewrite an order the
	// administrator set in the control plane — breaking control-plane authority
	// (I8) and creating a second source of truth for ordering (I7) at the same
	// time. A pin either restricts the chain to one hop or it does nothing to the
	// order.
	if pin != nil &&
		(pin.KeySourceType == "team" || pin.KeySourceType == "managed_virtual_key") &&
		pin.KeySourceRef == route.VirtualKeyID {
		binding := pin

		switch DerivePinScope(binding.RouteGroupID, binding.ProviderCode) {
		case PinScopeMember:
			for _, candidate := range route.Bindings {
				if strings.EqualFold(candidate.ProviderCode, binding.ProviderCode) &&
					(binding.ProtocolType == "" || strings.EqualFold(candidate.ProtocolType, binding.ProtocolType)) {
					pick := *candidate
					return &candidateChain{
						candidates: []*vkeys.ResolvedRoute{&pick},
						pinned:     true,
						grouped:    candidate.RouteGroupID != "",
						groupID:    candidate.RouteGroupID,
						groupName:  candidate.RouteGroupName,
					}, nil
				}
			}
			// 🔴 The pinned hop is no longer in the group (0b.8c). Fall back to
			// pinning the GROUP and say so. The two outcomes forbidden here are
			// "the pin silently evaporates" and "we keep routing at an upstream
			// the administrator already removed"; both leave the user with a
			// belief about their traffic that is no longer true.
			if logger != nil {
				logger.Warn("pinned upstream is no longer in the route group; falling back to the whole chain",
					"event.name", observability.EventProxyRouteFallback,
					"virtual_key_id", route.VirtualKeyID,
					"pinned_provider", binding.ProviderCode,
					"route_group_id", binding.RouteGroupID,
				)
			}
		case PinScopeLegacy:
			// 🔴 A row written by `aikey use` BEFORE route groups existed, and this
			// branch is the one most likely to be got wrong.
			//
			// The literal reading of the three-state table — "no group id, so treat
			// it as a pin to that exact binding" — would suppress failover for
			// every developer who has ever run `aikey use`, which is very nearly
			// all of them. The administrator's chain would be configured, visible
			// in the console, and inert. That is the precise 「配了但没生效」 failure
			// this whole change exists to remove, reintroduced by the upgrade
			// itself.
			//
			// What the user actually expressed, at a time when chains did not
			// exist, was "serve this client route from THIS KEY" — not "only ever
			// use this one vendor". So:
			//
			//	the matched binding belongs to a group → pin the GROUP (fall
			//	  through; the chain below applies, and the administrator's
			//	  fallback works).
			//	it belongs to no group               → keep the exact binding,
			//	  single shot. Byte-identical to before, and there is no chain to
			//	  fail over to anyway.
			//
			// 🔴 Restricting to ONE vendor stays reserved for an explicit
			// `aikey use --only`, which is required to print the consequence at
			// the moment it happens (D-1③ / F-16④).
			for _, candidate := range route.Bindings {
				if strings.EqualFold(candidate.ProviderCode, binding.ProviderCode) &&
					(binding.ProtocolType == "" || strings.EqualFold(candidate.ProtocolType, binding.ProtocolType)) {
					if candidate.RouteGroupID != "" {
						break // grouped → the whole chain applies
					}
					pick := *candidate
					return &candidateChain{
						candidates: []*vkeys.ResolvedRoute{&pick},
						pinned:     true,
					}, nil
				}
			}
		case PinScopeGroup:
			// The default. Nothing to restrict — the whole chain below applies.
		}
	}

	// ── The chain ──────────────────────────────────────────────────────────
	var candidates []*vkeys.ResolvedRoute
	for _, candidate := range route.Bindings {
		if requestedProtocol == "" || strings.EqualFold(candidate.ProtocolType, requestedProtocol) {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("managed token has no binding for protocol %q", requestedProtocol)
	}

	// 🔴 The NARROWED ambiguity (2.27b). Two members at the same priority cannot
	// be ordered, so there is no chain to walk — that, and only that, is what
	// PROVIDER_ROUTE_AMBIGUOUS now means.
	//
	// It should be unreachable from the control plane: `UNIQUE(route_group_id,
	// priority) WHERE active` makes duplicate priorities unsavable. Meeting one at
	// runtime therefore means the DATA is inconsistent — a stale vault, or a
	// half-applied migration — so it is logged as such. 🚫 Do not blame the user
	// for a configuration they were never able to write.
	if dup, ambiguous := duplicatePriority(candidates); ambiguous {
		if logger != nil {
			logger.Warn("route group has two members at the same priority — the chain cannot be ordered",
				"event.name", observability.EventProxyRouteFallback,
				"error.code", "PROVIDER_ROUTE_AMBIGUOUS",
				"virtual_key_id", route.VirtualKeyID,
				"protocol_type", requestedProtocol,
				"priority", dup,
				"route_group_id", candidates[0].RouteGroupID,
			)
		}
		return nil, fmt.Errorf(
			"this key's upstream chain has two entries at position %d, so the order is undefined. "+
				"Ask an administrator to re-save the route group's order in the console; "+
				"the local vault copy may also be out of date (run `aikey key sync`)", dup)
	}

	// 🔴 Sort HERE as well as in the registry builder. This is the point where a
	// candidate SEQUENCE is defined, so it must not depend on an upstream caller
	// having ordered the slice correctly — a second producer of `Bindings` would
	// otherwise silently serve the administrator's fallback as the primary, and
	// the request would SUCCEED, so nothing would report it. Sorting an
	// already-sorted slice costs nothing.
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Priority < candidates[j].Priority
	})
	ordered := make([]*vkeys.ResolvedRoute, 0, len(candidates))
	for _, c := range candidates {
		pick := *c
		ordered = append(ordered, &pick)
	}
	return &candidateChain{
		candidates: ordered,
		grouped:    ordered[0].RouteGroupID != "",
		groupID:    ordered[0].RouteGroupID,
		groupName:  ordered[0].RouteGroupName,
	}, nil
}

// duplicatePriority returns the first priority shared by two candidates.
//
// 🔴 Two results, not a sentinel. Returning "0 means none" would be wrong for the
// one value most likely to appear by accident: a route built in code without an
// explicit Priority carries 0, and a pair of those is exactly the ambiguity this
// is meant to catch.
//
// Only meaningful for a real chain: a set of ONE can never be ambiguous, and
// legacy rows all carry priority 1 by construction (the vault reader defaults an
// absent column to 1, never 0), so a pre-upgrade multi-protocol token would look
// "ambiguous" if we compared it blindly. Candidates here are already filtered to a
// single protocol, which is what makes the comparison meaningful.
func duplicatePriority(candidates []*vkeys.ResolvedRoute) (int64, bool) {
	if len(candidates) < 2 {
		return 0, false
	}
	seen := make(map[int64]bool, len(candidates))
	for _, c := range candidates {
		if seen[c.Priority] {
			return c.Priority, true
		}
		seen[c.Priority] = true
	}
	return 0, false
}

// hopKey is the identity cooldown and stickiness track a hop by.
//
// 🔴 It exists because `ResolvedRoute.BindingID` is EMPTY on every chain built
// from the local vault cache — the field's own comment says so ("empty if not
// available in local cache (schema gap)"), and nothing in this repo ever
// populates it. That turned F-6 cooldown and F-7 switch-back into silent no-ops:
// `note("")` recorded one entry under the empty key and `cooling("")` then
// reported EVERY candidate as cooling, which bands them all equally and leaves
// the original order untouched. A dead primary was therefore re-dialed on every
// request, on staging, ~56s after failing — well inside the 5-minute builtin
// cooldown.
//
// 🚫 Not fixed by keying on credential_id alone: one credential can back hops in
// several virtual keys, so cooling it would pull an upstream out of OTHER
// people's chains because of a failure in this one. The blast radius of a
// cooldown is one binding, and (virtual key, credential) reproduces exactly that
// without needing a column the vault does not have yet.
//
// The real binding id still belongs here when it arrives — carrying it through
// the delivery wire into the cache is the proper fix, and it is what the event's
// from_binding_id/to_binding_id fields (still empty, I4) are waiting on. This
// keeps the RUNTIME correct meanwhile; it deliberately does not fake the
// reported identity, because an invented binding id in the ledger would be worse
// than an absent one.
func hopKey(r *vkeys.ResolvedRoute) string {
	if r == nil {
		return ""
	}
	if r.BindingID != "" {
		return r.BindingID
	}
	if r.CredentialID == "" && r.VirtualKeyID == "" {
		// Nothing stable to key on. Return empty and let the caller treat it as
		// "unknown identity" rather than inventing one that would collide.
		return ""
	}
	return r.VirtualKeyID + "|" + r.CredentialID
}
