package mcp

// delegation.go — the delegation boundary evaluator (K1, task 15.3/15.4).
//
// # Where this runs, and why that matters more than it looks
//
// 🔴 IN THE LOCAL PROXY, from the snapshot the policy rail already pulled. It
// makes no network call. Spawning a sub-agent is on the path a developer walks
// every time they ask their Agent to do anything, so one round trip to the
// control plane here is a stall the user feels — and a governance hook that
// makes the tool feel slow gets uninstalled in week one. A gate nobody runs is
// worth less than no gate, because it is also believed in.
//
// The same reasoning is why a lost control plane FAILS OPEN here (D-29): the
// snapshot keeps deciding, and the caller emits a WARN saying it is stale.
// Fence: TestDelegationIsEvaluatedWithoutNetwork (asserted structurally — this
// file imports no HTTP client).
//
// # The subset invariant is a property of the CODE SHAPE, not of a check
//
// R60/I30 requires child ⊆ parent ⊆ seat. This file gets that by INTERSECTING
// the tier with the parent's own toolsets and returning the intersection. There
// is no branch that could widen anything, so the invariant cannot be broken by
// adding a case later — only by rewriting the intersection itself, which is
// what TestChildIsAlwaysASubsetOfParent watches.
//
// 🚫 Do not "optimise" the intersection away when a tier lists exactly what the
// parent has. The intersection IS the invariant.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// DelegationRequest is one spawn attempt, as the gate sees it.
type DelegationRequest struct {
	// AgentType is the harness's sub-agent type ("Explore", "general-purpose",
	// a custom agent's name). Client-asserted; used only to select a tier.
	AgentType string

	// Depth is how deep the CHILD would sit, with the human at 0 and the main
	// agent at 1.
	//
	// 🔴 Computed by US from the runtime chain, 🚫 never read from the client.
	// A client that reports its own depth can report 0 forever and walk past any
	// limit — the same trust rule that keeps app_slug and session_id out of
	// authorisation (R62). Fence: TestDepthComesFromUsNotFromTheClient.
	Depth int
}

// EvaluateDelegation decides one spawn, from a tier list and the parent's own
// toolsets.
//
// It is a pure function: no clock, no I/O, no store. Everything that varies
// lives in the arguments, which is what lets the console's "who would this tier
// affect" preview and the live hook share ONE evaluator (task 15.3). Two
// evaluators would eventually disagree, and the user believes the console.
// Fence: TestConsolePreviewAndHookShareTheEvaluator.
func EvaluateDelegation(pol mcpwire.DelegationPolicy, parentToolsets []string, req DelegationRequest) mcpwire.Decision {
	parent := normalizeSlugs(parentToolsets)

	// 🔴 THREE states, not two, and the first one is what keeps upgrade day
	// boring:
	//
	//	no tiers at all      → the org has not configured delegation. Pass through.
	//	tiers, none matched  → the org HAS an opinion; DefaultAllow decides.
	//	a tier matched       → that tier decides.
	//
	// Folding the first into the second is the D-27 failure mode in one line:
	// DelegationPolicy's zero value has DefaultAllow=false, so an older control
	// plane that does not send the field yet — or an org that simply has not
	// configured anything — would start refusing every spawn in the fleet the
	// moment a proxy upgraded. "Not configured" and "configured to refuse" are
	// different facts and must not share a code path.
	// Fence: TestZeroPolicyAllowsEverything.
	if len(pol.Tiers) == 0 {
		return mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Toolsets: parent}
	}

	tier, matched := matchTier(pol, req.AgentType)
	if !matched {
		if !pol.DefaultAllow {
			return mcpwire.Decision{
				Verdict: mcpwire.VerdictDeny,
				Code:    mcpwire.DelegationDenied,
				Reason:  denyReason("", req.AgentType, pol),
			}
		}
		// 🔴 The unconfigured org. Nothing is narrowed: today's behaviour is
		// preserved exactly, which is the whole of D-27. The value of shipping
		// in this state is that delegation becomes VISIBLE — see the caller's
		// EventDelegationRequested — not that it becomes restricted.
		return mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Toolsets: parent}
	}

	// Depth first: it is the cheaper refusal and it has its own code, because
	// "ask for a wider tier" and "your chain is too deep" are different fixes.
	if tier.MaxDepth != nil && req.Depth > *tier.MaxDepth {
		return mcpwire.Decision{
			Verdict: mcpwire.VerdictDeny,
			Tier:    tier.Name,
			Code:    mcpwire.DelegationDepthExceeded,
			Reason: fmt.Sprintf(
				"AiKey delegation tier %q allows a delegation depth of at most %d, and this spawn would be at depth %d (MCP_DELEGATION_DEPTH_EXCEEDED). Next: ask an administrator to raise the depth on that tier, or have the current agent do this work itself.",
				tier.Name, *tier.MaxDepth, req.Depth),
		}
	}

	// 🔴 nil ToolsetSlugs is "this tier does not narrow", NOT "narrow to
	// nothing". See DelegationTier.ToolsetSlugs — collapsing the two turns an
	// unconfigured tier into a total lockout.
	if tier.ToolsetSlugs == nil {
		return mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Tier: tier.Name, Toolsets: parent}
	}

	child := intersect(parent, normalizeSlugs(tier.ToolsetSlugs))

	switch {
	case len(child) == 0:
		// The tier and the parent share nothing. Spawning a child that can call
		// nothing is worse than refusing: it burns a turn and produces a
		// confusing empty result the developer cannot diagnose.
		return mcpwire.Decision{
			Verdict: mcpwire.VerdictDeny,
			Tier:    tier.Name,
			Code:    mcpwire.DelegationDenied,
			Reason:  denyReason(tier.Name, req.AgentType, pol),
		}
	case len(child) == len(parent):
		return mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Tier: tier.Name, Toolsets: child}
	default:
		return mcpwire.Decision{Verdict: mcpwire.VerdictNarrow, Tier: tier.Name, Toolsets: child}
	}
}

// matchTier returns the FIRST tier whose AgentTypes cover agentType.
//
// 🔴 First match, not most-specific match. Most-specific needs a ranking rule,
// and a ranking rule is one more thing an administrator must simulate in their
// head to predict what their own config does.
func matchTier(pol mcpwire.DelegationPolicy, agentType string) (mcpwire.DelegationTier, bool) {
	for _, t := range pol.Tiers {
		for _, at := range t.AgentTypes {
			if at == "*" || strings.EqualFold(at, agentType) {
				return t, true
			}
		}
	}
	return mcpwire.DelegationTier{}, false
}

// denyReason builds the sentence a developer actually reads.
//
// 🔴 Three obligations, all from R61 / PRD §2.6, all fenced by
// TestDenialReasonNamesAikeyAndTheTier:
//
//  1. Say WHO refused. The harness refuses spawns too — depth, concurrency and
//     budget limits of its own (measured in subagent_stats.refused). A message
//     that does not name AiKey leaves the developer unable to tell which of two
//     completely different fixes applies. This is the D-24 口径 in one string.
//  2. Say WHAT IS allowed, not only what is not.
//  3. Say the NEXT STEP.
func denyReason(tier, agentType string, pol mcpwire.DelegationPolicy) string {
	var b strings.Builder
	b.WriteString("AiKey refused this delegation")
	if tier != "" {
		fmt.Fprintf(&b, " under tier %q", tier)
	}
	fmt.Fprintf(&b, ": spawning a %q sub-agent is not permitted (%s).", agentType, mcpwire.DelegationDenied)

	if allowed := allowedAgentTypes(pol); len(allowed) > 0 {
		fmt.Fprintf(&b, " Allowed here: %s.", strings.Join(allowed, ", "))
	}
	b.WriteString(" Next: ask an administrator to widen the delegation tier in Console → Tool grants, or re-run the task with an allowed agent type.")
	return b.String()
}

func allowedAgentTypes(pol mcpwire.DelegationPolicy) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range pol.Tiers {
		for _, at := range t.AgentTypes {
			if at == "*" || seen[at] {
				continue
			}
			seen[at] = true
			out = append(out, at)
		}
	}
	sort.Strings(out)
	return out
}

// intersect returns the members of a that also appear in b, preserving a's
// order so a refusal message lists toolsets the way the operator wrote them.
func intersect(a, b []string) []string {
	inB := make(map[string]bool, len(b))
	for _, s := range b {
		inB[s] = true
	}
	var out []string
	for _, s := range a {
		if inB[s] {
			out = append(out, s)
		}
	}
	return out
}

func normalizeSlugs(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		n := NormalizeSlug(s)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// ---------------------------------------------------------------------------
// Store-backed entry point
// ---------------------------------------------------------------------------

// GrantedSlugs returns every toolset slug this seat is authorised for.
//
// This is the "parent's own set" the evaluator intersects against, so the seat
// grant stays the outer bound of the whole chain (R60).
func (c *PolicyCatalog) GrantedSlugs(ctx context.Context, orgID, seatID string) []string {
	c.store.mu.RLock()
	idx := c.store.indexed
	c.store.mu.RUnlock()
	if idx == nil {
		return nil
	}
	var out []string
	for slug, ts := range idx.toolsetBySlug {
		if ts.Status == StatusDisabled {
			continue
		}
		if c.isGranted(ctx, idx, orgID, seatID, ts.ID) {
			out = append(out, slug)
		}
	}
	sort.Strings(out)
	return out
}

// DelegationGate answers spawn requests from the live snapshot.
type DelegationGate struct {
	store   *PolicyStore
	catalog *PolicyCatalog
}

// NewDelegationGate wires the gate to the snapshot the policy rail maintains.
func NewDelegationGate(store *PolicyStore, catalog *PolicyCatalog) *DelegationGate {
	return &DelegationGate{store: store, catalog: catalog}
}

// Decide evaluates one spawn for one seat.
//
// 🔴 D-29 — the fail-open, ratified explicitly on 2026-09-03 rather than
// arrived at by default:
//
//   - never polled → ALLOW, Stale=true. A machine that has not yet reached the
//     control plane must behave exactly as it did before the gate existed.
//     Refusing here would make a first run after install look like the tool is
//     broken.
//   - polled before, cannot refresh now → decide from the last known snapshot,
//     Stale=true. Same keep-last-known contract the quota rail already has.
//
// In both cases Stale=true, and the caller MUST emit mcpwire.EventPolicyStale.
// 🚫 A silent fail-open is the failure mode this whole design exists to avoid:
// it is indistinguishable, from the outside, from a gate that is working.
// Fences: TestNeverPolledAllowsAndFlagsStale, TestStalePolicyStillDecides.
func (g *DelegationGate) Decide(ctx context.Context, orgID, seatID string, req DelegationRequest) mcpwire.Decision {
	if !g.store.Synced() {
		return mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Stale: true}
	}
	snap := g.store.Snapshot()
	if snap == nil {
		return mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Stale: true}
	}
	d := EvaluateDelegation(snap.Delegation, g.catalog.GrantedSlugs(ctx, orgID, seatID), req)
	// A snapshot older than the rail's own staleness bound still decides — it
	// is simply marked, so the WARN fires and /health/mcp can show the age.
	// 🔴 StalerThan, 🚫 NOT `AgeSeconds() > n`. A store restored from the disk
	// cache is synced but never-polled, and AgeSeconds() reports the sentinel
	// -1 there — the raw comparison reads that as FRESH and the D-29 WARN never
	// fires. See PolicyStore.StalerThan.
	d.Stale = g.store.StalerThan(delegationStaleAfterSeconds)
	return d
}

// delegationStaleAfterSeconds is two poll intervals. One missed poll is a
// network blip and not worth a WARN; two means the rail is actually down.
const delegationStaleAfterSeconds = 120
