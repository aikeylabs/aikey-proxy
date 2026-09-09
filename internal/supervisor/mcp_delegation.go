package supervisor

// mcp_delegation.go — the node's answer to "may this agent spawn that one?"
// (P15 · task 15.7, the proxy half of the hook path).
//
// # Why the decision lives here and not in the CLI
//
// The hook that Claude Code invokes is a SHELL: it decodes the harness event,
// asks this process, and encodes the answer back. It holds no policy of its own.
// That split is the repo's `internal-command-reuses-public-core` rule applied to
// a hook — the alternative, a second copy of the tier rules written in Rust,
// gives two implementations that drift and a user who cannot tell which one
// refused them.
//
// # Why a loopback admin route rather than an authenticated API
//
// Same posture as /admin/mcp/local-manifest, which already answers "what are
// this node's tools" with no credential: the caller is the developer's own CLI,
// on the developer's own machine, asking about the developer's own seat. Adding
// a token here would put a password on the path a developer walks every time
// their agent delegates — and the interaction-simplicity rule is explicit that
// wrapper-shaped entry points must be zero-password.
//
// 🔴 It answers only for THIS NODE'S identity. There is no org/seat parameter,
// on purpose: a parameter would make it a lookup service for other people's
// policy, reachable by anything that can open a loopback socket.

import (
	"context"
	"os"

	"github.com/AiKeyLabs/aikey-proxy/internal/mcp"
	"github.com/AiKeyLabs/pkg/mcpwire"
)

// MCPDelegationIdentity returns the (org, seat) this node acts as.
//
// 🔴 Read from the SAME source mcpPolicyTarget uses — the active generation's
// managed keys — so "which org is this node in" keeps exactly one answer. A
// second resolution path is how a node comes to enforce one org's tiers while
// reporting another's.
//
// Both empty on a node with no vault or no managed key. The caller treats that
// as "cannot identify" and fails OPEN (D-29): a developer whose vault is locked
// must not lose the ability to delegate.
func (s *Supervisor) MCPDelegationIdentity() (orgID, seatID string) {
	gen := s.active.Load()
	if gen == nil || gen.vault == nil {
		return "", ""
	}
	mks, _ := gen.vault.GetActiveManagedKeys()
	orgID = resolveTeamOrgIDFromKeys(os.Getenv("AIKEY_HUB_ORG_ID"), mks)
	for _, mk := range mks {
		if mk.SeatID != "" {
			seatID = mk.SeatID
			break
		}
	}
	return orgID, seatID
}

// NoteMCPGuardSeen records that the delegation hook reached this gateway.
//
// 🔴 Called from the HTTP handler, before the body is parsed — a malformed
// request still proves the hook is installed and talking to us, and that is the
// only thing this flag claims. Parsing success is a different question, already
// answered by the decision itself.
func (s *Supervisor) NoteMCPGuardSeen() { s.mcpGuardSeen.Store(true) }

// MCPGuardActivity reports what this node knows about its own gate.
//
// 🔴 Two values here, three on the wire: a proxy too old to have this method
// sends no parameter at all, and the control plane keeps that apart from Idle.
// See mcpwire.GuardActivity for why those must not be folded together.
func (s *Supervisor) MCPGuardActivity() mcpwire.GuardActivity {
	if s.mcpGuardSeen.Load() {
		return mcpwire.GuardActive
	}
	return mcpwire.GuardIdle
}

// MCPDelegationDecision evaluates one spawn request for this node.
//
// 🔴 THREE fail-open paths, all deliberate and all flagged Stale so the caller
// emits the WARN (D-29, ratified 2026-09-03 rather than arrived at by default):
//
//   - no policy store at all (this machine has no mcp.json and no control plane)
//   - no resolvable identity (vault locked, no managed key yet)
//   - a store that has never been polled, or is stale (handled inside the gate)
//
// Every one of them is a state a developer can be in through no fault of their
// own, mid-task. Refusing there would make the governance hook look like
// breakage, and its first casualty would be the hook itself: an uninstalled gate
// leaves the organisation with no control AND no signal that it lost one.
//
// 🚫 Do not "tighten" any of these into a refusal without re-opening D-29.
// Fence: TestDelegationDecisionFailsOpenOnEveryMissingPiece.
// 🔴 It returns the (org, seat) it DECIDED WITH, not just the verdict.
//
// The caller logs them, and the alternative — the caller asking
// MCPDelegationIdentity() a second time — would resolve the vault generation
// twice. Two resolutions can disagree across a reload, and a record naming a
// seat that is not the seat the rules were applied for is precisely the
// confidently-wrong answer the executor-attribution fences exist to prevent.
// One resolution, one answer, both reported together.
//
// 🚫 The identity does NOT go on mcpwire.Decision: that struct is the reply the
// hook receives, and a seat id has no business travelling to a harness that
// already knows whose machine it is running on.
func (s *Supervisor) MCPDelegationDecision(agentType string, depth int) (mcpwire.Decision, string, string) {
	store := s.MCPPolicyStore()
	if store == nil {
		return mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Stale: true}, "", ""
	}
	orgID, seatID := s.MCPDelegationIdentity()
	if orgID == "" || seatID == "" {
		// 🔴 Empty, and the caller logs it as empty. "We could not identify this
		// node" is a finding an operator can act on; inventing a placeholder
		// would hide the one case where the gate is passing everything through.
		return mcpwire.Decision{Verdict: mcpwire.VerdictAllow, Stale: true}, orgID, seatID
	}
	// 🔴 seatGroups is nil here for the same reason it is nil in the serving
	// catalog (app.go): a missing group resolver can only FAIL to grant, never
	// grant something extra. Passing nil is the safe direction.
	gate := mcp.NewDelegationGate(store, mcp.NewPolicyCatalog(store, nil))
	return gate.Decide(context.Background(), orgID, seatID,
		mcp.DelegationRequest{AgentType: agentType, Depth: depth}), orgID, seatID
}
