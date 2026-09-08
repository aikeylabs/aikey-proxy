package mcp

// instance.go — which upstream instance one call goes to (task 6.4).
//
// # The problem
//
// A service registry advertises a service as N addresses. Until alpha.12 the
// control plane collapsed that list to one before it reached the database, so
// the fleet only ever had a single address per backend and R5 — session
// stickiness — described a choice that was never made: there was nothing to be
// sticky to. The list now travels on the policy rail as PolicyBackend.Instances,
// and this file is the one place that picks from it.
//
// # 🔴 Stickiness first, allocation second — and never reassignment
//
// Requirement R5 (workflow/CI/requirements/2026-08-20-mcp-gateway.md):
//
//	持有 Mcp-Session-Id 的请求必须回到同一后端实例。
//	实例不健康时：让会话失败并给出明确错误，不许静默改派。
//	无会话的调用才走分配。
//
// MCP is a STATEFUL protocol. An upstream that minted state during initialize
// holds that state on ONE instance; moving a live session to a sibling gets the
// client "session not found" from a server it never talked to, which is close to
// the most expensive error we could produce — the developer investigates their
// own client, then the tool, and the address only comes up last.
//
// Fences: 6.F4 is the DECLARED fence for this task — a session keeps its
// instance (TestFence_6F4_*: pinned across calls · a retired pin fails and stays
// pinned · an empty list behaves exactly as before alpha.12 · sessionless calls
// spread). 6.F7 is the security half: a credential-bound backend never fans out
// (TestFence_6F7_*, one half here and two in the control plane).
//
// So a pinned instance that leaves the advertised set FAILS the call. It does
// not silently re-allocate, and it does not drop the pin so that the next call
// re-allocates either — that would be the same reassignment arriving one call
// later. The pin dies with the session, and the client's remedy is to
// initialize again, which the error says.

import (
	"sync/atomic"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// instanceCursor spreads sessionless calls across a backend's instances.
//
// 🔴 One counter for the whole process, not one per backend. Per-backend state
// would have to be created, found and eventually reaped — a lifecycle — to buy
// a fairer spread over a list that is usually two or three long and whose
// callers are one developer's laptop. A single counter has none of that and is
// still uniform over any one backend's list.
//
// 🔴 This is NOT load balancing, and it must not grow into it. R5 explicitly
// overruled weighted / least-connection balancing: those are stateless
// assumptions applied to a stateful protocol. This exists only so that calls
// arriving with no session at all do not all land on instances[0].
var instanceCursor atomic.Uint64

// selectInstance returns the address this call must be sent to.
//
// sessionID is empty when the request carries no Mcp-Session-Id — legal, and the
// only case in which allocation happens at all.
//
// The returned *UpstreamError is non-nil only for the R5 refusal.
func selectInstance(sessions *SessionStore, sessionID string, b PolicyBackend) (string, *UpstreamError) {
	candidates := instanceCandidates(b)
	if len(candidates) < 2 {
		// One address (or none, for stdio). Nothing to choose, nothing to pin:
		// behaviour is byte-identical to every release before alpha.12, which is
		// what makes this feature safe to ship dark for every customer who does
		// not run a service registry.
		return b.EndpointURL, nil
	}
	if sessions == nil || sessionID == "" {
		return candidates[instanceCursor.Add(1)%uint64(len(candidates))], nil
	}

	if pinned, ok := sessions.StickyInstance(sessionID, b.ID); ok {
		if containsString(candidates, pinned) {
			return pinned, nil
		}
		// 🔴 R5's refusal. The message names the remedy, because the client
		// cannot deduce it: nothing about "backend unavailable" says "your
		// session is the part that is stale".
		return "", &UpstreamError{
			Code: mcpwire.ErrBackendUnavailable,
			Detail: "The instance of backend \"" + b.Name + "\" that this session was started on is " +
				"no longer available. MCP sessions hold state on one instance, so this session " +
				"cannot be moved to another. Run initialize again to start a new session.",
			// 🔴 NotAccepted: the request never left this process, so the tool
			// certainly did not run. Saying so is what lets a client retry a
			// non-idempotent call safely after re-initializing (R4).
			NotAccepted: true,
		}
	}

	// First call of this session against this backend: allocate, then pin.
	// PinInstance returns the pin in force, which under a concurrent first call
	// may be the other goroutine's choice — we follow it rather than compete.
	chosen := candidates[instanceCursor.Add(1)%uint64(len(candidates))]
	return sessions.PinInstance(sessionID, b.ID, chosen), nil
}

// instanceCandidates is the set selectInstance may choose from.
//
// 🔴 A backend with a CREDENTIAL BOUND is pinned to its single approved address,
// whatever the instance list says. This is the same refusal the control plane's
// discovery reconciler makes when it declines to follow an address change on a
// credential-bound backend (DiscoveryHold), restated at the point of USE:
//
//	An attacker who can write to the service registry can add an instance. If we
//	dialled it, we would hand him the customer's credential on the first call —
//	and the manifest freeze cannot see it, because he can serve an identical
//	manifest. Meanwhile endpoint_url still shows the approved address, so the
//	console shows nothing wrong.
//
// The control plane already declines to WRITE such a list. This declines to USE
// one, so a control plane that is older, wrong or compromised cannot cause the
// fan-out on its own. The two checks are in different processes and different
// repositories on purpose; neither is redundant with the other.
//
// Fence: TestFence_6F7_CredentialBoundBackendNeverFansOutAcrossInstances.
func instanceCandidates(b PolicyBackend) []string {
	if b.CredentialID != "" {
		return []string{b.EndpointURL}
	}
	if len(b.Instances) == 0 {
		return []string{b.EndpointURL}
	}
	return b.Instances
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
