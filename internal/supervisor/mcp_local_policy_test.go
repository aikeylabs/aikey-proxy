package supervisor

// P5 — the boundary between Personal's local config and an org's policy.
//
// 🔴 This is the security-relevant half of local config. Everything else in P5
// is about processes; this is about who decides what a developer may run.
//
// A node that honoured BOTH producers would let a developer grant themselves a
// tool their administrator did not — by editing a JSON file on the machine
// where the tools actually execute, with the control plane none the wiser.

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/mcp"
)

// TestLocalMCPPolicyIsRefusedWhenTheNodeFollowsAControlPlane.
//
// 能红: delete the `s.mcpRail != nil` guard in EnableLocalMCPPolicy.
func TestLocalMCPPolicyIsRefusedWhenTheNodeFollowsAControlPlane(t *testing.T) {
	s := &Supervisor{}
	s.mcpRail = NewMCPPolicyRail("org-1", nil)

	err := s.EnableLocalMCPPolicy(mcp.NewPolicyStore())
	if err == nil {
		t.Fatal("🔴 a node that follows a control plane accepted a locally-authored MCP policy. " +
			"On that node a developer can grant themselves tools by editing a file, on the " +
			"machine where the tools run, and nothing in the console would show it.")
	}
	if s.mcpLocalPolicy != nil {
		t.Fatal("the local store was installed despite the refusal")
	}
	// And the policy the plane reads must still be the ORG's.
	if got := s.MCPPolicyStore(); got != s.mcpRail.Store() {
		t.Fatal("MCPPolicyStore returned something other than the control-plane store")
	}
}

// TestLocalMCPPolicyIsServedWhenThereIsNoControlPlane — the other direction,
// so the guard above cannot be satisfied by refusing everything.
func TestLocalMCPPolicyIsServedWhenThereIsNoControlPlane(t *testing.T) {
	s := &Supervisor{}
	store := mcp.NewPolicyStore()
	if err := s.EnableLocalMCPPolicy(store); err != nil {
		t.Fatalf("Personal must accept a local policy: %v", err)
	}
	if s.MCPPolicyStore() != store {
		t.Fatal("the plane would not see the local policy, so Personal serves nothing")
	}
}

// TestMCPPolicyStoreIsNilWhenNeitherProducerRan — a node with no control plane
// AND no local config must mount nothing.
//
// 🔴 nil is the truthful answer: a plane mounted with no policy would answer
// every request from inside the gateway, which reads to a client as "the
// gateway is broken" rather than "there is nothing configured here".
func TestMCPPolicyStoreIsNilWhenNeitherProducerRan(t *testing.T) {
	s := &Supervisor{}
	if s.MCPPolicyStore() != nil {
		t.Fatal("a node with neither producer must expose no policy store")
	}
}

// TestLocalManifestSyncIsANoOpWithoutALocalPolicy — the start hook is called
// unconditionally from app wiring, so it must be inert on the edition it does
// not belong to.
func TestLocalManifestSyncIsANoOpWithoutALocalPolicy(t *testing.T) {
	s := &Supervisor{}
	s.StartLocalMCPManifestSync() // must not panic, must not start anything
	if s.MCPManifestSyncer() != nil {
		t.Fatal("a syncer was created with no local policy to probe")
	}
}

// TestLocalPublisherIsCreatedWithoutStartingTheProber — the split that P14.3's
// review surface depends on.
//
// # Why this fence exists
//
// bugfix: workflow/CI/bugfix/20260904-personal-mcp-review-surface-was-never-wired.md
//
// The admin handler captures MCPLocalPublisher() ONCE, while it is being built,
// which is before the listener serves. The prober can only start after. While
// publisher creation lived inside StartLocalMCPManifestSync, the capture always
// saw nil on a Personal node, so `aikey mcp review --accept` — the only way to
// release a hosted server's tools — answered 503 "this node follows a control
// plane" on the edition that has none.
//
// 能红: fold the NewLocalPublisher call back into StartLocalMCPManifestSync (or
// make EnableLocalMCPPublisher start the prober), and this goes red on the
// second assertion.
func TestLocalPublisherIsCreatedWithoutStartingTheProber(t *testing.T) {
	s := &Supervisor{}
	if err := s.EnableLocalMCPPolicy(mcp.NewPolicyStore()); err != nil {
		t.Fatalf("Personal must accept a local policy: %v", err)
	}

	pub := s.EnableLocalMCPPublisher()
	if pub == nil || s.MCPLocalPublisher() == nil {
		t.Fatal("🔴 a Personal node has no approval state before the prober starts, so the " +
			"admin handler captures nil and `aikey mcp review --accept` refuses — leaving " +
			"every hosted tool unreleasable")
	}
	// 🔴 The negative half: creation must NOT drag the prober in. If it did, the
	// call would move back behind "the listener is serving" and the capture
	// would be nil again for a different reason.
	if s.MCPManifestSyncer() != nil {
		t.Fatal("creating the publisher started the manifest prober; the two must stay separable")
	}
}

// TestLocalPublisherIsIdempotent — both call sites may run, in either order.
//
// 能红: drop the early return in EnableLocalMCPPublisher, so the prober replaces
// the publisher the admin handler already holds a pointer to (accepting a tool
// would then write into an object nothing serves from).
func TestLocalPublisherIsIdempotent(t *testing.T) {
	s := &Supervisor{}
	if err := s.EnableLocalMCPPolicy(mcp.NewPolicyStore()); err != nil {
		t.Fatalf("Personal must accept a local policy: %v", err)
	}
	first := s.EnableLocalMCPPublisher()
	if second := s.EnableLocalMCPPublisher(); second != first {
		t.Fatal("🔴 the second call replaced the publisher. The admin handler captured the " +
			"first one, so reviews would be accepted into an object the gateway no longer reads")
	}
}

// TestLocalPublisherIsAbsentWithoutALocalPolicy — a node that follows a control
// plane must NOT get one, because that is what makes the admin surface answer
// "review happens in the console" instead of an empty list.
//
// 能红: remove the `s.mcpLocalPolicy == nil` guard.
func TestLocalPublisherIsAbsentWithoutALocalPolicy(t *testing.T) {
	s := &Supervisor{}
	s.mcpRail = NewMCPPolicyRail("org-1", nil)
	if pub := s.EnableLocalMCPPublisher(); pub != nil || s.MCPLocalPublisher() != nil {
		t.Fatal("a control-plane node grew a local approval surface; reviewing there is the " +
			"console's job and a local one is a second, unaudited approver")
	}
}
