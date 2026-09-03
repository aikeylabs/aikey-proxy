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
