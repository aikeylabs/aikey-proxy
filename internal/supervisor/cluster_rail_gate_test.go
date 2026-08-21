package supervisor

// D2 fence (方案 20260819-集群TeamOAuth-调度一致性与投影对账): the two team-JWT
// rails must be GATED OFF on cluster nodes. Cluster workers have no human login
// credential, so running these rails there can only produce a permanent
// "no team credential in vault" failure loop — pure noise that misled the
// 2026-08-19 P0-3 triage. Cluster material and engine assignments travel the
// daemon spine (org key-delivery), and my_assignment_override must keep exactly
// ONE writer per edition (non-cluster = routing_override rail; cluster = cli
// apply) — both gates opening on cluster would split that source of truth.

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
)

func TestClusterMode_TeamJWTRailsAreGatedOff(t *testing.T) {
	t.Setenv("AIKEY_PROXY_OAUTH_GROUP_ENABLED", "1")
	// A REAL vault with a group VK: without the cluster check BOTH gates return
	// true on this fixture (asserted below as the anti-vacuity control), so the
	// cluster assertions can only pass through the Cluster.Enabled branch —
	// a nil-vault gen would leave the routing_override half vacuous
	// (localSeatGroupsFor is nil-safe and empty ⇒ gate false regardless).
	_, reader := newOpenableVault(t, []map[string]string{
		{"vk": "vk-a", "seat": "seat-1", "group": "grp-1", "override": ""},
	})
	gen := &generation{vault: reader}

	s := &Supervisor{cfg: &config.Config{}}
	s.cfg.Cluster.Enabled = true
	if s.groupRuntimeRail().gate(gen) {
		t.Fatal("group_runtime rail must be gated off on cluster nodes (daemon spine delivers the material)")
	}
	if s.routingOverrideRail().gate(gen) {
		t.Fatal("routing_override rail must be gated off on cluster nodes (single writer for my_assignment_override)")
	}

	// Anti-vacuity control: the SAME fixture with cluster off opens both gates —
	// proving the assertions above exercised the cluster branch, not an
	// accidentally-empty gate input.
	nc := &Supervisor{cfg: &config.Config{}}
	if !nc.groupRuntimeRail().gate(gen) || !nc.routingOverrideRail().gate(gen) {
		t.Fatal("control leg broken: fixture must open both gates when cluster is off (fence would be vacuous)")
	}
}
