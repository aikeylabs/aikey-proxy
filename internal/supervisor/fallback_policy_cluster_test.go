package supervisor

// fallback_policy_cluster_test.go — the policy rail on a cluster node.
//
// A worker has no team JWT and cannot get one: that credential is minted from a
// vault refresh token written by `aikey login`, and nobody logs in on a node. So
// the rail failed every cycle, all five thresholds read `source: builtin`, and an
// administrator's saved policy reached nothing in the fleet.
//
// 🔴 The org id is CONFIGURED. The first version derived it from the vault on the
// premise that a node serves one organization; a staging worker disproved that —
// its cache held live keys from two orgs (101 rows and 3, the minority ones not
// stale). This value picks whose attempt timeout, cooldown and chain budget the
// node enforces, so "unknown" has to stay unknown rather than be resolved by
// majority or row order.

import (
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
)

func TestIsClusterNode_NeedsBothEnabledAndAToken(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		token   string
		want    bool
	}{
		{"cluster worker", true, "svc-tok", true},
		{"cluster flag without a control token", true, "", false},
		{"token but not a cluster", false, "svc-tok", false},
		{"personal install", false, "", false},
	} {
		s := &Supervisor{cfg: &config.Config{}}
		s.cfg.Cluster.Enabled = tc.enabled
		s.cfg.Cluster.ControlServiceToken = tc.token
		if got := s.isClusterNode(); got != tc.want {
			t.Errorf("%s: isClusterNode() = %v, want %v — a node without a token cannot "+
				"authenticate to the org surface, and must keep using the seat path rather "+
				"than sending an empty bearer", tc.name, got, tc.want)
		}
	}
}

func TestClusterOrgID_UnsetStaysUnknown(t *testing.T) {
	s := &Supervisor{cfg: &config.Config{}}
	s.cfg.Cluster.Enabled = true
	s.cfg.Cluster.ControlServiceToken = "svc-tok"
	if got, ok := s.clusterOrgID(); ok {
		t.Fatalf("clusterOrgID = (%q, true) with no org_id configured. Guessing here points "+
			"this node's timeouts and cooldown at an organization nobody chose; unknown must "+
			"leave it on builtin defaults, which /status shows as source=builtin", got)
	}
}

func TestClusterOrgID_UsesTheConfiguredValue(t *testing.T) {
	s := &Supervisor{cfg: &config.Config{}}
	s.cfg.Cluster.Enabled = true
	s.cfg.Cluster.ControlServiceToken = "svc-tok"
	s.cfg.Cluster.OrgID = "org-42"
	got, ok := s.clusterOrgID()
	if !ok || got != "org-42" {
		t.Fatalf("clusterOrgID = (%q, %v), want (\"org-42\", true)", got, ok)
	}
}
