package supervisor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// railFor builds the minimum Supervisor syncFallbackPolicy touches: a config and
// a threshold cache. Nothing else on the rail path is reachable from here.
func railFor(cfg *config.Config) *Supervisor {
	return &Supervisor{cfg: cfg, fallbackPolicy: proxy.NewFallbackPolicyCache(nil)}
}

func clusterCfg(nodeID string) *config.Config {
	c := &config.Config{}
	c.Cluster.Enabled = true
	c.Cluster.OrgID = "org-1"
	c.Cluster.ControlServiceToken = "svc-token"
	c.Cluster.NodeID = nodeID
	return c
}

// TestRailNamesTheNodeSoTheFleetCanBeCounted is the proxy half of the
// 2026-08-04 staging finding: the console reported a fully-synced two-worker
// cluster as one machine.
//
// 🔴 The control plane cannot discover this on its own. Every worker in a
// cluster authenticates with the SAME `control_service_token`, so from the
// server's side two nodes and one node are indistinguishable — it was counting
// distinct accounts and could never exceed 1. Only the node knows which node it
// is, so if this header is not sent the server-side fix is inert.
//
// 能红: drop the `req.Header.Set(fallbackPolicyNodeHeader, ...)` line in
// syncFallbackPolicy → the header is absent and the fleet collapses to one again.
func TestRailNamesTheNodeSoTheFleetCanBeCounted(t *testing.T) {
	var got string
	var seen bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, seen = r.Header.Get("X-Aikey-Node-Id"), true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":1,"policy":{}}`))
	}))
	defer srv.Close()

	s := railFor(clusterCfg("node-2"))
	if err := s.syncFallbackPolicy(context.Background(), nil, srv.URL, ""); err != nil {
		t.Fatalf("syncFallbackPolicy: %v", err)
	}
	if !seen {
		t.Fatal("the rail never reached the server")
	}
	if got != "node-2" {
		t.Errorf("X-Aikey-Node-Id = %q, want \"node-2\" — without it the control plane "+
			"cannot tell this worker from its siblings (they share one service token) "+
			"and reports the whole fleet as a single machine", got)
	}
}

// A seat install must send NOTHING. There the account genuinely is the machine,
// and the server's per-account counting is correct — sending a header would
// invent a second identity dimension for a deployment that has only one.
func TestRailSendsNoNodeHeaderOnASeatInstall(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Aikey-Node-Id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":1,"policy":{}}`))
	}))
	defer srv.Close()

	// Not a cluster node: no Cluster.Enabled, no service token.
	s := railFor(&config.Config{})
	if err := s.syncFallbackPolicy(context.Background(), nil, srv.URL, "seat-bearer"); err != nil {
		t.Fatalf("syncFallbackPolicy: %v", err)
	}
	if got != "" {
		t.Errorf("a seat install sent X-Aikey-Node-Id = %q; it has no node identity to claim", got)
	}
}

// A cluster node with no node_id configured must stay silent rather than send an
// empty header: "" is not a machine name, and the server would have to decide
// what an empty identity means. config.Validate already rejects this combination
// at startup, so this pins the rail's own behavior if it is ever reached.
func TestRailOmitsTheHeaderRatherThanSendingAnEmptyNodeID(t *testing.T) {
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["X-Aikey-Node-Id"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":1,"policy":{}}`))
	}))
	defer srv.Close()

	s := railFor(clusterCfg("")) // clustered, but unnamed
	if err := s.syncFallbackPolicy(context.Background(), nil, srv.URL, ""); err != nil {
		t.Fatalf("syncFallbackPolicy: %v", err)
	}
	if present {
		t.Error("an unnamed node sent the header anyway; absent and empty must not be the same claim")
	}
}

// Older node packages export the control token and org for the daemon but may
// not have rendered the two newer YAML fields. The scheduler must still classify
// this as a service-token rail; asking the empty node vault for a human team JWT
// prevents syncFallbackPolicy from ever running.
func TestFallbackPolicyRailUsesClusterEnvironmentWithoutATeamJWT(t *testing.T) {
	t.Setenv(clusterControlServiceTokenEnv, "control-token")
	t.Setenv(clusterOrgIDEnv, "org-env")

	cfg := &config.Config{}
	cfg.Cluster.Enabled = true
	cfg.Cluster.NodeID = "node-env"
	s := railFor(cfg)
	if spec := s.fallbackPolicyRail(); spec.needsTeamJWT {
		t.Fatal("cluster environment was classified as a team-JWT rail")
	}

	var gotPath, gotAuth, gotNode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotNode = r.Header.Get(fallbackPolicyNodeHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":4,"policy":{}}`))
	}))
	defer srv.Close()

	if err := s.syncFallbackPolicy(context.Background(), nil, srv.URL, ""); err != nil {
		t.Fatalf("syncFallbackPolicy: %v", err)
	}
	if gotPath != "/internal/org/org-env/fallback-policy" {
		t.Errorf("path = %q, want env-configured org policy path", gotPath)
	}
	if gotAuth != "Bearer control-token" {
		t.Error("authorization did not use the environment-configured control token")
	}
	if gotNode != "node-env" {
		t.Errorf("node header = %q, want node-env", gotNode)
	}
}
