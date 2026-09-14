package supervisor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/pkg/scannode"
)

func nodesBody(token string, expiresAt int64) string {
	b, _ := json.Marshal(map[string]any{
		"team_async_scan": "nodes",
		"nodes": []map[string]any{
			{"id": "scan-1", "addr": "https://10.2.3.4:27411", "fingerprint": "AA:BB", "weight": 2},
			{"id": "scan-2", "addr": "https://10.2.3.5:27411", "fingerprint": "ccdd"},
		},
		"token": token, "token_expires_at": expiresAt,
	})
	return string(b)
}

func newRailSupervisor(t *testing.T, now time.Time) *Supervisor {
	t.Helper()
	s := &Supervisor{cfg: &config.Config{}}
	s.nowFn = func() time.Time { return now }
	return s
}

// TestScanNodesRail_PlaintextControlPlaneDisablesNodes is the disclosure fence.
//
// 🔴 The response carries certificate FINGERPRINTS and a bearer TOKEN. Over
// plaintext both are readable and, worse, REWRITABLE by anyone on the path: an
// attacker who can modify this body names their own box as a scan node and
// starts receiving employees' raw prompts, with the proxy's own pin check
// happily confirming the fingerprint they supplied.
//
// So the rail publishes NO nodes over http — not a degraded set, none — and
// says why. Losing asynchronous coverage is visible and recoverable; handing raw
// content to an unauthenticated third party is neither.
func TestScanNodesRail_PlaintextControlPlaneDisablesNodes(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(nodesBody("sct1.org_a.9999999999.k1.mac", 9_999_999_999)))
	}))
	defer srv.Close()

	s := newRailSupervisor(t, time.Unix(1_757_620_000, 0))
	if err := s.syncScanNodes(context.Background(), nil, srv.URL, "jwt"); err != nil {
		t.Fatalf("sync must not error on a plaintext control plane, it must disable: %v", err)
	}
	if hits != 0 {
		t.Errorf("the rail contacted a plaintext control plane %d time(s); the check must come BEFORE the request", hits)
	}

	set := s.scanNodes.Load()
	if set == nil {
		t.Fatal("nothing was published; the health section would show no reason at all")
	}
	if len(set.Nodes) != 0 {
		t.Errorf("%d nodes published over http: %+v", len(set.Nodes), set.Nodes)
	}
	if set.Reason != scannode.ReasonInsecureControlPlane {
		t.Errorf("reason = %q, want %q — an operator needs to know it is the control plane, not the nodes",
			set.Reason, scannode.ReasonInsecureControlPlane)
	}
	if set.Trusted == nil || set.Trusted("aabb") {
		t.Error("the trust predicate must be present and trust nothing")
	}
}

// TestScanNodesRail_404MeansNoNodesNotFailure: a master older than this feature
// has no such route, which is the common case mid-rollout (master upgrades
// first, a fleet does not upgrade at once). Counting it as a failure would put
// every un-upgraded deployment's sync health permanently red for a feature it
// does not have — and a permanently red light is one operators stop reading.
func TestScanNodesRail_404MeansNoNodesNotFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	s := newRailSupervisor(t, time.Unix(1_757_620_000, 0))
	s.scanNodesHTTP = srv.Client()
	if err := s.syncScanNodes(context.Background(), nil, srv.URL, "jwt"); err != nil {
		t.Fatalf("404 must not be an error: %v", err)
	}
	set := s.scanNodes.Load()
	if set == nil || len(set.Nodes) != 0 || set.Reason != scannode.ReasonNoNodes {
		t.Errorf("want an empty set with reason %q, got %+v", scannode.ReasonNoNodes, set)
	}
}

// TestScanNodesRail_PublishesNodesAndTrustSet: the happy path, including that
// the trust set is CLOSED — only fingerprints this response named are trusted.
func TestScanNodesRail_PublishesNodesAndTrustSet(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jwt" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(nodesBody("sct1.org_a.9999999999.k1.mac", 9_999_999_999)))
	}))
	defer srv.Close()
	s := newRailSupervisor(t, time.Unix(1_757_620_000, 0))
	s.scanNodesHTTP = srv.Client()
	if err := s.syncScanNodes(context.Background(), nil, srv.URL, "jwt"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	set := s.scanNodes.Load()
	if set == nil || len(set.Nodes) != 2 {
		t.Fatalf("want 2 nodes, got %+v", set)
	}
	if set.Nodes[0].Fingerprint != "aabb" {
		t.Errorf("fingerprint not normalised: %q", set.Nodes[0].Fingerprint)
	}
	if !set.Trusted("aabb") || !set.Trusted("ccdd") {
		t.Error("an advertised fingerprint is not trusted")
	}
	if set.Trusted("deadbeef") {
		t.Error("the trust set is OPEN — a fingerprint nobody advertised was accepted")
	}
	if tok := s.scanToken.Load(); tok == nil || *tok == "" {
		t.Error("no token was published; every delivery would be unauthorized")
	}
}

// TestScanNodesRail_ExpiredTokenClearsTheSet: nodes without a usable token are a
// lane that looks configured and delivers nothing. Empty + a reason is honest.
func TestScanNodesRail_ExpiredTokenClearsTheSet(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(nodesBody("sct1.org_a.1.k1.mac", 1_000)))
	}))
	defer srv.Close()
	s := newRailSupervisor(t, time.Unix(1_757_620_000, 0)) // long past the expiry
	s.scanNodesHTTP = srv.Client()
	if err := s.syncScanNodes(context.Background(), nil, srv.URL, "jwt"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	set := s.scanNodes.Load()
	if set == nil || len(set.Nodes) != 0 {
		t.Errorf("an expired token must clear the node set, got %+v", set)
	}
}
