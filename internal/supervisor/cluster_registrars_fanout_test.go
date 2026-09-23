package supervisor

// cluster_registrars_fanout_test.go — fences for the multi-hub fan-out wiring.
//
// internal/cluster fences that Registrar loops are independent of each other. It
// cannot fence that the supervisor actually starts one per configured hub: New()
// builds the registrars from closures over a whole Supervisor (vault,
// generations, live rails), which nothing in this package constructs. So the
// fan-out is a small helper that the runtime test below drives directly, and a
// source fence pins that New() feeds it the configured LIST rather than the
// legacy single hub_url — the one-line "simplification" that would leave every
// other hub with an empty node table while the node looks healthy.
//
// update: roadmap20260320/技术实现/update/20260922-集群入口高可用-hub多实例与两台入口机.md
// (DEC-cluster-ingress-ha-2) · workflow/CI/enviroment/tokenhub-gcp/ingress-ha.md §6.3
//nolint:misspell // that directory really is spelled "enviroment"; correcting it here would point at a path that does not exist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/cluster"
)

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for: %s", timeout, what)
}

// TestStartClusterRegistrars_EveryHubIsServedEvenWhenOneHangs proves the two
// halves of DEC-cluster-ingress-ha-2 at the production fan-out: build runs once
// per hub, and a hub that accepts connections and never answers (only the 5s
// client timeout ends that call) does not delay the register + heartbeat that
// the healthy hub must keep receiving.
func TestStartClusterRegistrars_EveryHubIsServedEvenWhenOneHangs(t *testing.T) {
	release := make(chan struct{})
	var attemptsA int32
	hubA := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attemptsA, 1)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() { close(release); hubA.Close() })

	// Hub B answers with the smallest heartbeat interval the wire allows (1s).
	var regB, hbB int32
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/register", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&regB, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"registered":true,"heartbeat_interval_seconds":1}`))
	})
	mux.HandleFunc("/cluster/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hbB, 1)
		w.WriteHeader(http.StatusOK)
	})
	hubB := httptest.NewServer(mux)
	t.Cleanup(hubB.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var built []string
	start := time.Now()
	startClusterRegistrars(ctx, []string{hubA.URL, hubB.URL}, func(hubURL string) *cluster.Registrar {
		built = append(built, hubURL)
		return cluster.NewRegistrar(hubURL, "worker-1", "10.0.0.11:27200", 1, "")
	})
	if len(built) != 2 || built[0] != hubA.URL || built[1] != hubB.URL {
		t.Fatalf("build must run once per hub, in order; got %q", built)
	}

	// A serialized fan-out would reach hub B only after hub A's 5s timeout.
	waitFor(t, 3*time.Second, func() bool {
		return atomic.LoadInt32(&attemptsA) >= 1 && atomic.LoadInt32(&regB) >= 1 && atomic.LoadInt32(&hbB) >= 1
	}, "hub B to receive register + heartbeat while hub A hangs")
	if elapsed := time.Since(start); elapsed >= 4*time.Second {
		t.Fatalf("hub B served only after %v: hub A's hang leaked into hub B's loop", elapsed)
	}
}

// TestClusterRegistrarsAreWiredFromTheConfiguredHubList pins the one thing the
// runtime test cannot reach: that New() hands the fan-out the configured hub
// LIST through cfg.Cluster.AllHubURLs() — the single place where hub_urls /
// hub_url precedence and normalization live — and no longer reads the legacy
// single Cluster.HubURL anywhere.
func TestClusterRegistrarsAreWiredFromTheConfiguredHubList(t *testing.T) {
	src := readSupervisorSource(t, "supervisor.go")

	if !strings.Contains(src, "startClusterRegistrars(") {
		t.Fatal("supervisor.go never calls startClusterRegistrars: no Registrar is started per hub, " +
			"so every hub but one keeps an empty node table (DEC-cluster-ingress-ha-2)")
	}
	if !strings.Contains(src, "s.cfg.Cluster.AllHubURLs()") {
		t.Fatal("supervisor.go does not read the hub set through s.cfg.Cluster.AllHubURLs(); " +
			"that method is the only place hub_urls / hub_url precedence and normalization live")
	}
	if loc := regexp.MustCompile(`\bCluster\.HubURL\b`).FindStringIndex(src); loc != nil {
		lineStart := strings.LastIndex(src[:loc[0]], "\n") + 1
		lineEnd := loc[1] + strings.Index(src[loc[1]:], "\n")
		t.Fatalf("supervisor.go still reads the legacy single Cluster.HubURL: %q — every hub in "+
			"cluster.hub_urls must come through AllHubURLs(), or the extra hubs silently get nothing",
			strings.TrimSpace(src[lineStart:lineEnd]))
	}
}
