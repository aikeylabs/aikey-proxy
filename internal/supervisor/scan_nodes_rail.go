// scan_nodes_rail.go — the `scan_nodes` sync rail: which scan nodes this proxy
// may hand raw content to, refreshed every 60s.
//
// spec: R-scan-node-infrastructure-1.S5 · design §4b.8
package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/pkg/scannode"
)

const scanNodesPollInterval = 60 * time.Second

var scanNodesHTTPClient = httpx.NewSwappableDirect(10 * time.Second)

// insecureControlPlaneOnce keeps the plaintext-control-plane WARN to one line
// per process. It is a deployment fact, not an event: repeating it every 60s
// would bury the logs that describe things that changed.
var insecureControlPlaneOnce sync.Once

// scanNodesClient returns the HTTP client this rail uses. The seam exists so a
// test can hand in an httptest TLS server's client — the https gate above means
// the rail CANNOT be exercised over plain http, so a test must be able to
// present a certificate the client trusts.
func (s *Supervisor) scanNodesClient() *http.Client {
	if s != nil && s.scanNodesHTTP != nil {
		return s.scanNodesHTTP
	}
	return scanNodesHTTPClient.Get()
}

// scanNodesRail declares the rail.
//
// needsTeamJWT is TRUE and has no cluster exemption, unlike fallback_policy.
// A Cluster node does not use this rail at all — its node list comes from the
// installer-rendered cluster-node.env (internal/cluster), because on a cluster
// node that rendered file IS the trust decision. So there is no "node has no
// JWT" case to accommodate here; a node that somehow ran this rail should skip
// it, which is what the gate does.
func (s *Supervisor) scanNodesRail() railSpec {
	return railSpec{
		name:         "scan_nodes",
		interval:     scanNodesPollInterval,
		needsTeamJWT: true,
		gate: func(_ *generation) bool {
			// Cluster reads its own rendered list; Personal has no control plane.
			return !s.isClusterNode()
		},
		sync: s.syncScanNodes,
	}
}

// syncScanNodes pulls GET /v1/compliance/scan-nodes and publishes the result.
func (s *Supervisor) syncScanNodes(ctx context.Context, _ *generation, masterURL, bearer string) error {
	// 🔴 HTTPS GATE, AND IT COMES FIRST. The response carries certificate
	// fingerprints and a bearer token; over plaintext both are readable and
	// REWRITABLE by anyone on the path, so an attacker could name their own box
	// as a scan node and receive employees' raw prompts. There is no partial
	// credit here — over http we publish NO nodes at all, and the health section
	// says why (design §4b.8: 控制面非 HTTPS 时 reason=insecure_control_plane).
	//
	// Failing closed loses asynchronous coverage, which is visible in the
	// counters and recoverable by fixing the control plane. Failing open would
	// hand raw content to an unauthenticated third party, which is not.
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(masterURL)), "https://") {
		s.publishScanNodes(scannode.NodeSet{Reason: scannode.ReasonInsecureControlPlane})
		insecureControlPlaneOnce.Do(func() {
			slog.Warn("scan nodes disabled: the control plane is not https, so node fingerprints and the scan token "+
				"would be readable and rewritable in transit",
				"event.name", observability.EventScanNodeInsecureControlPlane,
				"control_url_scheme", schemeOf(masterURL))
		})
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(masterURL, "/")+"/v1/compliance/scan-nodes", http.NoBody)
	if err != nil {
		return fmt.Errorf("scan_nodes: build request: %w", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := s.scanNodesClient().Do(req)
	if err != nil {
		return fmt.Errorf("scan_nodes: %w", err)
	}
	defer resp.Body.Close()

	// 🔴 404 IS NOT A FAILURE. A master older than this feature has no such
	// route, and that is the overwhelmingly common case during a rollout —
	// master is upgraded first, but a fleet is not upgraded at once. Counting it
	// as a failure would put every un-upgraded deployment's sync health into a
	// permanent red state for a feature it does not have, and operators would
	// learn to ignore the one signal that matters.
	if resp.StatusCode == http.StatusNotFound {
		s.publishScanNodes(scannode.NodeSet{Reason: scannode.ReasonNoNodes})
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("scan_nodes: control plane answered %d", resp.StatusCode)
	}

	var body struct {
		TeamAsyncScan string `json:"team_async_scan"`
		Nodes         []struct {
			ID          string `json:"id"`
			Addr        string `json:"addr"`
			Fingerprint string `json:"fingerprint"`
			Weight      int    `json:"weight"`
		} `json:"nodes"`
		Token          string `json:"token"`
		TokenExpiresAt int64  `json:"token_expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("scan_nodes: decode: %w", err)
	}

	// 🔴 AN EXPIRED (or absent) TOKEN CLEARS THE SET. Keeping the last-known
	// nodes without a usable token would leave the lane trying to deliver to
	// boxes that will answer `unauthorized` to everything — a lane that looks
	// configured and delivers nothing. Empty + a reason is the honest state.
	now := s.now()
	if body.Token == "" || (body.TokenExpiresAt > 0 && now.Unix() >= body.TokenExpiresAt) {
		s.publishScanNodes(scannode.NodeSet{Reason: scannode.ReasonNoNodes})
		return nil
	}

	nodes := make([]scannode.Node, 0, len(body.Nodes))
	trusted := make(map[string]bool, len(body.Nodes))
	for _, n := range body.Nodes {
		fp := strings.ToLower(strings.ReplaceAll(n.Fingerprint, ":", ""))
		if n.ID == "" || n.Addr == "" || fp == "" {
			// A half-formed entry cannot be trusted and must not be silently
			// dropped either — a node the control plane meant to advertise and
			// this proxy ignores is an invisible coverage gap.
			slog.Warn("scan_nodes: ignoring an incomplete node entry",
				"event.name", observability.EventScanNodeUntrustedFingerprint, "node", n.ID)
			continue
		}
		nodes = append(nodes, scannode.Node{ID: n.ID, Addr: n.Addr, Fingerprint: fp, Weight: n.Weight})
		trusted[fp] = true
	}

	reason := scannode.ReasonOK
	if len(nodes) == 0 {
		reason = scannode.ReasonNoNodes
	}
	s.publishScanNodes(scannode.NodeSet{
		Nodes: nodes,
		// The trust set is a CLOSED list built from this very response. A node
		// that later presents a different certificate is refused by the client,
		// and a node not named here can never be dialed at all.
		Trusted: func(fp string) bool { return trusted[strings.ToLower(fp)] },
		Reason:  reason,
	})
	s.scanToken.Store(&body.Token)
	// Stored even when it is "off" or "local": the ABSENCE of a value means "we
	// have never heard from a master", which the lane treats as off. Conflating
	// the two would make a master that explicitly says `local` look the same as
	// one that was never reached.
	mode := body.TeamAsyncScan
	s.teamAsyncScan.Store(&mode)
	return nil
}

// publishScanNodes swaps the published set atomically.
func (s *Supervisor) publishScanNodes(set scannode.NodeSet) {
	if set.Trusted == nil {
		// Never leave it nil: pkg/scannode treats a nil predicate as "trust
		// nothing", and an explicit empty set says the same thing out loud.
		set.Trusted = func(string) bool { return false }
	}
	s.scanNodes.Store(&set)
}

func (s *Supervisor) now() time.Time {
	if s != nil && s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

func schemeOf(u string) string {
	if i := strings.Index(u, "://"); i > 0 {
		return u[:i]
	}
	return "(none)"
}
