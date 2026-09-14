// scan_nodes.go — a Cluster node's scan-node list, read from the environment the
// installer rendered.
//
// 🔴 WHY CLUSTER DOES NOT USE THE CONTROL-PLANE RAIL. On Production the node list
// arrives over an authenticated HTTPS response, and the fingerprints in it are
// trustworthy because that channel is. A Cluster worker has no member JWT — nobody
// logs in on a node — so it has no such channel. What it does have is a file the
// installer wrote onto the box as root, which is a STRONGER statement: the
// operator who deployed this fleet listed these nodes and these fingerprints.
// That rendered list IS the trust decision here (design §4b.8).
//
// spec: R-scan-node-infrastructure-3.S1
package cluster

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/AiKeyLabs/pkg/scannode"
)

// Env keys the installer renders into cluster-node.env.
const (
	EnvScanNodeAddrs        = "AIKEY_PROXY_SCAN_NODE_ADDRS"
	EnvScanNodeFingerprints = "AIKEY_PROXY_SCAN_NODE_FINGERPRINTS"
	EnvScanTokenKeyFile     = "AIKEY_SCAN_TOKEN_KEY_FILE"
)

// LoadRenderedScanNodes builds the node set from the rendered environment.
//
// 🔴 A COUNT MISMATCH IS FATAL TO THE WHOLE LIST, not just the extra entry.
// The two variables are positional: addrs[i] is pinned to fingerprints[i]. If
// they differ in length, every pairing after the first divergence is a GUESS —
// and a wrong guess means sending raw employee prompts to one box while checking
// another box's certificate, which is precisely the substitution the pin exists
// to prevent. There is no safe partial interpretation, so the answer is zero
// nodes plus a loud ERROR naming both counts.
func LoadRenderedScanNodes(env map[string]string) (scannode.NodeSet, error) {
	addrs := splitList(env[EnvScanNodeAddrs])
	fps := splitList(env[EnvScanNodeFingerprints])

	if len(addrs) == 0 && len(fps) == 0 {
		// The normal state for a cluster without scan nodes.
		return scannode.NodeSet{
			Trusted: func(string) bool { return false },
			Reason:  scannode.ReasonNoNodes,
		}, nil
	}
	if len(addrs) != len(fps) {
		err := fmt.Errorf("scan node config is inconsistent: %d address(es) but %d fingerprint(s) — "+
			"they are positional, so no pairing can be trusted",
			len(addrs), len(fps))
		slog.Error("cluster scan nodes disabled: address and fingerprint counts differ, so raw content "+
			"could be sent to one box while another box's certificate is checked",
			"event.name", "proxy.scan_node.rendered_list_inconsistent",
			"addrs", len(addrs), "fingerprints", len(fps))
		return scannode.NodeSet{
			Trusted: func(string) bool { return false },
			Reason:  scannode.ReasonNoNodes,
		}, err
	}

	nodes := make([]scannode.Node, 0, len(addrs))
	trusted := make(map[string]bool, len(addrs))
	for i, addr := range addrs {
		fp := strings.ToLower(strings.ReplaceAll(fps[i], ":", ""))
		if fp == "" || addr == "" {
			slog.Error("cluster scan nodes disabled: a rendered entry is missing its address or fingerprint",
				"event.name", "proxy.scan_node.rendered_list_inconsistent", "index", i)
			return scannode.NodeSet{Trusted: func(string) bool { return false }, Reason: scannode.ReasonNoNodes},
				fmt.Errorf("scan node %d has an empty address or fingerprint", i)
		}
		// id is derived from position: the rendered list has no ids, and the id is
		// only ever used as a breaker key and a health-section label.
		nodes = append(nodes, scannode.Node{
			ID: fmt.Sprintf("scan-%d", i+1), Addr: addr, Fingerprint: fp, Weight: 1,
		})
		trusted[fp] = true
	}

	return scannode.NodeSet{
		Nodes:   nodes,
		Trusted: func(fp string) bool { return trusted[strings.ToLower(strings.ReplaceAll(fp, ":", ""))] },
		Reason:  scannode.ReasonOK,
	}, nil
}

// splitList parses a comma-separated env value, dropping empties so a trailing
// comma does not produce a phantom entry — which, given the positional pairing
// above, would shift every fingerprint by one.
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
