package cluster

import (
	"testing"

	"github.com/AiKeyLabs/pkg/scannode"
)

// TestClusterScanNodes_RenderedListOnly: on a Cluster node the installer's
// rendered list is the ONLY source, and it is positional.
//
// 🔴 THE COUNT-MISMATCH CASE IS THE POINT. addrs[i] is pinned to fps[i]; if the
// lists differ in length, every pairing past the divergence is a guess, and a
// wrong guess means shipping raw employee prompts to one box while validating a
// different box's certificate — exactly the substitution the pin exists to stop.
// There is no safe partial reading, so the whole list is refused.
func TestClusterScanNodes_RenderedListOnly(t *testing.T) {
	t.Run("paired list loads", func(t *testing.T) {
		set, err := LoadRenderedScanNodes(map[string]string{
			EnvScanNodeAddrs:        "https://10.2.3.4:27411,https://10.2.3.5:27411",
			EnvScanNodeFingerprints: "AA:BB:CC,ddeeff",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(set.Nodes) != 2 {
			t.Fatalf("want 2 nodes, got %+v", set.Nodes)
		}
		if set.Nodes[0].Addr != "https://10.2.3.4:27411" || set.Nodes[0].Fingerprint != "aabbcc" {
			t.Errorf("node 0 wrong (fingerprint must be lowercased, colons stripped): %+v", set.Nodes[0])
		}
		if set.Nodes[1].Fingerprint != "ddeeff" {
			t.Errorf("node 1 fingerprint wrong: %+v", set.Nodes[1])
		}
		if !set.Trusted("AA:BB:CC") || !set.Trusted("aabbcc") {
			t.Error("the trust predicate must accept either spelling of an advertised fingerprint")
		}
		if set.Trusted("deadbeef") {
			t.Error("the trust set is OPEN — an unrendered fingerprint was accepted")
		}
		if set.Reason != scannode.ReasonOK {
			t.Errorf("reason = %q, want %q", set.Reason, scannode.ReasonOK)
		}
	})

	t.Run("count mismatch refuses the WHOLE list", func(t *testing.T) {
		for name, env := range map[string]map[string]string{
			"more addrs": {
				EnvScanNodeAddrs:        "https://10.2.3.4:27411,https://10.2.3.5:27411",
				EnvScanNodeFingerprints: "aabbcc",
			},
			"more fingerprints": {
				EnvScanNodeAddrs:        "https://10.2.3.4:27411",
				EnvScanNodeFingerprints: "aabbcc,ddeeff",
			},
		} {
			t.Run(name, func(t *testing.T) {
				set, err := LoadRenderedScanNodes(env)
				if err == nil {
					t.Error("a count mismatch must be reported, not silently truncated")
				}
				if len(set.Nodes) != 0 {
					t.Errorf("%d node(s) survived a count mismatch: %+v", len(set.Nodes), set.Nodes)
				}
				if set.Trusted == nil || set.Trusted("aabbcc") {
					t.Error("nothing may be trusted when the pairing is unknown")
				}
			})
		}
	})

	t.Run("no config is not an error", func(t *testing.T) {
		set, err := LoadRenderedScanNodes(map[string]string{})
		if err != nil {
			t.Fatalf("a cluster without scan nodes must not error: %v", err)
		}
		if len(set.Nodes) != 0 || set.Reason != scannode.ReasonNoNodes {
			t.Errorf("want an empty set with reason %q, got %+v", scannode.ReasonNoNodes, set)
		}
		if set.Trusted == nil {
			t.Error("the trust predicate must never be nil — pkg/scannode treats nil as trust-nothing, " +
				"but an explicit empty predicate says so out loud")
		}
	})

	t.Run("a trailing comma does not shift the pairing", func(t *testing.T) {
		set, err := LoadRenderedScanNodes(map[string]string{
			EnvScanNodeAddrs:        "https://10.2.3.4:27411,",
			EnvScanNodeFingerprints: "aabbcc,",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(set.Nodes) != 1 || set.Nodes[0].Fingerprint != "aabbcc" {
			t.Errorf("a trailing comma produced a phantom entry: %+v", set.Nodes)
		}
	})
}
