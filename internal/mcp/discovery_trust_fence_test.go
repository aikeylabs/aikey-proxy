package mcp

// discovery_trust_fence_test.go — the proxy half of fence 10.F3 (阶段8 P10).
//
// # What this protects
//
// The control plane can learn a backend's address from a service registry
// (Nacos today, Polaris when a customer pulls it). Where that address came from
// travels down to the proxy in `PolicyBackend.DiscoverySource`, and the whole
// safety argument for automatic discovery is that the value changes NOTHING
// here: a discovered backend is probed the same way, fingerprinted the same
// way, frozen the same way and authorised the same way as one an administrator
// typed.
//
// 🔴 The change somebody will eventually want to make is the dangerous one:
// "registry backends are internal, skip the manifest probe / trust the
// manifest / skip the grant check for them". That is precisely the shortcut
// that turns "an entry appeared in the registry" into "a model gained a
// capability", and it would be one plausible-looking `if` in a diff whose
// commit message reads "avoid redundant probing of internal services".
//
// So the property is structural, not behavioural: no file on the proxy's MCP
// plane may BRANCH on this field. Carrying it (the wire struct, the local-config
// producer) is fine and is what the value is for.

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFence_10F3_TheProxyNeverBranchesOnDiscoverySource(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rErr := os.ReadFile(filepath.Join(".", name))
		if rErr != nil {
			t.Fatalf("read %s: %v", name, rErr)
		}
		scanned++
		for i, line := range strings.Split(string(src), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				// Comments EXPLAIN the rule; they must not trip it.
				code = code[:idx]
			}
			if !strings.Contains(code, "DiscoverySource") && !strings.Contains(code, "DiscoveryStatic") {
				continue
			}
			if strings.Contains(code, "if ") || strings.Contains(code, "switch ") ||
				strings.Contains(code, "case ") {
				t.Errorf("%s:%d branches on a backend's discovery source: %q\n"+
					"🔴 A backend found in a service registry gets the SAME probe, the SAME "+
					"manifest freeze and the SAME authorisation as one an administrator typed. "+
					"Where its address came from may never decide what an Agent can call — "+
					"otherwise writing an entry into the customer's registry becomes a way to "+
					"grant a capability.", name, i+1, strings.TrimSpace(line))
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no source files scanned — this fence would pass vacuously")
	}
}

// TestFence_10F3_TheManifestSyncerProbesDiscoveredBackendsToo is the
// behavioural companion: the structural fence above proves nobody branches,
// this proves the loop actually reaches such a backend at all. A syncer that
// skipped discovered backends for some unrelated reason would satisfy the
// structural fence and still leave them unfingerprinted.
func TestFence_10F3_TheManifestSyncerProbesDiscoveredBackendsToo(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()

	store := NewPolicyStore()
	store.Store(&Policy{
		OrgID: testOrg, Version: 1,
		Backends: []PolicyBackend{{
			ID: "b-nacos", Name: "orders-mcp", Transport: TransportStreamableHTTP,
			EndpointURL: srv.URL, Status: StatusActive,
			// 🔴 The only difference from a hand-registered backend.
			DiscoverySource: "nacos",
		}},
	})
	syncer := NewManifestSyncer(testOrg, store, nil, nil, nil, discardLogger())
	syncer.SyncOnce(context.Background())

	if len(up.calledMethods()) == 0 {
		t.Fatal("🔴 a discovered backend was never probed. Its tools would then never appear " +
			"for review, and the manifest freeze would have nothing to compare against — " +
			"discovery would be delivering backends nobody can ever use.")
	}
	st, ok := syncer.Status()["b-nacos"]
	if !ok || st.Health != BackendHealthy {
		t.Fatalf("a discovered backend must reach the same health states as any other, got %+v", st)
	}
}
