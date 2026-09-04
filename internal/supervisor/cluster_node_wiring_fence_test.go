package supervisor

// cluster_node_wiring_fence_test.go — the fence that the cluster-node
// authentication guard is actually TURNED ON.
//
// internal/proxy owns the guard and fences its behavior. It cannot fence the
// wiring: a Proxy built by a test sets clusterNode itself, so those fences stay
// green even if the supervisor never tells a real node what it is — and a guard
// nobody switches on is a guard that does not exist. This is the other half.
//
// See workflow/CI/bugfix/2026-09-02-集群节点代理是一个公网开放中继.md

import (
	"os"
	"strings"
	"testing"
)

// TestTheClusterNodeGuardIsWiredFromClusterEnabled asserts both that the
// supervisor turns the guard on and that it does so from the ONE value that
// decides what this process is.
//
// 🔴 The source of the flag is load-bearing, not stylistic. config.validate()
// lifts the loopback rail on `Cluster.Enabled`; if the guard were driven by
// anything else — a service token being present, listen.host looking routable —
// the two decisions could disagree, and the disagreement that matters is
// "routable, and not requiring a key". One value, read twice, cannot do that.
func TestTheClusterNodeGuardIsWiredFromClusterEnabled(t *testing.T) {
	raw, err := os.ReadFile("supervisor.go")
	if err != nil {
		t.Fatalf("read supervisor.go: %v", err)
	}
	src := string(raw)

	// Vacuity guard: if the setter is gone entirely this fence must say so
	// rather than pass over an absence.
	if !strings.Contains(src, "SetClusterNode(") {
		t.Fatal("supervisor.go never calls SetClusterNode. A cluster node then serves the " +
			"path-prefix branch to callers that name no virtual key — the open-relay defect " +
			"of 2026-09-02. internal/proxy's fences cannot catch this: they build the Proxy " +
			"themselves.")
	}

	if !strings.Contains(src, "SetClusterNode(s.cfg.Cluster.Enabled)") {
		// Name what was found, so the failure is diagnosable without opening the file.
		i := strings.Index(src, "SetClusterNode(")
		got := src[i:]
		if j := strings.IndexByte(got, '\n'); j > 0 {
			got = got[:j]
		}
		t.Fatalf("SetClusterNode is not driven by cfg.Cluster.Enabled: %q\n"+
			"That is the same single value config.validate() uses to lift the loopback "+
			"rail. Deriving the guard from anything else lets the two disagree, and the "+
			"disagreement that matters is 'routable, and not requiring a key'.", strings.TrimSpace(got))
	}
}

// TestTheGuardIsNotWiredBehindAnotherCondition catches the shape where the call
// is present but reached only sometimes.
//
// 🚫 A `if <something> { p.SetClusterNode(...) }` would satisfy the fence above
// and still leave real nodes unguarded whenever <something> is false. The
// setter's own argument is the only condition allowed to matter.
func TestTheGuardIsNotWiredBehindAnotherCondition(t *testing.T) {
	raw, err := os.ReadFile("supervisor.go")
	if err != nil {
		t.Fatalf("read supervisor.go: %v", err)
	}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		if !strings.Contains(line, "SetClusterNode(") {
			continue
		}
		// The call must sit at the same nesting depth as its neighbors in the
		// generation-build block, i.e. one tab. A deeper indent means a
		// conditional was wrapped around it.
		indent := len(line) - len(strings.TrimLeft(line, "\t"))
		if indent != 1 {
			t.Fatalf("supervisor.go:%d SetClusterNode is indented %d tabs, not 1 — it looks "+
				"conditional. Every generation on a node must be told what it is; a guard "+
				"that is set only sometimes is unset on the run that matters.\n  %s",
				i+1, indent, strings.TrimSpace(line))
		}
	}
}
