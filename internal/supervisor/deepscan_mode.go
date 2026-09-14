// deepscan_mode.go — which deep-scan lane this proxy generation runs, and the
// env the detector child must be spawned with so it never becomes a second
// forwarder.
//
// spec: R-scan-node-deepscan-2.S1 · design §4b.2
// baseline: openspec/changes/add-scan-node-deepscan/baseline-forensics.md §F2
package supervisor

import (
	"os"
	"strings"
)

// DeepScanMode is where this proxy sends asynchronous scan work.
//
// One enum, read from one function, rather than a handful of booleans: the mode
// decides the health section's `mode` field, where pieces are placed, and which
// counters mean anything, and three call sites deriving it independently is how
// a health page ends up disagreeing with what the data plane actually does.
type DeepScanMode string

const (
	// DeepScanModeRemote: team content goes to scan nodes over TLS.
	DeepScanModeRemote DeepScanMode = "remote"
	// DeepScanModeLocal: work runs on this machine (Personal/Trial, personal
	// routes anywhere, or team routes with no node available).
	DeepScanModeLocal DeepScanMode = "local"
	// DeepScanModeOff: the operator turned the lane off entirely.
	DeepScanModeOff DeepScanMode = "off"
)

// deepScanModeEnv is the operator kill switch (design §4b.10).
const deepScanModeEnv = "AIKEY_PROXY_DEEPSCAN_MODE"

// deepScanChildSocketEnv CLEARS AIKEY_DEEPSCAN_SOCKET for the detector child.
//
// 🔴 WHY AN EMPTY ASSIGNMENT AND NOT "just don't set it": the child inherits the
// proxy's environment (internal/apphook/childhook.go spawns with
// `append(os.Environ(), ExtraEnv...)`), and a Personal install DOES set this
// variable for the on-machine daemon. Saying nothing therefore means "inherit
// the proxy's value", which makes the detector forward every prompt to the
// daemon at the same time the proxy does — the same content scanned twice and
// uploaded twice, by two senders whose event_ids cannot collide.
//
// Measured, not assumed (baseline-forensics §F2): appending "KEY=" wins over an
// inherited value because Go's os/exec keeps the LAST occurrence of a duplicate
// key. The child then reads an empty string, and the detector treats empty as
// "deep scan disabled" (cmd/detector/main.go: strings.TrimSpace of the value).
//
// Applied in EVERY mode, including local and off. Local is the mode where the
// daemon IS the right destination — and precisely therefore the mode where a
// second sender doubles the work.
//
// Fence: TestDeepScanMode_ChildSocketAlwaysStripped.
const deepScanChildSocketEnv = "AIKEY_DEEPSCAN_SOCKET="

// deepScanMode reports the lane for this generation.
//
// Remote requires an actual trusted node set, which the `scan_nodes` sync rail
// (Production) or the rendered cluster-node.env (Cluster) publishes. No nodes is
// not an error — it is simply local, and the health section carries the reason.
func (s *Supervisor) deepScanMode() DeepScanMode {
	if strings.EqualFold(strings.TrimSpace(os.Getenv(deepScanModeEnv)), "off") {
		return DeepScanModeOff
	}
	if s != nil && s.hasTrustedScanNodes() {
		return DeepScanModeRemote
	}
	return DeepScanModeLocal
}

// hasTrustedScanNodes reports whether a usable node set is currently published.
// Populated by the scan_nodes rail (task 6.2) and the Cluster loader (task 6.3);
// until one of them publishes, this is false and the lane is local — which is the
// correct answer for Personal and Trial permanently.
func (s *Supervisor) hasTrustedScanNodes() bool {
	set := s.scanNodes.Load()
	return set != nil && len(set.Nodes) > 0
}
