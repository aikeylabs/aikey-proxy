package supervisor

import (
	"os"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
)

// TestDeepScanMode_ChildSocketAlwaysStripped is the double-send fence.
//
// THE BUG IT PREVENTS (design §4b.2, R-scan-node-deepscan-2.S1): until v1.1 the
// DETECTOR owned the deep-scan forwarder — it read AIKEY_DEEPSCAN_SOCKET and, if
// set, shipped every prompt to the on-machine daemon itself. From v1.1 the PROXY
// is the only forwarder, in every mode. If the detector child still inherits a
// non-empty socket from the proxy's own environment, BOTH of them forward the
// same content: the daemon scans each piece twice, uploads a second set of
// events, and the audit page shows duplicate findings whose event_ids do not
// collide because they were minted by different senders.
//
// "In every mode" is the part worth testing. It is tempting to strip the socket
// only in remote mode and leave it alone locally, because locally "the daemon is
// the right destination anyway" — which is exactly wrong: in local mode the
// proxy ALSO sends to that same socket, so leaving it set is precisely when the
// double-send happens.
//
// Measured baseline this rests on (baseline-forensics §F2, 2026-09-11): appending
// "KEY=" to ChildHookConfig.ExtraEnv does clear a value the proxy already has,
// because childhook.go spawns with append(os.Environ(), ExtraEnv...) and Go's
// os/exec keeps the LAST occurrence of a duplicated key.
func TestDeepScanMode_ChildSocketAlwaysStripped(t *testing.T) {
	// The proxy's own environment has a socket — the situation that produces the
	// bug, not a hypothetical one: Personal installs set it for the daemon.
	t.Setenv("AIKEY_DEEPSCAN_SOCKET", "/var/run/aikey/deepscan.sock")

	for _, tc := range []struct {
		name string
		sup  *Supervisor
	}{
		{"personal (no cluster, no nodes)", newTestSupervisor(t, false)},
		{"team / cluster", newTestSupervisor(t, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.sup.filterChildEnv("AIKEY_COMPLIANCE_RECORD_ALLOW=0", "AIKEY_COMPLIANCE_FILTER_MAX_ACTION=full")

			got, found := lastEnvValue(env, "AIKEY_DEEPSCAN_SOCKET")
			if !found {
				t.Fatalf("the child env does not mention AIKEY_DEEPSCAN_SOCKET at all, so it INHERITS %q from the proxy "+
					"and both processes forward the same content", os.Getenv("AIKEY_DEEPSCAN_SOCKET"))
			}
			if got != "" {
				t.Errorf("child would run with AIKEY_DEEPSCAN_SOCKET=%q; it must be empty in every mode (mode=%s)",
					got, tc.sup.deepScanMode())
			}
		})
	}
}

// TestDeepScanMode_OperatorOffIsHonoured pins the one explicit kill switch.
func TestDeepScanMode_OperatorOffIsHonoured(t *testing.T) {
	sup := newTestSupervisor(t, false)
	if got := sup.deepScanMode(); got != DeepScanModeLocal {
		t.Errorf("default mode with no nodes should be %q, got %q", DeepScanModeLocal, got)
	}
	t.Setenv("AIKEY_PROXY_DEEPSCAN_MODE", "off")
	if got := sup.deepScanMode(); got != DeepScanModeOff {
		t.Errorf("AIKEY_PROXY_DEEPSCAN_MODE=off must win, got %q", got)
	}
	// ...and the socket is still stripped when deep scan is off entirely: the
	// detector must not become the forwarder just because the proxy stopped.
	t.Setenv("AIKEY_DEEPSCAN_SOCKET", "/var/run/aikey/deepscan.sock")
	env := sup.filterChildEnv("AIKEY_COMPLIANCE_RECORD_ALLOW=0", "AIKEY_COMPLIANCE_FILTER_MAX_ACTION=full")
	if v, found := lastEnvValue(env, "AIKEY_DEEPSCAN_SOCKET"); !found || v != "" {
		t.Errorf("mode=off must still strip the child socket, got %q (found=%v)", v, found)
	}
}

// lastEnvValue mirrors os/exec's duplicate-key rule: the LAST occurrence wins.
func lastEnvValue(env []string, key string) (string, bool) {
	val, found := "", false
	for _, e := range env {
		if strings.HasPrefix(e, key+"=") {
			val, found = e[len(key)+1:], true
		}
	}
	return val, found
}

// newTestSupervisor builds the minimum Supervisor these fences need. Cluster
// mode is the axis that matters here: it is the one that changes which env the
// detector child gets.
func newTestSupervisor(t *testing.T, cluster bool) *Supervisor {
	t.Helper()
	cfg := &config.Config{}
	cfg.Cluster.Enabled = cluster
	return &Supervisor{cfg: cfg}
}
