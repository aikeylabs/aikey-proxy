// Package probes holds one-off SPIKE probes that measure real runtime behaviour
// the design has to assume. They are not fences: they answer a question once,
// the answer is written into the design package's baseline-forensics.md, and the
// probe stays only so the measurement can be re-run on a new Go / OS version.
//
// SPIKE — openspec/changes/add-scan-node-deepscan tasks.md 1.2
// Question: does appending "KEY=" to ChildHookConfig.ExtraEnv actually clear a
// KEY the proxy already has in its own environment, given that
// internal/apphook/childhook.go:251-253 spawns the child with
// `cmd.Env = append(os.Environ(), ExtraEnv...)`?
package probes

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const probeVar = "AIKEY_DEEPSCAN_SOCKET"

// TestSpikeExtraEnvEmptyValueOverridesParent re-executes this test binary as the
// "child" and has it print what it reads for probeVar. The parent side sets
// probeVar=/x in its OWN environment and then appends "probeVar=" the exact way
// spawnLocked does, so the measurement covers Go's os/exec duplicate-key rule
// rather than our belief about it.
func TestSpikeExtraEnvEmptyValueOverridesParent(t *testing.T) {
	if os.Getenv("AIKEY_PROBE_CHILD") == "1" {
		// Child leg: report what the environment actually holds.
		v, present := os.LookupEnv(probeVar)
		os.Stdout.WriteString("VALUE=[" + v + "] PRESENT=" + boolStr(present) + "\n")
		return
	}

	t.Setenv(probeVar, "/x") // the parent proxy's own env already has a socket

	cmd := exec.Command(os.Args[0], "-test.run", "^TestSpikeExtraEnvEmptyValueOverridesParent$")
	// Byte-for-byte the spawn shape of childhook.go:251-253.
	extraEnv := []string{"AIKEY_PROBE_CHILD=1", probeVar + "="}
	cmd.Env = append(os.Environ(), extraEnv...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("probe child failed: %v\n%s", err, out)
	}
	line := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "VALUE=") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("probe child printed no VALUE line:\n%s", out)
	}
	t.Logf("MEASURED parent %s=/x + ExtraEnv %q -> child reads %s", probeVar, probeVar+"=", line)

	if line != "VALUE=[] PRESENT=true" {
		t.Fatalf("ExtraEnv did NOT clear the inherited value: %s", line)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
