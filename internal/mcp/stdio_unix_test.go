//go:build !windows

package mcp

// Unix-only P5 fences and the process-table helpers they need.
//
// 🔴 What is NOT covered on Windows, stated rather than left to be discovered:
// the orphan-reaping property has a Windows fence
// (pkg/aikeycompat/procgroup_windows_test.go, Job Object), but the
// "credential is not in argv" check does NOT — it reads the process table via
// `ps`. A Windows equivalent would use WMI/CIM, and until somebody writes it,
// 5.F4 is proven on macOS/Linux only.
//
// 🔴 Split out under a build tag so the package still COMPILES on Windows.
// syscall.Kill does not exist there, and a test file that fails to build takes
// the whole package's Windows vet down with it — which is how a cross-platform
// product stops noticing that half its tests never run on half its platforms.
// The Windows equivalents live in pkg/aikeycompat/procgroup_windows_test.go.

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestStdio_CredentialReachesTheChildEnvironmentAndNotItsCommandLine.
//
// Both halves are required and neither alone is worth anything:
//
//	"not in argv"  passes trivially against a build that never delivers it
//	"in the env"   passes against a build that ALSO puts it in argv
func TestStdio_CredentialReachesTheChildEnvironmentAndNotItsCommandLine(t *testing.T) {
	const secret = "pg_PLAINTEXT_MUST_ONLY_BE_IN_ENV_4a91"
	tr := newStdio(t)
	b := stdioBackend(t, map[string]string{"FAKEMCP_SECRET_ENV": "PGPASSWORD"},
		UpstreamCredential{Kind: CredentialKindEnv, HeaderName: "PGPASSWORD", Secret: secret})
	b.CredentialID = "c1"

	res, err := tr.CallTool(context.Background(), b, "echo_secret_presence", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	// (1) The child really did receive it.
	if want := "secret_from_env=" + secret; res.Content[0].Text != want {
		t.Fatalf("the credential did not reach the child's environment: %q", res.Content[0].Text)
	}

	// (2) It is nowhere in the process's command line.
	//
	// 🔴 Read from the OS, not from our own struct: argv is what `ps` shows to
	// every other user on the machine, and the whole point is what an outsider
	// can see.
	pid := childPID(t, tr, b.ID)
	cmdline := processCommandLine(t, pid)
	if cmdline == "" {
		t.Fatalf("could not read the command line of pid %d; this fence cannot be trusted "+
			"on this platform and must not be reported as passing", pid)
	}
	if strings.Contains(cmdline, secret) {
		t.Fatalf("🔴 the credential is in the child's ARGV, visible to every user on this "+
			"machine via ps:\n%s", cmdline)
	}
	if strings.Contains(cmdline, "PLAINTEXT_MUST_ONLY_BE_IN_ENV") {
		t.Fatalf("🔴 part of the credential is in the child's ARGV:\n%s", cmdline)
	}
}

// TestStdio_ShutdownReapsTheChildAndItsDescendants.
//
// aikeycompat has its own fence for the process-tree primitive. This one proves
// the TRANSPORT actually uses it — a correct primitive that nobody calls reaps
// nothing.
func TestStdio_ShutdownReapsTheChildAndItsDescendants(t *testing.T) {
	tr := NewStdioTransport(nil)
	b := stdioBackend(t, map[string]string{"FAKEMCP_SPAWN_WORKER": "1"}, UpstreamCredential{})

	if _, err := tr.ListTools(context.Background(), b); err != nil {
		t.Fatalf("start: %v", err)
	}
	child := childPID(t, tr, b.ID)
	worker := waitForWorkerPID(t, child)

	tr.Shutdown(context.Background())

	if !waitPidGone(worker, 5*time.Second) {
		_ = syscall.Kill(worker, syscall.SIGKILL)
		t.Fatalf("🔴 ORPHAN: the backend's worker (pid %d) survived gateway shutdown. On a real "+
			"backend that process is holding the decrypted database password, reparented to "+
			"init, with no proxy left to ask it to exit.", worker)
	}
	if !waitPidGone(child, 5*time.Second) {
		t.Fatalf("🔴 ORPHAN: the backend process (pid %d) survived gateway shutdown", child)
	}
}

func waitPidGone(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return syscall.Kill(pid, 0) != nil
}

// processCommandLine reads a pid's argv from the OS.
func processCommandLine(t *testing.T, pid int) string {
	t.Helper()
	out, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// waitForWorkerPID reads the grandchild pid the fake server prints to stderr.
//
// The transport drains stderr into the logger, so the pid is recovered from the
// process table instead: the worker is the `sleep 300` whose parent is the
// backend process.
func waitForWorkerPID(t *testing.T, parent int) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("ps", "-o", "pid=,ppid=", "-ax").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				f := strings.Fields(line)
				if len(f) != 2 {
					continue
				}
				pid, _ := strconv.Atoi(f[0])
				ppid, _ := strconv.Atoi(f[1])
				if ppid == parent && pid != parent {
					return pid
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the backend never spawned a worker; the orphan scenario did not set up, so "+
		"this fence would pass vacuously (parent pid %d)", parent)
	return 0
}
