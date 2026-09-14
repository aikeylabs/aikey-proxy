package apphook

// detector_gate_test.go — the ONE sanctioned way an apphook test obtains the
// sibling ai-compliance-detector binary, plus the 能红 fence for that policy.
//
// ── The false green this file exists to prevent (BR-v1.0.5-26) ───────────────
// 11 tests in this package (childhook_test, childhook_sticky_test,
// childhook_bench_test, childhook_listpacks_test, filterpool_test,
// matrix_bench_test) are the ONLY coverage of the proxy↔detector IPC contract:
// concurrent request-id multiplexing, crash self-heal, sticky routing,
// list-packs, and the filter worker pool. Every one of them used to reach for a
// PRE-BUILT ../ai-compliance-detector/bin/detector and `t.Skipf` when it was not
// there — while nothing in the build ever produced it. So the whole suite could
// evaporate and the release log still read green.
//
// 🔴 The counter-intuitive half: `go test` WITHOUT -v pipes the test binary's
// stdout+stderr into its own buffer and DISCARDS that buffer for any package
// that passes — and a skipping test passes. A reason written into `t.Skipf` (or
// even os.Stderr) is therefore invisible in the default invocation this bug hid
// behind. That is why emitLoudBanner also writes /dev/tty.
//
// ── Policy ───────────────────────────────────────────────────────────────────
//
//	AIKEY_REQUIRE_NO_TEST_SKIPS=1  → any detector-related skip is a hard failure.
//	                                 `make test` sets this automatically whenever
//	                                 the sibling repo IS checked out, because it
//	                                 has just built the binary: nothing legitimate
//	                                 can skip after that.
//	unset / 0 (partial checkout)   → still skip (a developer must be able to run
//	                                 this repo's suite without the sibling repo),
//	                                 but loudly, on /dev/tty + stderr.
//	AIKEY_TEST_DETECTOR_BINARY=<p> → use THAT binary instead of the sibling repo's
//	                                 bin/detector (same variable and meaning as
//	                                 internal/proxy's live-test door). A named
//	                                 path that is not a file FAILS in both modes:
//	                                 a typo is a defect, not an environment fact.
//
// Missing repo and broken repo are deliberately NOT collapsed: "not cloned" is
// an environment fact (release.sh gates its own detector fences on
// `[ -d "${ACD_DIR}/.git" ]` for the same reason), "cloned but unusable" is a
// defect signal. Collapsing the two is the original bug.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/detectortest"
)

// requireNoSkipsEnv is the project-wide "a skip is not a pass" switch. Reused,
// NOT invented: workflow/CI/Makefile sets it on the release gate and
// aikey-control-master's Stage C E2E already honors it. Truthiness matches
// those exactly — the literal "1".
const requireNoSkipsEnv = "AIKEY_REQUIRE_NO_TEST_SKIPS"

// detectorRepoOverrideEnv relocates the sibling repo lookup. TEST-ONLY: it
// exists solely so the skip-policy fence below can exercise the "repo missing"
// branch without deleting the real sibling checkout (which other sessions may be
// editing). Same AIKEY_TEST_* family as aikey-control-master's identical hook;
// it lives in a _test.go file and reaches no shipped binary.
const detectorRepoOverrideEnv = "AIKEY_TEST_DETECTOR_REPO"

// detectorBinaryEnv names an explicitly built detector and takes precedence
// over the sibling repo lookup. Reused, NOT invented: internal/proxy's
// live-test door already reads this exact variable, and TestChildHook_ListPacks
// has described this gate as honoring it since 2026-08-17 — while the gate never
// read it. Without it, the only way to run this suite against a freshly built
// detector was to overwrite the SHARED sibling bin/detector, which other
// sessions on the same checkout may be executing.
// Bugfix: workflow/CI/bugfix/20260914-apphook-detector-gate-ignores-binary-env.md
// Fence: TestDetectorGateSkipPolicy/binary_env_wins_over_sibling_lookup
const detectorBinaryEnv = "AIKEY_TEST_DETECTOR_BINARY"

var (
	errDetectorRepoMissing      = errors.New("ai-compliance-detector repo is not checked out")
	errDetectorNotBuilt         = errors.New("ai-compliance-detector/bin/detector was never built")
	errDetectorEnvBinaryInvalid = errors.New("the explicitly named detector binary is not a usable file")
)

func strictNoSkips() bool {
	return strings.TrimSpace(os.Getenv(requireNoSkipsEnv)) == "1"
}

// detectorRepoDir resolves the sibling repo from THIS file's location, so the
// answer does not depend on the working directory `go test` happens to use.
func detectorRepoDir() string {
	if override := strings.TrimSpace(os.Getenv(detectorRepoOverrideEnv)); override != "" {
		return override
	}
	_, file, _, _ := runtime.Caller(0)
	apphookDir := filepath.Dir(file)                   // …/aikey-proxy/internal/apphook
	proxyDir := filepath.Dir(filepath.Dir(apphookDir)) // …/aikey-proxy
	return filepath.Join(filepath.Dir(proxyDir), "ai-compliance-detector")
}

// locateDetectorBinary returns the built detector, or a CLASSIFIED error.
//
// No exec-bit check on purpose: Go reports 0666 for ordinary files on Windows,
// so a permission probe there would reject a perfectly good binary. Existence +
// "not a directory" is what this layer can assert portably; an unusable binary
// surfaces as a Start() error, which the skip guard below also catches.
//
// The second return value names where the binary came from, so the door can
// say which detector answered — a stale sibling build (2026-09-14) turned
// TestChildHook_ListPacks red with nothing in the output pointing at the binary.
func locateDetectorBinary() (string, string, error) {
	// Explicit beats implicit: a caller who named a binary wants THAT binary,
	// even when a (possibly stale) sibling build also exists.
	if explicit := strings.TrimSpace(os.Getenv(detectorBinaryEnv)); explicit != "" {
		if statErr := statDetectorFile(explicit); statErr != nil {
			return "", "", fmt.Errorf("%w (%s=%s): %w", errDetectorEnvBinaryInvalid, detectorBinaryEnv, explicit, statErr)
		}
		return explicit, detectorBinaryEnv, nil
	}

	repo := detectorRepoDir()
	// `.git` (dir or gitdir-file, so linked worktrees count) mirrors release.sh's
	// own gate for "is this sibling repo part of the checkout at all".
	if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
		return "", "", fmt.Errorf("%w (looked in %s)", errDetectorRepoMissing, repo)
	}
	binary := filepath.Join(repo, "bin", "detector")
	if statErr := statDetectorFile(binary); statErr != nil {
		return "", "", fmt.Errorf("%w (%s): %w", errDetectorNotBuilt, binary, statErr)
	}
	return binary, "sibling repo build", nil
}

// statDetectorFile is the one existence check both sources share (existence +
// not a directory; see the exec-bit note on locateDetectorBinary).
func statDetectorFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	return nil
}

// requireSealedDetector is the ONLY sanctioned way for a test in this package to
// obtain the detector binary. Do not stat the path yourself and do not hand-roll
// a `t.Skipf` on the result — that is precisely the shape this replaces.
//
// ── The second thing this door owns (2026-08-14) ─────────────────────────────
//
// It also SEALS the host state before returning, so no test in this package can
// spawn a child that reads the developer's `~/.aikey`. See internal/detectortest
// for the four $HOME-rooted detector inputs and why sealing AIKEY_PACK_CACHE_DIR
// alone is not enough.
//
// This is not hypothetical here: TestChildHook_ListPacks asserts
// `lane_actions.CN_ADDRESS == "mask"`, and a policy.json ops override in a real
// home (host input #2, which has NO environment switch) turns it to "audit" —
// measured 2026-08-14, the test goes RED purely because of a file in the
// developer's home directory. Sealing is applied unconditionally, including for
// the `--echo-only` children that read none of the four inputs: an exemption is
// how a second, unsealed path gets established.
//
// Callers that spawn a REAL (non-echo) child must additionally call
// sealed.AssertHeld once the child is up. Setting the environment is not proof
// that the child honored it — deleting the seal must turn a test RED, not
// quietly hand it host state.
func requireSealedDetector(t *testing.T) (string, detectortest.Sealed) {
	t.Helper()

	binary, source, err := locateDetectorBinary()
	if err == nil {
		// Visible under -v and on any failure, so a red assertion downstream can
		// be traced to WHICH binary answered.
		t.Logf("detector binary: %s (from %s)", binary, source)
		// The binary exists, so from here on a skip can only come from the
		// test's own Start() failure path — a defect, not an environment fact.
		forbidSilentSkip(t)
		return binary, detectortest.Seal(t)
	}

	reason, fix := classifyDetectorErr(err)
	// A binary the caller NAMED that is not there is never an environment fact,
	// so the local-dev skip does not apply: skipping would print "ok" for a run
	// that tested nothing the caller asked for.
	if errors.Is(err, errDetectorEnvBinaryInvalid) {
		t.Fatalf("%s: %s\n  Fix: %s\n  Underlying error: %v", detectorBinaryEnv, reason, fix, err)
	}
	if strictNoSkips() {
		t.Fatalf("%s=1 forbids skipping: %s\n"+
			"  The internal/apphook suite is the ONLY coverage of the proxy↔detector IPC\n"+
			"  contract (multiplexing / crash self-heal / sticky / listpacks / filterpool);\n"+
			"  skipping here would report an unverified cross-repo contract as a pass.\n"+
			"  Fix: %s\n"+
			"  Underlying error: %v", requireNoSkipsEnv, reason, fix, err)
	}

	emitLoudBanner(fmt.Sprintf(detectorSkipBanner, t.Name(), reason, fix, err, requireNoSkipsEnv))
	t.Skipf("proxy↔detector IPC contract NOT covered — %s (set %s=1 to fail instead)",
		reason, requireNoSkipsEnv)
	return "", detectortest.Sealed{}
}

// requireDetectorBinary is the convenience form for the `--echo-only` children,
// which read none of the sealed inputs and therefore have nothing to assert
// afterwards. It is a thin wrapper, NOT a second door: the sealing (and the
// skip policy) still happens in exactly one place.
func requireDetectorBinary(t *testing.T) string {
	t.Helper()
	binary, _ := requireSealedDetector(t)
	return binary
}

func classifyDetectorErr(err error) (reason, fix string) {
	switch {
	case errors.Is(err, errDetectorEnvBinaryInvalid):
		return "the detector binary named by " + detectorBinaryEnv + " does not exist or is a directory",
			"point " + detectorBinaryEnv + " at a built detector (absolute path — `go test` runs in the package directory), " +
				"or unset it to use the sibling repo's bin/detector"
	case errors.Is(err, errDetectorRepoMissing):
		return "the sibling ai-compliance-detector repo is not checked out",
			"clone ai-compliance-detector next to aikey-proxy, or set " + detectorBinaryEnv + " to a detector you built"
	case errors.Is(err, errDetectorNotBuilt):
		return "the sibling ai-compliance-detector repo is checked out but its binary was never built",
			"run `make test` (it builds the sibling detector first) instead of a bare `go test`, " +
				"or set " + detectorBinaryEnv + " to a detector you built"
	default:
		return "the detector binary could not be located", "see the error above"
	}
}

// forbidSilentSkip closes the second half of the hole. requireDetectorBinary
// only proves the binary is ON DISK; each caller then runs Start() and, on
// failure, does its own `t.Skipf`. Those 11 skips would still be invisible.
//
// Registering ONE cleanup here — rather than editing 11 call sites — keeps a
// single door: "a test that asked for the detector must not end up skipped".
// Verified empirically 2026-08-10: t.Errorf inside a Cleanup turns a SKIP into
// a FAIL, and that FAIL is printed by plain `go test` (no -v needed).
func forbidSilentSkip(t *testing.T) {
	t.Cleanup(func() {
		if !t.Skipped() {
			return
		}
		reason := "the detector binary was found, but the test skipped anyway (Start() failed?)"
		fix := "read the skip message above; a built detector that will not start is a defect, not an environment fact"
		if strictNoSkips() {
			t.Errorf("%s=1 forbids skipping: %s\n  Fix: %s", requireNoSkipsEnv, reason, fix)
			return
		}
		emitLoudBanner(fmt.Sprintf(detectorSkipBanner, t.Name(), reason, fix,
			errors.New("see the skip message in this test's output"), requireNoSkipsEnv))
	})
}

const detectorSkipBanner = `
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! SKIPPED, NOT PASSED — %s
!!
!! The proxy<->detector IPC contract (request-id multiplexing / crash self-heal /
!! sticky routing / listpacks / filterpool) has ZERO coverage in this run. The
!! "ok" line for package internal/apphook does NOT mean that contract holds.
!!
!! Reason : %s
!! Fix    : %s
!! Detail : %v
!!
!! CI/release: export %s=1 to turn this into a hard
!! failure. ` + "`make test`" + ` does that automatically whenever the sibling repo is
!! present, so this banner must never appear in a release run.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

`

// emitLoudBanner writes to BOTH the controlling terminal and stderr, on purpose.
//
// 🔴 Why not just os.Stderr (the obvious implementation — and a no-op): `go test`
// discards the test binary's output for any package that passes, and a skipping
// test passes. /dev/tty bypasses that buffer so a developer in a terminal
// actually sees this; os.Stderr is the machine-readable copy the fence asserts
// on. The tty handle is opened (functional probe), never stat-probed, per the
// project's installer-TTY rule; absent/unopenable (CI, Windows, nohup) is fine.
func emitLoudBanner(msg string) {
	if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
		_, _ = io.WriteString(tty, msg)
		_ = tty.Close()
	}
	_, _ = io.WriteString(os.Stderr, msg)
}

// ─────────────────────────────────────────────────────────────────────────────
// 能红 fence
// ─────────────────────────────────────────────────────────────────────────────

// detectorGateChildEnv re-enters this test binary as a child so the policy can
// be OBSERVED (exit code + output) instead of asserted about.
const detectorGateChildEnv = "AIKEY_TEST_APPHOOK_GATE_CHILD"

// TestDetectorGateProbe is the child leg: it does nothing but ask the gate for a
// binary. Driven by TestDetectorGateSkipPolicy; inert in a normal run.
func TestDetectorGateProbe(t *testing.T) {
	if os.Getenv(detectorGateChildEnv) != "1" {
		t.Skip("child-only probe, driven by TestDetectorGateSkipPolicy")
	}
	_ = requireDetectorBinary(t)
}

// TestDetectorGateSkipPolicy proves both legs of the policy actually behave that
// way. Without it, "a missing sibling repo now fails the release gate" is a
// claim; the first attempt at this class of fix in aikey-control-master was
// itself a silent no-op for exactly this reason.
func TestDetectorGateSkipPolicy(t *testing.T) {
	if os.Getenv(detectorGateChildEnv) == "1" {
		t.Skip("parent leg does not re-enter itself")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}

	run := func(t *testing.T, strict, binaryEnv string) (string, int) {
		t.Helper()
		cmd := exec.Command(self, "-test.run", "^TestDetectorGateProbe$", "-test.v")
		cmd.Env = append(os.Environ(),
			detectorGateChildEnv+"=1",
			// A path that cannot exist → the "repo missing" branch, without
			// touching the real sibling checkout.
			detectorRepoOverrideEnv+"="+filepath.Join(t.TempDir(), "no-such-detector-repo"),
			requireNoSkipsEnv+"="+strict,
			// Always set, even to "": a developer's exported binary variable would
			// otherwise bypass the repo-missing branch the first two legs observe.
			detectorBinaryEnv+"="+binaryEnv,
		)
		out, err := cmd.CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("run child (%s=%q): %v\n%s", requireNoSkipsEnv, strict, err, out)
		}
		return string(out), code
	}

	t.Run("strict_fails_never_skips", func(t *testing.T) {
		out, code := run(t, "1", "")
		if code == 0 {
			t.Fatalf("strict leg exited 0 — a missing sibling repo still reads as a pass:\n%s", out)
		}
		if !strings.Contains(out, "--- FAIL") {
			t.Errorf("strict leg has no --- FAIL:\n%s", out)
		}
		if strings.Contains(out, "--- SKIP") {
			t.Errorf("strict leg SKIPPED — %s=1 must forbid that:\n%s", requireNoSkipsEnv, out)
		}
		if !strings.Contains(out, "repo is not checked out") {
			t.Errorf("strict leg does not name the cause:\n%s", out)
		}
	})

	t.Run("local_skips_but_is_loud", func(t *testing.T) {
		out, code := run(t, "", "")
		if code != 0 {
			t.Fatalf("non-strict leg exited %d — local dev must stay runnable without the sibling repo:\n%s", code, out)
		}
		if !strings.Contains(out, "--- SKIP") {
			t.Errorf("non-strict leg did not skip:\n%s", out)
		}
		for _, want := range []string{"SKIPPED, NOT PASSED", "ZERO coverage", requireNoSkipsEnv} {
			if !strings.Contains(out, want) {
				t.Errorf("non-strict leg banner missing %q:\n%s", want, out)
			}
		}
	})

	// The sibling repo is deliberately missing and strict mode is on, so the ONLY
	// way this leg can exit 0 is that the gate read detectorBinaryEnv. The probe
	// never starts the child, so an empty placeholder file is enough.
	// Bugfix: workflow/CI/bugfix/20260914-apphook-detector-gate-ignores-binary-env.md
	t.Run("binary_env_wins_over_sibling_lookup", func(t *testing.T) {
		placeholder := filepath.Join(t.TempDir(), "detector")
		if err := os.WriteFile(placeholder, nil, 0o600); err != nil {
			t.Fatalf("write placeholder binary: %v", err)
		}
		out, code := run(t, "1", placeholder)
		if code != 0 {
			t.Fatalf("exited %d with %s set — the gate ignored it and fell back to the (missing) sibling repo:\n%s",
				code, detectorBinaryEnv, out)
		}
		if strings.Contains(out, "--- SKIP") {
			t.Errorf("skipped although %s named a file:\n%s", detectorBinaryEnv, out)
		}
		if !strings.Contains(out, placeholder) {
			t.Errorf("the gate did not name the binary it chose:\n%s", out)
		}
	})

	t.Run("missing_binary_env_fails_even_locally", func(t *testing.T) {
		out, code := run(t, "", filepath.Join(t.TempDir(), "no-such-detector"))
		if code == 0 {
			t.Fatalf("exited 0 — a %s naming nothing reads as a pass:\n%s", detectorBinaryEnv, out)
		}
		if !strings.Contains(out, "--- FAIL") {
			t.Errorf("no --- FAIL:\n%s", out)
		}
		if strings.Contains(out, "--- SKIP") {
			t.Errorf("SKIPPED — an explicitly named binary must never degrade to a skip:\n%s", out)
		}
		if !strings.Contains(out, detectorBinaryEnv) {
			t.Errorf("failure does not name %s:\n%s", detectorBinaryEnv, out)
		}
	})
}
