package detectortest

// seal_fence_test.go — makes "a new test spawns the detector without sealing the
// host state" a MACHINE failure instead of something someone has to notice.
//
// ── Why the fence is shaped like this ───────────────────────────────────────
//
// The rule this file enforces is written against the CONCEPT — "how many ways
// can a test in this repo obtain a real detector binary?" — not against the
// files that happened to be touched on 2026-08-14. There are exactly three
// primitive sources for that path, and a test cannot spawn the detector without
// one of them:
//
//	AIKEY_TEST_DETECTOR_BINARY   the env-provided binary (proxy live tests)
//	"bin", "detector"            the sibling repo's build output
//	locateDetectorBinary         the sibling repo resolver + skip policy (apphook)
//
// So the fence pins each of those tokens to ONE file per package, and requires
// that file to call detectortest.Seal. Anything else — a new live test reading
// the env var itself, a helper re-deriving ../ai-compliance-detector/bin — adds
// a second occurrence and turns this red, naming the file and the fix.
//
// Writing the rule that way immediately paid for itself: it found a FOURTH
// spawner nobody had listed, internal/supervisor's max-action integration
// harness, which built the sibling path by hand and sealed only HOME. The
// hand-written list would not have contained it.
//
// It also forbids re-rolling a PARTIAL seal by hand: AIKEY_PACK_CACHE_DIR
// outside this package is exactly the historical mistake (it covers one of the
// four $HOME-rooted detector inputs, and sealing only it is what let the NSFW
// live test read the developer's policy.json, address dictionaries and
// local-server config for months). See the package doc for the four inputs.
//
// Fence of the fence: TestScanPackage_CatchesAForgottenSeal plants a violating
// file in a temp dir and requires the scanner to report it, so "the fence is
// green" cannot mean "the scanner stopped looking".

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// detectorPathTokens are the source-level primitives that can yield a detector
// binary path. Keyed by a human name so a failure can say WHICH door leaked.
var detectorPathTokens = map[string]string{
	"env-provided binary":   "AIKEY_TEST_DETECTOR_BINARY",
	"sibling repo build":    `"bin", "detector"`,
	"sibling repo resolver": "locateDetectorBinary",
}

// sealTokens are the environment keys that constitute the seal. Spelled here as
// literals ON PURPOSE: this fence's job is to find hand-rolled copies, so it
// cannot look for the constant that the sanctioned implementation uses.
var sealTokens = []string{"AIKEY_PACK_CACHE_DIR"}

// sealCall is what a door must contain to count as sealing.
const sealCall = "detectortest.Seal("

// fencedPackages are the packages that spawn detector children. A package that
// starts spawning detectors and is not listed here is not protected — which is
// why TestFencedPackagesCoverEveryDetectorSpawner rediscovers the list from the
// source tree instead of trusting this one.
//
// supervisor is here because its max-action integration harness spawns a real
// child through the supervisor's own install path; it obtains the binary from
// detectortest.SiblingBinary, so it holds none of the tokens itself — the entry
// documents that it is IN scope, not that it currently violates anything.
var fencedPackages = []string{"proxy", "apphook", "supervisor"}

func repoInternalDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(file)) // .../aikey-proxy/internal
}

// TestDetectorBinaryHasExactlyOneDoorPerPackage is the fence.
func TestDetectorBinaryHasExactlyOneDoorPerPackage(t *testing.T) {
	internal := repoInternalDir(t)
	for _, pkg := range fencedPackages {
		dir := filepath.Join(internal, pkg)
		doors, err := scanPackage(dir)
		if err != nil {
			t.Fatalf("scan %s: %v", dir, err)
		}
		for name, files := range doors.byToken {
			if len(files) == 0 {
				continue // that package simply does not use this source
			}
			if len(files) > 1 {
				t.Errorf("internal/%s: the %q detector-binary source appears in %d files: %v\n"+
					"  Every detector-spawning test must obtain its binary from the package's ONE door,\n"+
					"  which seals the host state (see internal/detectortest for the four $HOME-rooted\n"+
					"  inputs the detector reads). A second source means a child can be spawned that\n"+
					"  reads the developer's ~/.aikey, and its verdicts are then not attributable to the\n"+
					"  binary under test.\n"+
					"  Fix: call liveDetectorBinary (internal/proxy), requireSealedDetector\n"+
					"  (internal/apphook), or detectortest.SiblingBinary (the sibling-repo build, usable\n"+
					"  from any package) instead of resolving the path yourself.",
					pkg, name, len(files), files)
				continue
			}
			if !doors.seals[files[0]] {
				t.Errorf("internal/%s: %s resolves a detector binary (%q) but never calls %s\n"+
					"  A door that does not seal is not a door — every child it hands out inherits the\n"+
					"  developer's ~/.aikey (pack cache, policy.json ops override, address dictionaries,\n"+
					"  local-server config).",
					pkg, files[0], name, sealCall)
			}
		}
		for _, tok := range doors.handRolledSeals {
			t.Errorf("internal/%s: %s\n"+
				"  Sealing belongs to internal/detectortest, which seals HOME + USERPROFILE +\n"+
				"  AIKEY_PACK_CACHE_DIR together. A hand-rolled partial seal is the exact 2026-08-14\n"+
				"  defect: AIKEY_PACK_CACHE_DIR covers ONE of the detector's four $HOME-rooted inputs,\n"+
				"  so setting it alone leaves policy.json / address assets / control.yaml wide open.",
				pkg, tok)
		}
	}
}

// TestFencedPackagesCoverEveryDetectorSpawner keeps the list above honest: any
// package under internal/ whose tests mention a detector-binary source must be
// fenced. Without this, adding a third spawning package would silently escape.
func TestFencedPackagesCoverEveryDetectorSpawner(t *testing.T) {
	internal := repoInternalDir(t)
	entries, err := os.ReadDir(internal)
	if err != nil {
		t.Fatalf("read %s: %v", internal, err)
	}
	fenced := map[string]bool{}
	for _, p := range fencedPackages {
		fenced[p] = true
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "detectortest" || fenced[e.Name()] {
			continue
		}
		doors, err := scanPackage(filepath.Join(internal, e.Name()))
		if err != nil {
			t.Fatalf("scan %s: %v", e.Name(), err)
		}
		for name, files := range doors.byToken {
			if len(files) > 0 {
				t.Errorf("internal/%s resolves a detector binary (%q in %v) but is not in fencedPackages\n"+
					"  Add it to fencedPackages and give it a sealing door, or the seal rule does not\n"+
					"  apply to it at all.", e.Name(), name, files)
			}
		}
	}
}

// TestDetectorTestIsNeverLinkedIntoTheBinary keeps this package's contract:
// production code must not import it (it pulls in `testing`, which registers
// flags on the shipped binary). Mirrors internal/egresstest's own contract.
func TestDetectorTestIsNeverLinkedIntoTheBinary(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(filepath.Dir(file))) // .../aikey-proxy
	const self = "aikey-proxy/internal/detectortest"
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil //nolint:nilerr // an unreadable tree entry is not this fence's business
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil || !strings.Contains(string(data), self) {
			return nil //nolint:nilerr // same
		}
		rel, _ := filepath.Rel(root, path)
		t.Errorf("%s is NOT a _test.go file but imports %s — that links `testing` into the shipped "+
			"binary and makes a test-only helper part of the product.", rel, self)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// ─── scanner ────────────────────────────────────────────────────────────────

type doorScan struct {
	// byToken maps a detector-binary source name → the _test.go files that use it.
	byToken map[string][]string
	// seals records which files call detectortest.Seal.
	seals map[string]bool
	// handRolledSeals describes seal environment keys found outside this package.
	handRolledSeals []string
}

// scanPackage reads the _test.go files of one package directory. It parses with
// go/parser so a token inside a /* … */ block comment (this fence's own prose,
// for one) is not mistaken for code.
func scanPackage(dir string) (doorScan, error) {
	out := doorScan{byToken: map[string][]string{}, seals: map[string]bool{}}
	for name := range detectorPathTokens {
		out.byToken[name] = nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out, err
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return out, readErr
		}
		// Comments are stripped so the WHY prose in a door (which necessarily
		// names the tokens) cannot register as a second occurrence.
		// ParseComments is REQUIRED: without it f.Comments is empty and renderCode
		// blanks nothing, so every door's own explanatory prose counts as a second
		// occurrence and the fence is permanently red for the wrong reason.
		f, parseErr := parser.ParseFile(fset, path, raw, parser.ParseComments|parser.SkipObjectResolution)
		if parseErr != nil {
			return out, fmt.Errorf("parse %s: %w", path, parseErr)
		}
		code := renderCode(fset, f, raw)
		for name, tok := range detectorPathTokens {
			if strings.Contains(code, tok) {
				out.byToken[name] = append(out.byToken[name], e.Name())
			}
		}
		if strings.Contains(code, sealCall) {
			out.seals[e.Name()] = true
		}
		for _, tok := range sealTokens {
			if strings.Contains(code, tok) {
				out.handRolledSeals = append(out.handRolledSeals,
					fmt.Sprintf("%s sets %s by hand", e.Name(), tok))
			}
		}
	}
	return out, nil
}

// renderCode returns the file's source with comments removed, by blanking out
// every comment span in the original bytes. Cheaper and more faithful than
// re-printing the AST (which would normalise string literals and could hide a
// token behind different quoting).
func renderCode(fset *token.FileSet, f *ast.File, raw []byte) string {
	out := append([]byte(nil), raw...)
	base := fset.File(f.Pos()).Base()
	for _, group := range f.Comments {
		start, end := int(group.Pos())-base, int(group.End())-base
		if start < 0 || end > len(out) || start >= end {
			continue
		}
		for i := start; i < end; i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	return string(out)
}

// ─── fence of the fence ─────────────────────────────────────────────────────

// TestScanPackage_CatchesAForgottenSeal is the 能红 proof. It plants the two
// shapes the fence exists to catch — a second file reaching for the binary, and
// a door that seals by hand — and requires the scanner to see both. A fence
// whose scanner silently stopped matching would otherwise report "no violations"
// forever.
func TestScanPackage_CatchesAForgottenSeal(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// The sanctioned door.
	write("door_test.go", `package p
func door(t *testing.T) string {
	bin := os.Getenv("AIKEY_TEST_DETECTOR_BINARY")
	_ = detectortest.Seal(t)
	return bin
}
`)
	// A new live test that reached for the env var itself — the thing that must
	// be impossible to do quietly.
	write("forgot_seal_live_test.go", `package p
func TestSomethingLive(t *testing.T) {
	bin := os.Getenv("AIKEY_TEST_DETECTOR_BINARY")
	_ = bin
}
`)
	// A hand-rolled partial seal.
	write("handrolled_test.go", `package p
func rollMyOwn(t *testing.T) {
	t.Setenv("AIKEY_PACK_CACHE_DIR", t.TempDir())
}
`)
	// Prose that merely MENTIONS the token must not count.
	write("prose_test.go", `package p

// This comment talks about AIKEY_TEST_DETECTOR_BINARY and "bin", "detector"
// on purpose, to prove comments are excluded.
func unrelated() {}
`)

	got, err := scanPackage(dir)
	if err != nil {
		t.Fatalf("scanPackage: %v", err)
	}

	files := got.byToken["env-provided binary"]
	if len(files) != 2 {
		t.Fatalf("scanner found the env-provided binary in %v, want exactly the door and the "+
			"forgetful live test — if this is 1, the scanner has stopped seeing new offenders and "+
			"the fence is decorative", files)
	}
	if !got.seals["door_test.go"] {
		t.Errorf("scanner did not recognize the sanctioned door's %s call", sealCall)
	}
	if got.seals["forgot_seal_live_test.go"] {
		t.Errorf("scanner credited an unsealed file with sealing")
	}
	if len(got.handRolledSeals) != 1 || !strings.Contains(got.handRolledSeals[0], "handrolled_test.go") {
		t.Errorf("hand-rolled partial seal not reported: %v", got.handRolledSeals)
	}
	if len(got.byToken["sibling repo build"]) != 0 {
		t.Errorf("a token that appears ONLY in a comment was counted as code: %v",
			got.byToken["sibling repo build"])
	}
}
