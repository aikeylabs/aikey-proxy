// Package detectortest is the ONE place a test in this repo makes a spawned
// ai-compliance-detector child hermetic, plus the assertion that proves the
// sealing was actually honored.
//
// It lives in a non-_test.go file so BOTH internal/proxy (the filter dispatch /
// pool / integration live tests) and internal/apphook (the proxy↔detector IPC
// contract suite) can use the SAME seal — a Go package cannot import another
// package's _test.go helpers, and duplicating this one would duplicate the
// rationale below, which is the part that rots. Imported only from _test.go
// files, so it is never linked into the production binary (same contract as
// internal/egresstest, and fenced by TestDetectorTestIsNeverLinkedIntoTheBinary).
//
// ── WHY THIS EXISTS (2026-08-14, generalised from the NSFW round) ────────────
//
// apphook spawns the child with `cmd.Env = append(os.Environ(), …)`
// (childhook.go), so the detector inherits the test process's environment and,
// with it, the developer's whole `~/.aikey` tree. The detector resolves FOUR
// independent inputs from $HOME, none of which belong in an assertion about
// what the SHIPPED binary does:
//
//	#  input                                                        env override
//	1  ~/.aikey/apps/ai-compliance-detector/var/packs.json          AIKEY_PACK_CACHE_DIR
//	   (cmd/detector/pack_puller.go — the pull cache the puller warm-starts from)
//	2  ~/.aikey/apps/ai-compliance-detector/policy.json             NONE
//	   (actionpolicy.DefaultOverridePath — the B5 ops override; it can rewrite
//	    entity actions and placeholder labels, i.e. the very mechanism most of
//	    these tests assert on)
//	3  ~/.aikey/apps/ai-compliance-detector/assets/address/*        NONE
//	   (address.DefaultAssetsDir — the installer-delivered dictionary layers,
//	    which change CN_ADDRESS recall)
//	4  ~/.aikey/config/control{,-trial}.yaml                        NONE
//	   (cmd/detector/local_intake.go — the local-server port probe)
//
// 🔴 WHY SEALING AIKEY_PACK_CACHE_DIR ALONE IS NOT ENOUGH — do not "simplify"
// this back. Only input #1 has an env override; #2/#3/#4 are $HOME-only. Sealing
// $HOME covers all four at once. Measured on 2026-08-14 with the shipped binary:
//
//	HOME=<tmp with policy.json {"entity_actions":{"CN_ADDRESS":"off"}}>
//	  → "action policy override applied … overridden=entity_actions.CN_ADDRESS=off"
//	  → "info: CN_ADDRESS lane off"           (input #2 silently rewrites enforcement)
//	HOME=<empty tmp>  → 3× "CN_ADDRESS dictionary layer did not land"
//	HOME=<real>       → no such warning        (input #3 silently changes recall)
//
// The same probe, run against internal/apphook's TestChildHook_ListPacks, turns
// that test RED purely because of a file in the developer's home directory —
// which is the red-direction twin of the false green that started this
// (bugfix 20260813-nsfw-family-loses-all-enforcement-after-bundle-migration.md).
//
// AIKEY_PACK_CACHE_DIR is still set ON TOP of the sealed home on purpose: it is
// read straight from the environment and would otherwise WIN over the sealed
// home if a developer or a CI job happens to export it.
//
// USERPROFILE is sealed alongside HOME because os.UserHomeDir reads that
// variable on Windows, and aikey-proxy is a supported Windows target.
package detectortest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// PackCacheDirEnv is the detector's pack-cache override. Named here rather than
// spelled as a literal at each use so the fence has exactly one symbol to pin.
const PackCacheDirEnv = "AIKEY_PACK_CACHE_DIR"

// Sealed is the host state a sealed child sees. Keep it and hand it to
// AssertHeld after the child is up — setting the environment is NOT proof that
// the child honored it.
type Sealed struct {
	// Home is the fake $HOME (and %USERPROFILE%) the child must resolve.
	Home string
	// PackCacheDir is the fake pack cache. Empty at Seal time; a test that
	// serves a mock pack master can assert its own snapshot landed here.
	PackCacheDir string
}

// sealed remembers the seal already installed for a given test, so a test that
// spawns SEVERAL children (a pool) through the door gets ONE sealed home rather
// than one per child. Without this, the Sealed value returned by the first call
// would silently describe a directory the children no longer resolve to — a
// stale handle is exactly the kind of "assertion that quietly checks nothing"
// this package exists to remove.
var sealedPerTest sync.Map // test name → Sealed

// Seal makes every detector child spawned from this test behave as if it were
// running on a machine where aikey was NEVER installed.
//
// Call it BEFORE the child is spawned (t.Setenv is what the child inherits).
// It is safe to call for an `--echo-only` child too — that mode reads none of
// the four inputs, but routing every detector-spawning test through one door is
// what makes "a new live test forgot to seal" a fence failure rather than a
// silent host dependency.
//
// Idempotent within one test: repeated calls return the same Sealed.
func Seal(tb testing.TB) Sealed {
	tb.Helper()
	if existing, ok := sealedPerTest.Load(tb.Name()); ok {
		// Checked rather than a bare assertion: sync.Map is untyped, and the lint
		// gate enables errcheck.check-type-assertions precisely so a wrong stored
		// type surfaces as a named failure instead of a panic mid-test. Nothing
		// but this function writes the map, so a miss means the map was corrupted
		// — which must be loud, not a zero-value Sealed that silently reports an
		// empty sealed home to AssertHeld.
		sealed, isSealed := existing.(Sealed)
		if !isSealed {
			tb.Fatalf("seal: cached host state for %s is %T, not detectortest.Sealed", tb.Name(), existing)
		}
		return sealed
	}
	home := tb.TempDir()
	cacheDir := tb.TempDir()
	tb.Setenv("HOME", home)
	tb.Setenv("USERPROFILE", home)
	tb.Setenv(PackCacheDirEnv, cacheDir)

	// Fail loudly if the "clean" directory is not clean. A silently pre-populated
	// cache would reintroduce the exact false green this package removes.
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		tb.Fatalf("seal: read pack cache dir: %v", err)
	}
	if len(entries) != 0 {
		tb.Fatalf("seal: pack cache dir %s is not empty before the run (%d entries) — "+
			"the detector would warm-start from state this test did not serve", cacheDir, len(entries))
	}
	s := Sealed{Home: home, PackCacheDir: cacheDir}
	sealedPerTest.Store(tb.Name(), s)
	tb.Cleanup(func() { sealedPerTest.Delete(tb.Name()) })
	return s
}

// SiblingBinary returns the sibling repo's built detector
// (<labs-root>/ai-compliance-detector/bin/detector, produced by
// `make -C ../ai-compliance-detector build`) and seals the host state.
//
// It lives here so the path is CONSTRUCTED IN ONE PLACE. Three packages used to
// build it independently — internal/proxy's integration harness,
// internal/supervisor's max-action harness, and internal/apphook's gate — and
// only one of them sealed anything. A path a test can rebuild for itself is a
// spawn the seal rule cannot reach, which is why the fence forbids the literal
// outside this package.
//
// Resolved from THIS file's location, so the answer does not depend on the
// working directory `go test` happens to use. Existence is NOT checked here: the
// callers differ on what a missing binary means (skip vs fail), and collapsing
// that distinction is a separate defect this package must not re-introduce.
func SiblingBinary(tb testing.TB) (string, Sealed) {
	tb.Helper()
	_, file, _, _ := runtime.Caller(0)
	proxyDir := filepath.Dir(filepath.Dir(filepath.Dir(file))) // .../aikey-proxy
	bin := filepath.Join(filepath.Dir(proxyDir), "ai-compliance-detector", "bin", "detector")
	return bin, Seal(tb)
}

// PackLister is the subset of the child hook / pool the seal assertion needs.
// Both *apphook.ChildHook and *apphook.FilterPool satisfy it.
type PackLister interface {
	ListPacks(ctx context.Context) ([]byte, error)
}

// AssertHeld proves the seal was HONORED, by asking the CHILD where it resolved
// $HOME to instead of trusting that setting an environment variable had an
// effect.
//
// 🔴 WHY A SEPARATE ASSERTION IS MANDATORY. Measured on 2026-08-14 on the NSFW
// live test: with the sealing calls deleted but the fixture left alone, the
// masking assertion STILL PASSED — the host's own lexicon did the masking. A
// test that only asserts the outcome cannot tell "the shipped binary did this"
// from "this developer's machine did this", so deleting the seal is a SILENT
// regression unless something asserts the seal itself.
//
// The probe: op=ListPacks reports `address_assets.assets_dir`, which the child
// builds as os.UserHomeDir() + "/.aikey/apps/ai-compliance-detector/assets/
// address". It is the only $HOME-rooted path the child publishes, and it is the
// child's OWN answer traveling the real v4 pipe — so it is red whenever the
// seal is removed, on any machine, installed or not.
//
// A missing address_assets block is treated as a failure, not as "nothing to
// check": it means either the seal leaked an ops override that switched the
// CN_ADDRESS lane off (exactly input #2), or the shipped default changed. Both
// must be loud (失败要显眼，不要沉默).
func (s Sealed) AssertHeld(tb testing.TB, child PackLister) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, err := child.ListPacks(ctx)
	if err != nil {
		tb.Fatalf("seal not verifiable: op=ListPacks failed (%v) — the child cannot report where it "+
			"resolved $HOME, so this run cannot distinguish the shipped binary's behavior from this "+
			"machine's ~/.aikey state", err)
	}
	var report struct {
		AddressAssets *struct {
			AssetsDir string `json:"assets_dir"`
		} `json:"address_assets"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		tb.Fatalf("seal not verifiable: ListPacks report is not JSON (%v): %s", err, raw)
	}
	if report.AddressAssets == nil || report.AddressAssets.AssetsDir == "" {
		tb.Fatalf("seal not verifiable: ListPacks reported no address_assets.assets_dir.\n"+
			"  That block is nil only when the CN_ADDRESS lane is off or its recognizer failed to build.\n"+
			"  Most likely cause: a policy.json ops override leaked in from a real $HOME (host input #2,\n"+
			"  which has NO environment switch) — i.e. the seal did not take. Sealed home was %s.\n"+
			"  Report: %s", s.Home, raw)
	}
	got := filepath.Clean(report.AddressAssets.AssetsDir)
	want := filepath.Clean(s.Home)
	if got != want && !strings.HasPrefix(got, want+string(os.PathSeparator)) {
		tb.Fatalf("host state NOT sealed: the child resolved its asset dir to\n"+
			"    %s\n"+
			"  which is outside the sealed home\n"+
			"    %s\n"+
			"  So this child read the developer's ~/.aikey (pack cache, policy.json ops override,\n"+
			"  address dictionaries, local-server port) and every assertion in this test may be\n"+
			"  borrowed from installed state rather than produced by the binary under test.\n"+
			"  Fix: obtain the detector binary through this package's door (which calls\n"+
			"  detectortest.Seal) instead of reading the path yourself.", got, want)
	}
}
