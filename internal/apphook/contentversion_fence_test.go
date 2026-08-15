package apphook

// contentversion_fence_test.go — source-level fence for "every filter the proxy
// can install must be able to state which content set it is detecting with".
//
// WHY A SOURCE SCAN AND NOT A BEHAVIOR TEST (the lesson from
// storage/pack_distribution_fence_test.go in aikey-control-master, whose absence
// let the same class of bug through twice): a behavior test only covers the
// implementations someone remembered to write a case for. Add a third
// FilterTarget — a remote filter, a WASM filter, a pool-of-pools — and a
// behavior test stays silent while its verdicts start being memoized under an
// epoch that never moves, which is precisely the P0 this fence guards.
//
// The default here is "you are fenced". Opting out requires editing this file,
// which is a reviewable action.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var compileTimeProof = regexp.MustCompile(`_\s+(FilterTarget|ContentVersioned)\s*=\s*\(\*(\w+)\)\(nil\)`)

// TestFence_EveryFilterTargetReportsItsContentVersion fails if a type is proven
// to satisfy FilterTarget without also being proven to satisfy ContentVersioned.
//
// It reads the compile-time proof blocks rather than using reflection because Go
// cannot enumerate a package's implementations at runtime — the proofs ARE the
// registry, and keeping the two lists side by side is the whole contract.
func TestFence_EveryFilterTargetReportsItsContentVersion(t *testing.T) {
	filterTargets, contentVersioned := map[string]string{}, map[string]bool{}

	for _, file := range packageSourceFiles(t) {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, m := range compileTimeProof.FindAllStringSubmatch(string(src), -1) {
			iface, typ := m[1], m[2]
			if iface == "FilterTarget" {
				filterTargets[typ] = filepath.Base(file)
			} else {
				contentVersioned[typ] = true
			}
		}
	}

	if len(filterTargets) == 0 {
		t.Fatal("fence found no FilterTarget proofs — the scan itself is broken, not the code " +
			"(a fence that cannot fail is worse than no fence)")
	}
	for typ, file := range filterTargets {
		if !contentVersioned[typ] {
			t.Errorf("%s is a FilterTarget (proven in %s) but is not proven to implement ContentVersioned.\n"+
				"Every installable filter can hot-swap its content, and anything memoizing its verdicts "+
				"keys on that token. Without it, apphook.CacheEpoch silently returns (\"\", true) and the "+
				"proxy caches verdicts under an epoch that never moves — a deleted rule keeps masking "+
				"(bugfix 20260813-pack-swap-does-not-invalidate-proxy-cache).\n"+
				"Fix: implement ContentVersion() and add `_ ContentVersioned = (*%s)(nil)` to contentversion.go.",
				typ, file, typ)
		}
	}
}

// TestFence_ContentVersionHasExactlyOneCallerFacingExit keeps CacheEpoch the
// single entry point. Its tri-state (not-versioned / known / unknown) is the
// contract; a caller that type-asserts ContentVersioned itself will handle two
// of the three branches and quietly drop the third — and the one that gets
// dropped is always the fail-safe branch, because it is the one with no visible
// symptom in a passing test.
func TestFence_ContentVersionHasExactlyOneCallerFacingExit(t *testing.T) {
	for _, file := range packageSourceFiles(t) {
		if filepath.Base(file) == "contentversion.go" {
			continue // the definition site
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.Contains(string(src), ".(ContentVersioned)") {
			t.Errorf("%s type-asserts ContentVersioned directly; go through CacheEpoch instead "+
				"(it owns the tri-state, including the fail-safe branch)", filepath.Base(file))
		}
	}
}

// packageSourceFiles lists this package's non-test .go files, parsed so a file
// that does not compile fails the fence loudly instead of being skipped.
func packageSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if _, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		out = append(out, name)
	}
	return out
}
