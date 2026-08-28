package proxy

// license_capability_test.go — fences under the release-gate marker.
//
// The marker's whole value is that a release pipeline can trust it. Two ways it
// silently stops being trustworthy, and one fence each:
//
//   - it drifts from what the build actually does (becomes aspirational);
//   - it stops being a single contiguous literal, so the linker scatters it and
//     `grep` on the binary finds only the prefix.
//
// See workflow/CI/bugfix/20260827-forwarding-gate-was-never-wired.md.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheLicenseConsumerMarkerMatchesWhatIsSupported keeps the marker honest.
func TestTheLicenseConsumerMarkerMatchesWhatIsSupported(t *testing.T) {
	want := LicenseConsumerMarkerPrefix +
		strings.Join(SupportedLicenseCapabilities, ",") +
		LicenseConsumerMarkerTerminator

	if LicenseConsumerMarker != want {
		t.Fatalf("the marker and the supported list disagree:\n  marker    %q\n  supported %q\n\n"+
			"The release gate reads the MARKER out of the shipped binary, so a marker that "+
			"names capabilities this build does not have would let an unenforcing proxy "+
			"through — and one that omits a capability it does have gets a good release "+
			"refused. Update both.", LicenseConsumerMarker, want)
	}
}

// TestTheMarkerIsWellFormed guards the shape the shell-side reader depends on.
func TestTheMarkerIsWellFormed(t *testing.T) {
	if !strings.HasPrefix(LicenseConsumerMarker, LicenseConsumerMarkerPrefix) {
		t.Fatal("the marker does not start with the prefix the release gate greps for")
	}
	if !strings.HasSuffix(LicenseConsumerMarker, LicenseConsumerMarkerTerminator) {
		t.Fatalf("the marker has no terminator. 🔴 This is not cosmetic: a cross-compiled "+
			"linker once packed an unrelated literal flush against an equivalent marker "+
			"(`aikeylic/capabilities:bearer-authnumber`), and a reader without an explicit "+
			"terminator read a capability that matched nothing — refusing a binary built "+
			"from that very source. Got %q", LicenseConsumerMarker)
	}
	if len(SupportedLicenseCapabilities) == 0 {
		t.Fatal("no capabilities are declared, so the marker asserts nothing")
	}
	for _, c := range SupportedLicenseCapabilities {
		if c == "" {
			t.Error("an empty capability name would make the list unparseable")
		}
		if strings.ContainsAny(c, ",;") {
			t.Errorf("capability %q contains a separator character; the list would be "+
				"misread by the release gate", c)
		}
	}
}

// TestTheMarkerIsAnchoredInShippedCode.
//
// 🔴 A const nothing references can be dropped by the linker, and a dropped
// marker reads to the release gate as "this build does not consume the gate" —
// getting a perfectly good release refused, which is the failure direction that
// teaches people to delete the gate. The anchor is app.Run's start-up log.
//
// This fence asserts a NON-TEST file references it, because a reference from a
// test does not put anything in the shipped binary.
func TestTheMarkerIsAnchoredInShippedCode(t *testing.T) {
	root := moduleRoot(t)
	var anchors []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return nil //nolint:nilerr // an unreadable subtree is not this fence's business
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// 🚫 Skip the declaration itself: the file that DEFINES the const does not
		// anchor it. Without this the fence would match its own source and pass
		// even with the anchor deleted — the "reads as coverage" failure again.
		if filepath.Base(path) == "license_capability.go" {
			return nil
		}
		b, readErr := os.ReadFile(path) // #nosec G304 -- walking this module's own tree
		if readErr != nil {
			return nil
		}
		if strings.Contains(string(b), "LicenseConsumerMarker") {
			rel, _ := filepath.Rel(root, path)
			anchors = append(anchors, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(anchors) == 0 {
		t.Fatal("no shipped (non-test) file outside its own declaration references " +
			"LicenseConsumerMarker, so the linker may drop it and the built binary would " +
			"carry no marker at all — the release gate would then refuse a perfectly good " +
			"release. Anchor it in code that ships; app.Run logs it at start-up.")
	}
	t.Logf("marker anchored in: %s", strings.Join(anchors, ", "))
}
