//go:build !aikey_license_off

package supervisor

import "testing"

// TestTheLicensePlaneRailIsRegisteredInANormalBuild is the half that matters most.
//
// 🔴 The license forwarding gate spent months wired on the control-plane side and
// unread on this one, and nothing was red because "the consumer was never
// written" and "everything is licensed" look identical. Making the registration
// build-tag split reintroduces exactly one way for that to happen again: a
// mistake in the tags that drops the rail from the NORMAL build too. Then every
// customer deployment forwards for ever while its console correctly shows
// expired, and no test fails.
//
// So the normal build asserts the rail is present, by name.
func TestTheLicensePlaneRailIsRegisteredInANormalBuild(t *testing.T) {
	s := &Supervisor{}
	rails := s.licenseRails()
	if len(rails) == 0 {
		t.Fatal("licenseRails() is empty in a NORMAL build: the forwarding gate would " +
			"never be fetched, so an expired deployment forwards for ever and nothing " +
			"goes red. Check the build tags on license_rail_{on,off}.go.")
	}
	found := false
	for _, r := range rails {
		if r.name == "license_plane" {
			found = true
		}
	}
	if !found {
		t.Fatalf("licenseRails() does not include the license_plane rail (got %d rail(s)); "+
			"the gate has no carrier", len(rails))
	}
}
