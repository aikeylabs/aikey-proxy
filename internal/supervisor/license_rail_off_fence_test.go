//go:build aikey_license_off

package supervisor

import "testing"

// TestNoLicenseRailInALicensingOffBuild is the inverse.
//
// The gate is compiled out, so a running rail cannot change behavior — it can
// only poll a control plane that serves no /v1/license/* and log a WARN several
// times a minute for the life of the deployment. Measured on staging before this
// was fixed: ~280 rejected requests per five minutes, all 404, all WARN.
//
// 🚫 Do not "fix" a future failure here by making the rail tolerate 404. That
// would put "the plane is unreachable" and "the plane says allow" on the same
// footing in the NORMAL build too, which is the ambiguity the whole licensing
// layer exists to remove.
func TestNoLicenseRailInALicensingOffBuild(t *testing.T) {
	s := &Supervisor{}
	if got := s.licenseRails(); len(got) != 0 {
		t.Fatalf("licenseRails() returned %d rail(s) in a -tags aikey_license_off build; "+
			"there is no gate for them to carry, so they would poll a 404 for ever", len(got))
	}
}
