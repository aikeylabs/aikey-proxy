//go:build !aikey_license_off

package supervisor

// licenseRails returns the licensing rails this build runs.
//
// 🔴 Split by build tag rather than branched at the registration site, because
// the registration site is a single expression listing every rail: a conditional
// there would make the rail list depend on a runtime value, and the whole point
// of railset.go is that the set is declarative and complete at construction.
func (s *Supervisor) licenseRails() []railSpec {
	return []railSpec{s.licensePlaneRail()}
}
