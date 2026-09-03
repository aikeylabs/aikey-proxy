//go:build aikey_license_off

package proxy

// licenseForwardingAllowed always allows in a LICENSING-OFF build.
//
// 🔴 This is the whole point of the tag, and it is why the tag may never reach a
// customer: this binary forwards without ever consulting the deployment's
// license. internal/licenseoff.RefuseUnlessAcknowledged is what stops such a
// build from running somewhere nobody intended — the gate cannot report its own
// absence, so the refusal lives at boot instead.
//
// 🚫 There is deliberately no "allow if the plane is unreachable" middle ground
// anywhere in this file's normal counterpart. An absent enforcement mechanism is
// indistinguishable from a satisfied one; making unreachability mean "allow"
// would put that ambiguity into every build rather than into one tagged build
// that refuses to start unannounced.
func licenseForwardingAllowed(*LicensePlaneCache) bool { return true }
