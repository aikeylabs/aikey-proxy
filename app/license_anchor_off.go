//go:build aikey_license_off

package app

import "log/slog"

// announceLicenseCapabilities says the opposite thing in a licensing-off build,
// and deliberately anchors NOTHING.
//
// 🔴 The absence of the consumer marker in this binary is what release.sh Step
// 8.9a inverts on, so this half must not reference proxy.LicenseConsumerMarker
// even in passing — a single reference would put the marker back into the
// artifact and make a licensing-off build indistinguishable from a normal one.
//
// The line is still emitted, on every boot, because "no gate" is exactly the
// fact an operator reading logs needs to find. internal/licenseoff prints the
// louder warning next to it.
func announceLicenseCapabilities() {
	slog.Warn("this proxy has NO license gate compiled in; it forwards without "+
		"consulting the deployment's license",
		"event.name", "proxy.license.compiled_out")
}
