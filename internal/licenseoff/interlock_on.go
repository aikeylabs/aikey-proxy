//go:build !aikey_license_off

package licenseoff

import "log/slog"

// AcknowledgementEnv is empty in a normal build: there is nothing to acknowledge.
const AcknowledgementEnv = ""

// RefuseUnlessAcknowledged is a no-op here. 🔴 It exists in both halves so the
// caller invokes it unconditionally: a call site guarded by its own build tag is
// one that can be forgotten on a side, and the side it gets forgotten on is
// whichever nobody builds daily.
func RefuseUnlessAcknowledged(*slog.Logger) {}
