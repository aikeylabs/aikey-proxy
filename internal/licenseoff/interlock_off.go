//go:build aikey_license_off

package licenseoff

import (
	"fmt"
	"log/slog"
	"os"
)

// AcknowledgementEnv is the variable an operator must set to run this build.
const AcknowledgementEnv = "AIKEY_LICENSE_OFF_I_UNDERSTAND"

// RefuseUnlessAcknowledged stops a licensing-off proxy that nobody meant to run.
//
// 🔴 Why the PROXY needs this at least as much as the control service does.
// The control service's licensing-off build still looks like a healthy console.
// A licensing-off PROXY is worse: it is the component that actually forwards, so
// a copy of it is a permanent, unmetered gateway to whatever credentials it can
// reach — and it presents exactly like a licensed one. No freeze, no refusal, no
// console banner. The forwarding gate is the thing being compiled out, so the
// gate cannot be the thing that reports its own absence.
//
// Refusing to start is the only signal that survives being inherited by someone
// who was not there when the binary was built. On a staging host the fix is one
// environment variable, written by cluster-install.sh for licensing-off packages.
//
// 🚫 There is deliberately no flag form, for the same reason as the control
// service: a flag lives in the unit file that whoever installed it by mistake
// would have copied along with the binary.
func RefuseUnlessAcknowledged(log *slog.Logger) {
	if os.Getenv(AcknowledgementEnv) == "1" {
		// Announced on EVERY boot, not once at install. An operator inheriting
		// this host months later reads logs, not install history.
		if log != nil {
			log.Warn("THIS PROXY HAS NO LICENSING LAYER. It forwards without consulting "+
				"the deployment's license, it can be copied and run anywhere, and it must "+
				"never be given to a customer.",
				"event.name", "proxy.license.compiled_out",
				"acknowledged_via", AcknowledgementEnv)
		}
		return
	}
	fmt.Fprintf(os.Stderr, `
================================================================================
REFUSING TO START: this aikey-proxy was built with -tags aikey_license_off.

It has NO license forwarding gate. It never asks the control plane whether this
deployment may forward, and it never refuses. A copy of it forwards anywhere,
forever, for anyone who can reach it.

That is correct for a staging cluster we own and is NEVER correct for a customer.

If this is that staging cluster, say so explicitly:

    %s=1

If you did not expect to see this message, you are holding an internal build.
Do not deploy it. Rebuild without -tags aikey_license_off.
================================================================================

`, AcknowledgementEnv)
	os.Exit(1)
}
