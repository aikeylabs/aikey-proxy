//go:build !aikey_license_off

package app

import (
	"log/slog"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// announceLicenseCapabilities is 🔴 NOT decoration, and 🚫 not safe to drop.
// Two jobs, unchanged from when it lived inline in Run():
//
//  1. an operator can see that this proxy consumes the license gate at all,
//     rather than inferring it from the absence of refusals;
//  2. it ANCHORS LicenseConsumerMarker into the binary. The marker is a const,
//     and a const nothing references can be dropped by the linker — a dropped
//     marker reads to the release gate as "this build does not consume the gate"
//     and gets a perfectly good release refused.
//
// It moved out of app.go so the licensing-off build can carry NO marker at all;
// see license_anchor_off.go. internal/proxy/license_capability.go has the rest.
func announceLicenseCapabilities() {
	slog.Info("license gate capabilities compiled into this build",
		"event.name", observability.EventProxyLicensePlaneCapabilities,
		"capabilities", strings.Join(proxy.SupportedLicenseCapabilities, ","),
		"marker", proxy.LicenseConsumerMarker)
}
