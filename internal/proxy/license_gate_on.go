//go:build !aikey_license_off

package proxy

// licenseForwardingAllowed asks the license plane cache the one question the
// request path is allowed to ask. See license_plane_cache.go.
//
// 🔴 This indirection exists ONLY so the gate can be compiled out by
// -tags aikey_license_off (staging clusters we own). It must stay a single call
// with no added logic: the narrowness of "one atomic load, one boolean" is the
// contract specs/edition-entitlement puts on this path.
func licenseForwardingAllowed(c *LicensePlaneCache) bool { return c.ForwardingAllowed() }
