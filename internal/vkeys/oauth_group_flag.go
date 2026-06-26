package vkeys

import "os"

// Seat-group (channel ③) routing feature flag — the single source of truth for
// the env gate, read by BOTH the supervisor (registry gate + group-runtime pull
// loop, N7c) and the proxy data plane (hot-path group resolver, N8). Keeping the
// env key in one place (here, the bottom of the dependency graph) avoids two
// packages drifting on the variable name.
//
// Group virtual keys carry no static PlaintextKey — their per-account material
// lives in managed_virtual_keys_cache.group_runtime and a request is routed by
// picking a candidate account (seatassign) + injecting its token. Until that
// path is complete + trusted, group VKs MUST NOT serve. Default OFF → the
// direct-bind path is byte-unchanged.

// OauthGroupEnvKey enables proxy-side group VK routing.
const OauthGroupEnvKey = "AIKEY_PROXY_OAUTH_GROUP_ENABLED"

// OauthGroupRoutingEnabled reports whether proxy-side group VK routing is on.
//
// Default ON since 2026-06-26 (user decision): seat-group is the supported way an
// enterprise shares a credential pool, so a freshly-installed proxy must route
// group VKs without an extra env toggle — otherwise a user who was issued a group
// VK can't use it after a plain install. Set AIKEY_PROXY_OAUTH_GROUP_ENABLED=0 (or
// "false") to force it off. Builds with no group VKs are unaffected: the registry
// has no group VK to register and the group-runtime pull returns empty (no-op).
func OauthGroupRoutingEnabled() bool {
	v := os.Getenv(OauthGroupEnvKey)
	if v == "" {
		return true
	}
	return v != "0" && v != "false"
}
