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

// SeatGroupEnvKey enables proxy-side group VK routing.
const SeatGroupEnvKey = "AIKEY_PROXY_SEAT_GROUP_ENABLED"

// SeatGroupRoutingEnabled reports whether proxy-side group VK routing is on.
func SeatGroupRoutingEnabled() bool {
	v := os.Getenv(SeatGroupEnvKey)
	return v == "1" || v == "true"
}
