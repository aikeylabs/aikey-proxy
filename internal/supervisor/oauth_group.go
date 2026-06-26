package supervisor

import "github.com/AiKeyLabs/aikey-proxy/internal/vkeys"

// Seat-group (channel ③) proxy-side gating (N7c). The env gate's single source
// of truth is vkeys.OauthGroupRoutingEnabled (read by both supervisor and the
// proxy data plane); this thin wrapper keeps supervisor call sites unchanged.
//
// Group virtual keys carry no PlaintextKey — their per-account material lives in
// managed_virtual_keys_cache.group_runtime, pulled from master by the proxy, and
// a request is routed by picking a candidate account (seatassign) + injecting its
// token (resolver = N8). Until that resolver + the group-runtime pull loop are
// complete, group VKs MUST NOT enter the route registry (they'd fall to the
// personal-key path and 401). Default OFF → the direct-bind path is byte-unchanged.

// oauthGroupRoutingEnabled reports whether proxy-side group VK routing is on.
func oauthGroupRoutingEnabled() bool { return vkeys.OauthGroupRoutingEnabled() }
