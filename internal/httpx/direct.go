// Package httpx holds HTTP client helpers shared across the proxy.
package httpx

import (
	"net/http"
	"time"
)

// NewDirectClient returns an *http.Client whose transport NEVER routes through
// the environment HTTP proxy (HTTP_PROXY / HTTPS_PROXY / ALL_PROXY). It clones
// http.DefaultTransport (keeping its connection-pool / dial-timeout defaults)
// and only disables the proxy lookup.
//
// WHY (2026-06-30): the aikey-proxy process commonly inherits an egress HTTP
// proxy in its env — e.g. Clash on 127.0.0.1:7890 on a CN dev box. That proxy
// is for the USER's upstream AI egress (reaching platform.claude.com out of the
// GFW), NOT for the proxy's own CONTROL-PLANE calls. Go's default transport
// honors the env proxy for EVERY destination with no LAN/localhost exception, so
// without this the proxy routes its control-plane traffic (team-master writeback
// + polls, collector upload, CLI-JWT refresh, signals, cluster register) through
// Clash, which cannot reach the internal / LAN control plane → 502 / timeout
// (e.g. the OAuth member-token writeback "context deadline exceeded" bug). The
// control plane is always direct-reachable, so these clients must bypass the env
// proxy.
//
// Do NOT use this for AI-egress / upstream-provider / request-forwarding clients
// — those deliberately honor the env (or configured upstream) proxy to get out.
func NewDirectClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	return &http.Client{Timeout: timeout, Transport: tr}
}
