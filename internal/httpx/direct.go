// Package httpx holds HTTP client helpers shared across the proxy.
package httpx

import (
	"net/http"
	"time"

	"github.com/AiKeyLabs/pkg/httpdirect"
)

// NewDirectClient returns an *http.Client for the proxy's CONTROL-PLANE calls
// — team-master writeback and polls, collector upload, CLI-JWT refresh,
// signals, cluster register. It never routes through the environment HTTP
// proxy (HTTP_PROXY / HTTPS_PROXY / ALL_PROXY).
//
// The implementation moved to pkg/httpdirect on 2026-08-03, when the master
// console turned out to make the same LAN calls with a plain http.Client and
// therefore carried the same latent bug. That package documents the full
// rationale — including why NO_PROXY was rejected as the mechanism — and adds
// the operator escape hatch (httpdirect.SetProxyOverride) for a site whose
// control plane is only reachable across a corporate proxy. This wrapper stays
// so the proxy's ~14 call sites keep reading in local terms.
//
// Do NOT use this for AI-egress / upstream-provider / request-forwarding
// clients — those deliberately honor the env (or configured upstream) proxy to
// get out.
func NewDirectClient(timeout time.Duration) *http.Client {
	return httpdirect.NewClient(timeout)
}
