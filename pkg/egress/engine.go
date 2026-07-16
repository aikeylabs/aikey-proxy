// Package egress is the pluggable per-account egress-engine registry (§11.7 /
// 多协议方案). It lives in a PUBLIC (non-internal) package on purpose: the
// open-source build registers only the built-in socks5 engine here, while the
// offline enterprise build composes in a SEPARATE private module that registers
// a mihomo-backed multi-protocol engine. mihomo is GPL-3.0 and must never be
// linked into the open-source GitHub release, so it lives outside this module
// and registers through this public seam.
//
// Contract: engines are tried in registration order; the first to Claim a spec
// Builds it. A spec no engine claims fails LOUDLY (the open-source build lacks
// the multi-protocol engine) — never silently, never out the wrong IP.
//
// See: 20260716-多协议出口代理-嵌mihomo库-技术方案.md
package egress

import (
	"fmt"

	xproxy "golang.org/x/net/proxy"
)

// Engine builds a dialer chain from a per-account egress spec. Claims is a cheap
// shape check (no dial); Build is only called after Claims returns true. The
// returned dialer's exit hop IP is what the upstream sees.
type Engine interface {
	Name() string
	Claims(spec string) bool
	Build(spec string) (xproxy.Dialer, error)
}

// engines is the ordered registry (first claim wins). Populated by Register from
// each engine's init(): built-in always; mihomo only in the enterprise build.
var engines []Engine

// Register appends an engine to the registry. Call from init() — registration
// order is priority order.
func Register(e Engine) { engines = append(engines, e) }

// BuildDialer runs the registry: the first engine to Claim(spec) builds it. No
// engine claims → an actionable error (the open-source build lacks the
// multi-protocol engine).
func BuildDialer(spec string) (xproxy.Dialer, error) {
	for _, e := range engines {
		if e.Claims(spec) {
			return e.Build(spec)
		}
	}
	return nil, fmt.Errorf("no egress engine handles this proxy spec: multi-protocol egress (ss/vmess/trojan/…) requires the offline enterprise package; this build supports socks5 chains only")
}

// Names returns the registered engine names, for diagnostics / health surfaces.
func Names() []string {
	out := make([]string, 0, len(engines))
	for _, e := range engines {
		out = append(out, e.Name())
	}
	return out
}
