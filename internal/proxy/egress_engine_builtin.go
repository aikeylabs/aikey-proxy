// egress_engine_builtin.go — built-in socks5 egress engine (§11.7, P7).
//
// Always registered, in every build (zero third-party deps, GPL-free). Handles
// the self-contained socks5 chain: egress_proxy_url is a comma-separated ordered
// list of socks5 hops, first hop closest to the node, LAST hop = the exit (its
// IP is what upstream sees). Deliberately does NOT consult the node's
// upstream_proxy — the field IS the chain, what you read is exactly what dials.
//
//	single hop : "socks5://A"                 node ─▶ A ─▶ upstream        (exit = A)
//	two hops   : "socks5://F,socks5://A"       node ─▶ F ─▶ A ─▶ upstream   (exit = A)
//	N hops     : "socks5://H1,...,socks5://Hn" node ─▶ H1 ─▶ … ─▶ Hn ─▶ up  (exit = Hn)
//
// A node fenced behind a mandatory front proxy includes that front as the FIRST
// hop of the chain (explicit). Multi-protocol specs (ss/vmess/…) are NOT claimed
// here — they fall to the mihomo engine (offline enterprise build only).
package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/AiKeyLabs/aikey-proxy/pkg/egress"
	xproxy "golang.org/x/net/proxy"
)

func init() { egress.Register(builtinEgressEngine{}) }

// builtinEgressEngine handles socks5-only chains.
type builtinEgressEngine struct{}

func (builtinEgressEngine) Name() string { return "builtin-socks5" }

// Claims iff EVERY non-empty comma hop is a socks5:// URL. A chain mixing in a
// non-socks5 hop (e.g. "socks5://a,ss://b") is NOT claimed → it falls through to
// the mihomo engine, which can do mixed protocols.
func (builtinEgressEngine) Claims(spec string) bool {
	any := false
	for _, raw := range strings.Split(spec, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.HasPrefix(raw, "socks5://") {
			return false
		}
		any = true
	}
	return any
}

func (builtinEgressEngine) Build(spec string) (xproxy.Dialer, error) {
	return buildSocks5Chain(spec)
}

// buildSocks5Chain composes the ordered socks5 hops into a single forward
// dialer. hop[0] is dialed first (from the node), each subsequent hop is dialed
// THROUGH the previous, so the returned dialer exits from the last hop's IP.
func buildSocks5Chain(spec string) (xproxy.Dialer, error) {
	hops, err := parseEgressChain(spec)
	if err != nil {
		return nil, err
	}
	var forward xproxy.Dialer = xproxy.Direct
	for i, h := range hops {
		d, derr := xproxy.SOCKS5("tcp", h.addr, h.auth, forward)
		if derr != nil {
			return nil, fmt.Errorf("egress chain hop %d (%s): %w", i+1, h.addr, derr)
		}
		forward = d
	}
	return forward, nil
}

// buildAccountEgressTransport builds the socks5 chain and wraps it into a
// transport. Kept as an intra-package helper (also exercised directly by the
// unit tests) — the request path goes through the engine registry via
// accountEgressTransport / buildEgressTransport.
func buildAccountEgressTransport(spec string) (*http.Transport, error) {
	d, err := buildSocks5Chain(spec)
	if err != nil {
		return nil, err
	}
	return dialerToTransport(d), nil
}

type egressHop struct {
	addr string
	auth *xproxy.Auth
}

// parseEgressChain splits a comma-separated socks5 chain into ordered hops.
// Empty segments (trailing/duplicate commas) are skipped; at least one valid hop
// is required.
func parseEgressChain(spec string) ([]egressHop, error) {
	parts := strings.Split(spec, ",")
	hops := make([]egressHop, 0, len(parts))
	for _, raw := range parts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		addr, auth, err := parseSocks5URL(raw)
		if err != nil {
			return nil, err
		}
		hops = append(hops, egressHop{addr: addr, auth: auth})
	}
	if len(hops) == 0 {
		return nil, fmt.Errorf("egress chain is empty")
	}
	return hops, nil
}

// parseSocks5URL validates a socks5 proxy URL and splits it into (host:port,
// optional auth). socks5h (DNS via proxy) is intentionally not accepted yet.
func parseSocks5URL(raw string) (addr string, auth *xproxy.Auth, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", nil, fmt.Errorf("invalid proxy url %q: %w", raw, err)
	}
	if u.Scheme != "socks5" {
		return "", nil, fmt.Errorf("unsupported proxy scheme %q (only socks5 in the built-in engine)", u.Scheme)
	}
	if u.Host == "" {
		return "", nil, fmt.Errorf("proxy url %q has no host", raw)
	}
	if pw, ok := u.User.Password(); ok {
		auth = &xproxy.Auth{User: u.User.Username(), Password: pw}
	} else if u.User != nil && u.User.Username() != "" {
		auth = &xproxy.Auth{User: u.User.Username()}
	}
	return u.Host, auth, nil
}
