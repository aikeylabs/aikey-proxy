package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/AiKeyLabs/pkg/egress"
)

// egress_attribution.go — per-request egress traceability (2026-07-19).
//
// WHY: the only per-request egress signal used to be a Debug line carrying just
// account_id (forward_and_resolve.go) — you could NOT take a real request's
// trace_id and confirm from logs which egress it exited through, and the usage
// event carried no egress field at all. This file is the SINGLE SOURCE deriving
// the request's egress attribution, consumed by BOTH the live Info log (A) and
// the durable usage-event ext_json audit (B) so the two can never disagree.
//
// It deliberately does NOT expose the exit IP (a mihomo fallback group picks a
// node dynamically per dial — resolving it on the hot path is expensive). It
// exposes a stable FINGERPRINT of the egress spec instead; the fingerprint→
// exit_ip mapping comes from the existing /admin/egress/selfcheck, off the hot
// path. And it NEVER logs the spec verbatim — a mihomo fragment carries socks5
// credentials, so only its sha256 prefix travels.

// egressAttribution derives the request's egress attribution from the resolved
// account egress spec and the node-level opt-in override.
//
//   - applied: the per-account egress WILL carry this request (spec present AND
//     the escape-hatch override is OFF) — byte-identical to the gate in
//     forward_and_resolve.go so the log/audit reflect the real routing decision.
//   - engine: coarse egress kind — "none" (direct/node) | "mihomo" (config
//     fragment) | "socks5-chain" | "single-url".
//   - fingerprint: hex(sha256(spec))[:12], "" when no spec. Non-secret, stable
//     per spec; correlate with the selfcheck to recover the exit IP.
func egressAttribution(spec string, overrideOn bool) (applied bool, engine, fingerprint string) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return false, "none", ""
	}
	sum := sha256.Sum256([]byte(s))
	fingerprint = hex.EncodeToString(sum[:])[:12]
	switch {
	case egress.IsFragment(s):
		engine = "mihomo"
	case strings.Contains(s, ","):
		engine = "socks5-chain"
	default:
		engine = "single-url"
	}
	// applied mirrors forward_and_resolve.go's gate: a per-account egress applies
	// whenever one is present UNLESS the member flipped the escape hatch ON.
	return !overrideOn, engine, fingerprint
}
