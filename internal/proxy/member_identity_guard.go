package proxy

import (
	"net/http"
	"regexp"
)

// Member-identity shape guard — the runtime half of fence I13.
//
// # WHAT THIS FILE PROMISES, STATED EXACTLY
//
// The 2026-07-20 first-login change gave every SSO member three identifying
// values: the Feishu union_id / open_id, the tenant_key, and a synthetic
// account handle (sso+<provider>.<digest>@sso.local). All three live in the
// control plane and have no business on the wire to Anthropic or OpenAI.
//
// The promise this code can actually keep is:
//
//	🔴 AiKey ITSELF never puts member identity onto an upstream request.
//
// It is deliberately NOT the absolute "no member identity ever reaches the
// upstream". That absolute is physically unenforceable on this path and
// claiming it would be the exact "page says enabled, filter is bypassed"
// false-safety shape:
//
//   - The main chat path forwards the client's body BYTE-FOR-BYTE. That is a
//     correctness requirement, not an oversight — body rewrites are known to
//     damage real-CLI traffic (see injectClaudeWAFFingerprintFull's guard on
//     inboundClientIsClaudeCode) and the WAF fingerprint check is byte-exact.
//   - oauth_inject.go's closing note is explicit that oauth_group POOL requests
//     "pass the REAL client identity upstream unchanged" — deliberately, because
//     a frozen synthetic persona became its own detection signal (2026-06-29).
//
// So a body allowlist on the main path would trade a level-2 stability risk
// (八级法则) for a level-1 gain we cannot complete anyway: a user who types
// their own union_id into a chat message will always ship it upstream. What we
// CAN fence is every value AiKey authors or annotates. That is what this does.
//
// # TWO CHOKEPOINTS
//
//  1. Headers — scrubMemberIdentityHeaders, called in serveRoute's Director
//     right after stripAikeyRequestHeaders. The namespace stripper only covers
//     X-Aikey-*; this covers identity VALUES under ANY header name, which is
//     the gap a future `X-Member-Union-Id` would have walked straight through.
//  2. Body — injectMetadataUserIDIfAbsent, the single place the proxy writes an
//     identifier into a request body. Guarded at the chokepoint, not at today's
//     one call site, so a future caller inherits the fence.
//
// 🚫 If a shape here starts firing, do NOT relax the pattern — ask why the data
// plane is holding a member's provider identity.
var (
	// syntheticHandleRe matches the control plane's synthetic account handle,
	// sso+<provider>.<hex digest>@... — produced by exactly one function
	// (aikey-control-master pkg/identity.syntheticEmail). The digest is
	// sha256(provider\x00union_id) truncated, so shipping the handle ships a
	// stable, cross-application identifier for a named employee.
	syntheticHandleRe = regexp.MustCompile(`(?i)sso\+[a-z0-9_.-]+\.[0-9a-f]{8,}@`)

	// ssoLocalDomainRe catches the handle's domain on its own, so a truncated,
	// re-hashed or otherwise reformatted derivative still trips the fence.
	ssoLocalDomainRe = regexp.MustCompile(`(?i)@sso\.local`)

	// feishuActorIDRe matches a Feishu union_id / open_id: on_ / ou_ followed by
	// a long unbroken alphanumeric run (the real values are a 32-char digest).
	//
	// No \b anchor in front, deliberately: these arrive EMBEDDED, e.g.
	// "…_account_on_8ed6aa…", and `_` is a word character so \b would never fire
	// there — the anchored first cut of this regex silently matched nothing,
	// which is why the body fence has a case pinned on exactly this string.
	// The 24-char floor is what replaces the anchor as the false-positive
	// defence: the persona user_id the proxy builds
	// (user_<64hex>_account_<uuid>_session_<uuid>) does contain the letters
	// "on_" inside "_session_", but a dashed UUID gives it only 8 unbroken
	// characters to work with. Opaque credentials are exempt entirely, below.
	feishuActorIDRe = regexp.MustCompile(`(?i)(?:on|ou)_[0-9a-z]{24,}`)
)

// memberIdentityShape returns the name of the member-identity shape found in s,
// or "" when s is clean. Name (not bool) so the WARN says WHICH shape fired —
// "identity leaked" with no discriminator is not actionable at 3am.
func memberIdentityShape(s string) string {
	switch {
	case syntheticHandleRe.MatchString(s):
		return "synthetic_account_handle"
	case ssoLocalDomainRe.MatchString(s):
		return "sso_local_domain"
	case feishuActorIDRe.MatchString(s):
		return "feishu_actor_id"
	}
	return ""
}

// identityScrubExemptHeaders are credential-bearing headers the shape scan skips.
//
// WHY an exemption exists at all: these carry opaque provider secrets — a Bearer
// token is a long random string, and a random string can accidentally satisfy
// feishuActorIDRe. Dropping Authorization on a false positive would fail EVERY
// request of that account (level-2 stability) to defend against a shape that
// cannot legitimately live in a credential anyway. These headers are set by the
// proxy itself from vault material; they are never an identity carrier.
var identityScrubExemptHeaders = map[string]struct{}{
	"Authorization":       {},
	"Proxy-Authorization": {},
	"X-Api-Key":           {},
	"Api-Key":             {},
	"X-Goog-Api-Key":      {},
}

// scrubMemberIdentityHeaders deletes outbound headers whose VALUE carries a
// member-identity shape, regardless of header name, and returns "<name>=<shape>"
// for each removal so the caller can WARN (never the value itself — logging the
// leak to defend against the leak is not a fix).
//
// Complements stripAikeyRequestHeaders rather than replacing it: that one is a
// namespace rule (cheap, total, covers annotations that do not exist yet), this
// one is a value rule (covers header names that do not exist yet). Neither
// subsumes the other.
func scrubMemberIdentityHeaders(h http.Header) []string {
	var removed []string
	for name, values := range h {
		if _, exempt := identityScrubExemptHeaders[http.CanonicalHeaderKey(name)]; exempt {
			continue
		}
		for _, v := range values {
			if shape := memberIdentityShape(v); shape != "" {
				removed = append(removed, http.CanonicalHeaderKey(name)+"="+shape)
				h.Del(name)
				break
			}
		}
	}
	return removed
}
