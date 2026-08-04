package proxy

// Single-source upstream resolution for a PERSONAL vault alias.
//
// # Why this file exists (2026-08-03)
//
// requirements/2026-07-18-provider-protocol-compatibility-and-baseurl.md
// §上游地址单一解析 fixes two rules that this package used to satisfy on the
// forwarding path only:
//
//	1. 「单一解析器」 — the upstream address comes from ONE resolver: the route
//	   row for (provider, protocol), with the key's own address as an explicit
//	   overlay on top.
//	2. 「展示=执行」 — what we SHOW (and what we PROBE) must be byte-identical to
//	   what we FORWARD to, "同一个解析函数". The spec goes further and says a
//	   second, parallel fallback 「应导致围栏变红」.
//
// The connectivity probe never obeyed either. It could not: the resolution
// lived inline in the Tier2Probe sentinel branch of pipelines.go, reachable
// only by a request that was already being forwarded. So `aikey test` guessed
// the upstream from the provider code instead — for a personal entry carrying a
// custom base_url (a self-hosted gateway, an OAuth ingress) it probed the
// PUBLIC provider host that the entry never talks to.
//
// The result was worse than a red row: the probe's verdict became uncorrelated
// with the thing it claimed to test. It went red when the public host was
// unreachable though the real upstream was fine, and — the dangerous half —
// GREEN when the public host was reachable though the real upstream was down.
//
// Extracting the resolver is therefore not a tidy-up. It is what makes rule 2
// checkable at all: two callers, one function, and a fence that fails if they
// ever diverge.
func ResolvePersonalUpstreamBase(entryBaseURL, entryProviderCode, canonicalCode string) string {
	// The key's own address is the OVERLAY (spec rule 1) and therefore wins
	// outright — a user who typed a base_url meant it.
	if entryBaseURL != "" {
		return entryBaseURL
	}
	// Then the entry's stored provider. This rung matters for personal keys
	// bound to several providers (one alias, several provider_code rows): the
	// entry knows which one it is, the request path may not.
	if entryProviderCode != "" {
		if base := providerDefaultBaseURL(entryProviderCode); base != "" {
			return base
		}
	}
	// Last rung: the provider implied by the client-facing path prefix. This
	// disambiguates a multi-provider alias at probe time.
	return providerDefaultBaseURL(canonicalCode)
}
