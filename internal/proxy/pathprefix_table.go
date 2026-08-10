package proxy

// pathprefix_table.go — the CLIENT PATH-PREFIX table that drives
// extractProviderFromPath, derived from provider_registry.yaml.
//
// # What problem this file solves
//
// `aikey use <provider>` hands the client two values (aikey-cli
// executor.rs:build_run_env):
//
//	<X>_API_KEY   = aikey_active_<client_route>          Tier-3 active sentinel
//	<X>_BASE_URL  = http://127.0.0.1:<port>/<proxy_path> proxy_path from the registry
//
// so the contract is exactly one sentence: `http://127.0.0.1:<port>/<proxy_path>`
// must be a DROP-IN REPLACEMENT for the vendor's own versioned base URL.
//
// Until 2026-08-08 the proxy decided which prefixes existed from a 16-entry
// hand-written string slice in middleware.go. The registry had 28 picker:true
// providers. The 15 it did not list were selectable in the CLI picker and
// completely unusable: the path-prefix branch never matched, the request fell
// through to token routing, and the Tier-3 sentinel `aikey use` had just
// injected was rejected with
//
//	401 "Active sentinel requires path-prefix routing (use /<provider>/v1/... URL)"
//
// i.e. the error told the user to do the thing they were already doing. That is
// defect D-1. Requirement spec
// workflow/CI/requirements/2026-07-18-provider-protocol-compatibility-and-baseurl.md
// §10 already forbade this shape of duplication ("不得维护硬编码 switch 作为第二套
// 静默真相源"); the slice was one, and nothing tested that it agreed with the yaml.
//
// Full evidence, per-provider measurements and the rejected alternative:
// workflow/CI/bugfix/20260808-provider-path-prefix-routing-registry-drift.md
//
// # The derivation
//
// Three candidate prefixes per registry row, all lowercase, no leading slash:
//
//  1. the full `proxy_path` ("groq/v1", "kimi/v1", "anthropic") — the value the
//     CLI actually prints, hence the one real clients send. Matching it means
//     the WHOLE proxy_path is stripped, which is also the fix for defect D-2
//     (see the longest-prefix note in extractProviderFromPath).
//  2. the canonical `code` and the FIRST SEGMENT of proxy_path — kept so a
//     base_url that carries only the short prefix still routes. Two real
//     sources of those: a user's shell env written by an older aikey, and
//     `/kimi_code/v1/...` (canonical code ≠ proxy_path first segment for the
//     kimi split).
//  3. every `oauth_aliases` entry — `/claude/...` and the deprecated `/kimi/...`
//     have to keep working because old shell hooks wrote them into users' env
//     and breaking those cuts off live traffic. The other aliases come along
//     because they are the same class of thing; the registry already guarantees
//     no alias collides with another row's code or alias.
//
// 🚫 A row with an EMPTY proxy_path contributes nothing — not even its code.
// Today that is `mock` only, and it is deliberate: Mock credentials must enter
// through `/anthropic` or `/openai` according to the exact protocol they were
// stored with, so `mock` must never become a URL namespace. Fenced by
// TestExtractProviderFromPath_MockProviderHasNoClientNamespace.
//
// # Cost
//
// Built once per process (sync.Once) and bucketed by first path segment, so the
// per-request cost is one map lookup plus a scan of 1-4 candidates — the same
// order as the old slice scan, and it no longer grows with the provider count.
// Nothing here parses yaml per request; providerregistry.Default() itself caches.

import (
	"sort"
	"strings"
	"sync"

	"github.com/AiKeyLabs/pkg/providerregistry"
)

// clientPathPrefix is one routable client namespace.
type clientPathPrefix struct {
	// prefix has no leading or trailing slash, e.g. "anthropic", "groq/v1".
	prefix string
	// code is the CANONICAL provider code the prefix resolves to. Returning the
	// canonical code (rather than the literal the client typed) keeps aliases and
	// proxy_paths from leaking into downstream lookups; handlePathPrefixRoute
	// canonicalizes as its first step anyway.
	code string
}

// clientPathPrefixTable is the built table, bucketed by first path segment.
type clientPathPrefixTable struct {
	byFirstSegment map[string][]clientPathPrefix
}

// candidatesFor returns the candidates whose first segment is seg, longest
// prefix first. Returns nil for an unknown segment.
func (t *clientPathPrefixTable) candidatesFor(seg string) []clientPathPrefix {
	return t.byFirstSegment[seg]
}

// all returns every candidate, sorted, for tests and diagnostics.
func (t *clientPathPrefixTable) all() []clientPathPrefix {
	out := make([]clientPathPrefix, 0, len(t.byFirstSegment)*2)
	for _, bucket := range t.byFirstSegment {
		out = append(out, bucket...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].prefix < out[j].prefix })
	return out
}

var (
	clientPathPrefixOnce  sync.Once
	clientPathPrefixBuilt *clientPathPrefixTable
)

// clientPathPrefixes returns the process-wide table.
func clientPathPrefixes() *clientPathPrefixTable {
	clientPathPrefixOnce.Do(func() {
		clientPathPrefixBuilt = buildClientPathPrefixTable(providerregistry.Default().Entries())
	})
	return clientPathPrefixBuilt
}

// buildClientPathPrefixTable is the pure derivation, kept separate from the
// sync.Once so tests can build a table from a synthetic registry.
//
// Conflict handling: the FIRST candidate wins, walking rows in yaml order and
// candidates in the documented order above. Registry invariants make a real
// cross-provider conflict impossible (Parse rejects duplicate codes and
// colliding aliases, and every proxy_path begins with its own code or with an
// alias of its own row), so first-wins is a determinism guarantee rather than a
// policy. Two providers claiming one prefix would be a registry defect that
// silently misroutes traffic, so it is asserted against directly by
// TestClientPathPrefixTable_NoConflictingPrefixes rather than left to chance.
func buildClientPathPrefixTable(entries []providerregistry.Entry) *clientPathPrefixTable {
	t := &clientPathPrefixTable{byFirstSegment: make(map[string][]clientPathPrefix, len(entries)*2)}
	claimed := make(map[string]string, len(entries)*3)

	add := func(raw, code string) {
		prefix := strings.Trim(strings.ToLower(strings.TrimSpace(raw)), "/")
		if prefix == "" {
			return
		}
		if _, dup := claimed[prefix]; dup {
			return
		}
		claimed[prefix] = code
		seg := prefix
		if i := strings.IndexByte(seg, '/'); i >= 0 {
			seg = seg[:i]
		}
		t.byFirstSegment[seg] = append(t.byFirstSegment[seg], clientPathPrefix{prefix: prefix, code: code})
	}

	for _, e := range entries {
		proxyPath := strings.Trim(strings.TrimSpace(e.ProxyPath), "/")
		if proxyPath == "" {
			// No client namespace at all — see the `mock` note in the file header.
			continue
		}
		// Candidate 1: the full proxy_path (the value `aikey use` prints).
		add(proxyPath, e.Code)
		// Candidate 2: canonical code + proxy_path's first segment.
		add(e.Code, e.Code)
		if i := strings.IndexByte(proxyPath, '/'); i >= 0 {
			add(proxyPath[:i], e.Code)
		}
		// Candidate 3: brand aliases (`claude`, deprecated `kimi`, …).
		for _, alias := range e.OAuthAliases {
			add(alias, e.Code)
		}
	}

	// Longest prefix first inside each bucket; alphabetical on ties keeps the
	// order stable across runs (map iteration above is unordered by segment, but
	// each bucket's own order is what matching depends on).
	for seg := range t.byFirstSegment {
		bucket := t.byFirstSegment[seg]
		sort.Slice(bucket, func(i, j int) bool {
			if len(bucket[i].prefix) != len(bucket[j].prefix) {
				return len(bucket[i].prefix) > len(bucket[j].prefix)
			}
			return bucket[i].prefix < bucket[j].prefix
		})
		t.byFirstSegment[seg] = bucket
	}
	return t
}
