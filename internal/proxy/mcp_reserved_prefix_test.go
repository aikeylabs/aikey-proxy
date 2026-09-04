package proxy

// mcp_reserved_prefix_test.go — the PROXY half of fence 1.F1 (I9 / R13).
//
// pkg/providerregistry refuses a row that claims a reserved prefix at PARSE
// time. This file asserts the consequence the proxy actually depends on: that
// the derived client path-prefix table contains no entry which would swallow
// /mcp/, /health/, /version or /.well-known/.
//
// Both halves are needed. The registry test proves the guard rejects; this one
// proves the guard is guarding the right thing — that the derivation really is
// the only way a prefix gets into the table, so blocking it at parse time is
// sufficient. If someone later adds a second source of prefixes (a hardcoded
// slice, an env override), the registry fence would still pass while this one
// starts failing, which is exactly the split that catches it.

import (
	"testing"

	"github.com/AiKeyLabs/pkg/providerregistry"
)

// TestMcpPrefixIsNotDerivable is fence 1.F1.
//
// Before the reserved-prefix set existed, a provider row whose proxy_path was
// written as `mcp` would have made /mcp/... resolve to that provider's
// forwarding path — silently hijacking the entire MCP gateway surface, with
// "cannot connect" as the only symptom the customer ever reports.
func TestMcpPrefixIsNotDerivable(t *testing.T) {
	table := clientPathPrefixes()
	if table == nil {
		t.Fatal("client path-prefix table is nil")
	}

	reserved := map[string]bool{}
	for _, p := range providerregistry.ReservedPrefixes() {
		reserved[p] = true
	}
	if !reserved["mcp"] {
		t.Fatal("`mcp` is no longer in the reserved set; the MCP gateway surface is unprotected")
	}

	for _, entry := range table.all() {
		if reserved[entry.prefix] {
			t.Errorf("client path prefix %q (from provider %q) collides with a reserved HTTP surface; "+
				"requests to /%s/... would be routed to that provider instead",
				entry.prefix, entry.code, entry.prefix)
		}
	}
}

// TestReservedPrefixesResolveToNoProvider is the same claim stated through the
// function the request path actually calls, rather than through the table.
//
// 🔴 Asserting on the table alone would miss a lookup that normalises or
// rewrites its input before consulting it. This asserts the observable
// behaviour: a request to a reserved prefix must not be claimed by any provider.
func TestReservedPrefixesResolveToNoProvider(t *testing.T) {
	for _, p := range providerregistry.ReservedPrefixes() {
		if got := clientPathPrefixes().candidatesFor(p); len(got) != 0 {
			t.Errorf("reserved prefix %q resolved to %d provider candidate(s); it must resolve to none", p, len(got))
		}
	}
}
