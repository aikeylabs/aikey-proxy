package proxy

import "testing"

// 🔴 Two axes, one list (bugfix 2026-08-20 NO_ACTIVE_KEY-for-moonshot).
//
// `active_key_providers` is meant to hold SUPPLIER codes, but vaults written
// before the CLI fix hold CLIENT ROUTE names. Both must resolve, or upgrading
// the CLI is required to keep an existing binding working — and a personal
// machine that never re-runs `aikey use` would just stop routing.
//
// The failing case that started this: a moonshot key bound to the kimi route
// wrote "kimi"; the proxy canonicalised it to "kimi_code" (registry alias) and
// refused every /moonshot/v1 request while /kimi/v1 on the SAME key worked.
func TestActiveKeyEntryMatches_BothAxes(t *testing.T) {
	cases := []struct {
		name         string
		entry        string // what active_key_providers holds
		requestCode  string // provider derived from the request path
		wantMatch    bool
	}{
		{"supplier entry, same supplier", "moonshot", "moonshot", true},
		{"supplier entry, sibling supplier", "moonshot", "kimi_code", false},
		{"legacy ROUTE entry, moonshot request", "kimi", "moonshot", true},
		{"legacy ROUTE entry, kimi_code request", "kimi", "kimi_code", true},
		{"unrelated provider", "moonshot", "anthropic", false},
		{"exact non-family match", "anthropic", "anthropic", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := activeEntryServesProvider(c.entry, c.requestCode); got != c.wantMatch {
				t.Fatalf("entry %q vs request %q: got %v, want %v",
					c.entry, c.requestCode, got, c.wantMatch)
			}
		})
	}
}
