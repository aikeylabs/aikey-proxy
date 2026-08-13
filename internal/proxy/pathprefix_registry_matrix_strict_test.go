//go:build pathprefix_matrix

package proxy

// The STRICT half of the path-prefix matrix — the actual acceptance bar.
//
// Build-tagged when it was RED (20 of 28 picker:true providers failed: 15 × D-1,
// 5 × D-2) so it would not block everybody else's CI. 🟢 GREEN 28/28 since the
// 2026-08-08 fix. The tag is kept because the ledger test in
// pathprefix_registry_matrix_test.go now carries the identical bar in DEFAULT CI
// (its ledger is empty), and this file's value is the printed per-provider table
// you want when diagnosing a specific provider.
//
// Run while fixing:
//
//	make -C aikey-proxy test-pathprefix-matrix
//	go test ./internal/proxy/ -tags pathprefix_matrix -run TestPathPrefixMatrix_Strict -v
//
// 🚫 Do not relax an assertion here to get it green. The definition of green is
// "every picker:true provider routes, and the vendor receives exactly the path
// it would have received from a direct client" — that is the contract
// `aikey use` prints to the user, nothing less.

import "testing"

func TestPathPrefixMatrix_Strict(t *testing.T) {
	results := runWholeMatrix(t)
	t.Log(renderMatrix(results))

	broken := 0
	for _, r := range results {
		if r.Failure != "" {
			broken++
			t.Errorf("%s (proxy_path %s): %s", r.Code, r.ProxyPath, r.Failure)
		}
	}
	if broken > 0 {
		t.Logf("%d/%d picker:true providers cannot be used through path-prefix routing", broken, len(results))
	}
}
