package proxy

import (
	"os"
	"testing"
)

// TestMain sandboxes AIKEY_RUN_DIR for the WHOLE package. Proxy instances
// write/remove the bypass ~/.aikey/run/group-login-required.json state file
// (group_login_state.go) on group-route 401s/successes; without this override
// every `go test` on a developer machine would transiently touch the REAL
// ~/.aikey/run — racing a live proxy's statusline hint (a success-path test
// would silently delete a genuine login prompt). Package-wide (not per-test
// t.Setenv) so future tests can't forget it.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "aikey-proxy-test-run-*")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("AIKEY_RUN_DIR", dir)
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
