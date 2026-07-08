//go:build darwin

package sysproxy

import "testing"

// Live exec smoke: `scutil --proxy` must run and parse on any macOS box —
// whatever it returns (proxy on/off) must not error. Guards the exec wiring
// the fixture tests can't cover.
func TestReadSystemProxy_ExecSmoke(t *testing.T) {
	snap, err := readSystemProxy()
	if err != nil {
		t.Fatalf("scutil exec path failed: %v", err)
	}
	t.Logf("live system proxy snapshot: %+v", snap)
}
