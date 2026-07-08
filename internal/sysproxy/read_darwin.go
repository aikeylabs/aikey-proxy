//go:build darwin

package sysproxy

import (
	"fmt"
	"os/exec"
	"time"
)

const platformSupported = true

// readSystemProxy shells out to `scutil --proxy` — the canonical, cgo-free way
// to read the primary network service's proxy settings. It reflects Clash /
// System Settings changes immediately. Cost ~10ms, run every pollInterval.
func readSystemProxy() (Snapshot, error) {
	cmd := exec.Command("/usr/sbin/scutil", "--proxy")
	// WaitDelay guards against a wedged scutil pinning the poll goroutine.
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.Output()
	if err != nil {
		return Snapshot{}, fmt.Errorf("scutil --proxy: %w", err)
	}
	return parseScutilProxy(string(out)), nil
}
