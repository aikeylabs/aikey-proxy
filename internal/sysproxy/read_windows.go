//go:build windows

package sysproxy

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const platformSupported = true

// readSystemProxy reads the per-user WinINET proxy settings — the registry
// location Windows' "Proxy" settings page (and Clash for Windows) writes.
// AutoConfigURL (PAC) is not evaluated (needs a JS engine); PAC-only setups
// yield an empty snapshot = direct, identical to pre-detection behavior.
func readSystemProxy() (Snapshot, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open Internet Settings key: %w", err)
	}
	defer k.Close()

	enabled, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil || enabled == 0 {
		// Missing value or disabled both mean "no system proxy" — not an error.
		return Snapshot{}, nil
	}
	server, _, err := k.GetStringValue("ProxyServer")
	if err != nil {
		return Snapshot{}, nil
	}
	return parseWindowsProxyServer(server), nil
}
