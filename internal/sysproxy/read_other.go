//go:build !darwin && !windows

package sysproxy

// Linux/other: no OS system-proxy detection (user-approved scope 2026-07-08).
// Server editions (Cluster nodes, CI) run here — the watcher stays inert and
// egress behavior is byte-identical to the pre-detection daemon (env vars via
// http.ProxyFromEnvironment). Desktop-Linux gsettings support is a future
// drop-in: implement readSystemProxy + flip platformSupported.
const platformSupported = false

func readSystemProxy() (Snapshot, error) { return Snapshot{}, nil }
