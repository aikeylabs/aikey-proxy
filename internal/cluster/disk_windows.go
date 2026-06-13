//go:build windows

package cluster

// diskFreeMB returns -1 ("unknown") on Windows. Cluster nodes ship as Linux
// binaries (hub-install.sh: binary+systemd); this stub only keeps the Personal
// Windows build compiling — cluster mode is never enabled there, so the
// collector doesn't run. -1 is the documented "unknown" sentinel the hub skips.
func diskFreeMB(string) int64 { return -1 }
