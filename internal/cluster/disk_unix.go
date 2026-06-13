//go:build !windows

package cluster

import "syscall"

// diskFreeMB returns the free disk space of dir's filesystem in MiB, or -1 if
// it cannot be determined. Statfs field types differ across darwin/linux
// (Bsize is uint32 vs int64), hence the explicit conversions.
func diskFreeMB(dir string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize) / (1024 * 1024)
}
