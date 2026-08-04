// Node-health collection for the cluster heartbeat piggyback (P0-B).
//
// Why this exists: the co-located aikey-cluster-daemon writes its sync health
// to `daemon-status.json` next to the node vault.db, but that file is only
// node-local. This collector reads it every heartbeat and forwards it — plus
// a few proxy-own metrics — inside the optional `health` heartbeat field, so
// the hub (and from there the master console) can see it. The proxy is a
// transparent transport: it never grades or interprets the daemon section
// (grading authority stays with the signal producer).
//
// Contract: the daemon section's shape is pinned by
// aikey-hub/contract/daemon-status.fixture.json (a copy lives in this
// package's testdata/ — keep in sync, see testdata/README.md).
package cluster

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// daemonStatusFileName matches the daemon's status.rs STATUS_FILE_NAME — both
// sides derive the same path from the shared vault.db location (single truth,
// no extra config key).
const daemonStatusFileName = "daemon-status.json"

// NodeHealthSource returns the heartbeat health collector for this node.
//
//   - vaultPath: the node vault.db path (config.Vault.Path) — the daemon
//     status file is derived as a sibling, and disk space is measured on its
//     directory (that's the disk that matters: vault + WAL live there).
//   - version: proxy build version (version-skew signal on the hub).
//   - startedAt: proxy process start (restart-churn signal on the hub).
//   - canaryFn: optional getter for the latest usage-pipeline canary result
//     (supervisor.CanaryResult adapted to any). nil func or nil result ⇒ no
//     canary section — same transparent-transport rule as the daemon section:
//     the canary grades itself (ok/partial/failed/unavailable), this collector
//     only ships the verdict.
//
// RuntimeMetrics is the proxy-runtime slice forwarded in health.proxy for the
// Phase-4 signals (upstream error rate + usage-report backlog). All values are
// cheap in-process reads. Requests/Errors are CUMULATIVE since proxy start —
// the hub turns them into a windowed rate by differencing consecutive
// heartbeats (cumulative-lifetime rate would stay stale after a recovery).
type RuntimeMetrics struct {
	Requests                  int64 // cumulative upstream forward attempts
	Errors                    int64 // cumulative upstream forward errors
	ReportConsecutiveFailures int   // reporter upload retry streak (0 = healthy)
	ReportLastUploadAgeS      int64 // seconds since last successful usage upload; -1 = never
	ReportTerminalFails       int64 // events permanently dropped to dead-letter
}

// The returned func never fails: on any read/parse problem it omits the
// daemon section (the hub renders the absence as "no health data" — absence
// is itself a signal) and WARNs once per distinct error, not per heartbeat
// (a corrupt file would otherwise spam every 5s).
//
// metricsFn (nil ⇒ omit the upstream/reporting fields) supplies the Phase-4
// runtime metrics; like canaryFn it is transparent transport — the hub grades.
func NodeHealthSource(vaultPath, version string, startedAt time.Time, canaryFn func() any, metricsFn func() RuntimeMetrics, poolRoutingFn func() any) func() map[string]any {
	dir := filepath.Dir(vaultPath)
	statusPath := filepath.Join(dir, daemonStatusFileName)
	var lastWarned string // last WARN'd error string, to de-duplicate logs

	return func() map[string]any {
		proxy := map[string]any{
			"started_at":   startedAt.Unix(),
			"version":      version,
			"node_time":    time.Now().Unix(),
			"disk_free_mb": diskFreeMB(dir), // -1 = unknown (see disk_windows.go)
		}
		if metricsFn != nil {
			m := metricsFn()
			proxy["requests"] = m.Requests
			proxy["errors"] = m.Errors
			proxy["report_consecutive_failures"] = m.ReportConsecutiveFailures
			proxy["report_last_upload_age_s"] = m.ReportLastUploadAgeS
			proxy["report_terminal_fails"] = m.ReportTerminalFails
		}
		h := map[string]any{"proxy": proxy}
		if poolRoutingFn != nil {
			if routing := poolRoutingFn(); routing != nil {
				h["pool_routing"] = routing
			}
		}
		if canaryFn != nil {
			if cr := canaryFn(); cr != nil {
				h["canary"] = cr
			}
		}

		raw, err := os.ReadFile(statusPath)
		if err != nil {
			// Missing file is expected during bring-up (daemon not started
			// yet) and is judged by the hub as "no health data" — no log spam.
			return h
		}
		var daemon map[string]any
		if uerr := json.Unmarshal(raw, &daemon); uerr != nil || daemon == nil {
			// A present-but-unparseable file is NOT expected — WARN (logging
			// conventions: parse-failure fallbacks must not be silent), but
			// only when the error changes, not every 5s heartbeat.
			msg := "unparseable daemon status file"
			if uerr != nil {
				msg = uerr.Error()
			}
			if msg != lastWarned {
				lastWarned = msg
				slog.Warn("cluster: daemon status file unreadable; omitting daemon health",
					"path", statusPath, "error", msg)
			}
			return h
		}
		lastWarned = ""
		h["daemon"] = daemon
		return h
	}
}
