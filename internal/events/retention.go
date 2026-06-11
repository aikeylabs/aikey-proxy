// retention.go — local usage-data retention: WAL archive/expiry + events.db prune.
//
// Implements the WAL retention designed in 费用小票-实施方案.md §11/§12
// (config keys events.wal_retention_days / events.wal_archive_days, daily
// sweep, manual `aikey-proxy wal vacuum`), extended per the 2026-06-10
// decision to also prune the local usage_events table in the same pass —
// that table previously grew unbounded and is full-scanned by QueryStats
// on every /metrics call (perf review P6).
//
// Policy:
//   - WAL files older than RetentionDays move into the usage-wal-archive/
//     subdirectory of the WAL dir. A SUBDIRECTORY is load-bearing: every WAL
//     consumer (reporter ListWALFiles, aikey watch, aikey statusline) lists
//     files via a non-recursive `usage-*.jsonl` match, so archived files
//     drop out of all reader paths with zero reader changes.
//   - Archived files older than ArchiveDays are deleted.
//   - usage_events rows older than RetentionDays are deleted.
//
// Why archive-then-delete instead of delete: a >retention-old UNCONFIRMED
// WAL file may still hold undelivered billing events. Archiving makes the
// gap "WAL-absent", which the reconcile pass (D3) then classifies as
// confirmed-lost — an auditable outcome, vs. silent deletion. The archive
// window (default 90d) keeps the raw lines recoverable by an operator.
//
// The current hour's open WAL file is never eligible (cutoff is days in
// the past), so sweeping concurrently with a writing proxy is safe; the
// standalone `wal vacuum` subcommand relies on the same property.
package events

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WALArchiveSubdir is the archive directory name under the WAL dir. Kept as
// the design's literal name (费用小票 §12 接入点: "usage-wal-archive/").
const WALArchiveSubdir = "usage-wal-archive"

// RetentionConfig carries the sweep policy. Zero values are not valid here —
// callers resolve defaults (30/90) from config before constructing it.
type RetentionConfig struct {
	WALDir        string
	RetentionDays int // WAL files + usage_events rows older than this are retired
	ArchiveDays   int // archived WAL files older than this are deleted
}

// RetentionResult summarizes one sweep for logs / `wal vacuum` output.
type RetentionResult struct {
	WALArchived     int
	ArchiveDeleted  int
	EventsPruned    int64
	Errors          []string // non-fatal per-file failures (sweep continues)
}

// walFileTime parses the UTC hour embedded in a WAL filename
// (usage-YYYYMMDD-HH.jsonl). Returns ok=false for names that don't parse —
// the sweep skips those rather than guessing.
func walFileTime(name string) (time.Time, bool) {
	base := strings.TrimSuffix(filepath.Base(name), ".jsonl")
	stamp := strings.TrimPrefix(base, "usage-")
	if stamp == base {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102-15", stamp)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// RunRetentionSweep performs one archive/expiry/prune pass. store may be nil
// (WAL-only sweep). Per-file failures are recorded and skipped, never fatal —
// a stuck file must not block the rest of the sweep.
func RunRetentionSweep(cfg RetentionConfig, store *Store, now time.Time) RetentionResult {
	var res RetentionResult
	retireBefore := now.UTC().AddDate(0, 0, -cfg.RetentionDays)
	deleteBefore := now.UTC().AddDate(0, 0, -cfg.ArchiveDays)
	archiveDir := filepath.Join(cfg.WALDir, WALArchiveSubdir)

	// 1. Archive expired live WAL files.
	if files, err := ListWALFiles(cfg.WALDir); err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("list wal: %v", err))
	} else {
		for _, f := range files {
			ts, ok := walFileTime(f)
			if !ok || !ts.Before(retireBefore) {
				continue
			}
			if err := os.MkdirAll(archiveDir, 0o755); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("mkdir archive: %v", err))
				break
			}
			dst := filepath.Join(archiveDir, filepath.Base(f))
			if err := os.Rename(f, dst); err != nil {
				// Another sweeper (vacuum vs in-process loop) may have moved it
				// first — ENOENT is benign; anything else is reported.
				if !os.IsNotExist(err) {
					res.Errors = append(res.Errors, fmt.Sprintf("archive %s: %v", filepath.Base(f), err))
				}
				continue
			}
			res.WALArchived++
		}
	}

	// 2. Delete archive files past the archive window. Negative ArchiveDays =
	// keep archives forever (operator opted out of the delete stage).
	if matches, err := filepath.Glob(filepath.Join(archiveDir, "usage-*.jsonl")); err == nil && cfg.ArchiveDays >= 0 {
		for _, f := range matches {
			ts, ok := walFileTime(f)
			if !ok || !ts.Before(deleteBefore) {
				continue
			}
			if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
				res.Errors = append(res.Errors, fmt.Sprintf("delete archived %s: %v", filepath.Base(f), err))
				continue
			}
			res.ArchiveDeleted++
		}
	}

	// 3. Prune local usage_events rows past retention. Same cutoff as the WAL:
	// rows that old have either been uploaded long ago (collector dedup makes
	// re-upload safe regardless) or are offline-local stats history.
	if store != nil {
		n, err := store.PruneOlderThan(retireBefore)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("prune usage_events: %v", err))
		} else {
			res.EventsPruned = n
		}
	}
	return res
}

// RetentionLoop runs RunRetentionSweep once at start and then daily at 00:00
// UTC (per the design's "每天 00:00 扫文件名"), until ctx is cancelled.
// Failures degrade per-item and are logged loudly; the loop itself never
// exits on error (bypass: must not require a restart to resume).
//
// storeFn is resolved at each sweep (not captured once) because the proxy
// hot-reloads generations: the events Store handle is per-generation, and a
// loop pinned to the first generation's handle would prune through a closed
// DB after the first reload. May return nil (WAL-only sweep).
func RetentionLoop(ctx context.Context, cfg RetentionConfig, storeFn func() *Store) {
	sweep := func() {
		var store *Store
		if storeFn != nil {
			store = storeFn()
		}
		res := RunRetentionSweep(cfg, store, time.Now())
		for _, e := range res.Errors {
			slog.Warn("usage retention: item failed",
				"event.name", "usage.retention.item_failed", "error", e)
		}
		slog.Info("usage retention sweep complete",
			"event.name", "usage.retention.sweep",
			"wal_archived", res.WALArchived,
			"archive_deleted", res.ArchiveDeleted,
			"events_pruned", res.EventsPruned,
			"retention_days", cfg.RetentionDays,
			"archive_days", cfg.ArchiveDays)
	}
	sweep()
	for {
		now := time.Now().UTC()
		next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
		t := time.NewTimer(next.Sub(now))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			sweep()
		}
	}
}
