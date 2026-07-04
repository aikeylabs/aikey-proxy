package quota

// local_usage.go — the proxy-OWNED write-behind persistence of the in-memory
// counter's local increment (design update/20260605, P0). The in-memory Counter
// stays the authority; this table is a crash-recovery checkpoint, written
// periodically (every 5s sync tick, NOT per request) and read ONCE at startup so
// an OFFLINE proxy restart resumes from the persisted usage instead of forgetting
// everything accrued since the last server baseline.
//
// Ownership: the PROXY is the sole writer of quota_local_usage; the CLI never
// touches it. That is the whole point — quota_rules_cache (CLI-written) is
// DELETE+rebuilt on every sync, so persisting increments there would wipe them;
// a separate proxy-owned table cannot be clobbered.

import (
	"database/sql"
	"fmt"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// LocalUsageRow is one persisted (subject, metric, period) increment. Mirrors the
// quota_local_usage columns; also the shape Counter.IncrementRows emits.
//
// NOTE: the quota_local_usage schema is owned by aikey-cli/src/migrations.rs.
// Keep the column list here in lockstep with that CREATE TABLE.
type LocalUsageRow struct {
	SubjectID string
	Metric    string
	PeriodKey string
	Increment float64
}

// LoadLocalUsage reads the persisted local increments at startup. Tolerant by
// design: a missing table (a vault that predates the P0 migration) returns an
// empty slice, not an error, so quota degrades to "start increments from zero"
// rather than disturbing the vault-sync loop.
func LoadLocalUsage(db *sql.DB) ([]LocalUsageRow, error) {
	rows, err := db.Query(`SELECT subject_id, metric, period_key, increment FROM quota_local_usage`)
	if err != nil {
		if isMissingTableOrColumn(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()

	var out []LocalUsageRow
	for rows.Next() {
		var r LocalUsageRow
		if err := rows.Scan(&r.SubjectID, &r.Metric, &r.PeriodKey, &r.Increment); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SeedLocalIncrements restores persisted increments into the counter at startup
// (calls Counter.SeedIncrement per row). MUST run once before serving — see
// SeedIncrement. nil-safe.
func SeedLocalIncrements(counter *Counter, rows []LocalUsageRow) {
	if counter == nil {
		return
	}
	for _, r := range rows {
		counter.SeedIncrement(r.SubjectID, r.Metric, r.PeriodKey, r.Increment)
	}
}

// WriteLocalUsage upserts the given increments (write-behind flush). Opens its own
// connection by path — mirroring vault.WriteConfigU64LE — so the proxy's flush
// never contends on the shared read connection. One transaction for the batch.
// A missing table is tolerated (no-op) so a pre-migration vault doesn't error the
// sync loop; the increments simply aren't persisted until the CLI migration runs.
func WriteLocalUsage(dbPath string, rows []LocalUsageRow) error {
	if len(rows) == 0 {
		return nil
	}
	// Same vault DB file as vault.WriteConfig*/WriteGroupRuntime — must carry the
	// busy_timeout guard (this is the busiest vault writer, 5s ticks), else it
	// fails instantly on SQLITE_BUSY under lock contention on Linux. Single source
	// of truth: vault.WithBusyTimeoutDSN (do not open the vault file raw).
	db, err := sql.Open("sqlite", vault.WithBusyTimeoutDSN(dbPath))
	if err != nil {
		return fmt.Errorf("open vault db for local-usage flush: %w", err)
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin local-usage flush: %w", err)
	}
	stmt, err := tx.Prepare(`
		INSERT INTO quota_local_usage (subject_id, metric, period_key, increment, updated_at)
		VALUES (?, ?, ?, ?, CAST(strftime('%s','now') AS INTEGER))
		ON CONFLICT (subject_id, metric, period_key) DO UPDATE
		    SET increment = excluded.increment, updated_at = excluded.updated_at`)
	if err != nil {
		_ = tx.Rollback()
		if isMissingTableOrColumn(err) {
			return nil
		}
		return fmt.Errorf("prepare local-usage flush: %w", err)
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.SubjectID, r.Metric, r.PeriodKey, r.Increment); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("flush local usage %s/%s/%s: %w", r.SubjectID, r.Metric, r.PeriodKey, err)
		}
	}
	return tx.Commit()
}
