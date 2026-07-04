package quota

// policy_write.go — C′ (2026-06-17): proxy-side writer for quota_rules_cache,
// fed by the supervisor's 60s GET /v1/quota/policy poll (quota_policy.go).
//
// Ownership note: quota_rules_cache was historically CLI-ONLY written (the CLI
// mirrors the control delivery snapshot into it). C′ makes the PROXY a second
// writer of the SAME table with the SAME full-replace semantics, so an admin's
// limit edit reaches a running proxy within 60s without any employee command.
// Both writers source identical data from the master, so last-writer-wins is
// safe. The proxy-owned local increment lives in quota_local_usage (a SEPARATE
// table) and is never touched by this rebuild — see local_usage.go.

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// PolicySubject is one subject as delivered by GET /v1/quota/policy. It mirrors
// the control SubjectSnapshot wire shape. rules + baselines stay as raw JSON so
// they're written verbatim into the quota_rules_cache.rules / .baseline columns
// (no re-encode drift; LoadSubjects re-parses them with the Rule/Baseline types).
type PolicySubject struct {
	SubjectID   string          `json:"subject_id"`
	SubjectKind string          `json:"subject_kind"`
	Members     []string        `json:"members,omitempty"`
	Rules       json.RawMessage `json:"rules"`
	Baselines   json.RawMessage `json:"baselines,omitempty"`
}

// WriteSubjects full-replaces quota_rules_cache with the given subjects, matching
// the CLI's apply_quota_snapshot_to_cache: DELETE all + INSERT each, so a deleted
// rule propagates by its row disappearing (an empty slice clears the table). Opens
// its own connection by path — mirroring WriteLocalUsage — so the poll never
// contends on the proxy's shared read connection. One transaction for the batch.
// A missing table (a vault that predates the Phase 2 schema) is tolerated (no-op)
// so the poll never errors a pre-migration vault.
func WriteSubjects(dbPath string, subjects []PolicySubject) error {
	// Same vault DB file — reuse the busy_timeout guard (single source of truth,
	// vault.WithBusyTimeoutDSN) so this poll's full-replace write retries on lock
	// contention instead of failing an admin's quota-limit edit with SQLITE_BUSY.
	db, err := sql.Open("sqlite", vault.WithBusyTimeoutDSN(dbPath))
	if err != nil {
		return fmt.Errorf("open vault db for quota policy write: %w", err)
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin quota policy write: %w", err)
	}
	if _, delErr := tx.Exec(`DELETE FROM quota_rules_cache`); delErr != nil {
		_ = tx.Rollback()
		if isMissingTableOrColumn(delErr) {
			return nil // pre-Phase-2 vault: nothing to write into yet
		}
		return fmt.Errorf("clear quota_rules_cache: %w", delErr)
	}
	stmt, err := tx.Prepare(`
		INSERT INTO quota_rules_cache (subject_id, subject_kind, members, rules, baseline, synced_at)
		VALUES (?, ?, ?, ?, ?, CAST(strftime('%s','now') AS INTEGER))`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare quota policy write: %w", err)
	}
	defer stmt.Close()
	for _, sub := range subjects {
		// members: NULL for a seat (nil), JSON array for a group — matches the CLI.
		var members any
		if len(sub.Members) > 0 {
			b, mErr := json.Marshal(sub.Members)
			if mErr != nil {
				_ = tx.Rollback()
				return fmt.Errorf("marshal members for %q: %w", sub.SubjectID, mErr)
			}
			members = string(b)
		}
		// rules column is NOT NULL DEFAULT '[]'; never write an empty string.
		rules := string(sub.Rules)
		if rules == "" {
			rules = "[]"
		}
		// baseline: NULL when absent (the column is nullable).
		var baseline any
		if len(sub.Baselines) > 0 {
			baseline = string(sub.Baselines)
		}
		if _, err := stmt.Exec(sub.SubjectID, sub.SubjectKind, members, rules, baseline); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("write quota subject %q: %w", sub.SubjectID, err)
		}
	}
	return tx.Commit()
}
