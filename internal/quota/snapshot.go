// Package quota holds the proxy-side enterprise-quota rule snapshot + in-memory
// counter (Phase 2 Stage 2 — design §0.5/§5.2).
//
// The proxy is a CLIENT-side component with no access to the control DB. Quota
// rules reach it the same way managed keys do: the control delivery snapshot
// inlines the seat's applicable rules → the CLI writes them into the local
// vault's quota_rules_cache → the proxy reads that table on its 5s vault sync
// and builds this in-memory snapshot + a seat→group reverse index.
//
// Stage 2 scope: LOAD rules + ACCUMULATE counts only. Request interception /
// enforcement (reading the snapshot at request time to allow/deny) is Stage 3.
package quota

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Subject kinds (mirror control). Only these two — org/tenant deliberately
// absent (decoupling, design §3.3).
const (
	KindSeat  = "seat"
	KindGroup = "group"
)

// Metrics (mirror control, design §3.4). Both are enforced: tokens from a local
// count, usd from a server-computed baseline read via UsdUsedSource (the proxy
// never computes cost — design D-U1).
const (
	MetricTokens = "tokens"
	MetricUSD    = "usd"
)

// Threshold is one tier of a Rule (design §5.6). Carried through for Stage 3; the
// proxy doesn't act on it in Stage 2.
type Threshold struct {
	Pct    int            `json:"pct"`
	Action string         `json:"action"`
	Config map[string]any `json:"config,omitempty"`
}

// Rule is one (metric, period) limit with tiered thresholds. Mirrors the
// control-side rule shape; parsed from quota_rules_cache.rules JSON.
type Rule struct {
	Metric      string      `json:"metric"`
	Period      string      `json:"period"`
	LimitAmount float64     `json:"limit_amount"`
	Thresholds  []Threshold `json:"thresholds"`
}

// Baseline is the control-reported current-period used for one (metric, period)
// of a subject (回填 — design §5.4). Delivered via the snapshot so a
// restart/another machine doesn't start the counter from zero. Carries BOTH
// metrics: tokens (top-up for the local increment) and usd (the enforcement
// value itself — the proxy reads it instead of computing cost).
type Baseline struct {
	Metric string  `json:"metric"`
	Period string  `json:"period"`
	Used   float64 `json:"used"`
}

// Subject is one limit subject (a seat or a group of seats) as cached locally.
type Subject struct {
	SubjectID   string
	SubjectKind string
	Members     []string // group: [seat_id...]; seat: nil
	Rules       []Rule
	Baselines   []Baseline // current-period used per (metric,period); may be empty
}

// ModelUnitPrices is one model's per-token USD rates. Mirrors control's
// quota.ModelUnitPrices and the per-event unit_prices_snapshot JSON — the
// cross-repo contract. Keep in lockstep with aikey-control-master
// .../quota/pricesummary.go and aikey-data .../internal/pricing/summary.go.
type ModelUnitPrices struct {
	Input         float64 `json:"input"`
	Output        float64 `json:"output"`
	CacheCreation float64 `json:"cache_creation"`
	CacheRead     float64 `json:"cache_read"`
	Reasoning     float64 `json:"reasoning"`
}

// PriceSummary is the deployment-global edge price table (design D-U8) the proxy
// uses for LOCAL usd pricing. Delivered inline in the control snapshot, cached by
// the CLI in the vault `config` table (quotaPriceSummaryKey), loaded here. P6 only
// LOADS + holds it; P7 consumes it for enforcement.
type PriceSummary struct {
	Version string                     `json:"version"`
	Models  map[string]ModelUnitPrices `json:"models"`
}

// quotaPriceSummaryKey mirrors aikey-cli storage_platform.rs QUOTA_PRICE_SUMMARY_KEY.
const quotaPriceSummaryKey = "quota.price_summary"

// Snapshot is the atomically-swappable rule set + seat→group reverse index.
// Read under RLock; replaced wholesale under Lock (gen-swap — mirrors
// vkeys.Registry.ReplaceAll so a 5s sync never tears a concurrent read).
type Snapshot struct {
	mu           sync.RWMutex
	subjects     map[string]*Subject // subject_id → subject
	seatToGroups map[string][]string // seat_id → [group subject_id...]
	priceSummary *PriceSummary       // D-U8/P6: edge prices for local usd pricing (P7)
	lastReachableAt time.Time         // D-U7/P9: proxy's last TRAFFIC-INDEPENDENT confirmation the server is reachable (heartbeat probe, pkg/heartbeat) — freshness for budget-mode staleness; zero = never confirmed (treated as fresh, not infinitely stale)
}

// NewSnapshot returns an empty snapshot (safe to read before the first load).
func NewSnapshot() *Snapshot {
	return &Snapshot{
		subjects:     map[string]*Subject{},
		seatToGroups: map[string][]string{},
	}
}

// ReplaceAll atomically swaps in a new subject set and rebuilds the seat→group
// reverse index by walking each group's members (design §3.5: the index is
// built at load time so enforcement finds a seat's groups in O(1)).
func (s *Snapshot) ReplaceAll(subjects []Subject) {
	subjMap := make(map[string]*Subject, len(subjects))
	rev := map[string][]string{}
	for i := range subjects {
		sub := subjects[i] // fresh copy per iteration → distinct &sub
		subjMap[sub.SubjectID] = &sub
		if sub.SubjectKind == KindGroup {
			for _, seatID := range sub.Members {
				rev[seatID] = append(rev[seatID], sub.SubjectID)
			}
		}
	}
	s.mu.Lock()
	s.subjects = subjMap
	s.seatToGroups = rev
	s.mu.Unlock()
}

// SetPriceSummary atomically swaps the edge price summary (D-U8/P6). nil-safe.
func (s *Snapshot) SetPriceSummary(ps *PriceSummary) {
	s.mu.Lock()
	s.priceSummary = ps
	s.mu.Unlock()
}

// PriceSummary returns the current edge price summary (nil if none delivered yet —
// P7 then falls back to the input-equivalent token floor).
func (s *Snapshot) PriceSummary() *PriceSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.priceSummary
}

// SetLastReachableAt records the last time the proxy confirmed the server is
// reachable — fed from the traffic-independent heartbeat probe (pkg/heartbeat),
// NOT from request-driven work. Using a traffic-independent source is the whole
// fix: a usage-bound signal goes stale when idle even though the server is up,
// which (under budget mode) blocks an idle node and then deadlocks because the
// block stops the traffic that would refresh it. Zero time = never confirmed.
// nil-safe via the mutex.
func (s *Snapshot) SetLastReachableAt(t time.Time) {
	s.mu.Lock()
	s.lastReachableAt = t
	s.mu.Unlock()
}

// LastReachableAt returns the last time the server was confirmed reachable (zero
// if never).
func (s *Snapshot) LastReachableAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastReachableAt
}

// budgetStale reports whether the server has been unreachable too long to trust
// the cached baseline under budget mode (D-U7/P9): now − lastReachableAt >
// maxStaleness. A ZERO lastReachableAt (heartbeat never succeeded yet — fresh
// boot, or no heartbeat configured) returns false: do NOT fail-closed on a
// signal that never started (rollout-safe, never over-blocks). Because the
// signal is traffic-independent, an idle-but-online node keeps its heartbeat
// fresh and is never wrongly marked stale (the deadlock this replaced).
func (s *Snapshot) budgetStale(now time.Time, maxStaleness time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastReachableAt.IsZero() {
		return false
	}
	return now.Sub(s.lastReachableAt) > maxStaleness
}

// SubjectsForSeat returns the seat's own subject (if any) plus every group
// subject the seat belongs to — the full set Stage 3 enforcement merges to take
// the strictest limit (design §5.3 D11). nil when the seat has no quota.
func (s *Snapshot) SubjectsForSeat(seatID string) []*Subject {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Subject
	if sub, ok := s.subjects[seatID]; ok {
		out = append(out, sub)
	}
	for _, gid := range s.seatToGroups[seatID] {
		if g, ok := s.subjects[gid]; ok {
			out = append(out, g)
		}
	}
	return out
}

// Len reports the number of subjects currently loaded (for the load log).
func (s *Snapshot) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subjects)
}

// LoadSubjects reads the cached quota rules from the vault DB's quota_rules_cache
// table (written by the CLI from the control delivery snapshot — design
// §0.5/§5.2). Tolerant by design: a missing table (a vault not yet carrying the
// Phase 2 schema) returns an empty slice, not an error, so quota degrades to "no
// rules" rather than disturbing the proxy's vault-sync loop.
//
// NOTE: the quota_rules_cache schema is owned by aikey-cli/src/migrations.rs.
// Keep the column list here in lockstep with that CREATE TABLE.
func LoadSubjects(db *sql.DB) ([]Subject, error) {
	rows, err := db.Query(`SELECT subject_id, subject_kind, members, rules, baseline FROM quota_rules_cache`)
	if err != nil {
		// Pre-Phase-2 vault (no table) or pre-Stage-4 vault (no baseline column):
		// degrade to "no quota" rather than disturbing the vault-sync loop.
		if isMissingTableOrColumn(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()

	var out []Subject
	for rows.Next() {
		var (
			sub         Subject
			members     sql.NullString
			rulesStr    string
			baselineStr sql.NullString
		)
		if err := rows.Scan(&sub.SubjectID, &sub.SubjectKind, &members, &rulesStr, &baselineStr); err != nil {
			return nil, err
		}
		if rulesStr != "" {
			if err := json.Unmarshal([]byte(rulesStr), &sub.Rules); err != nil {
				return nil, fmt.Errorf("quota: parse rules for %q: %w", sub.SubjectID, err)
			}
		}
		if members.Valid && members.String != "" {
			if err := json.Unmarshal([]byte(members.String), &sub.Members); err != nil {
				return nil, fmt.Errorf("quota: parse members for %q: %w", sub.SubjectID, err)
			}
		}
		if baselineStr.Valid && baselineStr.String != "" {
			if err := json.Unmarshal([]byte(baselineStr.String), &sub.Baselines); err != nil {
				return nil, fmt.Errorf("quota: parse baseline for %q: %w", sub.SubjectID, err)
			}
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// LoadPriceSummary reads the deployment-global edge price summary from the vault
// `config` table (key quota.price_summary, written by the CLI from the delivery
// snapshot — D-U8/P6). Tolerant: a missing config table / absent key / empty
// value yields (nil, nil), so the proxy falls back to the input-equivalent floor
// (P7) without disturbing the vault-sync loop.
func LoadPriceSummary(db *sql.DB) (*PriceSummary, error) {
	var raw string
	err := db.QueryRow(`SELECT CAST(value AS TEXT) FROM config WHERE key = ?`, quotaPriceSummaryKey).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		if isMissingTableOrColumn(err) {
			return nil, nil
		}
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}
	var ps PriceSummary
	if err := json.Unmarshal([]byte(raw), &ps); err != nil {
		return nil, fmt.Errorf("quota: parse price summary: %w", err)
	}
	return &ps, nil
}

// isMissingTableOrColumn detects SQLite "no such table"/"no such column" (the
// proxy vault is always SQLite) so a vault that predates the quota table or the
// Stage 4 baseline column loads as "no quota" instead of erroring.
func isMissingTableOrColumn(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "no such table") || strings.Contains(m, "no such column")
}
