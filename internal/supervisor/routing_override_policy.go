// routing_override_policy.go — I-side §6.5: the allocation engine's seat→account
// routing-override rail. Pulls GET /accounts/me/routing (account-JWT) and stores
// the sparse assignments in the shared in-memory RoutingOverrideCache the
// group-route resolver reads at request time.
//
// Since 2026-07-03 this rail is DRIVEN BY THE SYNCRAIL FRAMEWORK (railset.go):
// gate, generation, control URL and team credential are re-evaluated every
// cycle, failures are counted into the OK→STALE→OFFLINE visibility state
// machine, and Reload kicks an immediate cycle. The old hand-written loop built
// its credential once at start and early-returned forever on any precondition
// miss — silently (bugfix 2026-07-03-routing-override-rail-silent-stall.md).
//
// WHY proxy (not CLI): the engine recomputes overrides as account health drifts;
// the CLI isn't always running. Same master-poll rail compliance/quota/group-runtime
// already use.
//
// MAIN-LINK SAFETY: on master error / non-200 / timeout / no-auth the cycle
// returns an error WITHOUT touching the cache (keep-last-known, never flap) —
// the framework makes the failure visible, the cache is a pure redirect layer
// the resolver always falls back from.
package supervisor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/pkg/routingwire"
)

const routingOverridePollInterval = 60 * time.Second

var routingOverrideHTTPClient = httpx.NewSwappableDirect(10 * time.Second)

// routingOverrideRail declares this rail for the SyncRail framework. Gate: the
// oauth-group feature is on AND this vault actually has group VKs — a personal
// install without them is idle by design (no failure noise), and the old
// always-pull behavior fetched overrides no resolver would ever read.
func (s *Supervisor) routingOverrideRail() railSpec {
	return railSpec{
		name:         "routing_override",
		interval:     routingOverridePollInterval,
		needsTeamJWT: true,
		gate: func(gen *generation) bool {
			return oauthGroupRoutingEnabled() && len(s.localSeatGroupsFor(gen)) > 0
		},
		hydrate: s.hydrateRoutingOverrides,
		sync:    s.syncRoutingOverrides,
	}
}

// persistedAssignment is the my_assignment_override column payload — the
// engine's last-known assignment for one VK's (seat, group), written on each
// applied routing_version so a proxy restart resumes with the SAME pick the
// engine last issued (N12's persistence leg; without it the restart window fell
// back to the local ranked pick, the 2026-07-03 incident amplifier).
type persistedAssignment struct {
	AccountID string `json:"account_id,omitempty"`
	Blocked   bool   `json:"blocked,omitempty"`
	Removed   bool   `json:"removed,omitempty"`
	// RoutingVersion audits which engine version issued this assignment and
	// lets hydrate pick the newest across rows written at different times.
	RoutingVersion int64 `json:"routing_version"`
	// SyncedAt (unix) makes staleness inspectable (SELECT-level debugging).
	SyncedAt int64 `json:"synced_at"`
}

// hydrateRoutingOverrides preloads the in-memory override cache from the
// persisted my_assignment_override columns — runs once before the rail's first
// pull so the restart window serves the engine's last-known assignments instead
// of falling back to the local ranked pick (§5.3). A later successful pull is
// authoritative and overwrites both the cache and the columns.
func (s *Supervisor) hydrateRoutingOverrides(gen *generation) {
	if !oauthGroupRoutingEnabled() || s.routingOverrides == nil || s.routingOverrides.Stored() {
		return
	}
	mks, err := gen.vault.GetActiveManagedKeys()
	if err != nil {
		return // best-effort: the first pull populates the cache anyway
	}
	version, entries, corrupt := persistedRoutingEntries(mks)
	if corrupt > 0 {
		slog.Warn("startup routing assignments contain corrupt persisted rows; skipped corrupt rows",
			"event.name", observability.EventProxyClusterVaultAssignmentsCorrupt,
			"error.code", observability.ErrCodeClusterVaultAssignmentsCorrupt,
			"corrupt_rows", corrupt)
	}
	if len(entries) == 0 {
		return
	}
	s.routingOverrides.StoreRoutes(version, entries)
	slog.Info("routing overrides hydrated from vault (last-known, pre-pull)",
		"event.name", "proxy.routing_override.hydrated",
		"routing_version", version, "entries", len(entries))
}

// persistedRoutingEntries decodes the shared my_assignment_override wire for a
// complete managed-key snapshot. corrupt counts rows that could not be decoded;
// startup hydration may skip them best-effort, while the live Cluster refresh
// preserves its complete last-known cache rather than applying a partial map.
func persistedRoutingEntries(mks []vault.ManagedKey) (version int64, entries []routingwire.RouteEntry, corrupt int) {
	for i := range mks {
		mk := mks[i]
		if mk.OauthGroupID == "" || mk.SeatID == "" || mk.MyAssignmentOverride == "" {
			continue
		}
		var pa persistedAssignment
		if json.Unmarshal([]byte(mk.MyAssignmentOverride), &pa) != nil {
			corrupt++
			continue
		}
		if !pa.Blocked && !pa.Removed && pa.AccountID == "" {
			continue
		}
		entries = append(entries, routingwire.RouteEntry{
			SeatID: mk.SeatID, GroupID: mk.OauthGroupID,
			AccountID: pa.AccountID, Blocked: pa.Blocked, Removed: pa.Removed,
		})
		if pa.RoutingVersion > version {
			version = pa.RoutingVersion
		}
	}
	return version, entries, corrupt
}

// clusterRoutingSnapshotSignature fingerprints every local (seat, group)
// assignment column, including an empty column. Empty is the daemon's explicit
// pending/clear representation and therefore cannot be inferred from the max
// routing_version carried only by non-empty rows.
func clusterRoutingSnapshotSignature(mks []vault.ManagedKey) string {
	type assignmentRow struct {
		SeatID         string `json:"seat_id"`
		GroupID        string `json:"group_id"`
		State          string `json:"state"`
		AccountID      string `json:"account_id,omitempty"`
		Blocked        bool   `json:"blocked,omitempty"`
		Removed        bool   `json:"removed,omitempty"`
		RoutingVersion int64  `json:"routing_version,omitempty"`
	}
	rows := make([]assignmentRow, 0, len(mks))
	for i := range mks {
		mk := &mks[i]
		if mk.OauthGroupID == "" || mk.SeatID == "" {
			continue
		}
		row := assignmentRow{SeatID: mk.SeatID, GroupID: mk.OauthGroupID}
		if mk.MyAssignmentOverride == "" {
			row.State = "pending"
		} else {
			var assignment persistedAssignment
			if err := json.Unmarshal([]byte(mk.MyAssignmentOverride), &assignment); err != nil {
				// Corrupt snapshots are rejected by persistedRoutingEntries below and
				// never commit this signature. A stable marker is sufficient here.
				row.State = "corrupt"
			} else {
				row.State = "assigned"
				row.AccountID = assignment.AccountID
				row.Blocked = assignment.Blocked
				row.Removed = assignment.Removed
				row.RoutingVersion = assignment.RoutingVersion
			}
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].SeatID != rows[j].SeatID {
			return rows[i].SeatID < rows[j].SeatID
		}
		if rows[i].GroupID != rows[j].GroupID {
			return rows[i].GroupID < rows[j].GroupID
		}
		if rows[i].State != rows[j].State {
			return rows[i].State < rows[j].State
		}
		if rows[i].AccountID != rows[j].AccountID {
			return rows[i].AccountID < rows[j].AccountID
		}
		if rows[i].Blocked != rows[j].Blocked {
			return !rows[i].Blocked
		}
		if rows[i].Removed != rows[j].Removed {
			return !rows[i].Removed
		}
		return rows[i].RoutingVersion < rows[j].RoutingVersion
	})
	raw, _ := json.Marshal(rows) // fixed primitive shape cannot fail
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// refreshClusterRoutingOverrides applies daemon-written assignment columns to
// the running Worker's in-memory routing cache on the existing 5-second vault
// change-seq loop. Cluster Workers cannot use the member-JWT routing rail; a
// startup-only hydrate therefore leaves a running Worker on stale assignments
// after the engine rebinds a seat. Non-cluster editions deliberately stay on
// their existing network rail and never enter this path.
func (s *Supervisor) refreshClusterRoutingOverrides(mks []vault.ManagedKey) {
	if s.cfg == nil || !s.cfg.Cluster.Enabled || s.routingOverrides == nil {
		return
	}
	sig := clusterRoutingSnapshotSignature(mks)
	if previous := s.lastClusterRoutingSig.Load(); previous != nil && *previous == sig {
		return
	}
	version, entries, corrupt := persistedRoutingEntries(mks)
	if corrupt > 0 {
		slog.Warn("cluster routing assignments contain corrupt persisted rows; keeping last-known cache",
			"event.name", observability.EventProxyClusterVaultAssignmentsCorrupt,
			"error.code", observability.ErrCodeClusterVaultAssignmentsCorrupt,
			"corrupt_rows", corrupt)
		return
	}
	bound, blocked := s.routingOverrides.StoreRoutes(version, entries)
	s.lastClusterRoutingSig.Store(&sig)
	// Keep the display projection aligned with the hot-path cache. The helper is
	// network-free and safely returns when no active generation exists (unit tests
	// and early startup).
	s.restampCurrentRouted()
	slog.Info("cluster routing assignments refreshed from daemon-managed vault",
		"event.name", observability.EventProxyClusterVaultAssignmentsChanged,
		"routing_version", version, "route_entries", bound, "blocked_entries", blocked)
}

// persistAssignmentOverrides mirrors the freshly-stored cache into each group
// VK's my_assignment_override column. Write-on-change only (steady state is
// zero writes); a VK the engine no longer overrides gets its column cleared so
// hydrate can't resurrect a withdrawn assignment. The live pull is
// authoritative — it overwrites regardless of version direction (a reinstalled
// master may legitimately restart its version counter); RoutingVersion in the
// payload exists for hydrate ordering and auditability, not as a write gate.
func (s *Supervisor) persistAssignmentOverrides(gen *generation, version int64) {
	mks, err := gen.vault.GetActiveManagedKeys()
	if err != nil {
		return
	}
	now := time.Now().Unix()
	for i := range mks {
		mk := mks[i]
		if mk.OauthGroupID == "" || mk.SeatID == "" {
			continue
		}
		acct := s.routingOverrides.Assignment(mk.SeatID, mk.OauthGroupID)
		blk := s.routingOverrides.Blocked(mk.SeatID, mk.OauthGroupID)
		removed := s.routingOverrides.Removed(mk.SeatID, mk.OauthGroupID)
		desired := ""
		if acct != "" || blk || removed {
			b, mErr := json.Marshal(persistedAssignment{
				AccountID: acct, Blocked: blk, Removed: removed, RoutingVersion: version, SyncedAt: now,
			})
			if mErr != nil {
				continue
			}
			desired = string(b)
		}
		if sameAssignmentPayload(mk.MyAssignmentOverride, desired) {
			continue // steady state: same assignment at same version → no write
		}
		if err := vault.WriteAssignmentOverride(s.cfg.Vault.Path, mk.VirtualKeyID, desired); err != nil {
			// Persistence is an enhancement, not a dependency: the in-memory cache
			// already serves this cycle; WARN (mandatory-visibility) and move on.
			slog.Warn("my_assignment_override write failed — restart hydrate will miss this assignment",
				"event.name", "proxy.routing_override.persist_failed",
				"virtual_key_id", mk.VirtualKeyID, "error", err.Error())
		}
	}
}

// sameAssignmentPayload compares two persisted payloads ignoring synced_at (a
// re-write that only bumps the timestamp is churn, not information).
func sameAssignmentPayload(existing, desired string) bool {
	if existing == desired {
		return true
	}
	if existing == "" || desired == "" {
		return false
	}
	var a, b persistedAssignment
	if json.Unmarshal([]byte(existing), &a) != nil || json.Unmarshal([]byte(desired), &b) != nil {
		return false
	}
	return a.AccountID == b.AccountID && a.Blocked == b.Blocked && a.Removed == b.Removed && a.RoutingVersion == b.RoutingVersion
}

// syncRoutingOverrides runs one pull. Only when the routing_version actually
// advanced does it replace the shared cache; a fetch error keeps the last-known
// assignments in place (don't flap) and is COUNTED by the framework (no more
// silent returns). Mirrors syncGroupRuntime's version-skip + keep-last-known.
func (s *Supervisor) syncRoutingOverrides(ctx context.Context, gen *generation, masterURL, bearer string) error {
	if s.routingOverrides == nil {
		return nil
	}
	version, routes, err := fetchRoutingOverrides(ctx, masterURL, bearer)
	if err != nil {
		return err // keep last-known; framework counts + surfaces
	}
	// Skip only once we've ALREADY stored at this version. The Stored() guard
	// closes the first-pull-at-version-0 hole: the cache's version atomic starts
	// at 0, so without it master's first non-empty assignments carrying
	// routing_version:0 would match Version()==0 and be skipped forever (the
	// override never applied, no signal). After the first Store, steady-state
	// re-pulls of the same version skip as before (no churn, no log spam).
	if s.routingOverrides.Stored() && s.routingOverrides.Version() == version {
		return nil // unchanged → no churn (a successful no-op cycle IS a success)
	}
	bound, blocked := s.routingOverrides.StoreRoutes(version, routes)
	slog.Info("routing overrides updated",
		"event.name", "proxy.routing_override.changed",
		"routing_version", version, "route_entries", bound, "blocked_entries", blocked)
	// Format-mismatch fingerprint (2026-07-02, review F1): a NON-EMPTY route set in
	// which not a single entry matches any of this vault's local (seat,group) pairs
	// means the two sides disagree about the wire (or the payload is for the wrong
	// account) — a failure that is otherwise indistinguishable from "no overrides".
	// WARN once per routing_version (the ticker would repeat it every 60s otherwise).
	// Mandatory-WARN rule: fallback-to-default paths must log.
	if len(routes) > 0 && !routesMatchAnyLocal(routes, s.localSeatGroupsFor(gen)) {
		if s.lastRoutingMismatchVersion.Swap(version) != version {
			slog.Warn("routing overrides matched no local group VK — wire format / account mismatch?",
				"event.name", "proxy.routing_override.format_mismatch",
				"routing_version", version, "route_entries", len(routes))
		}
	}
	// C2 display coupling (owner-approved 2026-06-30): the engine just redirected one
	// or more seats. Re-stamp IsCurrentRouted on the affected group VKs' group_runtime
	// so /user/vault shows the new routed account within this override poll, not only on
	// the next material refresh. Display-only + network-free (RMW on the cached column);
	// the routing redirect itself already took effect via the override cache above.
	s.restampCurrentRouted()
	// N12 persistence leg (2026-07-03): mirror the applied assignments to the
	// my_assignment_override columns so a restart hydrates the same picks (§5.3).
	s.persistAssignmentOverrides(gen, version)
	return nil
}

// fetchRoutingOverrides GETs the routing endpoint with an account-JWT Bearer and
// decodes the SHARED wire DTO (pkg/routingwire — the same structs master emits, so
// the two repos cannot drift). Returns a non-nil error on ANY failure so the
// caller keeps the last-known cache AND the framework can surface the underlying
// cause (a bare ok=false hid the connection-refused detail that mattered most in
// the 2026-07-03 incident). nil routes normalize to an empty slice so a
// successful pull always carries a concrete (possibly empty) set.
func fetchRoutingOverrides(ctx context.Context, masterURL, bearer string) (int64, []routingwire.RouteEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, masterURL+"/accounts/me/routing", http.NoBody)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := routingOverrideHTTPClient.Get().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("GET /accounts/me/routing: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	var out routingwire.RoutingResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, nil, fmt.Errorf("decode routing response: %w", err)
	}
	if out.Routes == nil {
		out.Routes = []routingwire.RouteEntry{}
	}
	return out.RoutingVersion, out.Routes, nil
}

// routesMatchAnyLocal reports whether at least one wire entry targets one of this
// vault's local (seat, group) pairs. Pure — unit-tested as the format-mismatch
// fingerprint's decision core.
func routesMatchAnyLocal(routes []routingwire.RouteEntry, local map[[2]string]bool) bool {
	for _, r := range routes {
		if local[[2]string{r.SeatID, r.GroupID}] {
			return true
		}
	}
	return false
}

// localSeatGroupsFor collects the (seat, group) pairs of a generation's group VKs
// — the set a healthy routing payload should intersect, and this rail's gate
// ("is there anything to route locally?"). Empty on any read problem.
func (s *Supervisor) localSeatGroupsFor(gen *generation) map[[2]string]bool {
	if gen == nil || gen.vault == nil {
		return nil
	}
	mks, err := gen.vault.GetActiveManagedKeys()
	if err != nil {
		return nil
	}
	out := map[[2]string]bool{}
	for i := range mks {
		if mks[i].OauthGroupID != "" && mks[i].SeatID != "" {
			out[[2]string{mks[i].SeatID, mks[i].OauthGroupID}] = true
		}
	}
	return out
}

// localSeatGroups keeps the historical accessor shape (current generation).
func (s *Supervisor) localSeatGroups() map[[2]string]bool {
	return s.localSeatGroupsFor(s.active.Load())
}
