// key_revocation_rail.go — bounds how long a RUNNING proxy keeps honoring a
// virtual key the control plane has already stopped honoring.
//
// # The problem, in one sentence
//
// "Suspend this member" took effect on the control plane immediately, but the
// only thing that could tell THIS proxy about it was the member's own CLI: the
// data path resolves bearers from the local vault, and the vault only changes
// when `aikey key sync` / `aikey use` / a wrapper launch runs on that machine.
// A long-running proxy whose owner never types another aikey command therefore
// kept routing traffic for a suspended seat for an UNBOUNDED time — measured
// live on 2026-08-25 at 110 seconds and still serving, stopped only by a manual
// sync. Meanwhile the console's confirmation dialog said the seat's virtual keys
// stop routing "immediately".
//
// 🔴 The existing machinery was NOT broken, which is why this went unnoticed.
// supervisor.syncManagedKeys already replaces the whole registry (ReplaceAll,
// never Merge) precisely so revoked tokens disappear, and it does — within 5
// seconds OF A VAULT CHANGE. The defect was never "revocation does not apply";
// it was "nothing on this machine ever asks". A mechanism with no trigger is
// indistinguishable, from the outside, from a mechanism that does not work.
//
// # Why a rail and not a sixth hand-written loop
//
// railset.go exists because six hand-rolled pollers drifted apart and two of
// them starved silently for seven hours (bugfix
// 2026-07-03-routing-override-rail-silent-stall.md). Declaring a railSpec buys
// the per-cycle re-evaluation of gate / control URL / credential, the
// OK→STALE→OFFLINE visibility state machine, /status exposure and panic
// isolation — none of which this rail then gets to opt out of.
//
// # Why these two endpoints and no new API
//
// Both are the ones `aikey key sync` already calls, so this adds no control-plane
// surface and no new contract to keep in step:
//
//	GET /accounts/me/sync-version         → one integer, the account's change counter
//	GET /accounts/me/managed-keys-snapshot → per-VK effective status (no key material)
//
// The version probe is what makes a 60s cadence affordable on a customer's own
// hardware: the snapshot is fetched only when the counter actually moved.
// Verified live 2026-08-26 on a real tenant: suspending a seat moved
// sync_version 5 → 6, and re-activating it moved 6 → 7.
//
// 🔴 Read `effective_status`, NEVER `key_status`. On that same live run the
// suspended seat's VK reported key_status="active" with
// effective_status="inactive" / effective_reason="seat_disabled" — the VK itself
// was never revoked, its SEAT was. A rail keyed on key_status would poll
// correctly, parse correctly, decide "nothing to do", and change nothing. Fenced
// by TestKeyRevocationUsesEffectiveStatus.
//
// # What this rail deliberately does NOT do
//
// It only ever REMOVES routes. Re-adding a key needs its material, which needs
// the master password — and the wrapper path must stay zero-password
// (principles/interaction-simplicity-first.md). Grants therefore keep arriving
// on the existing CLI path exactly as before; this rail is a strict tightening,
// so a bug in it can cost availability but cannot grant access.
//
// See workflow/CI/bugfix/20260826-proxy-revocation-window-unbounded.md.
package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// keyRevocationPollInterval is the ceiling this rail puts on the revocation
// window. 60s matches the quota rail: the same cadence an administrator's quota
// edit already takes to reach a running proxy, so operators have one number to
// remember rather than two.
//
// 🚫 Deliberately not configurable. "How fast does a suspension take effect" is
// a security property of the deployment, not a knob for an operator to widen.
const keyRevocationPollInterval = 60 * time.Second

const (
	syncVersionPath         = "/accounts/me/sync-version"
	managedKeysSnapshotPath = "/accounts/me/managed-keys-snapshot"
)

// maxKeyRevocationBody caps both responses. A snapshot for one account is a few
// KB; anything past this means we are not talking to the endpoint we think we
// are, and reading it unbounded would let a misrouted response eat memory.
const maxKeyRevocationBody = 1 << 20

// effectiveStatusActive is the ONLY value that keeps a route alive. Matching on
// the good value rather than enumerating the bad ones is the point: a status the
// control plane adds later (say "expired") is then treated as not-active by
// default instead of being silently honored by a proxy that has not shipped yet.
const effectiveStatusActive = "active"

var keyRevocationHTTPClient = httpx.NewSwappableDirect(10 * time.Second)

type syncVersionResponse struct {
	AccountID   string `json:"account_id"`
	SyncVersion int64  `json:"sync_version"`
}

type managedKeysSnapshotResponse struct {
	SyncVersion int64 `json:"sync_version"`
	Keys        []struct {
		VirtualKeyID    string `json:"virtual_key_id"`
		SeatID          string `json:"seat_id"`
		EffectiveStatus string `json:"effective_status"`
		EffectiveReason string `json:"effective_reason"`
	} `json:"keys"`
}

// revokedVKs returns the current revocation set. Never nil, so callers can index
// it directly; an empty map means "nothing known to be revoked", which is also
// what a rail that has never succeeded reports (see Supervisor.revokedVKIDs).
func (s *Supervisor) revokedVKs() map[string]bool {
	if p := s.revokedVKIDs.Load(); p != nil {
		return *p
	}
	return map[string]bool{}
}

// keyRevocationRail declares the rail.
//
// Gate: this vault holds at least one team managed key. A Personal install has
// none, so the cycle is skipped without counting a failure and without ever
// appearing in /status — the same "idle, not broken" shape the other rails use.
func (s *Supervisor) keyRevocationRail() railSpec {
	return railSpec{
		name:         "key_revocation",
		interval:     keyRevocationPollInterval,
		needsTeamJWT: true,
		gate: func(gen *generation) bool {
			if gen == nil || gen.vault == nil {
				return false
			}
			mks, err := gen.vault.GetActiveManagedKeys()
			return err == nil && len(mks) > 0
		},
		sync: s.syncKeyRevocation,
	}
}

// syncKeyRevocation performs one pull+apply cycle.
func (s *Supervisor) syncKeyRevocation(ctx context.Context, gen *generation, masterURL, bearer string) error {
	var ver syncVersionResponse
	if err := getJSONWithBearer(ctx, masterURL+syncVersionPath, bearer, &ver); err != nil {
		return fmt.Errorf("sync-version probe: %w", err)
	}

	// Cheap path: the account's change counter has not moved since we last
	// resolved it, so the snapshot cannot have changed either.
	//
	// 🔴 Guarded on a successful FIRST resolution, not just on equality: at boot
	// lastSyncVersion is 0, and a control plane that legitimately reports 0 would
	// otherwise let the rail report success forever without ever having fetched a
	// snapshot — a rail that is green and blind.
	if s.revokedVKIDs.Load() != nil && s.lastSyncVersion.Load() == ver.SyncVersion {
		return nil
	}

	var snap managedKeysSnapshotResponse
	if err := getJSONWithBearer(ctx, masterURL+managedKeysSnapshotPath, bearer, &snap); err != nil {
		return fmt.Errorf("managed-keys snapshot: %w", err)
	}

	// 🔴 An empty key list is NOT proof that nothing is revoked — it is what a
	// wrong account, a wrong endpoint, or a projection that failed to refresh also
	// looks like. Acting on it would drop every team route on this machine, so the
	// only safe reading is "this told us nothing": keep the last known set and
	// make the oddity loud. This is the same class of trap as the directory
	// sync's "not computed vs nobody disappeared" distinction.
	if len(snap.Keys) == 0 {
		slog.Warn("key revocation: snapshot returned no keys while this vault holds team keys; keeping the last known revocation set",
			"event.name", observability.EventProxyKeyRevocationMalformed,
			"sync_version", ver.SyncVersion)
		return nil
	}

	revoked := make(map[string]bool)
	for _, k := range snap.Keys {
		if k.VirtualKeyID == "" {
			continue
		}
		if !strings.EqualFold(k.EffectiveStatus, effectiveStatusActive) {
			revoked[k.VirtualKeyID] = true
		}
	}

	prev := s.revokedVKs()
	s.revokedVKIDs.Store(&revoked)
	s.lastSyncVersion.Store(ver.SyncVersion)

	// 🔴 Publish into the vault reader BEFORE the registry rebuild, and do it on
	// every cycle rather than only when the set changed. This reader is the very
	// same instance the data path holds (buildGeneration passes it to both
	// gen.vault and proxy.New), so this is what closes the follow-active path —
	// `aikey_active_<provider>` resolves through GetTeamKeyByID, which never
	// consults the vkeys registry. Publishing unconditionally also re-arms the
	// filter after a Reload swapped in a fresh reader.
	if gen.vault != nil {
		gen.vault.SetRevokedVirtualKeys(revoked)
	}

	if sameRevocationSet(prev, revoked) {
		return nil
	}

	slog.Info("key revocation: set changed; rebuilding routes",
		"event.name", observability.EventProxyKeyRevocationChanged,
		"sync_version", ver.SyncVersion,
		"revoked_count", len(revoked),
		"previous_count", len(prev),
		"revoked_vk_ids", sortedKeys(revoked))

	total := s.rebuildRouteRegistry(gen)
	slog.Info("key revocation: registry rebuilt",
		"event.name", observability.EventProxyKeyRevocationChanged,
		"total_routes", total)
	return nil
}

func sameRevocationSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// getJSONWithBearer issues one authenticated GET and decodes the body.
//
// 🚫 No X-Aikey-* request headers here beyond the bearer: this call goes to the
// control plane, but keeping the same discipline everywhere is what stops one
// from later being copied onto an upstream request
// (principles/no-aikey-headers-to-llm-upstream.md).
func getJSONWithBearer(ctx context.Context, url, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")

	resp, err := keyRevocationHTTPClient.Get().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeyRevocationBody))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}
