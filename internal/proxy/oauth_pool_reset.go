// oauth_pool_reset.go — Path Z (per-window cap re-roll, signal-up half).
//
// The proxy observes each pool account's upstream window-reset epoch
// (anthropic-ratelimit-unified-reset) in ModifyResponse and records the latest
// per account here. Non-Cluster supervisors piggyback the snapshot on the
// existing GET /accounts/me/group-runtime Path Z pull. Cluster Workers keep
// that member rail disabled and coalesce the same process-owned observations
// by credential onto the existing org signal endpoint. Master re-rolls only
// when a reset strictly advances; the fresh cap comes back through the edition's
// existing delivery rail. See 通道3系统设计 §14 and the Cluster D3 design.
package proxy

import (
	"sort"
	"sync"
)

// ObservedWindowResets is the independent reset observation sent to master.
// The JSON keys are part of the rolling-compatible Path-Z header contract.
type ObservedWindowResets struct {
	FiveHour int64 `json:"5h,omitempty"`
	SevenDay int64 `json:"7d,omitempty"`
}

// observedWindowResetSample is the Cluster org-signal representation. The
// member pull keys resets by oauth_group_account.account_id, while the signal
// endpoint authorizes credential_id; retaining both identities at observation
// time lets each existing rail use its native authorization key.
type observedWindowResetSample struct {
	CredentialID    string `json:"credential_id"`
	WindowResetAt   int64  `json:"window_reset_at,omitempty"`
	Window7dResetAt int64  `json:"window_7d_reset_at,omitempty"`
}

type poolResetEntry struct {
	CredentialID string
	Resets       ObservedWindowResets
}

// poolResetStore holds the latest observed upstream window-reset epoch per pool
// account. Concurrency-safe. Monotonic per account (resets only advance across
// windows; a stale/smaller value never overwrites), so master's
// "observed > stored" re-roll guard stays idempotent — re-sending the same reset
// over either existing rail triggers at most one re-roll.
type poolResetStore struct {
	mu sync.Mutex
	m  map[string]poolResetEntry
}

func newPoolResetStore() *poolResetStore {
	return &poolResetStore{m: make(map[string]poolResetEntry)}
}

// record stores the account's observed reset epoch, keeping the max. No-op for
// an empty id or a non-positive epoch.
func (s *poolResetStore) record(accountID string, observed ObservedWindowResets) {
	s.recordRoute(accountID, "", observed)
}

// recordRoute is the production observation path. accountID remains the Path-Z
// member-pull key; credentialID is the org-signal authorization key. Each
// window advances independently and neither a stale response nor a route
// refresh may erase the other window's newest fact.
func (s *poolResetStore) recordRoute(accountID, credentialID string, observed ObservedWindowResets) {
	if accountID == "" || (observed.FiveHour <= 0 && observed.SevenDay <= 0) {
		return
	}
	s.mu.Lock()
	current := s.m[accountID]
	if credentialID != "" {
		current.CredentialID = credentialID
	}
	if observed.FiveHour > current.Resets.FiveHour {
		current.Resets.FiveHour = observed.FiveHour
	}
	if observed.SevenDay > current.Resets.SevenDay {
		current.Resets.SevenDay = observed.SevenDay
	}
	s.m[accountID] = current
	s.mu.Unlock()
}

// snapshot returns a copy of the per-account observed resets for the pull to
// piggyback. Returns nil when empty (so the pull omits the header).
func (s *poolResetStore) snapshot() map[string]ObservedWindowResets {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) == 0 {
		return nil
	}
	out := make(map[string]ObservedWindowResets, len(s.m))
	for k, v := range s.m {
		out[k] = v.Resets
	}
	return out
}

// signalSnapshot coalesces account observations by credential because the
// signal endpoint authorizes and persists in credential id space. It is a live
// reconcile snapshot: HTTP success does not delete it, so a false/partial ack
// cannot permanently lose the only reset observation.
func (s *poolResetStore) signalSnapshot() []observedWindowResetSample {
	s.mu.Lock()
	defer s.mu.Unlock()
	byCredential := make(map[string]observedWindowResetSample)
	for _, entry := range s.m {
		if entry.CredentialID == "" {
			continue
		}
		current := byCredential[entry.CredentialID]
		current.CredentialID = entry.CredentialID
		if entry.Resets.FiveHour > current.WindowResetAt {
			current.WindowResetAt = entry.Resets.FiveHour
		}
		if entry.Resets.SevenDay > current.Window7dResetAt {
			current.Window7dResetAt = entry.Resets.SevenDay
		}
		byCredential[entry.CredentialID] = current
	}
	if len(byCredential) == 0 {
		return nil
	}
	credentials := make([]string, 0, len(byCredential))
	for credentialID := range byCredential {
		credentials = append(credentials, credentialID)
	}
	sort.Strings(credentials)
	out := make([]observedWindowResetSample, 0, len(credentials))
	for _, credentialID := range credentials {
		out = append(out, byCredential[credentialID])
	}
	return out
}
