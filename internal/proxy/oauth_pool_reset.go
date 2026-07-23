// oauth_pool_reset.go — Path Z (per-window cap re-roll, signal-up half).
//
// The proxy observes each pool account's upstream window-reset epoch
// (anthropic-ratelimit-unified-reset) in ModifyResponse and records the latest
// per account here. The supervisor's N7c pull (fetchGroupRuntime) piggybacks the
// snapshot to master on the EXISTING GET /accounts/me/group-runtime call, and
// master re-rolls window_max_util_pct when it sees a newer reset (a new window).
// master learns the reset no other way today, so this is the signal-up half of
// the re-roll loop; the fresh cap comes back down via the same pull. Reuses the
// pull channel — no new endpoint, no usage-pipeline schema change. See
// 通道3系统设计 §14.
package proxy

import "sync"

// ObservedWindowResets is the independent reset observation sent to master.
// The JSON keys are part of the rolling-compatible Path-Z header contract.
type ObservedWindowResets struct {
	FiveHour int64 `json:"5h,omitempty"`
	SevenDay int64 `json:"7d,omitempty"`
}

// poolResetStore holds the latest observed upstream window-reset epoch per pool
// account. Concurrency-safe. Monotonic per account (resets only advance across
// windows; a stale/smaller value never overwrites), so master's
// "observed > stored" re-roll guard stays idempotent — re-sending the same reset
// every pull triggers at most one re-roll.
type poolResetStore struct {
	mu sync.Mutex
	m  map[string]ObservedWindowResets
}

func newPoolResetStore() *poolResetStore {
	return &poolResetStore{m: make(map[string]ObservedWindowResets)}
}

// record stores the account's observed reset epoch, keeping the max. No-op for
// an empty id or a non-positive epoch.
func (s *poolResetStore) record(accountID string, observed ObservedWindowResets) {
	if accountID == "" || (observed.FiveHour <= 0 && observed.SevenDay <= 0) {
		return
	}
	s.mu.Lock()
	current := s.m[accountID]
	if observed.FiveHour > current.FiveHour {
		current.FiveHour = observed.FiveHour
	}
	if observed.SevenDay > current.SevenDay {
		current.SevenDay = observed.SevenDay
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
		out[k] = v
	}
	return out
}
