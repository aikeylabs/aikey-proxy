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

// poolResetStore holds the latest observed upstream window-reset epoch per pool
// account. Concurrency-safe. Monotonic per account (resets only advance across
// windows; a stale/smaller value never overwrites), so master's
// "observed > stored" re-roll guard stays idempotent — re-sending the same reset
// every pull triggers at most one re-roll.
type poolResetStore struct {
	mu sync.Mutex
	m  map[string]int64 // accountID → latest observed unified-reset epoch (seconds)
}

func newPoolResetStore() *poolResetStore {
	return &poolResetStore{m: make(map[string]int64)}
}

// record stores the account's observed reset epoch, keeping the max. No-op for
// an empty id or a non-positive epoch.
func (s *poolResetStore) record(accountID string, resetEpoch int64) {
	if accountID == "" || resetEpoch <= 0 {
		return
	}
	s.mu.Lock()
	if resetEpoch > s.m[accountID] {
		s.m[accountID] = resetEpoch
	}
	s.mu.Unlock()
}

// snapshot returns a copy of the per-account observed resets for the pull to
// piggyback. Returns nil when empty (so the pull omits the header).
func (s *poolResetStore) snapshot() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) == 0 {
		return nil
	}
	out := make(map[string]int64, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out
}
