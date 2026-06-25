// oauth_pool_session.go — NP-2: rolling masked session for pool accounts.
//
// NP-1 collapsed all of a pool account's traffic onto ONE session id, but a
// constant-forever session is itself a weak signal (real sessions rotate). This
// replaces the constant with a rolling masked session per account (sub2api
// RewriteUserIDWithMasking strong mode + a max-age 防永生 cap):
//
//   - all N employees on the account still share ONE session id (N→1 collapse);
//   - the id stays stable while the account keeps sending traffic (a work
//     session looks continuous, cache stays warm);
//   - it ROTATES after poolSessionIdleTTL of silence (an idle account's session
//     dies, as a real one would) OR poolSessionMaxAge of total life (so no
//     account ever carries one implausibly immortal session — the 防永生 dim).
package proxy

import (
	"sync"
	"time"
)

const (
	poolSessionIdleTTL = 15 * time.Minute // rotate after this much silence (sub2api window)
	poolSessionMaxAge  = 12 * time.Hour   // rotate after this total life regardless (防永生)
)

type rollingSession struct {
	id        string
	createdAt time.Time
	lastUsed  time.Time
}

// poolSessionStore holds one rolling masked session per pool account. Safe for
// concurrent use (many proxy goroutines). Entry count is bounded by the number
// of distinct pool accounts the proxy serves (small — a customer's pool), so the
// map is not actively evicted; rotation reuses the same key in place.
type poolSessionStore struct {
	mu  sync.Mutex
	m   map[string]*rollingSession
	now func() time.Time // injectable clock (tests)
}

func newPoolSessionStore() *poolSessionStore {
	return &poolSessionStore{m: make(map[string]*rollingSession), now: time.Now}
}

// defaultPoolSessions is the process-wide store applyPoolPersona uses.
var defaultPoolSessions = newPoolSessionStore()

// sessionID returns the account's current masked session id, rotating it when
// idle-expired or past max age. accountID seeds the deterministic fallback when
// the CSPRNG is unavailable, so the request still collapses to one session.
func (s *poolSessionStore) sessionID(accountID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	rs := s.m[accountID]
	if rs == nil ||
		now.Sub(rs.lastUsed) > poolSessionIdleTTL ||
		now.Sub(rs.createdAt) > poolSessionMaxAge {
		rs = &rollingSession{id: newMaskedSessionID(accountID), createdAt: now}
		s.m[accountID] = rs
	}
	rs.lastUsed = now
	return rs.id
}

// newMaskedSessionID mints a fresh random session id. On CSPRNG failure it falls
// back to the deterministic per-account id so the request still collapses to one
// session for the account (degrade, don't fail the request).
func newMaskedSessionID(accountID string) string {
	if id, err := generateUUID(); err == nil {
		return id
	}
	return poolSessionID(accountID)
}
