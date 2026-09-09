package mcp

// session.go — MCP sessions, in memory only.
//
// # What an MCP session actually is
//
// The Streamable HTTP transport mints an `Mcp-Session-Id` at `initialize` and
// the client echoes it on every later request. It exists so a stateful
// server can correlate a client's requests — and, for us, so a call can be
// pinned to the SAME upstream backend instance it started on (requirement R5,
// session stickiness).
//
// # 🔴 Why in-memory, and why that is not a shortcut
//
// Three independent reasons, any one of which would be enough:
//
//  1. A session is NOT an authorisation. R8 requires every single tools/call to
//     re-evaluate the grant, so nothing security-relevant may be cached on a
//     session anyway. Persisting one would create a second place where
//     permission APPEARS to live, and the first person to optimise "we already
//     checked this session" reintroduces the classic "revocation does not take
//     effect" bug. 🚫 Never put a grant decision in Session.
//  2. It dies with the process by design. A restarted proxy has lost its
//     upstream connections and its stickiness targets; resurrecting session ids
//     across a restart would hand clients handles that point at nothing.
//     Answering MCP_SESSION_NOT_FOUND and letting the client re-initialize is
//     both correct and what the spec expects.
//  3. Personal edition has no database to persist to. A design that needs one
//     would not work in the edition where stdio backends — the main form — live.
//
// Frozen in the technical design §3.1: sessions are memory state, 🚫 not stored.
//
// # Expiry
//
// Idle sessions are reaped so a long-running proxy does not accumulate handles
// from clients that went away without calling DELETE. Reaping happens lazily on
// access plus on an interval — 🚫 no dedicated goroutine per session, which
// would make session count a goroutine-count problem.

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/AiKeyLabs/pkg/mcpwire"
)

// DefaultSessionIdleTimeout is how long a session survives with no requests.
//
// 30 minutes is well above any interactive gap (a developer reading code
// between tool calls) and well below "this process has been up for a week".
const DefaultSessionIdleTimeout = 30 * time.Minute

// Session is one client's negotiated connection state.
//
// 🔴 Everything here is transport correlation. There is deliberately no grant
// set, no allow-list, no cached authorisation — see the file header.
type Session struct {
	// ID is the value handed back in Mcp-Session-Id.
	ID string
	// ToolsetSlug is the toolset this session was opened against. A session is
	// scoped to one toolset; presenting it on a different /mcp/<slug> is a
	// client bug and is rejected rather than silently re-scoped.
	ToolsetSlug string
	// OrgID / SeatID are the identity the bearer resolved to at initialize.
	//
	// They are kept for ATTRIBUTION and for the stickiness key, never for
	// authorisation: the bearer is re-resolved on every request, so a revoked
	// key stops working immediately instead of riding the session.
	OrgID  string
	SeatID string
	// ProtocolVersion is what the two sides agreed on.
	ProtocolVersion mcpwire.ProtocolVersion
	// ClientInfo is what the client called itself. Display only.
	ClientInfo mcpwire.Implementation
	// StickyBackends pins backend id → chosen upstream instance, so R5's
	// stickiness survives across the session.
	StickyBackends map[string]string

	createdAt  time.Time
	lastSeenAt time.Time
}

// SessionStore holds live sessions for this process.
type SessionStore struct {
	mu          sync.Mutex
	byID        map[string]*Session
	idleTimeout time.Duration
	now         func() time.Time
	// lastReap bounds how often a full sweep runs, so a busy server does not
	// walk every session on every request.
	lastReap time.Time
}

// NewSessionStore builds an empty store. idleTimeout <= 0 selects the default.
func NewSessionStore(idleTimeout time.Duration) *SessionStore {
	if idleTimeout <= 0 {
		idleTimeout = DefaultSessionIdleTimeout
	}
	return &SessionStore{
		byID:        make(map[string]*Session),
		idleTimeout: idleTimeout,
		now:         time.Now,
	}
}

// Create mints a new session.
//
// The id is 32 bytes of crypto/rand, base64url-encoded without padding.
//
// 🔴 It must be unguessable. The session id is presented on subsequent requests
// alongside the bearer; if it were sequential or time-derived, a client that
// obtained one id could probe for other tenants' sessions and at minimum learn
// that they exist. crypto/rand rather than math/rand is not a stylistic choice.
//
// An error from crypto/rand is returned rather than swallowed: falling back to
// a weaker source on failure is how a "temporary" degradation becomes a
// permanent vulnerability nobody notices.
func (s *SessionStore) Create(toolsetSlug, orgID, seatID string, version mcpwire.ProtocolVersion, client mcpwire.Implementation) (*Session, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	now := s.now()
	sess := &Session{
		ID:              base64.RawURLEncoding.EncodeToString(raw),
		ToolsetSlug:     toolsetSlug,
		OrgID:           orgID,
		SeatID:          seatID,
		ProtocolVersion: version,
		ClientInfo:      client,
		StickyBackends:  make(map[string]string),
		createdAt:       now,
		lastSeenAt:      now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked(now)
	s.byID[sess.ID] = sess
	return sess, nil
}

// Get returns the session for id and refreshes its idle clock.
//
// The second return is false for both "never existed" and "expired". The caller
// answers MCP_SESSION_NOT_FOUND for either, because from the client's point of
// view they are the same situation with the same fix: run initialize again.
// Distinguishing them in the response would also tell an unauthenticated prober
// which ids once existed.
func (s *SessionStore) Get(id string) (*Session, bool) {
	if id == "" {
		return nil, false
	}
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	if now.Sub(sess.lastSeenAt) > s.idleTimeout {
		delete(s.byID, id)
		return nil, false
	}
	sess.lastSeenAt = now
	return sess, true
}

// Delete ends a session. Idempotent: deleting an unknown id is success, because
// the spec's DELETE means "I am done with this", and a client retrying after a
// dropped response must not get an error for having succeeded the first time.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

// Count returns the number of live sessions, for GET /health/mcp.
func (s *SessionStore) Count() int {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked(now)
	return len(s.byID)
}

// reapLocked drops idle sessions. Caller holds the mutex.
//
// Rate-limited to one sweep per idleTimeout/4 so the cost is amortised: without
// that bound, a server with many sessions would walk the whole map on every
// single request, turning session count into a per-request cost.
func (s *SessionStore) reapLocked(now time.Time) {
	if now.Sub(s.lastReap) < s.idleTimeout/4 {
		return
	}
	s.lastReap = now
	for id, sess := range s.byID {
		if now.Sub(sess.lastSeenAt) > s.idleTimeout {
			delete(s.byID, id)
		}
	}
}
