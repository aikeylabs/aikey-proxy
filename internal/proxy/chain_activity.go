package proxy

// chain_activity.go — coming back to the primary upstream without probing it
// (openspec change `aliyun-aigw-p0-upstream-fallback`, tasks 2.19–2.25,
// contract freeze §9).
//
// # 🔴 The problem, stated precisely
//
// Once a request has failed over, something has to decide when to try the
// primary again. Four options were considered (F-7) and three were rejected for
// reasons worth keeping:
//
//	B fixed TTL              — expiry can land in the MIDDLE of a conversation.
//	C periodic active probe  — burns real tokens on every cycle, and each probe
//	                           carries a real credential to one more place.
//	D never return           — one bad minute pins an organization to its
//	                           fallback until a restart.
//
// What ships is A: the first request after a QUIET GAP tries the primary again.
// It costs nothing extra (the user's own request is the probe), and it cannot
// interrupt a conversation, because by definition there is no conversation in
// progress after a gap.
//
// # 🔴 Zero synthetic probes (I16)
//
// A "hello?" request would be cheaper to write and worse in three ways: it spends
// real money every cycle, it exposes a credential on a path no user asked for,
// and it is much SMALLER than a real request — so it can succeed against an
// upstream that would still fail the real thing, which is the worst possible
// answer because it looks like proof.
//
// # 🔴 The gap is measured from SERVER-SIDE FACTS ONLY (I18)
//
// 🚫 `session_id` must never enter this decision. The sessionid package's own
// documentation says the value is client-controlled and trivially forged, and
// that routing, authentication and billing never consult it. If it drove
// switch-back, any client could force us to re-hit a known-dead upstream simply
// by minting a new id on every request.
//
// # 🔴 Stickiness is not just comfort (I17)
//
// While a conversation is in progress the current upstream is kept, without
// re-running selection. The same model name can behave subtly differently at
// different vendors — that difference is the entire reason the confidence-check
// feature exists — so switching mid-conversation makes the model's behavior jump
// under the user. The maximum-stickiness bound then keeps a heavy continuous user
// from being stuck on the fallback all day.
//
// # 🔴 Never leaves this machine (1b.8 / I23)
//
// This table is process-local. Derived NUMBERS may travel (the inter-arrival gap
// on a usage event is the only calibration data the thresholds will ever have);
// LIVE STATE may not. A per-person "was active at 14:03" timeline must not exist
// anywhere, and building one here would be the easiest possible accident.

import (
	"sync"
	"time"
)

// chainActivityKey is `(virtual_key_id, protocol_type)` — the chain's identity.
//
// 🚫 NOT per seat: one person running two clients would have them interfere with
// each other's gap measurement.
// 🚫 NOT per session: see the file doc.
type chainActivityKey struct {
	virtualKeyID string
	protocolType string
}

type chainActivityEntry struct {
	lastRequestAt    time.Time
	lastProbeAt      time.Time
	currentBindingID string
}

type chainActivityStore struct {
	mu      sync.Mutex
	entries map[chainActivityKey]chainActivityEntry
}

func newChainActivityStore() *chainActivityStore {
	return &chainActivityStore{entries: make(map[chainActivityKey]chainActivityEntry)}
}

// stickDecision is what the candidate loop needs to know before it picks.
type stickDecision struct {
	// stickTo is a binding id to keep using without re-selecting. Empty = run
	// normal selection (which will start at the primary).
	stickTo string
	// gap is how long since the previous request on this chain. Zero on the first
	// request of a process.
	//
	// 🔴 This DERIVED number is the only calibration data the idle-gap and
	// stickiness defaults will ever have — F-9b says outright that they are
	// guesses. It may be emitted on a usage event; the timestamps it was computed
	// from may not.
	gap time.Duration
	// firstEver marks a chain with no recorded history, which is a real state and
	// not a zero gap: after a restart the correct behavior is to treat the gap as
	// infinite and try the primary, exactly as a genuinely idle chain would.
	firstEver bool
}

// observe records this request and decides whether to stick to the current hop.
//
// idleGap: below this, a conversation is considered in progress → stick.
// maxStickiness: above this since the last probe, try the primary anyway, so a
// continuously busy user is not pinned to the fallback for a whole day.
func (s *chainActivityStore) observe(key chainActivityKey, idleGap, maxStickiness time.Duration, now time.Time) stickDecision {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok {
		s.entries[key] = chainActivityEntry{lastRequestAt: now, lastProbeAt: now}
		return stickDecision{firstEver: true}
	}

	gap := now.Sub(entry.lastRequestAt)
	entry.lastRequestAt = now

	decision := stickDecision{gap: gap}
	switch {
	case entry.currentBindingID == "":
		// Never failed over, or the last request was served by the primary.
		// Nothing to stick to; normal selection already starts at the primary.
		entry.lastProbeAt = now
	case gap >= idleGap:
		// Quiet long enough that no conversation is in progress → let the primary
		// be tried again. The user's own next request is the probe.
		entry.lastProbeAt = now
	case maxStickiness > 0 && now.Sub(entry.lastProbeAt) >= maxStickiness:
		// Busy the whole time, but we have been on the fallback long enough. Take
		// the one-attempt cost now rather than leaving them there all day.
		entry.lastProbeAt = now
	default:
		decision.stickTo = entry.currentBindingID
	}
	s.entries[key] = entry
	return decision
}

// noteServed records which hop actually produced the response.
//
// Passing the PRIMARY's binding id clears the sticky state: there is nothing to
// come back from once we are back.
func (s *chainActivityStore) noteServed(key chainActivityKey, bindingID string, isPrimary bool, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[key]
	entry.lastRequestAt = now
	if isPrimary {
		entry.currentBindingID = ""
	} else {
		entry.currentBindingID = bindingID
	}
	s.entries[key] = entry
}
