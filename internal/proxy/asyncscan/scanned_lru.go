package asyncscan

import (
	"container/list"
	"sync"
)

// maxTransientAttempts is how often a piece may fail transiently before the lane
// gives up and finalises it as partial.
//
// Why a limit at all: a transient failure (result timeout, node dropped the
// connection) leaves the piece unscanned, so the correct response is to try
// again when it reappears. But a node that is permanently unreachable produces
// transient failures forever, and an agent turn resends its whole history every
// round — so "retry when it reappears" without a cap means every turn re-enqueues
// every piece of the conversation, for as long as the node is down. Three is
// enough to ride out a restart and small enough that a real outage settles.
const maxTransientAttempts = 3

// ScannedLRU remembers which pieces this process has already scanned, so a
// conversation's history is not re-scanned on every turn.
//
// 🔴 Deliberately IN-MEMORY and per-process. It is a cost optimisation, not a
// correctness mechanism: losing it on restart costs a re-scan, and the re-scan is
// harmless because the event ids are content-derived (see identity.go) so the
// database absorbs the duplicate. Persisting it would buy a little CPU and cost a
// new file to keep consistent, corrupt-proof and migrated — the trade the project
// rule 「慎重建表」 exists to refuse.
type ScannedLRU struct {
	capacity int

	mu    sync.Mutex
	items map[string]*list.Element
	order *list.List
}

type lruEntry struct {
	key      string
	final    bool
	inFlight bool
	attempts int
}

// NewScannedLRU returns a record holding at most capacity pieces.
func NewScannedLRU(capacity int) *ScannedLRU {
	if capacity <= 0 {
		capacity = 4096
	}
	return &ScannedLRU{capacity: capacity, items: map[string]*list.Element{}, order: list.New()}
}

// Claim reports whether the caller should scan this piece, and marks it in
// flight if so. It is the single-flight gate as well as the already-done gate:
// two concurrent requests carrying the same paragraph must not both send it.
func (l *ScannedLRU) Claim(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		e := el.Value.(*lruEntry)
		l.order.MoveToFront(el)
		if e.final || e.inFlight {
			return false
		}
		e.inFlight = true
		return true
	}
	l.put(&lruEntry{key: key, inFlight: true})
	return true
}

// Finalize marks a piece as scanned for good. Only a FINAL result may call it —
// a transient failure must leave the piece claimable (see Transient).
func (l *ScannedLRU) Finalize(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		e := el.Value.(*lruEntry)
		e.final, e.inFlight = true, false
		l.order.MoveToFront(el)
		return
	}
	l.put(&lruEntry{key: key, final: true})
}

// Transient records a transient failure and returns how many have now occurred.
// At maxTransientAttempts the piece is finalised so it stops being re-enqueued.
func (l *ScannedLRU) Transient(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.items[key]
	if !ok {
		l.put(&lruEntry{key: key, attempts: 1})
		return 1
	}
	e := el.Value.(*lruEntry)
	e.attempts++
	e.inFlight = false
	if e.attempts >= maxTransientAttempts {
		e.final = true
	}
	l.order.MoveToFront(el)
	return e.attempts
}

// Release clears the in-flight mark without finalising (the piece was never sent).
func (l *ScannedLRU) Release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		el.Value.(*lruEntry).inFlight = false
	}
}

func (l *ScannedLRU) put(e *lruEntry) {
	el := l.order.PushFront(e)
	l.items[e.key] = el
	for l.order.Len() > l.capacity {
		oldest := l.order.Back()
		if oldest == nil {
			return
		}
		l.order.Remove(oldest)
		delete(l.items, oldest.Value.(*lruEntry).key)
	}
}
