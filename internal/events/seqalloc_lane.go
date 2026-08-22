package events

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// LaneAllocator hands out a SEPARATE dense sequence per delivery lane.
//
// WHY (2026-08-21, plan: roadmap20260320/技术实现/update/20260821-用量序号流按收件方切分-方案.md):
// integrity is proven by asking "is this sequence dense?", and density is a
// property of whatever GENERATES the numbers. The server accounts per
// (org_id, source_id); the client used to allocate ONE stream per source and
// fan it out across orgs, so each org's ledger saw only a subsequence — full of
// holes that were never lost. A live machine wrote 768 real events off as
// "confirmed lost" this way.
//
// The rule this type exists to enforce:
//
//	The grouping key of the allocator MUST equal the grouping key of the
//	server's watermark. Any mismatch manufactures phantom gaps.
//
// LANE KEY = the event's org_id, not its route_source. Today the two coincide
// (personal/oauth events carry the "personal" sentinel and go to the local
// collector; team events carry the real org and go to the team collector), and
// operators are told about "local" and "team" lanes because that is the useful
// mental model. But keying on route_source would re-split the moment personal
// events are routed to a team collector, or a machine belongs to two orgs —
// with exactly the same silent failure mode. Key on what the server keys on.
//
// Each lane is a full SeqAllocator with its own state file, so reserve-ahead,
// the fsync-blocks-allocation rule, and the graceful-Close shrink are inherited
// verbatim rather than reimplemented per lane (a second copy of that logic is
// how the never-reuse guarantee would quietly drift).
type LaneAllocator struct {
	dir       string
	blockSize int64
	legacy    string // pre-split single-stream state file, used to seed new lanes

	mu    sync.Mutex
	lanes map[string]*SeqAllocator
	// pendingFloor holds lanes seeded from the legacy single stream that have
	// not yet told the server about it. Seeding above the old high-water is
	// what keeps never-reuse intact across the split, and the price is a
	// bounded span of numbers that will never arrive — which the server would
	// read as a gap and eventually write off as lost. The declaration
	// (POST /v1/diagnostics/stream-switch) is what settles that span as
	// TERMINATED instead. Until it is sent, the gap is real and visible.
	pendingFloor map[string]int64
}

// LegacySeqStateFile is the single-stream state file written before lanes
// existed. It is never deleted: it is the floor every new lane starts above,
// and removing it would let a lane reissue seqs the old stream already used.
const LegacySeqStateFile = "seq.state"

// laneStateFile is the per-lane state file name. Kept next to the WAL like the
// legacy one so operators find both in the same place.
func laneStateFile(lane string) string { return "seq." + sanitizeLane(lane) + ".state" }

// sanitizeLane keeps a lane key usable as a filename. org ids are UUIDs or the
// "personal" sentinel today, but they arrive from event data, so anything that
// could escape the directory is replaced rather than trusted.
func sanitizeLane(lane string) string {
	if lane == "" {
		return "unknown"
	}
	out := []rune(lane)
	for i, r := range out {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			out[i] = '_'
		}
	}
	return string(out)
}

// NewLaneAllocator prepares per-lane allocation under dir (the WAL directory).
// Lanes are created lazily on first use — a machine that never talks to a team
// never grows a team state file.
func NewLaneAllocator(dir string, blockSize int64) *LaneAllocator {
	if blockSize <= 0 {
		blockSize = DefaultSeqBlockSize
	}
	return &LaneAllocator{
		dir:          dir,
		blockSize:    blockSize,
		legacy:       filepath.Join(dir, LegacySeqStateFile),
		lanes:        map[string]*SeqAllocator{},
		pendingFloor: map[string]int64{},
	}
}

// For returns the allocator for one lane, creating it on first use.
//
// 🔴 Seeding: a lane with no state file of its own starts above the LEGACY
// single-stream high-water, not at zero. Before the split every event drew from
// one stream, so seq 700 may already have been used by what is now the team
// lane; starting a fresh lane at 1 would reissue it. Never-reuse is a
// per-source guarantee and it has to survive the split.
//
// The cost is a one-time hole between the legacy high-water and each lane's
// first number, which the server would otherwise read as a gap — that is what
// the stream-switch declaration (plan P3) exists to settle. It is NOT settled
// here, and until it is, an upgraded machine will show one bounded gap per lane.
func (l *LaneAllocator) For(lane string) (*SeqAllocator, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if a, ok := l.lanes[lane]; ok {
		return a, nil
	}

	path := filepath.Join(l.dir, laneStateFile(lane))
	if _, err := os.Stat(path); os.IsNotExist(err) {
		legacyHi, lerr := loadSeqState(l.legacy)
		if lerr != nil {
			// Refuse rather than guess: seeding below the legacy high-water
			// would reissue numbers, and reissued seqs are indistinguishable
			// from duplicates at the collector.
			return nil, fmt.Errorf("seqalloc: cannot read legacy state to seed lane %q: %w", lane, lerr)
		}
		if legacyHi > 0 {
			if werr := writeSeqStateAtomic(path, legacyHi); werr != nil {
				return nil, fmt.Errorf("seqalloc: cannot seed lane %q from legacy hi=%d: %w", lane, legacyHi, werr)
			}
			// Owed to the server: everything up to legacyHi on this lane is
			// terminated. Recorded here rather than sent here because the
			// allocator has no collector, no credential and no business
			// blocking a request on an HTTP call.
			l.pendingFloor[lane] = legacyHi
		}
	}

	a, err := NewSeqAllocator(path, l.blockSize)
	if err != nil {
		return nil, err
	}
	l.lanes[lane] = a
	return a, nil
}

// Next hands out the next seq for one lane. A reservation that cannot be
// durably persisted fails THIS lane only — the other lane keeps working, which
// is the point of separating them (a full disk must not take down team
// reporting because the personal lane's fsync failed, or vice versa).
func (l *LaneAllocator) Next(lane string) (int64, error) {
	a, err := l.For(lane)
	if err != nil {
		return 0, err
	}
	return a.Next()
}

// Allocated is the high-water actually handed out on one lane — the value to
// report as client_allocated_seq for the destination that lane feeds. Reporting
// any other lane's number here is the original defect.
func (l *LaneAllocator) Allocated(lane string) int64 {
	a, err := l.For(lane)
	if err != nil {
		return 0
	}
	return a.Allocated()
}

// Lanes lists the lanes this process has touched, sorted for stable output in
// diagnostics and tests.
func (l *LaneAllocator) Lanes() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.lanes))
	for k := range l.lanes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Close shrinks every lane. One lane failing to shrink must not stop the
// others: the failure only costs bounded, auditable burn on that lane.
func (l *LaneAllocator) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var firstErr error
	for lane, a := range l.lanes {
		if err := a.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("lane %q: %w", lane, err)
		}
	}
	return firstErr
}

// PendingFloor returns the floor this lane still owes the server, or 0 if none.
func (l *LaneAllocator) PendingFloor(lane string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pendingFloor[lane]
}

// ClearPendingFloor marks a lane's declaration as delivered.
//
// Only call this after the server ACCEPTED it. The declaration is idempotent
// server-side, so re-sending costs nothing, whereas clearing on a failed send
// loses the obligation forever — and the stranded span silently becomes a gap
// that reconcile will eventually ledger as loss. Conserve, never assume.
func (l *LaneAllocator) ClearPendingFloor(lane string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.pendingFloor, lane)
}
