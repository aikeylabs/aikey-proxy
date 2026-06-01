package events

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// SeqAllocator hands out per-source, strictly monotonic, NEVER-REUSED sequence
// numbers for the delivery-integrity pipeline (design doc §5.2 reserve-ahead).
//
// Why never-reused matters: a seq is a completeness proof. If a crash loses
// page-cached WAL events (assigned a seq but not fsync'd) and the next start
// re-derived "next" by scanning the WAL's max seq, those seqs would be REUSED
// by fresh events — the server's sequence stays gap-free and the loss is
// SILENT. Reserve-ahead prevents this: the high-water mark is persisted (with
// fsync) BEFORE any seq in that block is handed out, so a restart always
// resumes strictly above anything that could have been used.
//
// reserve-ahead mechanics:
//   - reservedHi is the highest seq persisted as "reserved" in seq.state.
//   - We hand out seqs from memory in (prevHi, reservedHi]; when exhausted we
//     bump reservedHi by blockSize, fsync seq.state, THEN continue. The fsync
//     MUST succeed before a seq from the new block is returned — otherwise the
//     reuse bug returns. A failed reserve blocks allocation (returns error).
//
// crash vs graceful, and the known-loss tradeoff:
//   - On a HARD crash, reservedHi sits at the last block boundary, which may be
//     above the last seq actually written. The unused tail (lastUsed+1 ..
//     reservedHi) is "burned": those seqs never appear, so the server sees a
//     permanent gap and reconcile classifies them as known-loss (the power-loss
//     window — design doc §6.1 H2). Burn is bounded by blockSize.
//   - On a GRACEFUL Close we shrink seq.state down to the actual last-used seq,
//     so the next start resumes exactly there and burns ZERO. This keeps the
//     common restart path (config reload, normal stop/start) gap-free; only a
//     true crash produces (bounded, auditable) burn.
//
// The state file is independent of the WAL and has its own mutex — it must not
// contend on WALWriter.mu, and its tiny (one integer) fsync is unrelated to the
// WAL's group-commit cadence.
type SeqAllocator struct {
	mu         sync.Mutex
	statePath  string
	blockSize  int64
	next       int64 // next seq to hand out
	reservedHi int64 // highest seq persisted as reserved in statePath
}

// DefaultSeqBlockSize is the reserve-ahead block size. Larger = fewer
// seq.state fsyncs but more seqs burned (as known-loss) per hard crash;
// smaller = more fsyncs, less crash burn. 256 per design doc §5.2; graceful
// Close shrink (see above) means this only bounds HARD-crash burn, not
// every-restart burn.
const DefaultSeqBlockSize int64 = 256

// NewSeqAllocator loads the persisted reserved high-water mark from statePath
// (treating absent/empty as 0) and prepares to hand out seqs strictly above it.
// next = reservedHi + 1 — anything ≤ reservedHi is considered possibly-used or
// burned and is never reissued.
func NewSeqAllocator(statePath string, blockSize int64) (*SeqAllocator, error) {
	if blockSize <= 0 {
		blockSize = DefaultSeqBlockSize
	}
	hi, err := loadSeqState(statePath)
	if err != nil {
		return nil, fmt.Errorf("seqalloc: load state %s: %w", statePath, err)
	}
	return &SeqAllocator{
		statePath:  statePath,
		blockSize:  blockSize,
		next:       hi + 1,
		reservedHi: hi,
	}, nil
}

// Next returns the next sequence number, reserving a new block (persisted with
// fsync) first if the current block is exhausted. Returns an error WITHOUT
// handing out a seq if the reservation cannot be durably persisted — callers
// MUST treat this as "cannot record this event right now" rather than proceed,
// or the never-reuse guarantee breaks.
func (a *SeqAllocator) Next() (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.next > a.reservedHi {
		newHi := a.reservedHi + a.blockSize
		if err := writeSeqStateAtomic(a.statePath, newHi); err != nil {
			return 0, fmt.Errorf("seqalloc: reserve block (hi=%d): %w", newHi, err)
		}
		a.reservedHi = newHi
	}
	seq := a.next
	a.next++
	return seq, nil
}

// Allocated returns the highest seq handed out so far (next-1), i.e. the
// "actual allocated" upper bound the client reports to the server as
// client_allocated_seq. This is distinct from the reserved high-water mark:
// reporting reservedHi would manufacture false tail gaps for the unused tail of
// the current block. Always report THIS value, never the reserved hi.
func (a *SeqAllocator) Allocated() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.next - 1
}

// Close shrinks the persisted high-water mark down to the actual last-used seq
// so the next start resumes exactly there (zero burn on graceful restart). Safe
// to call once at shutdown. If shrinking fails the on-disk value simply stays
// at the block boundary and the next start burns the tail as known-loss — never
// a correctness problem, only extra auditable gaps.
func (a *SeqAllocator) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	used := a.next - 1
	if used < 0 {
		used = 0
	}
	if used == a.reservedHi {
		return nil // nothing handed out beyond what's persisted; no shrink needed
	}
	if err := writeSeqStateAtomic(a.statePath, used); err != nil {
		return fmt.Errorf("seqalloc: close shrink to %d: %w", used, err)
	}
	a.reservedHi = used
	return nil
}

// loadSeqState reads the integer high-water mark from path. Absent file → 0.
func loadSeqState(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("corrupt seq state %q: %w", s, err)
	}
	if v < 0 {
		return 0, fmt.Errorf("negative seq state %d", v)
	}
	return v, nil
}

// writeSeqStateAtomic durably writes the high-water mark: write to a temp file
// in the same dir, fsync the temp file, rename over the target. The rename is
// atomic on POSIX so a crash mid-write never yields a torn value — readers see
// either the old or new integer, nothing in between. The temp file's fsync is
// what makes the new value survive power loss before any seq from the block is
// used.
func writeSeqStateAtomic(path string, hi int64) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".seqstate-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename.
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.WriteString(strconv.FormatInt(hi, 10)); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpName, path, err)
	}
	tmpName = "" // committed; skip cleanup
	return nil
}
