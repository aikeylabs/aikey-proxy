package proxy

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

const (
	// A prompt larger than 64 MiB is outside the supported in-request failover
	// envelope. Keeping it in RAM would multiply by concurrent users and retries;
	// spilling OAuth prompts to disk would create a worse confidentiality boundary.
	groupReplayBodyLimit = int64(64 << 20)
	// One process can retain at most four maximum-size requests. Normal prompts
	// are far smaller, so hundreds of developers still fit; pathological payloads
	// fail locally instead of taking the Proxy down for everyone.
	groupReplayProcessBudget = int64(256 << 20)
	groupReplayInitialChunk  = int64(64 << 10)
)

var (
	errGroupReplayBodyTooLarge = errors.New("group request body exceeds replay limit")
	errGroupReplayCapacity     = errors.New("group request replay memory budget exhausted")
	processGroupReplayBudget   = newGroupReplayBudget(groupReplayProcessBudget)
)

type groupReplayBudget struct {
	limit int64
	used  atomic.Int64
}

func newGroupReplayBudget(limit int64) *groupReplayBudget {
	return &groupReplayBudget{limit: max(int64(0), limit)}
}

func (b *groupReplayBudget) reserve(n int64) bool {
	if n <= 0 {
		return true
	}
	for {
		used := b.used.Load()
		if n > b.limit-used {
			return false
		}
		if b.used.CompareAndSwap(used, used+n) {
			return true
		}
	}
}

func (b *groupReplayBudget) release(n int64) {
	if n > 0 {
		b.used.Add(-n)
	}
}

// groupReplayBody owns one bounded immutable request body. Commit is called at
// the first client-visible response header; memory is released as soon as the
// active transport closes its reader, so a long SSE response does not retain the
// prompt for the stream's lifetime. Captured errors do not commit and can retry.
type groupReplayBody struct {
	mu        sync.Mutex
	data      []byte
	budget    *groupReplayBudget
	reserved  int64
	readers   int
	committed bool
	released  bool
}

func readGroupReplayBody(body io.Reader, contentLength, limit int64, budget *groupReplayBudget) (*groupReplayBody, error) {
	if contentLength > limit {
		return nil, errGroupReplayBodyTooLarge
	}
	initial := contentLength
	if initial < 0 {
		initial = groupReplayInitialChunk
	}
	if initial > limit {
		initial = limit
	}
	if initial < 0 {
		initial = 0
	}
	if !budget.reserve(initial) {
		return nil, errGroupReplayCapacity
	}
	reserved := initial
	data := make([]byte, 0, int(initial))
	release := func() { budget.release(reserved) }

	for {
		if contentLength >= 0 && int64(len(data)) == contentLength {
			break // net/http already frames the body to the declared length
		}
		if int64(len(data)) == limit {
			var extra [1]byte
			n, err := body.Read(extra[:])
			if n > 0 {
				release()
				return nil, errGroupReplayBodyTooLarge
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				release()
				return nil, err
			}
			continue
		}
		if len(data) == cap(data) {
			newCap := max(int64(cap(data))*2, groupReplayInitialChunk)
			if newCap > limit {
				newCap = limit
			}
			// Reserve the whole new allocation before creating it because the old
			// backing array remains live during copy. Release old capacity after.
			if !budget.reserve(newCap) {
				release()
				return nil, errGroupReplayCapacity
			}
			next := make([]byte, len(data), int(newCap))
			copy(next, data)
			budget.release(reserved)
			reserved = newCap
			data = next
		}
		before := len(data)
		data = data[:cap(data)]
		n, err := body.Read(data[before:])
		data = data[:before+n]
		if err == io.EOF {
			break
		}
		if err != nil {
			release()
			return nil, err
		}
	}
	return &groupReplayBody{data: data, budget: budget, reserved: reserved}, nil
}

func (b *groupReplayBody) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.data)
}

func (b *groupReplayBody) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data
}

func (b *groupReplayBody) Open() io.ReadCloser {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.released || len(b.data) == 0 {
		return io.NopCloser(bytes.NewReader(nil))
	}
	b.readers++
	return &groupReplayReader{Reader: bytes.NewReader(b.data), owner: b}
}

func (b *groupReplayBody) Commit() {
	b.mu.Lock()
	b.committed = true
	b.releaseIfIdleLocked()
	b.mu.Unlock()
}

func (b *groupReplayBody) Close() {
	if b == nil {
		return
	}
	b.Commit()
}

func (b *groupReplayBody) readerClosed() {
	b.mu.Lock()
	if b.readers > 0 {
		b.readers--
	}
	b.releaseIfIdleLocked()
	b.mu.Unlock()
}

func (b *groupReplayBody) releaseIfIdleLocked() {
	if b.released || !b.committed || b.readers != 0 {
		return
	}
	b.released = true
	b.data = nil
	b.budget.release(b.reserved)
	b.reserved = 0
}

type groupReplayReader struct {
	*bytes.Reader
	owner *groupReplayBody
	once  sync.Once
}

func (r *groupReplayReader) Close() error {
	r.once.Do(r.owner.readerClosed)
	return nil
}
