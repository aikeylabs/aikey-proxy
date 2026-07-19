package events

import "testing"

// TestCanaryProbe_CloseIsIdempotent pins the io.Closer convention on
// CanaryProbe (bugfix 2026-07-19): a supervisor reload's async drain_old and a
// concurrent shutdown both tore down the same generation, and the second
// Close() panicked "close of closed channel" — recovered as an isolated
// goroutine panic, but the rest of the old generation's teardown was skipped
// (reporter/WAL/seq-allocator leaked). Double Close must be a no-op.
// 能红: revert Close to a bare close(p.done) and the second call panics.
func TestCanaryProbe_CloseIsIdempotent(t *testing.T) {
	p := &CanaryProbe{done: make(chan struct{})} // loop not started; wg is zero
	p.Close()
	p.Close() // must not panic
}
