package heartbeat

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestProbe_TracksLastOKAndFailures is the core contract: a success stamps
// LastOKAt (from the injected clock) and clears the failure streak; a failure
// leaves LastOKAt untouched and grows the streak. This is white-box on runOnce so
// it's deterministic (no real ticker / wall clock).
func TestProbe_TracksLastOKAndFailures(t *testing.T) {
	clk := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	var fail bool
	p := New(time.Minute, func(context.Context) error {
		if fail {
			return errors.New("unreachable")
		}
		return nil
	}).withClock(func() time.Time { return clk })

	// First success → LastOKAt = now, no failures.
	p.runOnce(context.Background())
	if got := p.LastOKAt(); !got.Equal(clk) {
		t.Fatalf("after success want LastOKAt=%v, got %v", clk, got)
	}
	if n := p.ConsecutiveFailures(); n != 0 {
		t.Fatalf("after success want 0 failures, got %d", n)
	}

	// Two failures later: LastOKAt frozen at the last success, streak = 2.
	okAt := clk
	fail = true
	clk = clk.Add(time.Minute)
	p.runOnce(context.Background())
	clk = clk.Add(time.Minute)
	p.runOnce(context.Background())
	if got := p.LastOKAt(); !got.Equal(okAt) {
		t.Fatalf("failures must not move LastOKAt: want %v, got %v", okAt, got)
	}
	if n := p.ConsecutiveFailures(); n != 2 {
		t.Fatalf("want 2 consecutive failures, got %d", n)
	}

	// Recovery: success clears the streak and re-stamps LastOKAt.
	fail = false
	clk = clk.Add(time.Minute)
	p.runOnce(context.Background())
	if got := p.LastOKAt(); !got.Equal(clk) {
		t.Fatalf("recovery want LastOKAt=%v, got %v", clk, got)
	}
	if n := p.ConsecutiveFailures(); n != 0 {
		t.Fatalf("recovery want 0 failures, got %d", n)
	}
}

// TestProbe_TrafficIndependent pins the property that fixes the budget deadlock:
// the probe advances LastOKAt purely from its own ticks, never needing any
// request to drive it. We simulate "no traffic, server up" by only invoking the
// probe loop's unit of work (runOnce) and asserting LastOKAt keeps advancing.
func TestProbe_TrafficIndependent(t *testing.T) {
	clk := time.Unix(0, 0).UTC()
	p := New(time.Minute, func(context.Context) error { return nil }).
		withClock(func() time.Time { return clk })

	var last time.Time
	for i := 0; i < 5; i++ {
		clk = clk.Add(30 * time.Second)
		p.runOnce(context.Background())
		got := p.LastOKAt()
		if !got.After(last) {
			t.Fatalf("tick %d: LastOKAt did not advance (server up, no traffic): prev %v got %v", i, last, got)
		}
		last = got
	}
}

// TestProbe_Nil is a no-op on a nil receiver so flag-gated callers can hold nil.
func TestProbe_Nil(t *testing.T) {
	var p *Probe
	if !p.LastOKAt().IsZero() {
		t.Error("nil probe LastOKAt should be zero")
	}
	if p.ConsecutiveFailures() != 0 {
		t.Error("nil probe failures should be 0")
	}
}

// TestProbe_RunFirstProbeImmediate verifies Run probes once up front (a fresh
// node gets a reachability stamp without waiting a full interval) then stops on
// ctx cancel without hanging.
func TestProbe_RunFirstProbeImmediate(t *testing.T) {
	probed := make(chan struct{}, 1)
	p := New(time.Hour, func(context.Context) error { // long interval: only the immediate probe fires
		select {
		case probed <- struct{}{}:
		default:
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	select {
	case <-probed:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not probe immediately")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on ctx cancel")
	}
	if p.LastOKAt().IsZero() {
		t.Error("immediate probe should have stamped LastOKAt")
	}
}
