package supervisor

import (
	"context"
	"testing"
	"time"
)

func TestChangeDetector(t *testing.T) {
	var d changeDetector
	// first observation primes the baseline — never a change
	if changed, _ := d.observe("A"); changed {
		t.Fatal("first observe reported a change (should prime baseline)")
	}
	// same value → no change
	if changed, _ := d.observe("A"); changed {
		t.Fatal("same fingerprint reported a change")
	}
	// flip → change, prev is the old value
	changed, prev := d.observe("B")
	if !changed || prev != "A" {
		t.Fatalf("flip A→B: changed=%v prev=%q, want true/\"A\"", changed, prev)
	}
	// stays at B → no change
	if changed, _ := d.observe("B"); changed {
		t.Fatal("stable B reported a change")
	}
	// flip back → change, prev=B
	if changed, prev := d.observe("A"); !changed || prev != "B" {
		t.Fatalf("flip B→A: changed=%v prev=%q, want true/\"B\"", changed, prev)
	}
}

func TestWatchNetworkChanges_FiresOnlyOnFlip(t *testing.T) {
	// scripted fingerprint sequence: baseline X, then X (no fire), Y (fire),
	// Y (no fire), Z (fire). Driven by a counter so it's deterministic.
	seq := []string{"X", "X", "Y", "Y", "Z"}
	i := 0
	fp := func() string {
		v := seq[i]
		if i < len(seq)-1 {
			i++
		}
		return v
	}
	var fires [][2]string
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	onChange := func(old, cur string) {
		fires = append(fires, [2]string{old, cur})
		if len(fires) == 2 { // both flips seen → stop
			cancel()
		}
	}
	go func() { watchNetworkChanges(ctx, time.Millisecond, fp, onChange); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("watchNetworkChanges did not report the expected flips in time")
	}
	if len(fires) != 2 || fires[0] != [2]string{"X", "Y"} || fires[1] != [2]string{"Y", "Z"} {
		t.Fatalf("fires=%v, want [X→Y, Y→Z]", fires)
	}
}

func TestInterfaceFingerprint_StableAndBounded(t *testing.T) {
	a := interfaceFingerprint()
	b := interfaceFingerprint()
	if a != b {
		t.Fatalf("fingerprint not stable across calls: %q vs %q", a, b)
	}
	// Loopback must be excluded — it is never a routing change signal.
	if a == "127.0.0.1" || a == "::1" {
		t.Fatalf("fingerprint leaked loopback: %q", a)
	}
}
