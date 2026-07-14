package supervisor

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
)

func TestIsNetChangeDialErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"dial EHOSTUNREACH", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}, true},
		{"dial ENETUNREACH", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}, true},
		{"string no route to host", errors.New(`Post "http://x/y": dial tcp 1.2.3.4:3000: connect: no route to host`), true},
		{"string network is unreachable", errors.New("dial tcp: connect: network is unreachable"), true},
		{"read op (not dial) is not a net-change", &net.OpError{Op: "read", Err: syscall.EHOSTUNREACH}, false},
		{"connection refused is not net-change", errors.New("dial tcp 1.2.3.4:3000: connect: connection refused"), false},
		{"timeout is not net-change", errors.New("context deadline exceeded"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isNetChangeDialErr(c.err); got != c.want {
				t.Fatalf("isNetChangeDialErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// newTestHealer builds a healer with tiny/injected knobs — a fake clock, a
// recorded exit, and a scripted reachability probe — so the escalation logic is
// deterministic without a real os.Exit or a real clock.
func newTestHealer(reachable bool) (*controlPlaneHealer, *int, *time.Time) {
	exits := 0
	clk := time.Unix(1_700_000_000, 0)
	h := &controlPlaneHealer{
		threshold: 3,
		cooldown:  2 * time.Minute,
		window:    30 * time.Minute,
		budget:    4,
		now:       func() time.Time { return clk },
		exit:      func(int) { exits++ },
		probe:     func(string) bool { return reachable },
	}
	return h, &exits, &clk
}

func TestHealer_BelowThreshold_NoRestart(t *testing.T) {
	h, exits, _ := newTestHealer(true)
	for i := 0; i < h.threshold-1; i++ {
		if d := h.onPollNetChange("http://master:3000"); d == restartNow {
			t.Fatalf("restarted before threshold at i=%d", i)
		}
	}
	if *exits != 0 {
		t.Fatalf("exit called %d times below threshold, want 0", *exits)
	}
}

func TestHealer_AtThreshold_ReachableMaster_Restarts(t *testing.T) {
	h, exits, _ := newTestHealer(true) // fresh probe says master IS reachable → it's us
	var last restartDecision
	for i := 0; i < h.threshold; i++ {
		last = h.onPollNetChange("http://master:3000")
	}
	if last != restartNow {
		t.Fatalf("decision at threshold = %v, want restartNow", last)
	}
	if *exits != 1 {
		t.Fatalf("exit called %d times, want 1", *exits)
	}
}

func TestHealer_MasterUnreachable_NeverRestarts(t *testing.T) {
	h, exits, _ := newTestHealer(false) // real outage: fresh probe ALSO fails
	for i := 0; i < h.threshold+5; i++ {
		if d := h.onPollNetChange("http://master:3000"); d == restartNow {
			t.Fatalf("restarted during a genuine outage at i=%d", i)
		}
	}
	if *exits != 0 {
		t.Fatalf("exit called %d times during outage, want 0", *exits)
	}
}

func TestHealer_PollOK_ResetsCounter(t *testing.T) {
	h, exits, _ := newTestHealer(true)
	h.onPollNetChange("http://master:3000")
	h.onPollNetChange("http://master:3000")
	h.onPollOK() // master came back → counter resets
	// two more failures should NOT reach the threshold now
	h.onPollNetChange("http://master:3000")
	if d := h.onPollNetChange("http://master:3000"); d == restartNow {
		t.Fatal("restarted after onPollOK reset — counter did not clear")
	}
	if *exits != 0 {
		t.Fatalf("exit called %d times, want 0", *exits)
	}
}

func TestHealer_Cooldown_And_Breaker(t *testing.T) {
	h, exits, clk := newTestHealer(true)
	fire := func() restartDecision { // drive one full escalation (threshold cycles)
		h.onPollOK() // reset counter between escalations
		var d restartDecision
		for i := 0; i < h.threshold; i++ {
			d = h.onPollNetChange("http://master:3000")
		}
		return d
	}
	// 1st escalation → restarts
	if d := fire(); d != restartNow {
		t.Fatalf("1st = %v, want restartNow", d)
	}
	// immediately again (same clock) → cooldown blocks it
	if d := fire(); d != restartSkipCooldown {
		t.Fatalf("2nd within cooldown = %v, want restartSkipCooldown", d)
	}
	// advance past cooldown 3 more times → restarts up to the budget (4 total)
	for n := 2; n <= h.budget; n++ {
		*clk = clk.Add(h.cooldown + time.Second)
		if d := fire(); d != restartNow {
			t.Fatalf("escalation %d past cooldown = %v, want restartNow", n, d)
		}
	}
	// budget now exhausted → breaker trips even past cooldown
	*clk = clk.Add(h.cooldown + time.Second)
	if d := fire(); d != restartSkipBreaker {
		t.Fatalf("past budget = %v, want restartSkipBreaker", d)
	}
	if *exits != h.budget {
		t.Fatalf("exit called %d times, want %d (budget)", *exits, h.budget)
	}
}

func TestMasterReachableFresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // even a 404 proves the path is alive
	}))
	defer srv.Close()
	if !masterReachableFresh(srv.Client(), srv.URL) {
		t.Fatal("reachable server reported unreachable")
	}
	// A dead address must report unreachable (short timeout so the test is fast).
	if masterReachableFresh(&http.Client{Timeout: time.Second}, "http://127.0.0.1:1") {
		t.Fatal("dead address reported reachable")
	}
}

func TestRebuildAllControlPlane_SwapsGroupRuntimeClient(t *testing.T) {
	before := groupRuntimeClient()
	if n := httpx.RebuildAllControlPlane(); n == 0 {
		t.Fatal("RebuildAllControlPlane rebuilt 0 clients — group-runtime not registered?")
	}
	if after := groupRuntimeClient(); before == after {
		t.Fatal("RebuildAllControlPlane did not install a new group-runtime client")
	}
}
