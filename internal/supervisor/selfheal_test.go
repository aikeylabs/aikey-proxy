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

		// Windows FormatMessage texts. Platform-independent (they are just
		// strings), so these run everywhere and pin the string half of the
		// 2026-08-04 fix. Before it, none of the three matched and the
		// self-healer was dead code on Windows.
		{"windows text unreachable host", errors.New(`Get "http://master/x": dial tcp 10.0.0.9:8080: connectex: A socket operation was attempted to an unreachable host.`), true},
		{"windows text unreachable network", errors.New(`dial tcp: connectex: A socket operation was attempted to an unreachable network.`), true},
		{"windows text dead network", errors.New(`dial tcp: connectex: A socket operation encountered a dead network.`), true},
		{"windows text connection refused stays out", errors.New(`dial tcp: connectex: No connection could be made because the target machine actively refused it.`), false},
		{"windows text timeout stays out", errors.New(`dial tcp: connectex: A connection attempt failed because the connected party did not properly respond after a period of time.`), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isNetChangeDialErr(c.err); got != c.want {
				t.Fatalf("isNetChangeDialErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// TestWindowsSyntheticErrnoIsNotTheWireErrno pins the ROOT CAUSE of the
// 2026-08-04 Windows defect, so nobody "simplifies" the WSA block away.
//
// On Windows the stdlib defines EHOSTUNREACH/ENETUNREACH/ENETDOWN as synthetic
// APPLICATION_ERROR offsets purely so portable code compiles. The socket stack
// returns the raw WSA codes instead. The two are different numbers, so the
// errors.Is check that looks correct is guaranteed to miss every real Windows
// network-change failure.
func TestWindowsSyntheticErrnoIsNotTheWireErrno(t *testing.T) {
	if errors.Is(wsaeHostUnreach, syscall.EHOSTUNREACH) {
		t.Fatal("WSAEHOSTUNREACH(10065) now equals syscall.EHOSTUNREACH — if the " +
			"stdlib started mapping these, the goos-guarded WSA branch can be " +
			"revisited; until then it is the only thing that fires on Windows")
	}
	if errors.Is(wsaeNetUnreach, syscall.ENETUNREACH) {
		t.Fatal("WSAENETUNREACH(10051) now equals syscall.ENETUNREACH — see above")
	}
}

// TestIsNetChangeErrnoFor_Windows exercises the Windows numeric branch from a
// non-Windows host. This is the whole point of parameterising on goos: the bug
// survived because the Windows path was unreachable from every test we could
// actually run.
func TestIsNetChangeErrnoFor_Windows(t *testing.T) {
	dialErr := func(e syscall.Errno) error {
		return &net.OpError{Op: "dial", Err: os.NewSyscallError("connectex", e)}
	}
	cases := []struct {
		name string
		goos string
		err  error
		want bool
	}{
		{"WSAEHOSTUNREACH on windows", "windows", dialErr(wsaeHostUnreach), true},
		{"WSAENETUNREACH on windows", "windows", dialErr(wsaeNetUnreach), true},
		{"WSAENETDOWN on windows", "windows", dialErr(wsaeNetDown), true},

		// The guard: those numbers are unrelated errno's off Windows and
		// must not be honoured there.
		{"WSAEHOSTUNREACH on linux is not honoured", "linux", dialErr(wsaeHostUnreach), false},

		// Not every Winsock failure is a routing change. WSAECONNREFUSED
		// means we reached the host and it said no — a fresh client or a
		// process restart fixes nothing, and treating it as net-change
		// would arm the restart escalation against a healthy network.
		{"WSAECONNREFUSED on windows is not net-change", "windows", dialErr(syscall.Errno(10061)), false},
		{"WSAETIMEDOUT on windows is not net-change", "windows", dialErr(syscall.Errno(10060)), false},

		// Unix path unchanged.
		{"EHOSTUNREACH on darwin", "darwin", dialErr(syscall.EHOSTUNREACH), true},
		{"nil", "windows", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isNetChangeErrnoFor(c.goos, c.err); got != c.want {
				t.Fatalf("isNetChangeErrnoFor(%q, %v) = %v, want %v", c.goos, c.err, got, c.want)
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
		// Models a launchd/systemd host: exiting non-zero gets us
		// relaunched, so Tier3 escalation is meaningful. The Windows
		// (unsupervised) answer has its own test below — it must not be
		// the silent default here, or these tests would pass for the wrong
		// reason on a platform that never restarts.
		supervised: true,
		now:        func() time.Time { return clk },
		exit:       func(int) { exits++ },
		probe:      func(string) bool { return reachable },
	}
	return h, &exits, &clk
}

// TestSelfRestartIsSupervised pins WHICH platforms Tier3 is allowed on.
func TestSelfRestartIsSupervised(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		if !selfRestartIsSupervised(goos) {
			t.Fatalf("%s has launchd/systemd relaunch — Tier3 must stay enabled", goos)
		}
	}
	if selfRestartIsSupervised("windows") {
		t.Fatal("windows has no relaunch in our install: `aikey proxy start` spawns " +
			"detached and supervises nothing, and the AikeyProxy ScheduledTask gives " +
			"up after RestartCount 3. exit(75) there is an outage, not a heal")
	}
}

// TestHealer_Unsupervised_RebuildsButNeverExits is the guard rail on fixing
// isNetChangeDialErr (2026-08-04). Repairing the classifier made Tier3
// reachable on Windows for the first time; without this gate the "self-heal"
// would exit a process that nothing relaunches, converting a recoverable stale
// transport into a dead proxy.
//
// Tier1 must still run every cycle — that is the part that actually clears the
// stale client — but the escalation must stop short of exiting.
func TestHealer_Unsupervised_RebuildsButNeverExits(t *testing.T) {
	h, exits, _ := newTestHealer(true) // master IS reachable: Tier3 would fire
	h.supervised = false               // ...but nothing would relaunch us

	// Well past the threshold, and past the budget too.
	for i := 0; i < h.threshold*4; i++ {
		d := h.onPollNetChange("http://master.example")
		if i >= h.threshold-1 && d != restartSkipUnsupervised {
			t.Fatalf("cycle %d: decision = %v, want restartSkipUnsupervised", i, d)
		}
	}
	if *exits != 0 {
		t.Fatalf("exited %d time(s) on a platform that does not relaunch — "+
			"the proxy would simply be gone", *exits)
	}
}

// The supervised counterpart, asserting the gate did not just disable Tier3
// everywhere. Without this, deleting the whole escalation would pass.
func TestHealer_Supervised_StillExits(t *testing.T) {
	h, exits, _ := newTestHealer(true)
	for i := 0; i < h.threshold; i++ {
		h.onPollNetChange("http://master.example")
	}
	if *exits != 1 {
		t.Fatalf("exits = %d, want 1 — Tier3 must remain live where a service "+
			"manager relaunches us", *exits)
	}
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
