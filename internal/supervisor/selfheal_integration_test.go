package supervisor

import (
	"context"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
)

// These are INTEGRATION tests: they drive the REAL production self-heal wiring
// (the real onNetworkChange callback, the real postMemberToken retry loop, the
// real isNetChangeDialErr classifier, the real httpx control-plane registry) and
// assert observable effects — no copied/re-implemented logic. Only the trigger
// (a network-change fingerprint flip / a routing-layer dial error) is injected.

// netChangeRoundTripper makes every request fail with a genuine routing-layer
// dial error — the exact error type the kernel produces after a host network
// change — so the REAL postMemberToken path classifies it and self-heals.
type netChangeRoundTripper struct{}

func (netChangeRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp",
		Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}
}

// TestIntegration_NetChangeMonitor_RebuildsAllRegisteredClients drives the REAL
// watchNetworkChanges loop with the REAL onNetworkChange callback and asserts the
// central registry rebuilt EVERY registered control-plane client (group-runtime +
// an extra registered probe client), and reset the self-heal streak.
func TestIntegration_NetChangeMonitor_RebuildsAllRegisteredClients(t *testing.T) {
	// A second registered control-plane client, to prove RebuildAll hits more than
	// just group-runtime (i.e. the registry, not a single client).
	probe := httpx.NewSwappable(func() *http.Client { return &http.Client{} })

	grBefore := groupRuntimeClient()
	probeBefore := probe.Get()

	// Prime the healer streak so we can prove onNetworkChange resets it.
	controlPlaneHeal.mu.Lock()
	controlPlaneHeal.consecutive = 2
	controlPlaneHeal.mu.Unlock()

	// Drive the REAL monitor loop: a fingerprint that flips once (A→B) triggers the
	// REAL onNetworkChange (rebuild-all + reset). fp returns A, then B forever.
	calls := 0
	fp := func() string {
		calls++
		if calls <= 1 {
			return "A"
		}
		return "B"
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchNetworkChanges(ctx, time.Millisecond, fp, onNetworkChange)

	// Wait for the rebuild to land (both clients swapped).
	deadline := time.After(3 * time.Second)
	for {
		if groupRuntimeClient() != grBefore && probe.Get() != probeBefore {
			break
		}
		select {
		case <-deadline:
			t.Fatal("onNetworkChange did not rebuild all registered clients in time")
		case <-time.After(5 * time.Millisecond):
		}
	}

	controlPlaneHeal.mu.Lock()
	streak := controlPlaneHeal.consecutive
	controlPlaneHeal.mu.Unlock()
	if streak != 0 {
		t.Fatalf("onNetworkChange did not reset the self-heal streak: consecutive=%d, want 0", streak)
	}
}

// TestIntegration_Writeback_SelfHealsOnNetChange drives the REAL postMemberToken
// retry loop with a client whose transport returns a genuine EHOSTUNREACH. It
// asserts the real path classified it and rebuilt the registry (a registered
// client instance changed) while still surfacing the final error.
func TestIntegration_Writeback_SelfHealsOnNetChange(t *testing.T) {
	// Speed up the 6-attempt backoff for the test.
	orig := writebackBaseBackoff
	writebackBaseBackoff = time.Millisecond
	defer func() { writebackBaseBackoff = orig }()

	probe := httpx.NewSwappable(func() *http.Client { return &http.Client{} })
	probeBefore := probe.Get()

	// The writeback's client always returns a net-change dial error.
	clientFn := func() *http.Client { return &http.Client{Transport: netChangeRoundTripper{}} }

	err := postMemberToken(context.Background(), clientFn, "http://master.invalid", "JWT",
		memberTokenWriteback{CredentialID: "c1", AccessToken: "tok"})
	if err == nil {
		t.Fatal("postMemberToken returned nil despite persistent no-route errors")
	}
	// The REAL net-change branch must have invoked the REAL registry rebuild.
	if probe.Get() == probeBefore {
		t.Fatal("postMemberToken did not rebuild control-plane clients on the net-change dial error")
	}
}
