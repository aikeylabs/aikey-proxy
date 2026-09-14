package deepscanfwd

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/deepscan"
	"github.com/AiKeyLabs/pkg/scannode"
)

// --- a scriptable stand-in for one node -------------------------------------

type fakeNode struct {
	id      string
	delay   time.Duration
	reject  string
	failAll bool

	mu       sync.Mutex
	received int
	closed   bool
}

func (f *fakeNode) Send(ctx context.Context, frame []byte) error {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	f.received++
	f.mu.Unlock()
	if f.failAll {
		return fmt.Errorf("fakeNode %s: unreachable", f.id)
	}
	return nil
}

func (f *fakeNode) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *fakeNode) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.received
}

func nodes(ids ...string) []scannode.Node {
	out := make([]scannode.Node, 0, len(ids))
	for _, id := range ids {
		out = append(out, scannode.Node{ID: id, Addr: "https://10.0.0.1:27411", Fingerprint: "ff", Weight: 1})
	}
	return out
}

func testFrame(i int) deepscan.FrameV2 {
	return deepscan.FrameV2{
		Version: int(deepscan.FrameVersionV2), JobID: fmt.Sprintf("job-%d", i),
		TenantID: "org_a", ContentSHA256: fmt.Sprintf("sha-%d", i),
		Source: deepscan.SourceRequest, Prompt: strings.Repeat("x", 1024),
	}
}

// TestDeepScanForward_SlowNodeNeverDelaysRequests is THE fence for this package.
//
// 🔴 The user's constraint, verbatim (2026-09-11): 「这个不能对 AiKey proxy 造成
// 任何阻塞」. Async scan is a side channel bolted onto the request path; if it can
// ever make a request wait, it has traded the product's main promise for a
// background nicety. So this test makes the node take FIVE SECONDS per frame —
// far longer than any request — and asserts the enqueueing side is unaffected.
//
// It measures the ENQUEUE call, not a whole request, on purpose: Enqueue is the
// only thing the request path actually executes, so it is the only thing whose
// latency can possibly leak into a user's turn. A test that timed a full fake
// request would mostly measure the fake.
func TestDeepScanForward_SlowNodeNeverDelaysRequests(t *testing.T) {
	slow := &fakeNode{id: "scan-1", delay: 5 * time.Second}
	r := NewRemoteForwarder(Config{
		Nodes:      nodes("scan-1"),
		QueueMax:   8, // deliberately small: the queue WILL fill while the node crawls
		QueueBytes: 1 << 20,
		DialSink:   func(scannode.Node) deepscan.Sink { return slow },
	})
	r.Start()
	defer r.Close(context.Background())

	const callers, each = 100, 5
	var wg sync.WaitGroup
	lat := make([]time.Duration, 0, callers*each)
	var mu sync.Mutex
	for c := 0; c < callers; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				start := time.Now()
				r.Enqueue(testFrame(c*each + i))
				d := time.Since(start)
				mu.Lock()
				lat = append(lat, d)
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p95 := lat[int(float64(len(lat))*0.95)]
	worst := lat[len(lat)-1]
	t.Logf("MEASURED %d Enqueue calls against a node taking %v per frame: p95=%v worst=%v",
		len(lat), slow.delay, p95, worst)

	// Enqueue is a channel send with a default branch. Anything in the
	// milliseconds means it waited on something it must never wait on.
	if p95 > 2*time.Millisecond {
		t.Errorf("Enqueue p95 is %v — the request path is paying for a slow node", p95)
	}
	if worst > 50*time.Millisecond {
		t.Errorf("worst Enqueue took %v — a request would have felt that", worst)
	}
	if st := r.Stats(); st.Dropped == 0 {
		t.Error("with a 5s-per-frame node and 500 enqueues, work must have been DROPPED, not buffered without bound")
	}
}

// TestDeepScanForward_DegradesAfterThreeFailuresAndRecovers pins the health
// transition an operator reads (design §3.4): three consecutive delivery
// failures ⇒ degraded; one success clears it.
func TestDeepScanForward_DegradesAfterThreeFailuresAndRecovers(t *testing.T) {
	bad := &fakeNode{id: "scan-1", failAll: true}
	r := NewRemoteForwarder(Config{
		Nodes: nodes("scan-1"), QueueMax: 64, QueueBytes: 1 << 20,
		DialSink: func(scannode.Node) deepscan.Sink { return bad },
		// A short cooldown so the recovery leg does not wait 30s. The cooldown
		// itself is what makes recovery POSSIBLE at all — see
		// scannode.NewBreakerWithCooldown.
		Breaker: scannode.NewBreakerWithCooldown(3, 40*time.Millisecond),
	})
	r.Start()
	defer r.Close(context.Background())

	for i := 0; i < 3; i++ {
		r.Enqueue(testFrame(i))
	}
	waitFor(t, func() bool { return r.Stats().Status == StatusDegraded })

	bad.mu.Lock()
	bad.failAll = false
	bad.mu.Unlock()

	// 🔴 Recovery arrives with the NEXT piece, not by retrying the failed one.
	// design §3.5 makes `failed → sending` an illegal transition on purpose: a
	// task that failed is dropped, and the content is re-scanned only if it is
	// sent again. So the lane comes back when (a) the breaker's cooldown has
	// elapsed AND (b) new work shows up — which is exactly what a real proxy
	// does on the user's next turn. A test that expected the forwarder to retry
	// on its own would be asserting a retry loop the design forbids.
	waitFor(t, func() bool {
		r.Enqueue(testFrame(100 + int(r.Stats().Enqueued)))
		return r.Stats().Status == StatusOK
	})
}

// TestDeepScanForward_ByteBudgetDropsNeverBlocks: the queue holds WHOLE pieces,
// so bounding it by item count alone bounds nothing — 256 slots of 256 KiB is
// 64 MiB of an employee's RAM. The byte budget is the real bound, and hitting it
// must drop, never block.
func TestDeepScanForward_ByteBudgetDropsNeverBlocks(t *testing.T) {
	slow := &fakeNode{id: "scan-1", delay: 2 * time.Second}
	const budget = 64 * 1024
	r := NewRemoteForwarder(Config{
		Nodes: nodes("scan-1"), QueueMax: 1000, QueueBytes: budget,
		DialSink: func(scannode.Node) deepscan.Sink { return slow },
	})
	r.Start()
	defer r.Close(context.Background())

	big := deepscan.FrameV2{
		Version: int(deepscan.FrameVersionV2), JobID: "big", TenantID: "org_a",
		Source: deepscan.SourceRequest, Prompt: strings.Repeat("y", 16*1024),
	}
	accepted := 0
	start := time.Now()
	for i := 0; i < 200; i++ {
		if r.Enqueue(big) {
			accepted++
		}
	}
	elapsed := time.Since(start)

	if elapsed > 200*time.Millisecond {
		t.Errorf("200 enqueues took %v — the byte budget blocked instead of dropping", elapsed)
	}
	if accepted >= 200 {
		t.Errorf("every frame was accepted; the %d-byte budget did nothing", budget)
	}
	st := r.Stats()
	if st.Dropped == 0 || st.DroppedBytes == 0 {
		t.Errorf("drops must be COUNTED (and their bytes), got %+v — a silent drop is an invisible coverage hole", st)
	}
	t.Logf("MEASURED budget=%dB frame=%dB accepted=%d dropped=%d dropped_bytes=%d in %v",
		budget, len(big.Prompt), accepted, st.Dropped, st.DroppedBytes, elapsed)
}

// TestDeepScanForward_TenantMismatchDoesNotTryAnotherNode: some rejects mean
// "try the next box" and some mean "this frame is wrong". Retrying a
// tenant_mismatch across every node would walk the same content past every node
// in the fleet — turning one refusal into a fleet-wide exposure attempt.
func TestDeepScanForward_TenantMismatchDoesNotTryAnotherNode(t *testing.T) {
	n1 := &fakeNode{id: "scan-1", reject: deepscan.RejectTenantMismatch}
	n2 := &fakeNode{id: "scan-2"}
	byID := map[string]*fakeNode{"scan-1": n1, "scan-2": n2}

	r := NewRemoteForwarder(Config{
		Nodes: nodes("scan-1", "scan-2"), QueueMax: 16, QueueBytes: 1 << 20,
		DialSink:  func(n scannode.Node) deepscan.Sink { return byID[n.ID] },
		RejectFor: func(n scannode.Node) string { return byID[n.ID].reject },
	})
	r.Start()
	defer r.Close(context.Background())

	r.Enqueue(testFrame(1))
	waitFor(t, func() bool { return r.Stats().Failed > 0 })

	if got := n1.count() + n2.count(); got > 1 {
		t.Errorf("a tenant_mismatch frame was delivered %d times; it must stop at the first node", got)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	const d = 3 * time.Second
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", d)
}

// answeringNode is a sink that, like a real node, answers each frame with a
// result (or a refusal) on the same call.
type answeringNode struct {
	reject  string
	mu      sync.Mutex
	sent    int
	results chan deepscan.ResultFrame
}

func newAnsweringNode(reject string) *answeringNode {
	return &answeringNode{reject: reject, results: make(chan deepscan.ResultFrame, 8)}
}

func (a *answeringNode) Send(_ context.Context, frame []byte) error {
	a.mu.Lock()
	a.sent++
	a.mu.Unlock()
	if a.reject != "" {
		return &deepscan.RejectError{Code: a.reject}
	}
	f, err := deepscan.DecodeFrameV2(frame)
	if err != nil {
		return err
	}
	a.results <- deepscan.ResultFrame{JobID: f.JobID, Status: deepscan.StatusComplete}
	return nil
}
func (a *answeringNode) Close() error                         { return nil }
func (a *answeringNode) Results() <-chan deepscan.ResultFrame { return a.results }
func (a *answeringNode) count() int                           { a.mu.Lock(); defer a.mu.Unlock(); return a.sent }

// TestDeepScanForward_NodeResultReachesTheLane — what a node answers comes out
// of the forwarder's Results(), which is what the lane's pump files.
// bugfix: workflow/CI/bugfix/20260913-async-scan-lane-never-returned-findings.md
func TestDeepScanForward_NodeResultReachesTheLane(t *testing.T) {
	n1 := newAnsweringNode("")
	r := NewRemoteForwarder(Config{
		Nodes: nodes("scan-1"), QueueMax: 16, QueueBytes: 1 << 20,
		DialSink: func(scannode.Node) deepscan.Sink { return n1 },
	})
	r.Start()
	defer r.Close(context.Background())

	fr := testFrame(1)
	r.Enqueue(fr)
	select {
	case res := <-r.Results():
		if res.JobID != fr.JobID {
			t.Fatalf("result for job %q, want %q", res.JobID, fr.JobID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the node answered but no result came out of the forwarder — it would never be filed")
	}
}

// TestDeepScanForward_TenantMismatchFromTheNodeStopsAtOneNode — the same rule as
// TenantMismatchDoesNotTryAnotherNode, but with the refusal arriving the way a
// real node sends it: in its answer, not from a pre-send hook.
func TestDeepScanForward_TenantMismatchFromTheNodeStopsAtOneNode(t *testing.T) {
	n1, n2 := newAnsweringNode(deepscan.RejectTenantMismatch), newAnsweringNode(deepscan.RejectTenantMismatch)
	byID := map[string]*answeringNode{"scan-1": n1, "scan-2": n2}
	r := NewRemoteForwarder(Config{
		Nodes: nodes("scan-1", "scan-2"), QueueMax: 16, QueueBytes: 1 << 20,
		DialSink: func(n scannode.Node) deepscan.Sink { return byID[n.ID] },
	})
	r.Start()
	defer r.Close(context.Background())

	r.Enqueue(testFrame(1))
	waitFor(t, func() bool { return r.Stats().Failed > 0 })
	time.Sleep(100 * time.Millisecond)
	if got := n1.count() + n2.count(); got != 1 {
		t.Fatalf("a tenant_mismatch answer led to %d deliveries; it must stop at the first node", got)
	}
}
