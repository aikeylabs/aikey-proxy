package proxy

// chain_confidence_coverage_test.go — P5.1 of openspec change
// `aliyun-aigw-p0-upstream-fallback`.
//
// # 🔴 Switching upstream without changing the model name is the confidence
// check's main event, not an edge case
//
// The whole point of this capability is that the same model is served by a
// different vendor. Whether it is still the same thing is exactly the question
// the confidence check exists to ask — so the ONE response the client actually
// receives has to reach the detector, whichever attempt produced it.
//
// Two ways to get this wrong, and both leave a green build:
//
//	🚫 observe only the first attempt — after any switch there is NO detection
//	   coverage at all, and nothing says so;
//	🚫 skip observation on a switched response ("it is an emergency path") —
//	   that turns the detector off at the exact moment it is most needed.
//
// # 🔴 Why this is a wiring fence and not a detector test
//
// The detector lives in another process (ai-degrade-detector, subscribed through
// the observer registry). What this package owns is whether the served response
// is HANDED to it. A detector that is never called scores nothing, and its own
// tests all pass.
//
// 🔴 Coverage is asserted on the SERVING hop specifically. Asserting merely that
// "some observation happened" would stay green under the first failure mode
// above: the first, failing attempt is observed too.

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// chainObserverRecorder records EVERY notification in arrival order.
//
// 🔴 Deliberately not keyed by TraceID, unlike rhythmHooksRecorder. Every hop of
// one chain shares a trace id (I25), so a map keyed on it silently collapses the
// attempts into whichever wrote last — and this fence exists to tell those
// attempts apart.
type chainObserverRecorder struct {
	mu        sync.Mutex
	startedOn []string // ProviderID per OnRequestStart, in order
	endedOn   []string // ProviderID per OnRequestEnd, in order
}

func (r *chainObserverRecorder) OnRequestStart(_ context.Context, req *observer.RequestContext) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.startedOn = append(r.startedOn, req.ProviderID)
}

func (r *chainObserverRecorder) OnSSEEvent(context.Context, *observer.RequestContext, string, []byte) {
}

func (r *chainObserverRecorder) OnRequestEnd(_ context.Context, req *observer.RequestContext, _ int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endedOn = append(r.endedOn, req.ProviderID)
}

func (r *chainObserverRecorder) snapshot() (starts, ends []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.startedOn...), append([]string(nil), r.endedOn...)
}

// waitForEnds blocks until `want` end-notifications have arrived, or fails.
//
// 🔴 Not optional politeness. The registry fans out to observers on a DETACHED
// context so a slow detector cannot hold up the client's response — which means
// `Handle` returning does not mean the detector has been told anything. A first
// version of this fence asserted immediately and reported "the serving hop was
// started but never ENDED", which was a race in the test, not a gap in the
// product. 🚫 Asserting on ends without waiting would make this fence flaky in
// BOTH directions: green when the scheduler is kind, and red on a build that is
// perfectly correct.
func (r *chainObserverRecorder) waitForEnds(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		n := len(r.endedOn)
		r.mu.Unlock()
		if n >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, ends := r.snapshot()
	t.Fatalf("waited 3s for %d end-notifications, saw %d (%v)", want, len(ends), ends)
}

// TestChain_ConfidenceCheckCoversTheResponseTheClientActuallyGot is the P5.1
// fence. The primary fails, the fallback serves, and the detector must have been
// handed the FALLBACK's turn — the one the user is reading.
func TestChain_ConfidenceCheckCoversTheResponseTheClientActuallyGot(t *testing.T) {
	p, cap := twoHopChain(t)
	cap.statusByHost["primary.invalid"] = http.StatusInternalServerError

	rec := &chainObserverRecorder{}
	p.SetObserverRegistry(buildChainObserverRegistry(t, rec))

	req, w := chainReq()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("client status = %d, want 200 (the fallback served)", w.Code)
	}
	if got := w.Header().Get(observability.HeaderUpstreamFallback); got == "" {
		t.Fatalf("no %s header — no switch happened, so this fence proves nothing",
			observability.HeaderUpstreamFallback)
	}

	rec.waitForEnds(t, 2) // both hops: the one that failed and the one that served
	starts, ends := rec.snapshot()
	// 🔴 The SERVING hop, named. "mock" is hop two of twoHopChain; "anthropic" is
	// the one that 500'd. A build that only observes the first attempt produces
	// ["anthropic"] here and must fail.
	if !containsProvider(starts, "mock") {
		t.Fatalf("the confidence check never saw the response the client got.\n"+
			"observed starts = %v; the serving hop (mock) is missing.\n"+
			"After a switch this means ZERO detection coverage — and nothing anywhere says so.",
			starts)
	}
	if !containsProvider(ends, "mock") {
		t.Fatalf("the serving hop was started but never ENDED on the detector: ends = %v.\n"+
			"A turn that never closes is a turn the detector cannot score.", ends)
	}
}

// TestChain_EveryAttemptIsObservedNotJustTheLast guards the other direction.
//
// A future "optimisation" that observes only the winning hop would look tidy and
// would quietly delete the evidence that the chain was walked at all — the
// detector's own health surface (§11 of the AI-engineering workflow) then cannot
// distinguish "one upstream, healthy" from "three upstreams, two of them down".
func TestChain_EveryAttemptIsObservedNotJustTheLast(t *testing.T) {
	p, cap := twoHopChain(t)
	cap.statusByHost["primary.invalid"] = http.StatusInternalServerError

	rec := &chainObserverRecorder{}
	p.SetObserverRegistry(buildChainObserverRegistry(t, rec))

	req, w := chainReq()
	p.Handle(w, req)

	rec.waitForEnds(t, 2)
	starts, _ := rec.snapshot()
	if len(starts) != 2 {
		t.Fatalf("observed %d attempts (%v), want 2 — one per hop actually dialled", len(starts), starts)
	}
	if starts[0] != "anthropic" || starts[1] != "mock" {
		t.Fatalf("observed order = %v, want [anthropic mock] — the order the chain was walked in", starts)
	}
}

// TestChain_SingleHopIsStillObserved keeps the fence honest about the case with
// no switch at all: if this went red, the two tests above could pass for the
// trivial reason that nothing is ever observed on the happy path either.
func TestChain_SingleHopIsStillObserved(t *testing.T) {
	p, _ := twoHopChain(t)

	rec := &chainObserverRecorder{}
	p.SetObserverRegistry(buildChainObserverRegistry(t, rec))

	req, w := chainReq()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("client status = %d, want 200", w.Code)
	}
	rec.waitForEnds(t, 1)
	starts, ends := rec.snapshot()
	if len(starts) != 1 || starts[0] != "anthropic" {
		t.Fatalf("starts = %v, want exactly [anthropic]", starts)
	}
	if len(ends) != 1 {
		t.Fatalf("ends = %v, want exactly one", ends)
	}
}

func containsProvider(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// buildChainObserverRegistry mirrors buildUserChatObserverRegistry but takes the
// order-preserving recorder above.
func buildChainObserverRegistry(t *testing.T, rec *chainObserverRecorder) *observer.Registry {
	t.Helper()
	observer.ResetRegistrationsForTest()
	t.Cleanup(observer.ResetRegistrationsForTest)
	observer.RegisterObserver(observer.Observer{
		Name:         "chain-coverage-" + t.Name(),
		OwnerAppSlug: "degrade-detector", // the confidence check's own slug
		Streams:      []string{observer.StreamUserChat},
		Build: func(map[string]any) (observer.StreamingObserver, error) {
			return rec, nil
		},
	})
	reg := observer.NewRegistry(slog.Default())
	reg.BuildObservers(func(string) bool { return true }, nil)
	if reg.Active() != 1 {
		t.Fatalf("expected exactly 1 active observer, got %d", reg.Active())
	}
	return reg
}
