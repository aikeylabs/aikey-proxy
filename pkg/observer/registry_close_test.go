package observer

import (
	"context"

	"sync/atomic"
	"testing"
	"time"
)

// Registry.Close is the retirement path for observers (2026-08-15).
//
// BuildObservers runs once per SUPERVISOR GENERATION, not once per process, so
// anything an observer starts in Build (goroutines, tickers, connections) is
// re-created on every reload. Before Close existed there was no way to retire
// them: the rhythm observer's 5s settings poller accumulated one live copy per
// generation, and a single toggle flip produced four
// `settings_poller.toggle_changed` events from four leaked pollers.
//
// 能红 (how to make these red): drop the ClosableObserver type-assert in
// Registry.Close, or stop iterating r.observers there.

// closableObserver is a no-op StreamingObserver that counts Close calls, and
// can misbehave (panic / hang) the way a third-party plugin might.
type closableObserver struct {
	closed       atomic.Int32
	panicOnClose bool
	blockClose   chan struct{} // when non-nil, Close blocks until it is closed
}

func (c *closableObserver) OnRequestStart(context.Context, *RequestContext)             {}
func (c *closableObserver) OnSSEEvent(context.Context, *RequestContext, string, []byte) {}
func (c *closableObserver) OnRequestEnd(context.Context, *RequestContext, int)          {}

func (c *closableObserver) Close() {
	c.closed.Add(1)
	if c.panicOnClose {
		panic("closableObserver: Close panic (test)")
	}
	if c.blockClose != nil {
		<-c.blockClose
	}
}

// plainObserver implements only StreamingObserver — Close must skip it rather
// than assume every observer is closable.
type plainObserver struct{}

func (plainObserver) OnRequestStart(context.Context, *RequestContext)             {}
func (plainObserver) OnSSEEvent(context.Context, *RequestContext, string, []byte) {}
func (plainObserver) OnRequestEnd(context.Context, *RequestContext, int)          {}

// closableRegistry builds a Registry over the given observers, one descriptor
// each. (full_payload_test.go already owns `registryWith` with a different
// shape; this one is variadic so a test can exercise multi-observer teardown.)
func closableRegistry(t *testing.T, impls ...StreamingObserver) *Registry {
	t.Helper()
	const slug = "test-closable-slug"
	originalAllow := FirstPartyAllowlist[slug]
	FirstPartyAllowlist[slug] = true
	t.Cleanup(func() {
		if !originalAllow {
			delete(FirstPartyAllowlist, slug)
		}
	})

	resetRegistrationsForTest()
	for i, impl := range impls {
		impl := impl
		RegisterObserver(Observer{
			Name:         "test-closable-" + string(rune('a'+i)),
			OwnerAppSlug: slug,
			Streams:      []string{StreamAppPipeline},
			Build: func(map[string]any) (StreamingObserver, error) {
				return impl, nil
			},
		})
	}
	r := NewRegistry(nil)
	r.BuildObservers(func(string) bool { return true }, nil)
	if got := r.Active(); got != len(impls) {
		t.Fatalf("expected %d active observers; got %d", len(impls), got)
	}
	return r
}

func TestRegistryCloseRetiresClosableObservers(t *testing.T) {
	a, b := &closableObserver{}, &closableObserver{}
	r := closableRegistry(t, a, b)

	r.Close()

	// 能红: remove the ClosableObserver assert in Registry.Close.
	if got := a.closed.Load(); got != 1 {
		t.Errorf("observer A: Close called %d times, want 1. Without this the "+
			"goroutines it started in Build outlive the generation — the "+
			"2026-08-15 rhythm settings-poller leak (one live 5s poller per reload).", got)
	}
	if got := b.closed.Load(); got != 1 {
		t.Errorf("observer B: Close called %d times, want 1 — Close must retire "+
			"EVERY closable observer, not just the first.", got)
	}
}

func TestRegistryCloseSkipsNonClosableObservers(t *testing.T) {
	// A StreamingObserver that does not opt in must not break teardown: Close
	// is an OPTIONAL capability (same idiom as FullPayloadObserver).
	c := &closableObserver{}
	r := closableRegistry(t, plainObserver{}, c)

	r.Close() // must not panic on the plain observer

	if got := c.closed.Load(); got != 1 {
		t.Errorf("closable observer got %d Close calls, want 1 — a non-closable "+
			"sibling must not stop teardown reaching it", got)
	}
}

func TestRegistryClosePanicInOneObserverDoesNotAbortTheRest(t *testing.T) {
	bad := &closableObserver{panicOnClose: true}
	good := &closableObserver{}
	r := closableRegistry(t, bad, good)

	r.Close() // must not propagate the panic

	if got := good.closed.Load(); got != 1 {
		t.Errorf("observer after the panicking one got %d Close calls, want 1. "+
			"A misbehaving plugin must not take down the rest of teardown — "+
			"same containment rule as the request hooks.", got)
	}
}

func TestRegistryCloseIsBoundedWhenAnObserverHangs(t *testing.T) {
	// generation.closeAll runs on the reload's async drain goroutine. A plugin
	// that blocks forever must not pin it for the process lifetime.
	block := make(chan struct{})
	hang := &closableObserver{blockClose: block}
	defer close(block) // let the leaked goroutine finish after the test

	r := closableRegistry(t, hang)

	// Shrink the wait by asserting Close returns well before a "hangs forever"
	// implementation would. closeBudget is 10s; a blocked Close that ignored
	// the budget would never return.
	done := make(chan struct{})
	go func() { r.Close(); close(done) }()

	select {
	case <-done:
	case <-time.After(closeBudget + 5*time.Second):
		t.Fatal("Registry.Close did not return: a hanging observer pinned the " +
			"reload drain goroutine. Close must be bounded by closeBudget.")
	}
}

func TestRegistryCloseIsNilSafe(t *testing.T) {
	// Proxy.StopObservers calls through to a registry that is nil whenever no
	// observer descriptors were registered (buildObserverRegistry returns nil).
	var r *Registry
	r.Close() // must not panic
}

func TestRegistryCloseIsIdempotent(t *testing.T) {
	// generation.close() is sync.Once-guarded, but Shutdown and the async
	// drain can both reach teardown under the restart-during-reload race the
	// 2026-07-19 bugfix describes. Two Closes must stay harmless.
	c := &closableObserver{}
	r := closableRegistry(t, c)

	r.Close()
	r.Close()

	if got := c.closed.Load(); got != 2 {
		t.Errorf("got %d Close calls after two Close() calls, want 2 — the "+
			"observer's own Stop is required to be idempotent, so the registry "+
			"deliberately does not de-duplicate", got)
	}
}
