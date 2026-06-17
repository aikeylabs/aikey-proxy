package observer

import (
	"context"
	"sync/atomic"
	"testing"
)

// togglePayloadObserver implements StreamingObserver + the optional
// FullPayloadObserver; `wants` flips at runtime to exercise the
// re-evaluated-per-request contract.
type togglePayloadObserver struct {
	wants atomic.Bool
}

func (o *togglePayloadObserver) OnRequestStart(context.Context, *RequestContext)             {}
func (o *togglePayloadObserver) OnSSEEvent(context.Context, *RequestContext, string, []byte) {}
func (o *togglePayloadObserver) OnRequestEnd(context.Context, *RequestContext, int)          {}
func (o *togglePayloadObserver) WantsFullPayload() bool                                      { return o.wants.Load() }

// registryWith builds a single-observer registry under a test slug, bypassing
// the first-party allowlist for the test's duration. Mirrors makeRegistry but
// takes an arbitrary StreamingObserver so FullPayloadObserver doubles work.
func registryWith(t *testing.T, slug, name string, obs StreamingObserver) *Registry {
	t.Helper()
	original := FirstPartyAllowlist[slug]
	FirstPartyAllowlist[slug] = true
	t.Cleanup(func() {
		if !original {
			delete(FirstPartyAllowlist, slug)
		}
	})
	resetRegistrationsForTest()
	RegisterObserver(Observer{
		Name:         name,
		OwnerAppSlug: slug,
		Streams:      []string{StreamUserChat},
		Build:        func(map[string]any) (StreamingObserver, error) { return obs, nil },
	})
	r := NewRegistry(nil)
	r.BuildObservers(func(string) bool { return true }, nil)
	if got := r.Active(); got != 1 {
		t.Fatalf("active observers=%d want 1", got)
	}
	return r
}

// An observer that does NOT implement FullPayloadObserver must never make the
// registry want the body (the common case — rhythm/billing pay nothing).
func TestWantsFullPayload_AbsentInterfaceIsFalse(t *testing.T) {
	r := registryWith(t, "_test-plain", "test-plain", &recordingObserver{})
	if r.WantsFullPayload() {
		t.Fatalf("WantsFullPayload=true for observer without FullPayloadObserver; want false")
	}
}

// With the interface present, the registry mirrors the observer's live answer —
// false stays false, and a runtime flip to true is reflected on the next call
// (the enterprise-audit policy-flip scenario).
func TestWantsFullPayload_ReflectsLiveAnswer(t *testing.T) {
	obs := &togglePayloadObserver{}
	r := registryWith(t, "_test-fp", "test-fp", obs)

	if r.WantsFullPayload() {
		t.Fatalf("WantsFullPayload=true while observer wants=false")
	}
	obs.wants.Store(true)
	if !r.WantsFullPayload() {
		t.Fatalf("WantsFullPayload=false after observer flipped wants=true (must re-evaluate per call)")
	}
	obs.wants.Store(false)
	if r.WantsFullPayload() {
		t.Fatalf("WantsFullPayload stuck true after observer flipped back to false")
	}
}

// A disabled (auto-disabled) observer is skipped — a crashed audit observer must
// not keep forcing the hot-path body buffering it can no longer consume.
func TestWantsFullPayload_SkipsDisabled(t *testing.T) {
	obs := &togglePayloadObserver{}
	obs.wants.Store(true)
	r := registryWith(t, "_test-fp-dis", "test-fp-dis", obs)

	if !r.WantsFullPayload() {
		t.Fatalf("precondition: WantsFullPayload should be true before disable")
	}
	r.observers[0].disabled.Store(true)
	if r.WantsFullPayload() {
		t.Fatalf("WantsFullPayload=true for disabled observer; must skip disabled")
	}
}
