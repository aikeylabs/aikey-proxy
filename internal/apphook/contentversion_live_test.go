package apphook

// contentversion_live_test.go — the content-version mechanism against the REAL
// ai-compliance-detector binary over the REAL pipe (op=ListPacks).
//
// Why these cannot be unit tests: the fingerprint is taken over whatever bytes
// the detector's effective-content report actually contains, and the mechanism's
// central assumption is that those bytes are STABLE between two polls when
// nothing changed. A hand-written fixture cannot falsify that assumption — only
// the real report can. If the detector ever adds a timestamp, a counter, or a
// map serialized in random order to that report, the fingerprint would change on
// every poll and the caller's cache would drop to a 0% hit rate while still
// looking correct. TestContentVersion_LiveFingerprintIsStableAcrossPolls is the
// tripwire for that, and it belongs in this repo because this repo is the one
// that depends on the property.

import (
	"context"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/detectortest"
)

// newLiveHook spawns the detector in its REAL mode.
//
// 🔴 Deliberately NOT detectorArgs() (`--echo-only`), which most tests in this
// package use: the echo stub has no pack machinery, so op=ListPacks returns an
// empty report and every assertion here would be measuring the stub. This
// mirrors TestChildHook_ListPacks, the other test that needs the real engine.
//
// Worth knowing, because it is also a real deployment state rather than a test
// detail: a child that cannot answer op=ListPacks — the echo stub, or a detector
// build predating the op — reports its content version as UNKNOWN, and the proxy
// then disables verdict memoization entirely (fail-safe). Correct, and slower.
//
// The door also seals the host state, and the returned Sealed must be asserted
// once the child is up: the content fingerprint is taken over the child's
// EFFECTIVE content set, which a host pack cache changes outright — an unsealed
// run would be fingerprinting the developer's installed lexicon.
func newLiveHook(t *testing.T, name string) (*ChildHook, detectortest.Sealed) {
	t.Helper()
	binary, sealed := requireSealedDetector(t)
	return NewChildHook(&ChildHookConfig{
		Name: name, BinaryPath: binary,
		Timeout: 2 * time.Second, ReadyTimeout: 5 * time.Second,
	}), sealed
}

// The child reports a content version at all, and it survives repeated polling
// unchanged. Both halves matter: no version ⇒ the caller can never cache; an
// unstable version ⇒ the caller can never hit.
func TestContentVersion_LiveFingerprintIsStableAcrossPolls(t *testing.T) {
	h, sealed := newLiveHook(t, "contentversion-live")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Skipf("child binary unavailable (build first): %v", err)
	}
	defer func() { _ = h.Shutdown(context.Background()) }()
	sealed.AssertHeld(t, h)

	// Start() kicks the poll off asynchronously; drive it explicitly so the test
	// does not race the goroutine's first tick.
	h.refreshContentVersion()
	first, ok := h.ContentVersion()
	if !ok || first == "" {
		t.Fatalf("live detector reported no content version (ok=%v, v=%q) — the proxy cache would be permanently disabled", ok, first)
	}
	if len(first) != contentVersionTokenLen {
		t.Errorf("token length = %d, want %d", len(first), contentVersionTokenLen)
	}

	for i := 0; i < 5; i++ {
		h.refreshContentVersion()
		got, ok := h.ContentVersion()
		if !ok || got != first {
			t.Fatalf("poll %d: content version moved with no pack change (%q → %q, ok=%v). "+
				"Something volatile (timestamp / counter / unordered map) entered the detector's "+
				"effective-content report; every one of those flushes the proxy's verdict cache on "+
				"every poll and drops its hit rate to zero.", i+1, first, got, ok)
		}
	}

	// The report the fingerprint is taken over is the same one the admin surface
	// serves, so the two can never disagree about what is live on this box.
	report, err := h.ListPacks(ctx)
	if err != nil {
		t.Fatalf("ListPacks: %v", err)
	}
	if got := contentFingerprint(report); got != first {
		t.Errorf("fingerprint disagrees with the operator-visible report: %q vs %q", got, first)
	}

	// Detect still works on the same pipe after all that polling — the meta query
	// must never wedge the data plane.
	if res := h.Detect(ctx, &Request{Payload: []byte("How do I write a for loop?")}); res.Degraded {
		t.Errorf("Detect degraded after content-version polling: %s", res.Reason)
	}
}

// A real 2-process pool converges on ONE token: both children load the same
// baseline, so a pool that cannot agree with itself at rest would flush the
// caller's cache forever.
func TestFilterPool_LiveWorkersAgreeOnContentVersion(t *testing.T) {
	// Both workers go through the same door; Seal is idempotent within a test, so
	// the two children share ONE sealed home (a pool whose workers saw different
	// homes could not be asked to agree on a content version).
	w0, sealed := newLiveHook(t, "pool-cv-0")
	w1, _ := newLiveHook(t, "pool-cv-1")
	pool := NewFilterPool("pool-cv", []*ChildHook{w0, w1})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := pool.Start(ctx); err != nil {
		t.Skipf("child binary unavailable (build first): %v", err)
	}
	defer func() { _ = pool.Shutdown(context.Background()) }()
	sealed.AssertHeld(t, pool)

	w0.refreshContentVersion()
	w1.refreshContentVersion()

	v0, ok0 := w0.ContentVersion()
	v1, ok1 := w1.ContentVersion()
	if !ok0 || !ok1 {
		t.Fatalf("both live workers must report a content version (ok0=%v ok1=%v)", ok0, ok1)
	}
	if v0 != v1 {
		t.Fatalf("two workers on the same box loaded different content sets: %q vs %q", v0, v1)
	}
	poolV, ok := pool.ContentVersion()
	if !ok {
		t.Fatal("converged pool must report a known content version")
	}
	if poolV != v0 {
		t.Errorf("a converged pool must be indistinguishable from a single worker: pool=%q worker=%q", poolV, v0)
	}
}
