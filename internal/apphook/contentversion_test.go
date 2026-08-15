package apphook

// contentversion_test.go — the content-version mechanism that keeps a caller's
// verdict cache honest across an in-place ruleset swap
// (bugfix 20260813-pack-swap-does-not-invalidate-proxy-cache).
//
// Two layers are covered here:
//   - CacheEpoch's tri-state (the contract every caller depends on)
//   - FilterPool aggregation across M workers with INDEPENDENT pullers, which is
//     the part a single-process test can never reach
//
// The live half (real detector binary, real op=ListPacks) is in
// contentversion_live_test.go.

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// newUnstartedWorker builds a ChildHook without spawning anything. Every field
// the aggregation reads (degraded flag, contentVersion pointer) is package-local,
// so the pool logic is exercised on the REAL types rather than on an interface
// double — the aggregation is what is under test, not the IPC.
func newUnstartedWorker(t *testing.T, name string) *ChildHook {
	t.Helper()
	return NewChildHook(&ChildHookConfig{Name: name, BinaryPath: "/nonexistent", Timeout: time.Second})
}

// setContentVersion puts a worker into the "healthy, knows its ruleset" state.
func setContentVersion(h *ChildHook, v string) {
	h.degraded.Store(false)
	h.status.Store(&Status{Healthy: true})
	h.contentVersion.Store(&v)
}

// setHealthyButBlind: serving traffic, but its last content poll failed.
func setHealthyButBlind(h *ChildHook) {
	h.degraded.Store(false)
	h.status.Store(&Status{Healthy: true})
	h.contentVersion.Store(nil)
}

func TestCacheEpoch_TriState(t *testing.T) {
	// 1. No hot-swappable content declared → cacheable with an empty epoch.
	//    Disabled is a real production Hook (the no-op slot), not a test double.
	if epoch, ok := CacheEpoch(NewDisabled("none")); !ok || epoch != "" {
		t.Errorf("hook without ContentVersioned: got (%q,%v), want (\"\",true)", epoch, ok)
	}

	h := newUnstartedWorker(t, "tri")
	// 2. Declares it but cannot state it (never started → degraded) → NOT cacheable.
	if epoch, ok := CacheEpoch(h); ok {
		t.Errorf("unstarted child must not be cacheable: got (%q,%v)", epoch, ok)
	}
	// 3. Declares it and knows it → cacheable under that token.
	setContentVersion(h, "abc123")
	if epoch, ok := CacheEpoch(h); !ok || epoch != "abc123" {
		t.Errorf("known content set: got (%q,%v), want (\"abc123\",true)", epoch, ok)
	}
	// 4. Degrading again must revoke it — a stale token is worse than none.
	h.markDegraded("test")
	if epoch, ok := CacheEpoch(h); ok {
		t.Errorf("degraded child must revoke its epoch, got (%q,%v)", epoch, ok)
	}
}

// TestFilterPool_ContentVersion_DivergentWorkersInvalidate is constraint #2 of
// the fix: workers pull independently, so mid-propagation they hold DIFFERENT
// rulesets and the caller cannot tell which one served any given verdict.
// Sampling worker 0 would make every other worker's swap invisible.
func TestFilterPool_ContentVersion_DivergentWorkersInvalidate(t *testing.T) {
	w0, w1 := newUnstartedWorker(t, "w0"), newUnstartedWorker(t, "w1")
	pool := NewFilterPool("p", []*ChildHook{w0, w1})

	setContentVersion(w0, "packs-v1")
	setContentVersion(w1, "packs-v1")
	converged, ok := pool.ContentVersion()
	if !ok {
		t.Fatal("two agreeing workers must yield a known pool version")
	}

	// Worker 1 pulls the admin's rule deletion first; worker 0 has not yet.
	setContentVersion(w1, "packs-v2")
	diverged, ok := pool.ContentVersion()
	if !ok {
		t.Fatal("divergence is a known state, not an unknown one")
	}
	if diverged == converged {
		t.Fatal("ONE worker swapping must change the pool version, else its new ruleset is invisible to the cache")
	}
	if diverged == "packs-v1" || diverged == "packs-v2" {
		t.Errorf("pool version must not be a single worker's token (that is the sample-worker-0 bug): %q", diverged)
	}

	// Worker 0 catches up. The pool settles on a new stable token.
	setContentVersion(w0, "packs-v2")
	settled, ok := pool.ContentVersion()
	if !ok || settled != "packs-v2" {
		t.Errorf("converged pool should collapse to the shared token: got (%q,%v)", settled, ok)
	}
	if settled == converged {
		t.Error("the settled token must differ from the pre-swap one")
	}
}

// Round-robin position must not perturb the token: the pool is a SET of
// interchangeable workers. Without the sort, the same fleet state would produce
// different tokens depending on worker order and flush the cache for nothing.
func TestFilterPool_ContentVersion_OrderIndependent(t *testing.T) {
	a, b := newUnstartedWorker(t, "a"), newUnstartedWorker(t, "b")
	setContentVersion(a, "aaa")
	setContentVersion(b, "bbb")
	ab, _ := NewFilterPool("p", []*ChildHook{a, b}).ContentVersion()
	ba, _ := NewFilterPool("p", []*ChildHook{b, a}).ContentVersion()
	if ab != ba {
		t.Errorf("pool token depends on worker order: %q vs %q", ab, ba)
	}
}

// A worker that is SERVING but cannot state its ruleset makes the whole pool
// unknown: its verdicts can enter the caller's cache and we cannot say under
// which ruleset. Fail-safe over fail-stale.
func TestFilterPool_ContentVersion_HealthyButBlindWorkerBlocksCaching(t *testing.T) {
	good, blind := newUnstartedWorker(t, "good"), newUnstartedWorker(t, "blind")
	setContentVersion(good, "packs-v1")
	setHealthyButBlind(blind)

	pool := NewFilterPool("p", []*ChildHook{good, blind})
	if v, ok := pool.ContentVersion(); ok {
		t.Fatalf("a serving worker with an unknown ruleset must block caching pool-wide, got %q", v)
	}
	if _, cacheable := CacheEpoch(pool); cacheable {
		t.Fatal("CacheEpoch must propagate the pool's unknown state")
	}
}

// A DEGRADED worker is skipped rather than treated as unknown: it cannot
// contribute cacheable verdicts (Detect fails open and degraded responses are
// never cached), so counting it would disable the cache for the whole pool on
// account of a worker that cannot poison it. When it recovers, the token moves.
func TestFilterPool_ContentVersion_DegradedWorkerSkippedThenRejoins(t *testing.T) {
	up, down := newUnstartedWorker(t, "up"), newUnstartedWorker(t, "down")
	setContentVersion(up, "packs-v1")
	down.markDegraded("test: crashed")

	v, ok := pooled(up, down).ContentVersion()
	if !ok || v != "packs-v1" {
		t.Fatalf("a degraded worker must not disable caching: got (%q,%v)", v, ok)
	}

	// It comes back carrying the ruleset it pulled while it was away.
	setContentVersion(down, "packs-v2")
	v2, ok := pooled(up, down).ContentVersion()
	if !ok {
		t.Fatal("recovered pool should be known")
	}
	if v2 == v {
		t.Error("a recovered worker rejoining with a different ruleset must invalidate the cache")
	}
}

// All workers down → unknown, not "empty pool is fine".
func TestFilterPool_ContentVersion_AllDownIsUnknown(t *testing.T) {
	a, b := newUnstartedWorker(t, "a"), newUnstartedWorker(t, "b")
	a.markDegraded("x")
	b.markDegraded("x")
	if v, ok := pooled(a, b).ContentVersion(); ok {
		t.Fatalf("a pool with no serving worker must be unknown, got %q", v)
	}
}

func pooled(workers ...*ChildHook) *FilterPool { return NewFilterPool("p", workers) }

// contentFingerprint must be a pure function of the bytes: identical reports
// give identical tokens (that is what keeps a stable ruleset hitting the cache),
// and a one-byte difference gives a different one.
func TestContentFingerprint_StableAndSensitive(t *testing.T) {
	const report = `{"built_in":[{"name":"pii","kind":"built-in"}],"pulled":[],"cursor":7}`
	a := contentFingerprint([]byte(report))
	if a != contentFingerprint([]byte(report)) {
		t.Fatal("fingerprint is not deterministic")
	}
	if len(a) != contentVersionTokenLen {
		t.Errorf("token length = %d, want %d", len(a), contentVersionTokenLen)
	}
	if a == contentFingerprint([]byte(strings.Replace(report, `"cursor":7`, `"cursor":8`, 1))) {
		t.Error("fingerprint did not move when the report changed")
	}
}

// A failed poll must publish "unknown", never keep the last good token. The
// caller reads "unknown" as "do not memoize" — keeping the stale token would be
// exactly the fail-stale behavior this whole change exists to remove.
//
// The other half of the poll's contract — that a poll failure does not attach a
// `listpacks_failed` label to a child that is happily serving Detect — needs a
// live child to be discriminating (an unspawned hook fails earlier, inside
// roundtrip, for a reason that IS a genuine health fact). It is asserted in
// contentversion_live_test.go: TestContentVersionPoll_QuietFailureDoesNotRelabel.
func TestRefreshContentVersion_FailedPollPublishesUnknown(t *testing.T) {
	h := newUnstartedWorker(t, "quiet")
	h.degraded.Store(false)
	h.status.Store(&Status{Healthy: true})
	stale := "stale-token"
	h.contentVersion.Store(&stale)

	h.refreshContentVersion() // no child → the roundtrip fails

	if v, ok := h.ContentVersion(); ok {
		t.Errorf("a failed poll must clear the token, got %q", v)
	}
	if _, cacheable := CacheEpoch(h); cacheable {
		t.Error("CacheEpoch must report not-cacheable after a failed poll")
	}
}

// Shutdown must release the poll goroutine even for a hook that never spawned,
// and must stay idempotent (Shutdown is called from several unwind paths).
func TestStopContentVersionPoll_IsIdempotent(t *testing.T) {
	h := newUnstartedWorker(t, "shut")
	h.startContentVersionPoll()
	if err := h.Shutdown(context.Background()); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := h.Shutdown(context.Background()); err != nil {
		t.Fatalf("second shutdown must be a no-op, got %v", err)
	}
}

// BenchmarkCacheEpoch measures what the fix costs on the HOT PATH — the proxy
// resolves the epoch once per filtered request, so this number is per-request.
//
// The design point being verified: resolving the epoch is a type assertion plus
// an atomic load (M=1) or a short loop plus one hash (M>1). There is NO IPC here.
// The IPC lives on the 15s background poll, off the request path entirely — an
// epoch resolved by asking the child would have added a pipe roundtrip to every
// single request, which is why the poll exists.
func BenchmarkCacheEpoch(b *testing.B) {
	mk := func(n int) Hook {
		workers := make([]*ChildHook, n)
		for i := range workers {
			w := NewChildHook(&ChildHookConfig{Name: "bench", BinaryPath: "/nonexistent", Timeout: time.Second})
			v := "packs-v1"
			w.degraded.Store(false)
			w.status.Store(&Status{Healthy: true})
			w.contentVersion.Store(&v)
			workers[i] = w
		}
		if n == 1 {
			return workers[0] // ChildHook directly (no pool indirection)
		}
		return NewFilterPool("bench", workers)
	}
	for _, n := range []int{1, 4} {
		h := mk(n)
		name := "pool-M4"
		if n == 1 {
			name = "single-child"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, ok := CacheEpoch(h); !ok {
					b.Fatal("epoch unexpectedly unknown")
				}
			}
		})
	}
}

// drainingChild puts a hook into the one state that isolates a REPLY timeout:
// a live pipe whose far end accepts every byte and never answers.
//
// Real production code all the way down (roundtrip → writeFrame → the ctx.Done
// branch on the reply wait); only the child PROCESS is replaced, by a drain. The
// timing-based attempt to provoke this against the real detector was rejected
// because it is not reachable deterministically: on a fast machine any deadline
// short enough to beat the reply also races the write, and the call comes back
// as errWriteTimeout instead — a different path with different, correct,
// consequences (the session is torn down; see writeFrame's contract).
func drainingChild(t *testing.T, name string) *ChildHook {
	t.Helper()
	h := newUnstartedWorker(t, name)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	drained := make(chan struct{})
	go func() { defer close(drained); _, _ = io.Copy(io.Discard, r) }()
	t.Cleanup(func() { _ = w.Close(); <-drained; _ = r.Close() })

	h.session.Store(&pipeSession{w: bufio.NewWriterSize(w, 64*1024), pipe: w, writeSlot: make(chan struct{}, 1)})
	h.degraded.Store(false)
	h.status.Store(&Status{Healthy: true})
	return h
}

// TestContentVersionPoll_ReplyTimeoutStaysQuiet is the whole point of splitting
// listPacks on markOnErr.
//
// WHY IT MATTERS ON THE DATA PLANE: DegradedReason feeds Status().Healthy,
// FilterPool drops unhealthy workers from its serving set, and markDegraded is
// what triggers a respawn. Without this split, a meta query that timed out on
// its own 15s schedule could take a perfectly good detector process out of
// rotation and restart it — a side-car killing the main path, which is the
// failure mode this whole file's mechanism must not introduce.
//
// SCOPE (learned by writing this): only the reply timeout is quiet. A WRITE
// timeout still tears the session down and degrades the child even for a poll,
// because a half-written frame leaves the byte stream unparseable for every
// caller. That is correct: a child that has not drained stdin for the poll's
// full 5s budget is failing every concurrent Detect anyway, so an earlier
// self-heal is a benefit, not a regression.
func TestContentVersionPoll_ReplyTimeoutStaysQuiet(t *testing.T) {
	h := drainingChild(t, "quiet-poll")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := h.listPacks(ctx, false) // markOnErr=false → the background poll
	if err == nil || errors.Is(err, errWriteTimeout) {
		t.Fatalf("expected a reply timeout, got %v", err)
	}
	if reason := h.Status().DegradedReason; reason != "" {
		t.Errorf("the background poll relabelled a healthy child: DegradedReason=%q", reason)
	}
	if !h.Status().Healthy {
		t.Error("the background poll must not take a healthy child out of the pool's serving set")
	}

	// The operator-initiated path is deliberately the opposite: someone asked a
	// direct question, got no answer, and that IS a health signal about this child.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if _, err := h.listPacks(ctx2, true); err == nil {
		t.Fatal("expected the operator query to fail")
	}
	if reason := h.Status().DegradedReason; !strings.Contains(reason, "listpacks_failed") {
		t.Errorf("an operator-initiated ListPacks failure must be recorded, got %q", reason)
	}
}

// A poll that times out must publish "unknown" rather than keep the last good
// token — the fail-safe half, driven end to end through refreshContentVersion
// on a live pipe.
func TestRefreshContentVersion_TimeoutClearsTokenWithoutDegrading(t *testing.T) {
	h := drainingChild(t, "blind-poll")
	good := "packs-v1"
	h.contentVersion.Store(&good)

	// refreshContentVersion budgets itself (contentVersionPollTimeout, 5s); drive
	// the same two production functions with a tight deadline instead of waiting
	// it out. publishContentVersion is the real publish rule, not a restatement.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	report, err := h.listPacks(ctx, false)
	if err == nil {
		t.Fatal("expected the poll to time out")
	}
	h.publishContentVersion(report, err)

	if v, ok := h.ContentVersion(); ok {
		t.Errorf("a timed-out poll must clear the token, got %q", v)
	}
	if !h.Status().Healthy {
		t.Error("...but must leave the child serving")
	}
}

// TestContentVersionPoll_NeverDrivesChildLifecycle is the regression fence for a
// bug this very mechanism introduced on 2026-08-13 and that only surfaced as a
// ~50% flake in an UNRELATED test (TestChildHook_RestartRecovers).
//
// roundtrip's first act on a degraded hook is `go h.lazyRecover()` — a
// background respawn. A poll that reached roundtrip therefore inherited it, and
// a 15s observability timer silently became a restart trigger: it raced
// operator-initiated restarts (killing a child that had just been handed a
// request, which then never answered), and it changed a broken child's respawn
// cadence from "when a request arrives" to "every 15s forever", even on an idle
// proxy.
//
// lastRecoverAt is the observable: lazyRecover stamps it before restarting, so a
// zero value proves no respawn was attempted. Asserted without a child process
// on purpose — the guard must hold before any IPC is reachable.
func TestContentVersionPoll_NeverDrivesChildLifecycle(t *testing.T) {
	h := newUnstartedWorker(t, "no-lifecycle")
	h.markDegraded("pretend the child crashed")
	if got := h.lastRecoverAt.Load(); got != 0 {
		t.Fatalf("precondition: no recovery attempted yet, got %d", got)
	}

	h.refreshContentVersion()

	// lazyRecover is kicked off with `go`, so absence has to be observed over a
	// window rather than at an instant — checking immediately would pass even with
	// the guard removed, which is how a fence becomes decorative. 300ms is ~5
	// orders of magnitude more than the goroutine needs to be scheduled and stamp
	// the field; verified to go red when the guard is deleted.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if h.lastRecoverAt.Load() != 0 {
			t.Fatal("the content-version poll triggered a child respawn. It must OBSERVE, never DRIVE: " +
				"the child's lifecycle belongs to Detect's self-heal path and the supervisor, and a poll-driven " +
				"restart races them and respawns a broken child every 15s on an idle proxy.")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := h.ContentVersion(); ok {
		t.Error("a degraded child must report an unknown content set")
	}
	if reason := h.Status().DegradedReason; reason != "pretend the child crashed" {
		t.Errorf("the poll overwrote the real degrade reason: %q", reason)
	}
}
