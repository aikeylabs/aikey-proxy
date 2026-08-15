package apphook

// status_external_readability_test.go — the health signals a ChildHook / FilterPool
// must be able to hand to an EXTERNAL reader.
//
// WHY THIS SUITE EXISTS (review findings B5 / B36 / B6, 2026-08-13).
// apphook.Status already held Healthy / DegradedReason / RestartCount and every
// one of them went to a slog line and nowhere else — the struct did not even
// have json tags. So the write-timeout fix landed a NEW and important degraded
// cause (`write_timeout`) with no external出口, and `ak doctor` had to infer
// everything from a single `available:false` on /admin/compliance/packs, which
// cannot tell "the child wedged mid-write" from "the child was never started".
//
// Three properties are pinned here, one per way the previous shape lied:
//
//  1. DegradedReason survives to a READER and discriminates the two causes.
//  2. FilterPool.Status()'s aggregate is NOT a health verdict — WorkerStatuses
//     is — because a 2-worker pool with one dead process reports Healthy=true
//     while round-robin keeps feeding the corpse (B39).
//  3. "I cannot state my ruleset" carries WHY, because the remedy differs:
//     restart (child_degraded) vs upgrade the detector (unsupported_op_list_packs).
//
// The live wedge (real process, real OS pipe back-pressure) lives in
// childhook_write_deadline_test.go; this suite covers the projection.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1. DegradedReason reaches a reader, and discriminates wedged from never-started
// ─────────────────────────────────────────────────────────────────────────────

// TestStatus_WedgedAndNeverStartedAreDistinguishable is the B5 core: before this,
// both states presented to the outside world as one undifferentiated
// `available:false`.
func TestStatus_WedgedAndNeverStartedAreDistinguishable(t *testing.T) {
	neverStarted := newUnstartedWorker(t, "never-started")
	wedged := newUnstartedWorker(t, "wedged")
	// The production raise site: writeFrame calls exactly this on a write deadline
	// (childhook.go). Using the constant, not the literal, is the point — a
	// renamed cause must break this test rather than silently change what doctor
	// branches on.
	wedged.markDegraded(DegradeReasonWriteTimeout)

	nsReason := neverStarted.Status().DegradedReason
	wReason := wedged.Status().DegradedReason

	if nsReason != DegradeReasonNotStarted {
		t.Errorf("a hook that was never started must report %q, got %q", DegradeReasonNotStarted, nsReason)
	}
	if wReason != DegradeReasonWriteTimeout {
		t.Errorf("a wedged hook must report %q, got %q", DegradeReasonWriteTimeout, wReason)
	}
	if nsReason == wReason {
		t.Fatal("wedged and never-started collapsed to the same reason — that IS the bug (B5): " +
			"the operator cannot tell 'restart the proxy' from 'the detector never spawned'")
	}
	// Both are unhealthy: the discrimination must not come at the cost of one of
	// them reading as fine.
	if neverStarted.Status().Healthy || wedged.Status().Healthy {
		t.Error("neither state may report Healthy")
	}
}

// Status() must return a snapshot the caller cannot corrupt for everyone else —
// it is now handed to an HTTP encoder on the diagnostics path.
func TestStatus_ReturnsAnIndependentSnapshot(t *testing.T) {
	h := newUnstartedWorker(t, "snapshot")
	first := h.Status()
	first.DegradedReason = "mutated by a reader"
	if got := h.Status().DegradedReason; got != DegradeReasonNotStarted {
		t.Errorf("a reader mutated shared hook state: got %q, want %q", got, DegradeReasonNotStarted)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. The pool's aggregate is not a health verdict
// ─────────────────────────────────────────────────────────────────────────────

// TestWorkerStatuses_PoolExposesEachWorkerBehindTheFalseGreen is the B39/B5
// intersection, and the core judgment of this change.
//
// Measured during review: a 2-worker pool with one worker down reported
// Status().Healthy = true and "1/2 workers healthy", while 10 Detect calls
// produced 5 fail-opens — i.e. half of all content forwarded un-inspected while
// the health surface said "up". This test pins BOTH halves: the aggregate still
// says keep-serving (that is correct for the dispatcher and must not change),
// and the per-worker enumeration exposes what the aggregate hides.
func TestWorkerStatuses_PoolExposesEachWorkerBehindTheFalseGreen(t *testing.T) {
	alive, dead := newUnstartedWorker(t, "alive"), newUnstartedWorker(t, "dead")
	setContentVersion(alive, "packs-v1")
	dead.markDegraded(DegradeReasonWriteTimeout)
	pool := NewFilterPool("p", []*ChildHook{alive, dead})

	// The aggregate: unchanged on purpose. It answers "should the pool keep
	// serving?" and the answer is yes.
	if agg := pool.Status(); !agg.Healthy {
		t.Fatalf("the dispatch-facing aggregate must stay 'keep serving' with 1/2 up, got %+v", agg)
	}

	statuses := WorkerStatuses(pool)
	if len(statuses) != 2 {
		t.Fatalf("WorkerStatuses must expose every unit: got %d, want 2", len(statuses))
	}
	if !statuses[0].Healthy {
		t.Error("worker 0 is up and must be reported up")
	}
	if statuses[1].Healthy {
		t.Fatal("worker 1 is DOWN but the enumeration reported it healthy — this is the exact " +
			"false green the endpoint exists to prevent")
	}
	if statuses[1].DegradedReason != DegradeReasonWriteTimeout {
		t.Errorf("the dead worker's cause must survive to the reader: got %q, want %q",
			statuses[1].DegradedReason, DegradeReasonWriteTimeout)
	}
	// Dispatch order is the whole reason an operator can translate "worker 1 is
	// down" into "≈half my requests fail open".
	if statuses[0].ContentVersion != "packs-v1" {
		t.Errorf("WorkerStatuses must preserve dispatch order (pick() round-robins this slice); "+
			"worker 0 reported content version %q", statuses[0].ContentVersion)
	}
}

// A hook that is a single unit must come back as a pool of one, so no reader
// needs an "is it a pool?" branch (that branch is where the pool case gets lost).
func TestWorkerStatuses_SingleHookIsAPoolOfOne(t *testing.T) {
	h := newUnstartedWorker(t, "solo")
	got := WorkerStatuses(h)
	if len(got) != 1 || got[0].DegradedReason != DegradeReasonNotStarted {
		t.Fatalf("single hook must yield exactly its own Status: %+v", got)
	}
	// Disabled is a real production Hook (the no-op slot), not a test double.
	if got := WorkerStatuses(NewDisabled("none")); len(got) != 1 || !got[0].Healthy {
		t.Fatalf("Disabled must yield one healthy unit: %+v", got)
	}
	if got := WorkerStatuses(nil); got != nil {
		t.Errorf("a nil hook is 'no filter installed', not a fault: %+v", got)
	}
}

// TestFence_WorkerStatusesHasExactlyOneCallerFacingExit keeps MultiUnit behind
// the sanctioned accessor, matching the posture CacheEpoch already has (see
// contentversion_fence_test.go for why a source scan and not a behavior test).
// A reader that type-asserts MultiUnit itself has to re-derive the pool-of-one
// fallback, and that is precisely the branch that gets forgotten — a health
// surface that silently skips pools reports M=1 for a 4-worker Production node.
func TestFence_WorkerStatusesHasExactlyOneCallerFacingExit(t *testing.T) {
	for _, file := range packageSourceFiles(t) {
		if filepath.Base(file) == "apphook.go" {
			continue // the definition site
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.Contains(string(src), ".(MultiUnit)") {
			t.Errorf("%s type-asserts MultiUnit directly; go through apphook.WorkerStatuses instead "+
				"(it owns the pool-of-one fallback)", filepath.Base(file))
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. "I cannot state my ruleset" carries WHY (B6: restart vs upgrade)
// ─────────────────────────────────────────────────────────────────────────────

// TestContentVersionReason_DiscriminatesRestartFromUpgrade pins the mapping that
// decides which remedy `ak doctor` prints. Getting it wrong is worse than saying
// nothing: telling an operator to restart a healthy-but-old detector sends them
// round a loop that cannot terminate.
func TestContentVersionReason_DiscriminatesRestartFromUpgrade(t *testing.T) {
	cases := []struct {
		name       string
		arrange    func(h *ChildHook)
		wantToken  string
		wantReason string
	}{{
		name:       "never polled — self-clearing, not a fault",
		arrange:    func(h *ChildHook) { setHealthyButBlind(h) },
		wantReason: ContentVersionReasonPollPending,
	}, {
		name: "child degraded — remedy is a RESTART",
		arrange: func(h *ChildHook) {
			h.markDegraded(DegradeReasonWriteTimeout)
			h.publishContentVersion(nil, errDegraded)
		},
		wantReason: ContentVersionReasonChildDegraded,
	}, {
		name: "alive but answers op=ListPacks with nothing — remedy is an UPGRADE",
		arrange: func(h *ChildHook) {
			// listPacks maps "child does not implement op=4 → empty report" onto
			// ErrPacksUnavailable; this is that value, not a stand-in for it.
			setHealthyButBlind(h)
			h.publishContentVersion(nil, ErrPacksUnavailable)
		},
		wantReason: ContentVersionReasonUnsupported,
	}, {
		name: "alive, poll errored for some other reason — transient",
		arrange: func(h *ChildHook) {
			setHealthyButBlind(h)
			h.publishContentVersion(nil, errors.New("ipc read: connection reset"))
		},
		wantReason: ContentVersionReasonPollFailed,
	}, {
		name: "knows its ruleset — no reason at all",
		arrange: func(h *ChildHook) {
			h.degraded.Store(false)
			h.status.Store(&Status{Healthy: true})
			h.publishContentVersion([]byte(`{"packs":[{"id":"p1"}]}`), nil)
		},
		wantToken: "", // asserted as "non-empty" below; the digest itself is opaque
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUnstartedWorker(t, "reason")
			tc.arrange(h)
			st := h.Status()

			if tc.wantReason == "" {
				if st.ContentVersion == "" {
					t.Fatalf("a child that just reported its content set must publish a token, got %+v", st)
				}
				if st.ContentVersionReason != "" {
					t.Errorf("a known content set must carry no reason, got %q", st.ContentVersionReason)
				}
				// The cacheability contract and the health projection are derived from
				// ONE function; they must never disagree about this child.
				if v, ok := h.ContentVersion(); !ok || v != st.ContentVersion {
					t.Errorf("ContentVersion() and Status() disagree: (%q,%v) vs %q", v, ok, st.ContentVersion)
				}
				return
			}

			if st.ContentVersion != "" {
				t.Errorf("an unknown content set must not publish a token, got %q", st.ContentVersion)
			}
			if st.ContentVersionReason != tc.wantReason {
				t.Errorf("reason = %q, want %q", st.ContentVersionReason, tc.wantReason)
			}
			if _, ok := h.ContentVersion(); ok {
				t.Error("an unknown content set must report NOT cacheable — fail-safe, not fail-stale")
			}
		})
	}
}

// A child that degrades DURING a poll must not be labeled "too old": listPacks
// converts errDegraded into the same ErrPacksUnavailable it returns for an empty
// report, so the classifier re-reads the degraded flag. Mislabelling here hands
// an operator an upgrade instruction for what is actually a crash.
func TestContentVersionReason_MidPollDegradeIsNotMisreadAsAnOldBuild(t *testing.T) {
	h := newUnstartedWorker(t, "mid-poll")
	setHealthyButBlind(h) // poll starts against a healthy child …
	h.markDegraded("crash")
	// … and the roundtrip comes back as ErrPacksUnavailable after it died.
	h.publishContentVersion(nil, ErrPacksUnavailable)
	if got := h.Status().ContentVersionReason; got != ContentVersionReasonChildDegraded {
		t.Errorf("reason = %q, want %q — a crashed child must not be sent for an upgrade",
			got, ContentVersionReasonChildDegraded)
	}
}

// Recovery must clear the reason, not leave a stale one next to a fresh token —
// a health surface that latches is a health surface operators stop believing.
func TestContentVersionReason_ClearsOnRecovery(t *testing.T) {
	h := newUnstartedWorker(t, "recovers")
	setHealthyButBlind(h)
	h.publishContentVersion(nil, ErrPacksUnavailable)
	if h.Status().ContentVersionReason != ContentVersionReasonUnsupported {
		t.Fatal("arrange failed")
	}
	h.publishContentVersion([]byte(`{"packs":[]}`), nil)
	st := h.Status()
	if st.ContentVersion == "" || st.ContentVersionReason != "" {
		t.Errorf("recovery must publish a token and drop the reason, got %+v", st)
	}
}

// The pool's per-worker projection is what lets a reader say WHY the whole pool
// went uncacheable: one healthy-but-blind worker suspends caching pool-wide
// (contentversion.go's fail-safe), and only the per-worker reason says whether
// that worker needs a restart or an upgrade.
func TestWorkerStatuses_PoolCarriesEachWorkersContentVersionReason(t *testing.T) {
	good, old := newUnstartedWorker(t, "good"), newUnstartedWorker(t, "old")
	setContentVersion(good, "packs-v1")
	setHealthyButBlind(old)
	old.publishContentVersion(nil, ErrPacksUnavailable)
	pool := NewFilterPool("p", []*ChildHook{good, old})

	if _, cacheable := CacheEpoch(pool); cacheable {
		t.Fatal("a serving worker with an unknown ruleset must suspend caching pool-wide")
	}
	sts := WorkerStatuses(pool)
	if sts[0].ContentVersion != "packs-v1" || sts[0].ContentVersionReason != "" {
		t.Errorf("the healthy worker's state was lost: %+v", sts[0])
	}
	if sts[1].ContentVersionReason != ContentVersionReasonUnsupported {
		t.Errorf("the blind worker must name its cause so the remedy is decidable: %+v", sts[1])
	}
	// Both workers are HEALTHY here. Without the per-worker reason the operator
	// sees a green pool and an inexplicably cold cache — the B6 shape exactly.
	if !sts[0].Healthy || !sts[1].Healthy {
		t.Fatal("arrange: both workers must be healthy for this to be the B6 shape")
	}
}

// Guard against the projection becoming expensive: Status() is called on the
// request path (the dispatcher reads Version and DegradedReason per request), so
// composing the content-version fields must stay allocation-cheap.
func BenchmarkChildHookStatus(b *testing.B) {
	h := NewChildHook(&ChildHookConfig{Name: "bench", BinaryPath: "/nonexistent", Timeout: time.Second})
	v := "abc123"
	h.degraded.Store(false)
	h.contentVersion.Store(&v)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if s := h.Status(); s.ContentVersion == "" {
			b.Fatal("unexpected")
		}
	}
}
