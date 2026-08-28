package proxy

import (
	"net/http"
	"testing"
)

func TestPoolResetStore_RecordKeepsMaxAndSnapshotIsCopy(t *testing.T) {
	s := newPoolResetStore()
	if s.snapshot() != nil {
		t.Fatal("empty store must snapshot nil")
	}
	s.record("acc-1", ObservedWindowResets{FiveHour: 100, SevenDay: 1000})
	s.record("acc-1", ObservedWindowResets{FiveHour: 50, SevenDay: 500})  // older → ignored independently
	s.record("acc-1", ObservedWindowResets{FiveHour: 200, SevenDay: 900}) // only 5h advances
	s.record("acc-2", ObservedWindowResets{FiveHour: 300})
	s.record("", ObservedWindowResets{FiveHour: 999}) // empty id → ignored
	s.record("acc-x", ObservedWindowResets{})         // non-positive → ignored

	snap := s.snapshot()
	if snap["acc-1"] != (ObservedWindowResets{FiveHour: 200, SevenDay: 1000}) {
		t.Fatalf("acc-1=%+v want independent maxima", snap["acc-1"])
	}
	if snap["acc-2"].FiveHour != 300 {
		t.Fatalf("acc-2=%+v want 5h=300", snap["acc-2"])
	}
	if len(snap) != 2 {
		t.Fatalf("snapshot size=%d want 2 (empty id + zero epoch dropped)", len(snap))
	}

	// snapshot is a copy — mutating it must not affect the store.
	snap["acc-1"] = ObservedWindowResets{FiveHour: 1}
	if s.snapshot()["acc-1"].FiveHour != 200 {
		t.Fatal("snapshot must be a defensive copy")
	}
}

func TestPoolResetStore_ClusterSignalKeepsCredentialAndIndependentMaxima(t *testing.T) {
	s := newPoolResetStore()
	s.recordRoute("acc-1", "cred-1", ObservedWindowResets{FiveHour: 100, SevenDay: 1000})
	s.recordRoute("acc-1", "cred-1", ObservedWindowResets{FiveHour: 200, SevenDay: 900})
	s.recordRoute("acc-2", "cred-1", ObservedWindowResets{FiveHour: 150, SevenDay: 1100})
	s.recordRoute("acc-3", "", ObservedWindowResets{FiveHour: 999})

	got := s.signalSnapshot()
	if len(got) != 1 {
		t.Fatalf("signal snapshot=%+v, want one credential-coalesced item", got)
	}
	if got[0] != (observedWindowResetSample{CredentialID: "cred-1", WindowResetAt: 200, Window7dResetAt: 1100}) {
		t.Fatalf("signal snapshot lost route identity or independent maxima: %+v", got[0])
	}
}

func TestObservedWindowResetEpochsAreIndependent(t *testing.T) {
	h := http.Header{}
	h.Set(hdrReset5h, "1750000500")
	h.Set(hdrReset7d, "1750600000")
	got, ok := observedWindowResetEpochs(h)
	if !ok || got.FiveHour != 1750000500 || got.SevenDay != 1750600000 {
		t.Fatalf("got=%+v ok=%v", got, ok)
	}
}

func TestObservedWindowResetEpochs_UnifiedCannotAdvanceWeekly(t *testing.T) {
	h := http.Header{}
	h.Set(hdrReset, "1750000000")
	got, ok := observedWindowResetEpochs(h)
	if !ok || got.FiveHour != 1750000000 || got.SevenDay != 0 {
		t.Fatalf("ambiguous unified reset must remain 5h-only: got=%+v ok=%v", got, ok)
	}
}

func TestObservedResetEpoch(t *testing.T) {
	// Unified reset preferred.
	h := http.Header{}
	h.Set("anthropic-ratelimit-unified-reset", "1750000000")
	if e, ok := observedResetEpoch(h); !ok || e != 1750000000 {
		t.Fatalf("unified reset: e=%d ok=%v", e, ok)
	}
	// Per-window fallback when unified absent.
	h2 := http.Header{}
	h2.Set("anthropic-ratelimit-unified-5h-reset", "1750000500")
	if e, ok := observedResetEpoch(h2); !ok || e != 1750000500 {
		t.Fatalf("5h reset fallback: e=%d ok=%v", e, ok)
	}
	// No reset header → false.
	if _, ok := observedResetEpoch(http.Header{}); ok {
		t.Fatal("absent reset → false")
	}
	// Garbage → false (not recorded).
	h3 := http.Header{}
	h3.Set("anthropic-ratelimit-unified-reset", "notanum")
	if _, ok := observedResetEpoch(h3); ok {
		t.Fatal("garbage epoch → false")
	}
}
