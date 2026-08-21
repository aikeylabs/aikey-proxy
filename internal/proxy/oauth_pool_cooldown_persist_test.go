package proxy

import (
	"os"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// ── cross-restart cooldown persistence (§S4, 2026-07-04 self-heal) ──────────
// Enhancement, NEVER a dependency (owner constraint): a missing / corrupt /
// unreadable state file must fall back to an empty store; the data path never
// blocks on it. 能红: drop hydrateFromFile from newPoolCooldownStore and the
// restart test fails; drop the corrupt-fallback and the corrupt test panics.

func TestPoolCooldown_PersistAndHydrateAcrossRestart(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())

	s1 := newPoolCooldownStore()
	until := time.Now().Add(30 * time.Minute)
	s1.mark("acc-cooled", until)
	s1.flushPersistence()
	path, _ := poolCooldownPath()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("mark must persist the state file: %v", err)
	}

	// "Restart": a fresh store hydrates the same skip view.
	s2 := newPoolCooldownStore()
	skip := s2.skipSet()
	if !skip["acc-cooled"] {
		t.Fatalf("hydrated store must keep cooling acc-cooled, skip=%v", skip)
	}
}

func TestPoolCooldown_ErrorCauseSurvivesRestart(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())

	s1 := newPoolCooldownStore()
	s1.markWithState("acc-egress", time.Now().Add(30*time.Minute), PoolAccountRouteState{
		Status:    poolRouteUpstreamUnavailable,
		ErrorCode: observability.ErrCodeAccountEgressProxy,
	})
	s1.flushPersistence()

	// "Restart": routing and its public failure reason must hydrate together;
	// otherwise the first post-restart request regresses to a fake quota 429.
	s2 := newPoolCooldownStore()
	state, ok := s2.routeStateSnapshot()["acc-egress"]
	if !ok {
		t.Fatal("hydrated store must retain the active egress cooldown")
	}
	if state.Status != poolRouteUpstreamUnavailable || state.ErrorCode != observability.ErrCodeAccountEgressProxy {
		t.Fatalf("hydrated cooldown lost its cause: %+v", state)
	}
}

func TestPoolCooldown_ExpiredEntriesNotHydrated(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())

	s1 := newPoolCooldownStore()
	s1.mark("acc-expired", time.Now().Add(50*time.Millisecond))
	s1.flushPersistence()
	time.Sleep(80 * time.Millisecond)

	s2 := newPoolCooldownStore()
	if skip := s2.skipSet(); skip != nil {
		t.Fatalf("expired persisted entries must not hydrate, skip=%v", skip)
	}
}

func TestPoolCooldown_CorruptOrMissingFileFallsBackEmpty(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())

	// Missing file → empty store, no error.
	s := newPoolCooldownStore()
	if skip := s.skipSet(); skip != nil {
		t.Fatalf("missing file must yield empty store, skip=%v", skip)
	}

	// Corrupt file → empty store (fallback), and the store still WORKS.
	path, _ := poolCooldownPath()
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := newPoolCooldownStore()
	if skip := s2.skipSet(); skip != nil {
		t.Fatalf("corrupt file must yield empty store, skip=%v", skip)
	}
	s2.mark("acc-new", time.Now().Add(time.Minute))
	s2.flushPersistence()
	if !s2.skipSet()["acc-new"] {
		t.Fatal("store must keep working after a corrupt-file fallback")
	}
	// The next mark overwrote the corrupt file with valid content.
	s3 := newPoolCooldownStore()
	if !s3.skipSet()["acc-new"] {
		t.Fatal("corrupt file must be replaced by the next persist")
	}
}

func TestPoolCooldown_AllExpiredRemovesFile(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())

	s := newPoolCooldownStore()
	s.mark("acc-1", time.Now().Add(40*time.Millisecond))
	s.flushPersistence()
	time.Sleep(60 * time.Millisecond)
	// skipSet prunes the lapsed entry; the NEXT mark persists the (now empty →
	// file removed on a later persist) view. Trigger a persist via a mark that
	// immediately lapses.
	_ = s.skipSet()
	s.mu.Lock()
	s.persistLocked()
	s.mu.Unlock()
	s.flushPersistence()
	path, _ := poolCooldownPath()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("all-expired persist must remove the state file, stat err=%v", err)
	}
}

func TestPoolCooldown_OlderBackgroundSnapshotCannotOverwriteNewerFlush(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	s := newPoolCooldownStore()
	until := time.Now().Add(time.Hour).Unix()

	s.writePersistenceSnapshot(poolCooldownFileBody{
		Accounts:  map[string]int64{"acc-new": until},
		WrittenAt: time.Now().UnixMilli(),
	}, 2)
	// Model a timer that captured revision 1 before shutdown, but only acquired
	// persistIO after the revision-2 shutdown flush completed.
	s.writePersistenceSnapshot(poolCooldownFileBody{
		Accounts:  map[string]int64{"acc-stale": until},
		WrittenAt: time.Now().UnixMilli(),
	}, 1)

	restarted := newPoolCooldownStore()
	skip := restarted.skipSet()
	if !skip["acc-new"] || skip["acc-stale"] {
		t.Fatalf("stale writer replaced newer shutdown snapshot: %v", skip)
	}
}
