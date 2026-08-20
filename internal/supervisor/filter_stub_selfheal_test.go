package supervisor

// Fence for the fail-loud 501 self-heal (bugfix 2026-08-20
// detector-binary-swap / change_seq gap).
//
// THE GAP, in one line: the latch's cause is a FILE (declared filter binary
// missing) but its only cure was a VAULT DECLARATION change — and laying the
// binary down (`aikey app install`) writes no vault row, so change_seq never
// advanced, no reload was triggered, and the machine kept refusing ALL traffic
// until someone restarted the proxy. Observed on staging 2026-08-20; the code
// even carried a comment claiming it "self-heals once aikey app install lays
// the binary down", which was false on exactly this path.

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy"
)

// latchedSupervisor builds a supervisor whose active generation is refusing
// traffic over a missing binary, with appsDir pointed at a temp tree.
func latchedSupervisor(t *testing.T, reason string) (*Supervisor, string, *proxy.Proxy) {
	t.Helper()
	home := t.TempDir()
	// appsDir() derives <home>/.aikey/apps from the vault path
	// <home>/.aikey/data/vault.db — mirror that layout exactly.
	dataDir := filepath.Join(home, ".aikey", "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	s := &Supervisor{cfg: &config.Config{}, ctx: context.Background()}
	s.cfg.Vault.Path = filepath.Join(dataDir, "vault.db")

	p := &proxy.Proxy{}
	slug := "ai-compliance-detector"
	p.SetFilterStub501(&proxy.FilterStubCause{
		Reason: reason, Slug: slug,
		ExpectedPath: filepath.Join(s.appsDir(), slug, "bin", appBinaryFileName(slug)),
	})
	s.active.Store(&generation{proxy: p})
	return s, slug, p
}

func layBinary(t *testing.T, s *Supervisor, slug string) {
	t.Helper()
	dir := filepath.Join(s.appsDir(), slug, "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, appBinaryFileName(slug)), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}
}

// The core contract: binary appears → reload happens, with no vault change of
// any kind. Before the fix nothing polled this and the reload never came.
func TestFilterStubSelfHeal_ReloadsWhenBinaryAppears(t *testing.T) {
	for _, reason := range []string{
		proxy.FilterStubReasonBinaryMissing,
		proxy.FilterStubReasonMandateNotInstalled,
	} {
		t.Run(reason, func(t *testing.T) {
			s, slug, _ := latchedSupervisor(t, reason)

			reloads := 0
			reload := func(context.Context) error { reloads++; return nil }

			// Still missing: must NOT reload (a reload storm every 5s while a
			// machine legitimately has no detector would be its own incident).
			s.healFilterStubWithReload(reload)
			if reloads != 0 {
				t.Fatalf("reloaded %d time(s) while the binary was still missing", reloads)
			}

			layBinary(t, s, slug)
			s.healFilterStubWithReload(reload)
			if reloads != 1 {
				t.Fatalf("binary appeared but reload count = %d, want 1 — the 501 would "+
					"outlive the fix until a manual restart", reloads)
			}
		})
	}
}

// A healthy proxy must cost nothing: no stat, no reload, ever.
func TestFilterStubSelfHeal_NoOpWhenServingNormally(t *testing.T) {
	s, slug, p := latchedSupervisor(t, proxy.FilterStubReasonBinaryMissing)
	p.SetFilterStub501(nil) // serving normally
	layBinary(t, s, slug)   // and the binary exists, so only the guard can stop a reload

	reloads := 0
	s.healFilterStubWithReload(func(context.Context) error { reloads++; return nil })
	if reloads != 0 {
		t.Fatalf("reloaded %d time(s) on a healthy proxy", reloads)
	}
}

// A spawn failure must NOT be retried on a timer: the child just failed to
// start, and re-spawning it every five seconds forever is a crash loop. Its
// cure (reinstall / fix the binary) goes through a declaration change or a
// restart, both of which already rebuild the generation.
func TestFilterStubSelfHeal_SpawnFailureIsNotRetriedOnATimer(t *testing.T) {
	s, slug, _ := latchedSupervisor(t, proxy.FilterStubReasonSpawnFailed)
	layBinary(t, s, slug)

	reloads := 0
	s.healFilterStubWithReload(func(context.Context) error { reloads++; return nil })
	if reloads != 0 {
		t.Fatalf("spawn-failure latch reloaded %d time(s) — that is a crash loop", reloads)
	}
}

// 🔴 WIRING fence — the one the others cannot replace.
//
// The three tests above call healFilterStubWithReload directly, so deleting or
// reordering its CALL SITE in syncManagedKeys would leave every one of them
// green while the bug walked straight back in. This test enters through the
// real tick entry point instead and asserts the heal actually ran. Placement
// matters as much as presence: the heal must sit BEFORE syncManagedKeys' early
// return on an unchanged change_seq, because "binary appeared" advances no
// vault sequence — that early return is exactly what swallowed the recovery.
// The vault path here does not exist, which forces that early return and so
// pins the ordering: a heal placed after it emits nothing.
func TestSyncManagedKeys_RunsTheFilterStubHeal(t *testing.T) {
	s, slug, _ := latchedSupervisor(t, proxy.FilterStubReasonBinaryMissing)
	layBinary(t, s, slug)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	// Reload will fail on this bare supervisor; that is fine and expected —
	// the assertion is that the heal was REACHED and attempted.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("syncManagedKeys panicked while healing: %v", r)
			}
		}()
		s.syncManagedKeys()
	}()

	if !strings.Contains(buf.String(), "proxy.filter_stub_healing") {
		t.Fatalf("syncManagedKeys did not run the fail-loud 501 heal — a machine whose "+
			"binary arrived later stays 501 until a manual restart.\nlogs:\n%s", buf.String())
	}
}
