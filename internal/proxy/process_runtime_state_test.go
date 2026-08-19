package proxy

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func TestOAuthPoolRuntimeStateIsSharedAcrossProxyGenerations(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	runtime := NewOAuthPoolRuntimeState()
	t.Cleanup(func() { _ = runtime.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	oldProxy := NewWithOAuthPoolRuntime(nil, nil, nil, nil, ctx, runtime)
	newProxy := NewWithOAuthPoolRuntime(nil, nil, nil, nil, ctx, runtime)

	if oldProxy.poolCooldown != newProxy.poolCooldown || oldProxy.poolCooldown != runtime.poolCooldown {
		t.Fatal("hot-reload generations do not share one process cooldown/tombstone store")
	}
	if oldProxy.signalReporter != newProxy.signalReporter || oldProxy.signalReporter != runtime.signalReporter {
		t.Fatal("hot-reload generations do not share one process signal reporter/outbox")
	}

	oldProxy.poolCooldown.mark("account-late-429", time.Now().Add(time.Minute))
	if !newProxy.CooldownSkipSet()["account-late-429"] {
		t.Fatal("active generation cannot see a cooldown learned by the draining generation")
	}

	oldProxy.poolCooldown.markAuthFailedToken("group-1", "seat-1", "account-late-401", "fingerprint-v1")
	failures := newProxy.AuthFailureRouteSnapshot()
	if len(failures) != 1 || failures[0].AccountID != "account-late-401" {
		t.Fatalf("active generation cannot see exact-token tombstone: %+v", failures)
	}
	if got := newProxy.poolCooldown.authFailedTokens[authFailureRouteKey("group-1", "seat-1", "account-late-401")]; got != "fingerprint-v1" {
		t.Fatalf("active generation tombstone fingerprint = %q, want fingerprint-v1", got)
	}

	oldProxy.signalReporter.enqueueAuthFailure("credential-1", "group-1", "seat-1", "fingerprint-v1")
	got := waitForAuthFailureSnapshot(t, newProxy.signalReporter, 1)
	if got[0].TokenFingerprint != "fingerprint-v1" {
		t.Fatalf("active generation cannot see draining generation's durable signal: %+v", got)
	}
}

func TestGenerationStopDoesNotCloseProcessSignalReporter(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	runtime := NewOAuthPoolRuntimeState()

	p := NewWithOAuthPoolRuntime(nil, nil, nil, nil, context.Background(), runtime)
	p.StopSignalReporting()
	select {
	case <-runtime.signalReporter.stop:
		t.Fatal("generation-level stop closed the process-owned signal reporter")
	default:
	}

	if err := runtime.Close(); err != nil {
		t.Fatalf("close process runtime: %v", err)
	}
	select {
	case <-runtime.signalReporter.stop:
	case <-time.After(time.Second):
		t.Fatal("process runtime close did not stop the signal reporter")
	}
}

func TestProcessRuntimeCloseDrainsAuthFailureToJournal(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	runtime := NewOAuthPoolRuntimeState()
	runtime.signalReporter.enqueueAuthFailure("credential-1", "group-1", "seat-1", "fingerprint-v1")

	// Close immediately: the request-side handoff may still be buffered. The
	// process lifecycle owner must wait until the reporter has durably drained
	// it, otherwise a restart directly after a 401 can forget the revocation.
	if err := runtime.Close(); err != nil {
		t.Fatalf("close process runtime: %v", err)
	}
	path, err := signalAuthFailurePath()
	if err != nil {
		t.Fatalf("resolve auth-failure journal: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read auth-failure journal after close: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"token_fingerprint":"fingerprint-v1"`)) {
		t.Fatalf("shutdown journal omitted queued auth failure: %s", raw)
	}
}

func TestProcessSignalReporterReconfiguresWithoutLosingPendingAuthFailure(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	runtime := NewOAuthPoolRuntimeState()
	t.Cleanup(func() { _ = runtime.Close() })

	oldProxy := NewWithOAuthPoolRuntime(nil, nil, nil, nil, context.Background(), runtime)
	newProxy := NewWithOAuthPoolRuntime(nil, nil, nil, nil, context.Background(), runtime)
	oldProxy.SetDeliveryIntegrity("worker-1", nil)
	newProxy.SetDeliveryIntegrity("worker-1", nil)

	oldProxy.EnableSignalReporting("http://old-control.invalid", func(context.Context) (string, error) { return "old", nil })
	oldProxy.signalReporter.enqueueAuthFailure("credential-1", "group-1", "seat-1", "fingerprint-v1")
	newProxy.EnableSignalReporting("http://new-control.invalid", func(context.Context) (string, error) { return "new", nil })

	got := waitForAuthFailureSnapshot(t, newProxy.signalReporter, 1)
	if got[0].TokenFingerprint != "fingerprint-v1" {
		t.Fatalf("reporter reconfiguration lost pending auth failure: %+v", got)
	}
	newProxy.signalReporter.configMu.RLock()
	endpoint := newProxy.signalReporter.url
	newProxy.signalReporter.configMu.RUnlock()
	if endpoint != "http://new-control.invalid/accounts/me/signals" {
		t.Fatalf("reporter endpoint = %q, want activated generation endpoint", endpoint)
	}
}

func waitForAuthFailureSnapshot(t *testing.T, reporter *signalReporter, want int) []authFailureSample {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got := reporter.snapshotAuthFailures()
		if len(got) == want {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	got := reporter.snapshotAuthFailures()
	t.Fatalf("auth-failure snapshot length = %d, want %d: %+v", len(got), want, got)
	return nil
}

func TestDormantProcessSignalReporterRetainsPendingWithoutFalseFailure(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	runtime := NewOAuthPoolRuntimeState()
	t.Cleanup(func() { _ = runtime.Close() })

	runtime.signalReporter.enqueueAuthFailure("credential-1", "group-1", "seat-1", "fingerprint-v1")
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		health := runtime.signalReporter.healthSnapshot()
		if health.PendingSignals == 1 {
			if health.Status != "disabled" || health.ConsecutiveFailures != 0 {
				t.Fatalf("dormant reporter health = %+v, want disabled pending without upload failure", health)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("dormant reporter did not expose retained pending work: %+v", runtime.signalReporter.healthSnapshot())
}
