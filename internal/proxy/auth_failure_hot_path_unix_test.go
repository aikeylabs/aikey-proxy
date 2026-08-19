//go:build darwin || linux || freebsd || netbsd || openbsd

package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestAuthFailureSignalPersistenceCannotBlockRequestPath is the deterministic
// failure witness for the 300-member 401 storm regression. A FIFO at the legacy
// snapshot temp path makes any request-path os.WriteFile block forever. The
// serving hook must still return promptly because persistence belongs to the
// reporter's bounded single-writer loop.
func TestAuthFailureSignalPersistenceCannotBlockRequestPath(t *testing.T) {
	runDir := t.TempDir()
	t.Setenv("AIKEY_RUN_DIR", runDir)
	legacyTemp := filepath.Join(runDir, signalAuthFailureFilename+".tmp")
	if err := unix.Mkfifo(legacyTemp, 0o600); err != nil {
		t.Fatalf("create blocked legacy signal snapshot: %v", err)
	}

	r := newDormantSignalReporter(slog.Default())
	defer r.Close()
	done := make(chan struct{})
	go func() {
		r.enqueueAuthFailure("credential-1", "group-1", "seat-1", "fingerprint-1")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("hard-revoke signal persistence blocked the request path on filesystem I/O")
	}
	deadline := time.Now().Add(time.Second)
	for len(r.snapshotAuthFailures()) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(r.snapshotAuthFailures()) != 1 {
		t.Fatal("background journal writer did not retain the hard-revoke before test cleanup")
	}
}

// TestAuthFailureRoutingPersistenceCannotBlockRequestPath protects the sibling
// local tombstone write performed by the same hard-revoke response. Fixing only
// the signal outbox would leave the request blocked on pool-cooldown.json.
func TestAuthFailureRoutingPersistenceCannotBlockRequestPath(t *testing.T) {
	runDir := t.TempDir()
	t.Setenv("AIKEY_RUN_DIR", runDir)
	legacyTemp := filepath.Join(runDir, poolCooldownFilename+".tmp")
	if err := unix.Mkfifo(legacyTemp, 0o600); err != nil {
		t.Fatalf("create blocked legacy cooldown snapshot: %v", err)
	}

	store := newPoolCooldownStore()
	done := make(chan struct{})
	go func() {
		store.markAuthFailedToken("group-1", "seat-1", "account-1", "fingerprint-1")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("hard-revoke routing persistence blocked the request path on filesystem I/O")
	}

	deadline := time.Now().Add(time.Second)
	for {
		store.mu.Lock()
		writing := store.persistWriting
		store.mu.Unlock()
		if writing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background cooldown writer did not reach the blocked FIFO")
		}
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 300; i++ {
		store.markAuthFailedToken("group-1", fmt.Sprintf("seat-%03d", i), "account-1", fmt.Sprintf("fingerprint-%03d", i))
	}
	store.mu.Lock()
	queuedWriter := store.persistTimer != nil
	store.mu.Unlock()
	if queuedWriter {
		t.Fatal("blocked cooldown disk write spawned another writer during the 401 burst")
	}

	// Release the intentionally blocked writer. Its atomic rename moves the FIFO
	// to the final path, so the one coalesced dirty follow-up creates a regular
	// temp file and completes normally. A regression that creates more work will
	// leave persistWriting/persistTimer non-idle below.
	readerDone := make(chan error, 1)
	go func() {
		f, err := os.Open(legacyTemp)
		if err != nil {
			readerDone <- err
			return
		}
		_, copyErr := io.Copy(io.Discard, f)
		closeErr := f.Close()
		if copyErr != nil {
			readerDone <- copyErr
			return
		}
		readerDone <- closeErr
	}()
	select {
	case err := <-readerDone:
		if err != nil {
			t.Fatalf("release blocked cooldown writer: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cooldown persistence did not release the single blocked writer")
	}
	deadline = time.Now().Add(time.Second)
	for {
		store.mu.Lock()
		idle := !store.persistWriting && store.persistTimer == nil
		store.mu.Unlock()
		if idle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cooldown persistence did not return to one-writer idle state")
		}
		time.Sleep(time.Millisecond)
	}
}
