package proxy

// Regression fence (2026-08-19 lint-blocking bug): compactAuthFailureJournal's
// mkdir→write→rename chain assigned its errors to a SHADOWED `err`, so the
// final failure check was `nil != nil` (govet nilness) and a failed compaction
// was silently swallowed — the journal WARN path never fired. The fence drives
// a real write failure (journal path's parent is a FILE, so MkdirAll fails)
// and asserts the failure reaches the auth-journal WARN counter/log path.

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestCompactAuthFailureJournal_WriteFailureIsNotSwallowed(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	r := looplessSignalReporter()
	r.logger = slog.New(slog.NewTextHandler(&logBuf, nil))
	// Parent of the journal path is a regular FILE → MkdirAll must fail.
	r.authJournalPath = filepath.Join(blocker, "auth-journal.jsonl")
	// One live failure so compaction takes the WRITE path — snapshotAuthFailures
	// reads authFailures, and the empty-set branch (journal Remove) has its own
	// intact WARN path that would make this fence pass vacuously.
	r.authFailures = map[string]authFailureSample{
		"k": {CredentialID: "cred-1"},
	}

	r.compactAuthFailureJournal()

	if !bytes.Contains(logBuf.Bytes(), []byte("auth-failure signal journal write failed")) {
		t.Fatalf("compaction write failure was silently swallowed (the shadowed-err bug): log=%s", logBuf.String())
	}
}
