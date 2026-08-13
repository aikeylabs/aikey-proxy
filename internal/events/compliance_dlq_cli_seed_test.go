package events

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Seed driver for the CLI half of the compliance dead-letter lane.
//
// # WHY THIS EXISTS (2026-08-10)
//
// TestLive_ComplianceDeadLetterSurvivesOutageAndVersionSkew proves the REPORTER
// recovers a conserved batch. It does not touch the only recovery entry point a
// human actually has: `aikey proxy replay-dead-letter` → the running proxy's
// POST /admin/replay-dead-letter → Reporter.ReplayDeadLetter. `aikey audit
// status` tells users to run exactly that command when it sees a backlog, so if
// that hop is broken the whole conservation design pays out nothing — the audit
// trail is merely stuck in a file the user cannot get at, while the CLI keeps
// confidently naming a command that does not work.
//
// Driving that hop needs a REAL proxy PROCESS (the admin endpoint only exists
// inside one) plus a REAL `aikey` binary, which live in aikey-test's sandbox rig
// — but the dead-letter file's on-disk format is package-private here. So this
// test is the one thing the rig cannot do for itself: it produces a REAL backlog
// with the REAL writer, in the two shapes the field actually produces:
//
//	entry 1  master unreachable  → transport failure, conserved
//	entry 2  unknown wire field  → live master's DisallowUnknownFields 400,
//	                               conserved (the version-skew shape that
//	                               motivated the whole lane)
//
// The rig then hands that file to a real proxy and drives recovery through the
// real CLI. Nothing here is a fixture: every byte is written by
// deadLetterWriter.write on the production path.
//
// Skipped when the rig is absent so `go test ./...` stays green standalone; the
// rig ALWAYS sets the variables, so there is a non-gated caller.
const (
	seedControlURLEnv = "AIKEY_CLI_REPLAY_SEED_URL"
	seedTokenEnv      = "AIKEY_CLI_REPLAY_SEED_TOKEN"
	seedDirEnv        = "AIKEY_CLI_REPLAY_SEED_DIR"
	seedResultEnv     = "AIKEY_CLI_REPLAY_SEED_RESULT"
)

// seedResult tells the rig which ids must (and must not) reach the database.
type seedResult struct {
	DeliverableEventID string `json:"deliverable_event_id"`
	SkewEventID        string `json:"skew_event_id"`
	Entries            int    `json:"entries"`
}

// TestLive_SeedComplianceDeadLetterForCLIReplay writes a two-entry compliance
// backlog into AIKEY_CLI_REPLAY_SEED_DIR using the production dead-letter
// writer, then exits leaving no open handles on it.
func TestLive_SeedComplianceDeadLetterForCLIReplay(t *testing.T) {
	controlURL := os.Getenv(seedControlURLEnv)
	token := os.Getenv(seedTokenEnv)
	seedDir := os.Getenv(seedDirEnv)
	if controlURL == "" || token == "" || seedDir == "" {
		t.Skipf("seed rig absent (set %s + %s + %s); run via aikey-test/compliancedlq",
			seedControlURLEnv, seedTokenEnv, seedDirEnv)
	}
	if err := os.MkdirAll(seedDir, 0o700); err != nil {
		t.Fatalf("mkdir seed dir: %v", err)
	}

	newRep := func(routeURL string) *Reporter {
		t.Helper()
		r, err := NewReporter(&ReporterConfig{
			CollectorRoutes:           map[string]string{"team": routeURL},
			CollectorRouteCredentials: map[string]Credential{"team": &StaticTokenCredential{Token: token}},
			WALDir:                    seedDir,
			// The seeder's own SQLite file, never the proxy's: the rig copies
			// only dead_letter.jsonl out of this directory.
			DBPath: filepath.Join(seedDir, "seed-events.db"),
		})
		if err != nil {
			t.Fatalf("NewReporter: %v", err)
		}
		t.Cleanup(func() { r.Close() })
		return r
	}

	deliverableID := fmt.Sprintf("cli-replay-%d", time.Now().UnixNano())
	skewID := deliverableID + "-skew"

	// Entry 1 — the recoverable shape: the master was simply unreachable.
	// 127.0.0.1:1 is a real dial failure, not a simulated one.
	offline := newRep("http://127.0.0.1:1")
	if err := offline.UploadComplianceEvents(context.Background(), "team",
		[][]byte{liveEvent(deliverableID, "")}); err == nil {
		t.Fatal("seed: upload against an unreachable master must fail")
	}

	// Entry 2 — the version-skew shape: refused by the LIVE master's own strict
	// decoder, so the 400 in the file is genuine.
	online := newRep(controlURL)
	if err := online.UploadComplianceEvents(context.Background(), "team",
		[][]byte{liveEvent(skewID, `"field_from_a_newer_proxy":"x",`)}); err == nil {
		t.Fatal("seed: the live master must refuse an unknown wire field (strict decoding must hold)")
	}

	entries := readDeadLetterEntries(t, seedDir)
	if len(entries) != 2 {
		t.Fatalf("seed: want 2 conserved entries, got %d (%+v)", len(entries), entries)
	}
	if entries[0].Kind != deadLetterKindCompliance || entries[1].Kind != deadLetterKindCompliance {
		t.Fatalf("seed: both entries must be on the compliance lane; got %q / %q", entries[0].Kind, entries[1].Kind)
	}
	if entries[1].ErrorCode != 400 {
		t.Fatalf("seed: the skew entry must carry the master's real 400; got %d body=%q",
			entries[1].ErrorCode, entries[1].ResponseBody)
	}
	if entries[0].RouteSource != "team" || entries[1].RouteSource != "team" {
		t.Fatalf("seed: replay resolves the destination from RouteSource; got %q / %q",
			entries[0].RouteSource, entries[1].RouteSource)
	}
	t.Logf("seed OK: %s (transport failure) + %s (live-master 400) conserved in %s/dead_letter.jsonl",
		deliverableID, skewID, seedDir)

	if p := os.Getenv(seedResultEnv); p != "" {
		out, _ := json.Marshal(seedResult{
			DeliverableEventID: deliverableID,
			SkewEventID:        skewID,
			Entries:            len(entries),
		})
		if err := os.WriteFile(p, out, 0o600); err != nil {
			t.Fatalf("write seed result: %v", err)
		}
	}
}
