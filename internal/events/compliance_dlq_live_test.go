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

// Live acceptance driver for the compliance dead-letter lane.
//
// WHY THIS FILE EXISTS SEPARATELY FROM compliance_upload_test.go: those tests
// drive the real Reporter against an httptest server, which proves the proxy's
// half. They cannot prove the half that actually matters to an auditor — that a
// conserved batch, replayed later, lands as a ROW in the real control-master
// schema. Per e2e-acceptance-live-events, HTTP 200 is not ingest evidence: the
// only evidence is a SELECT.
//
// The two halves live in different Go modules and `internal/events` cannot be
// imported across that boundary, so the split is:
//
//	aikey-test/compliancedlq  → boots REAL PostgreSQL + REAL control-master,
//	                            runs THIS test as a subprocess, then SELECTs.
//	this file                 → drives the REAL Reporter (real HTTP client, real
//	                            dead_letter.jsonl, real replay pass) against that
//	                            live master and reports what it did.
//
// It is skipped when the rig is absent so `go test ./...` stays green for
// everyone; the rig ALWAYS sets the variables, so there is a non-gated caller
// and this is not a tripwire that can quietly stop running.
const (
	liveControlURLEnv   = "AIKEY_LIVE_COMPLIANCE_URL"
	liveControlTokenEnv = "AIKEY_LIVE_COMPLIANCE_TOKEN"
	liveResultPathEnv   = "AIKEY_LIVE_COMPLIANCE_RESULT"
)

// liveResult is handed back to the orchestrating rig so it knows which ids to
// look for (and which must NOT be there).
type liveResult struct {
	LandedEventID  string `json:"landed_event_id"`
	RejectedID     string `json:"rejected_event_id"`
	ReplayedEvents int    `json:"replayed_events"`
	StillFailing   int    `json:"still_failing"`
}

func liveEvent(eventID string, extra string) []byte {
	body := fmt.Sprintf(`{"event_id":%q,"created_at":%q,"user_id":"live-user","tenant_id":"live-tenant",`+
		`"proxy_version":"dlq-live","target_model":"claude-live","scenario":"anthropic.messages",`+
		`"prompt_length":42,"action_taken":"mask",%s`+
		`"findings":[{"finding_id":%q,"rule_id":"cred.aws","category":"credentials",`+
		`"entity_type":"AWS_ACCESS_KEY","severity":"high","confidence":95,"start_offset":0,"end_offset":20,"detector":"regex"}]}`,
		eventID, time.Now().UTC().Format(time.RFC3339Nano), extra, eventID+"-f1")
	return []byte(body)
}

// TestLive_ComplianceDeadLetterSurvivesOutageAndVersionSkew is the live
// acceptance: a batch that cannot be delivered must come back later, and one the
// master genuinely refuses must be kept rather than lost.
func TestLive_ComplianceDeadLetterSurvivesOutageAndVersionSkew(t *testing.T) {
	controlURL := os.Getenv(liveControlURLEnv)
	token := os.Getenv(liveControlTokenEnv)
	if controlURL == "" || token == "" {
		t.Skipf("live rig absent (set %s + %s); run via aikey-test/compliancedlq", liveControlURLEnv, liveControlTokenEnv)
	}

	dir := t.TempDir()
	newRep := func(routeURL string) *Reporter {
		t.Helper()
		r, err := NewReporter(&ReporterConfig{
			CollectorRoutes:           map[string]string{"team": routeURL},
			CollectorRouteCredentials: map[string]Credential{"team": &StaticTokenCredential{Token: token}},
			WALDir:                    dir,
			DBPath:                    filepath.Join(dir, "events.db"),
		})
		if err != nil {
			t.Fatalf("NewReporter: %v", err)
		}
		t.Cleanup(func() { r.Close() })
		return r
	}

	landedID := fmt.Sprintf("live-dlq-%d", time.Now().UnixNano())
	rejectedID := landedID + "-skew"

	// --- Act 1: master unreachable. The event must be conserved, not dropped.
	// 127.0.0.1:1 is a real dial failure, not a mocked one.
	offline := newRep("http://127.0.0.1:1")
	if err := offline.UploadComplianceEvents(context.Background(), "team",
		[][]byte{liveEvent(landedID, "")}); err == nil {
		t.Fatal("act 1: expected the upload to fail against an unreachable master")
	}
	if n := len(readDeadLetterEntries(t, dir)); n != 1 {
		t.Fatalf("act 1: batch was not conserved — dead_letter entries=%d want 1", n)
	}
	st := offline.AuditStatus()
	if st.Compliance.DeadLetterEntries != 1 || st.Compliance.DeadLetterEvents != 1 {
		t.Fatalf("act 1: /admin/audit/status must show the stuck batch; got %+v", st.Compliance)
	}
	t.Logf("act 1 OK: %s conserved in dead_letter.jsonl while master unreachable (last_failure=%q)",
		landedID, st.Compliance.LastFailureReason)

	// --- Act 2: master reachable again (a new generation with a synced route,
	// same data dir → same queue). Replay must deliver it for real.
	online := newRep(controlURL)
	res, err := online.ReplayDeadLetter(context.Background())
	if err != nil {
		t.Fatalf("act 2: ReplayDeadLetter: %v", err)
	}
	if res.EntriesReplayedOK != 1 || res.EntriesStillFailing != 0 {
		t.Fatalf("act 2: replay did not deliver; got %+v", res)
	}
	if n := len(readDeadLetterEntries(t, dir)); n != 0 {
		t.Fatalf("act 2: queue should be drained; %d entries left", n)
	}
	t.Logf("act 2 OK: replay re-delivered %s to the live master (the rig now SELECTs it)", landedID)

	// --- Act 3: idempotence against the REAL schema. Send the identical batch
	// again — the master's ON CONFLICT (event_id) DO NOTHING must absorb it, and
	// the rig asserts the row count stays 1 with no duplicated finding.
	if err := online.UploadComplianceEvents(context.Background(), "team",
		[][]byte{liveEvent(landedID, "")}); err != nil {
		t.Fatalf("act 3: re-sending an already-ingested batch must succeed (idempotent ingest): %v", err)
	}
	t.Logf("act 3 OK: duplicate delivery of %s accepted without error", landedID)

	// --- Act 4: real version skew. The unknown field is refused by the live
	// master's real DisallowUnknownFields decoder — the exact failure that used
	// to erase a whole org's audit trail. It must be conserved, and it must stay
	// conserved across a replay that still fails.
	if err := online.UploadComplianceEvents(context.Background(), "team",
		[][]byte{liveEvent(rejectedID, `"field_from_a_newer_proxy":"x",`)}); err == nil {
		t.Fatal("act 4: expected the live master to refuse an unknown wire field (strict decoding must hold)")
	}
	skew := readDeadLetterEntries(t, dir)
	if len(skew) != 1 || skew[0].ErrorCode != 400 {
		t.Fatalf("act 4: version-skew batch not conserved as a 400 entry; got %+v", skew)
	}
	res2, err := online.ReplayDeadLetter(context.Background())
	if err != nil {
		t.Fatalf("act 4: ReplayDeadLetter: %v", err)
	}
	if res2.EntriesStillFailing != 1 || res2.EntriesReplayedOK != 0 {
		t.Fatalf("act 4: a still-incompatible entry must be KEPT, not consumed; got %+v", res2)
	}
	if n := len(readDeadLetterEntries(t, dir)); n != 1 {
		t.Fatalf("act 4: entry must survive a failed replay; %d left", n)
	}
	t.Logf("act 4 OK: %s refused (400) by the live master and still queued for a future replay", rejectedID)

	if p := os.Getenv(liveResultPathEnv); p != "" {
		out, _ := json.Marshal(liveResult{
			LandedEventID:  landedID,
			RejectedID:     rejectedID,
			ReplayedEvents: res.EventsReplayedOK,
			StillFailing:   res2.EntriesStillFailing,
		})
		if err := os.WriteFile(p, out, 0o600); err != nil {
			t.Fatalf("write live result: %v", err)
		}
	}
}
