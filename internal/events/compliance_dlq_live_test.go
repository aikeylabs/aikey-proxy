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

	// The grading leg (task 3.3) adds three more knobs. They are separate
	// variables rather than a richer AIKEY_LIVE_COMPLIANCE_URL so the original
	// driver above keeps its exact contract: a rig that only wires the first
	// three still runs it unchanged.
	//
	// liveMirrorURLEnv is the LOCAL SELF-VIEW receiver — the second outlet.
	// Without it the mirror leg cannot be asserted at all, and the mirror is the
	// outlet nobody looks at: master 落库 was fenced twice before, the mirror
	// never once.
	liveMirrorURLEnv = "AIKEY_LIVE_COMPLIANCE_MIRROR_URL"
	// liveTenantEnv is the org id the master will recognise. It MUST be a real
	// organizations row: applyGradingLevelPolicy strips every level whose tenant
	// has no grading document, so an unknown tenant makes `level IS NULL` for a
	// reason that has nothing to do with this proxy.
	liveTenantEnv = "AIKEY_LIVE_COMPLIANCE_TENANT"
	// liveLeafPathEnv is a classification path that exists in one of that
	// tenant's live packs; applyGradingLeafPathPolicy strips anything else.
	liveLeafPathEnv = "AIKEY_LIVE_COMPLIANCE_LEAF"
)

// liveGradingLevel is the sensitivity grade this driver stamps. The rig must
// define it in the tenant's `labels`, or the master strips it on the way in.
const liveGradingLevel = 3

// liveResult is handed back to the orchestrating rig so it knows which ids to
// look for (and which must NOT be there).
type liveResult struct {
	LandedEventID  string `json:"landed_event_id"`
	RejectedID     string `json:"rejected_event_id"`
	ReplayedEvents int    `json:"replayed_events"`
	StillFailing   int    `json:"still_failing"`
	// FindingID / Level / MaxLevel / LeafPath are written only by the grading
	// driver below. The rig SELECTs on them, so the values it checks are the
	// ones this process actually put on the wire rather than a second hand-typed
	// copy that can drift from it.
	FindingID string `json:"finding_id,omitempty"`
	Level     int    `json:"level,omitempty"`
	MaxLevel  int    `json:"max_level,omitempty"`
	LeafPath  string `json:"leaf_path,omitempty"`
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

// ─────────────────────────────────────────────────────────────────────────────
// TASK 3.3 — the grading fields' TRANSPORT leg, on BOTH outlets.
//
// # What this proves that nothing else does
//
// The detector stamps `findings[].level`, `findings[].leaf_path` and
// `max_level` (task 2.2 stampLeafGrades). The master declares them (1.5 / 1.18)
// and the Personal self-view declares them (5.1). Between those two ends sit
// the proxy's TWO compliance outlets, and each is a hand-written relay:
//
//	UploadComplianceEvents        → master           (dead-lettered on failure)
//	MirrorComplianceEventsLocally → local self-view  (never dead-lettered)
//
// `hand-copied-relay-drops-fields` has fired ELEVEN times in this need package,
// three of them because only ONE direction was done. The mirror is the outlet
// most likely to be the missed one: nothing else in the repo SELECTs its rows,
// so a relay that re-encoded the event through a typed struct would drop the
// three columns there while every master-side fence stayed green.
//
// So this driver asserts both, and the rig SELECTs both databases. Deleting the
// mirror's stamping relay must turn the mirror assertions RED while the master
// assertions stay GREEN — that independence is the point.
//
// # And the version-skew absorption (task 3.4 named this file as its backstop)
//
// Release order is master → console → detector → proxy, because intake decodes
// with DisallowUnknownFields. A proxy on an employee laptop upgrades on nobody's
// schedule, so "new proxy, old master" is not a mistake to be prevented, it is a
// state to be survived: the batch must land in dead_letter.jsonl and be
// re-delivered, degrading the outcome to AUDIT DELAY rather than audit loss.
// Act 1+2 prove a conserved grading batch really is re-delivered (a ROW, not a
// 200); act 4 proves a batch the live master genuinely refuses is kept for a
// later replay instead of consumed.
//
// spec: R-compliance-grading-13.S5 / R-compliance-grading-23.S4
// ─────────────────────────────────────────────────────────────────────────────

// liveGradingEvent builds ONE compliance event carrying the three grading
// fields, plus `extra` raw JSON pairs for the version-skew act.
//
// The shape is liveEvent's, with the grading fields added — deliberately not a
// second unrelated payload, so a difference in outcome between the two drivers
// can only come from the grading fields themselves.
func liveGradingEvent(eventID, tenantID, leafPath, extra string) []byte {
	body := fmt.Sprintf(`{"event_id":%q,"created_at":%q,"user_id":"live-user","tenant_id":%q,`+
		`"proxy_version":"dlq-live","target_model":"claude-live","scenario":"anthropic.messages",`+
		`"prompt_length":42,"action_taken":"mask","max_level":%d,%s`+
		`"findings":[{"finding_id":%q,"rule_id":"cred.aws","category":"credentials",`+
		`"entity_type":"AWS_ACCESS_KEY","severity":"high","confidence":95,"start_offset":0,"end_offset":20,`+
		`"detector":"regex","level":%d,"leaf_path":%q}]}`,
		eventID, time.Now().UTC().Format(time.RFC3339Nano), tenantID,
		liveGradingLevel, extra, eventID+"-f1", liveGradingLevel, leafPath)
	return []byte(body)
}

// TestLive_ComplianceGradingFieldsSurviveOutageReplayAndMirror is the proxy half
// of TestSyncComplianceDLQ_LevelSurvivesOutageReplay. It drives the REAL
// Reporter — real HTTP client, real dead_letter.jsonl, real replay pass — and
// reports what it sent; the rig owns the two databases and does the SELECTs.
func TestLive_ComplianceGradingFieldsSurviveOutageReplayAndMirror(t *testing.T) {
	controlURL := os.Getenv(liveControlURLEnv)
	token := os.Getenv(liveControlTokenEnv)
	mirrorURL := os.Getenv(liveMirrorURLEnv)
	tenantID := os.Getenv(liveTenantEnv)
	leafPath := os.Getenv(liveLeafPathEnv)
	if controlURL == "" || token == "" || mirrorURL == "" || tenantID == "" || leafPath == "" {
		t.Skipf("live grading rig absent (needs %s + %s + %s + %s + %s); run via aikey-test/compliancedlq",
			liveControlURLEnv, liveControlTokenEnv, liveMirrorURLEnv, liveTenantEnv, liveLeafPathEnv)
	}

	dir := t.TempDir()
	// Both outlets on every generation: "team" is the master upload, "personal"
	// is the local mirror's destination (Reporter.MirrorComplianceEventsLocally
	// posts to the personal route and returns nil when there is none — a rig
	// that forgot to wire it would go falsely green, so the driver asserts the
	// mirror's own HTTP outcome too).
	newRep := func(teamURL string) *Reporter {
		t.Helper()
		r, err := NewReporter(&ReporterConfig{
			CollectorRoutes: map[string]string{"team": teamURL, "personal": mirrorURL},
			CollectorRouteCredentials: map[string]Credential{
				"team": &StaticTokenCredential{Token: token},
			},
			WALDir: dir,
			DBPath: filepath.Join(dir, "events.db"),
		})
		if err != nil {
			t.Fatalf("NewReporter: %v", err)
		}
		t.Cleanup(func() { r.Close() })
		return r
	}

	landedID := fmt.Sprintf("live-grade-%d", time.Now().UnixNano())
	rejectedID := landedID + "-skew"
	payload := liveGradingEvent(landedID, tenantID, leafPath, "")

	// --- Act 1: master unreachable. The graded batch must be CONSERVED.
	offline := newRep("http://127.0.0.1:1")
	if err := offline.UploadComplianceEvents(context.Background(), "team", [][]byte{payload}); err == nil {
		t.Fatal("act 1: expected the upload to fail against an unreachable master")
	}
	if n := len(readDeadLetterEntries(t, dir)); n != 1 {
		t.Fatalf("act 1: graded batch was not conserved — dead_letter entries=%d want 1", n)
	}
	t.Logf("act 1 OK: %s (level=%d leaf_path=%q) conserved while master unreachable", landedID, liveGradingLevel, leafPath)

	// --- Act 2: the LOCAL MIRROR outlet, driven with the SAME bytes and while
	// the master is still down. The mirror is a separate contract on purpose:
	// its failure never touches the upload and it is never dead-lettered, which
	// is exactly why it needs its own assertion — a master outage must not take
	// the member's own record of their own detection with it.
	if err := offline.MirrorComplianceEventsLocally(context.Background(), "team", [][]byte{payload}); err != nil {
		t.Fatalf("act 2: local mirror of a graded event failed: %v", err)
	}
	t.Logf("act 2 OK: %s mirrored to the local self-view while the master was still unreachable", landedID)

	// --- Act 3: master reachable again (same data dir → same queue). Replay
	// must DELIVER the graded batch; the rig then SELECTs the columns.
	online := newRep(controlURL)
	res, err := online.ReplayDeadLetter(context.Background())
	if err != nil {
		t.Fatalf("act 3: ReplayDeadLetter: %v", err)
	}
	if res.EntriesReplayedOK != 1 || res.EntriesStillFailing != 0 {
		t.Fatalf("act 3: replay did not deliver the graded batch; got %+v", res)
	}
	if n := len(readDeadLetterEntries(t, dir)); n != 0 {
		t.Fatalf("act 3: queue should be drained; %d entries left", n)
	}
	t.Logf("act 3 OK: replay re-delivered %s to the live master", landedID)

	// --- Act 4: version skew ABSORPTION. A field this master has not declared
	// stands in for "the field the OLD master has not declared yet" — the same
	// DisallowUnknownFields mechanism, which is what makes new-proxy-old-master
	// a 400 on EVERY compliance event including the ordinary ones riding along.
	// It must be conserved as a 400 entry and SURVIVE a replay that still fails.
	if err := online.UploadComplianceEvents(context.Background(), "team",
		[][]byte{liveGradingEvent(rejectedID, tenantID, leafPath, `"grade_scheme_version":"from-a-newer-proxy",`)}); err == nil {
		t.Fatal("act 4: expected the live master to refuse an undeclared grading field (strict decoding must hold)")
	}
	skew := readDeadLetterEntries(t, dir)
	if len(skew) != 1 || skew[0].ErrorCode != 400 {
		t.Fatalf("act 4: skewed grading batch not conserved as a 400 entry; got %+v", skew)
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
	t.Logf("act 4 OK: %s refused (400) by the live master and still queued — audit DELAYED, not lost", rejectedID)

	if p := os.Getenv(liveResultPathEnv); p != "" {
		out, _ := json.Marshal(liveResult{
			LandedEventID:  landedID,
			RejectedID:     rejectedID,
			ReplayedEvents: res.EventsReplayedOK,
			StillFailing:   res2.EntriesStillFailing,
			FindingID:      landedID + "-f1",
			Level:          liveGradingLevel,
			MaxLevel:       liveGradingLevel,
			LeafPath:       leafPath,
		})
		if err := os.WriteFile(p, out, 0o600); err != nil {
			t.Fatalf("write live result: %v", err)
		}
	}
}
