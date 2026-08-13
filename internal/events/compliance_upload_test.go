package events

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestUploadComplianceEvents_ReusesRouteAndCredential proves the team→master
// compliance upload reuses the SAME per-RouteSource URL + credential as usage
// reporting: it POSTs to <route>/v1/compliance/events with the route's bearer
// and a {"events":[...]} envelope. (update doc 20260603 §3)
func TestUploadComplianceEvents_ReusesRouteAndCredential(t *testing.T) {
	var (
		gotPath string
		gotAuth string
		gotBody []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(map[string][]string{"accepted_ids": {"ok"}})
	}))
	defer srv.Close()

	r, err := NewReporter(&ReporterConfig{
		CollectorRoutes:           map[string]string{"team": srv.URL},
		CollectorRouteCredentials: map[string]Credential{"team": &StaticTokenCredential{Token: "member-jwt-x"}},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	evs := [][]byte{[]byte(`{"event_id":"e1","action_taken":"block"}`), []byte(`{"event_id":"e2","action_taken":"mask"}`)}
	if err := r.UploadComplianceEvents(ctx, "team", evs); err != nil {
		t.Fatalf("UploadComplianceEvents: %v", err)
	}

	if gotPath != "/v1/compliance/events" {
		t.Errorf("path: got %q want /v1/compliance/events", gotPath)
	}
	if gotAuth != "Bearer member-jwt-x" {
		t.Errorf("auth: got %q want 'Bearer member-jwt-x' (route credential reused)", gotAuth)
	}
	var pb struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(gotBody, &pb); err != nil {
		t.Fatalf("body not valid JSON envelope: %v (%s)", err, gotBody)
	}
	if len(pb.Events) != 2 {
		t.Errorf("events: got %d want 2", len(pb.Events))
	}

	// Empty source / no route → error (fail-loud, not silent).
	if err := r.UploadComplianceEvents(ctx, "nope", evs); err == nil {
		t.Error("expected error when no route URL configured for source")
	}
}

// --- Dead-letter + replay for the compliance lane (2026-08-10) ---------------
//
// The regression these fence: a team compliance upload that failed was gone.
// The upload runs on a fire-and-forget goroutine, the caller logged one WARN,
// and nothing anywhere held a second copy of the event. A master one release
// behind (strict DisallowUnknownFields vs. a proxy stamping a new wire field)
// therefore turned every compliance event into permanent audit loss — silently,
// on machines whose upgrade order nobody controls.

// versionSkewServer emulates an OLDER master: its strict decoder refuses the
// batch with the exact 400 shape control-master returns, until upgraded is
// flipped, after which it accepts and records what it received.
func versionSkewServer(t *testing.T, upgraded *atomic.Bool, seen *[][]byte, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !upgraded.Load() {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"request body is not valid JSON or carries fields this master does not accept","code":"INVALID_JSON","details":"json: unknown field \"trace_id\""}`))
			return
		}
		mu.Lock()
		*seen = append(*seen, body)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string][]string{"accepted_ids": {"ok"}})
	}))
}

func newComplianceReporter(t *testing.T, dir, url string) *Reporter {
	t.Helper()
	r, err := NewReporter(&ReporterConfig{
		CollectorRoutes:           map[string]string{"team": url},
		CollectorRouteCredentials: map[string]Credential{"team": &StaticTokenCredential{Token: "member-jwt-x"}},
		WALDir:                    dir,
		DBPath:                    filepath.Join(dir, "events.db"),
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// A 400 from an older master must CONSERVE the batch, not drop it. 400 is
// "terminal" only in the sense of "do not hot-retry" — the same bytes succeed
// after the master upgrades, so discarding them is wrong.
func TestComplianceUpload_400IsDeadLetteredNotDropped(t *testing.T) {
	var upgraded atomic.Bool
	var mu sync.Mutex
	var seen [][]byte
	srv := versionSkewServer(t, &upgraded, &seen, &mu)
	defer srv.Close()

	dir := t.TempDir()
	r := newComplianceReporter(t, dir, srv.URL)

	evs := [][]byte{
		[]byte(`{"event_id":"cev-1","tenant_id":"t","action_taken":"block","trace_id":"tr-1"}`),
		[]byte(`{"event_id":"cev-2","tenant_id":"t","action_taken":"mask","trace_id":"tr-1"}`),
	}
	err := r.UploadComplianceEvents(context.Background(), "team", evs)
	if err == nil {
		t.Fatal("expected the 400 to be returned to the caller (fail-loud is preserved)")
	}

	entries := readDeadLetterEntries(t, dir)
	if len(entries) != 1 {
		t.Fatalf("dead_letter.jsonl: got %d entries want 1 (the batch must be conserved)", len(entries))
	}
	e := entries[0]
	if e.Kind != deadLetterKindCompliance {
		t.Errorf("kind: got %q want %q", e.Kind, deadLetterKindCompliance)
	}
	if e.RouteSource != "team" {
		t.Errorf("route_source: got %q want team (replay resolves the URL from it)", e.RouteSource)
	}
	if e.ErrorCode != 400 || e.Reason != "terminal" {
		t.Errorf("error_code/reason: got %d/%q want 400/terminal", e.ErrorCode, e.Reason)
	}
	if len(e.Payloads) != 2 {
		t.Fatalf("payloads: got %d want 2 (the exact bytes must survive)", len(e.Payloads))
	}
	if string(e.Payloads[0]) != string(evs[0]) {
		t.Errorf("payload[0] mutated:\n got %s\nwant %s", e.Payloads[0], evs[0])
	}
	if len(e.EventIDs) != 2 || e.EventIDs[0] != "cev-1" {
		t.Errorf("event_ids: got %v want [cev-1 cev-2]", e.EventIDs)
	}
	// The master's response body is what tells an operator this is version skew
	// and not a corrupt payload — it must be kept verbatim.
	if !strings.Contains(e.ResponseBody, "unknown field") {
		t.Errorf("response_body should carry the master's diagnosis; got %q", e.ResponseBody)
	}
}

// After the master is upgraded, the SAME conserved bytes must land — this is
// the whole point of calling a 400 "deferred" rather than "failed".
func TestComplianceReplay_DeliversAfterMasterUpgrade(t *testing.T) {
	var upgraded atomic.Bool
	var mu sync.Mutex
	var seen [][]byte
	srv := versionSkewServer(t, &upgraded, &seen, &mu)
	defer srv.Close()

	dir := t.TempDir()
	r := newComplianceReporter(t, dir, srv.URL)

	original := []byte(`{"event_id":"cev-9","tenant_id":"t","action_taken":"block","trace_id":"tr-9"}`)
	if err := r.UploadComplianceEvents(context.Background(), "team", [][]byte{original}); err == nil {
		t.Fatal("setup: expected the pre-upgrade 400")
	}
	if len(readDeadLetterEntries(t, dir)) != 1 {
		t.Fatal("setup: batch was not conserved")
	}

	upgraded.Store(true) // operator upgrades control-master

	res, err := r.ReplayDeadLetter(context.Background())
	if err != nil {
		t.Fatalf("ReplayDeadLetter: %v", err)
	}
	if res.EntriesScanned != 1 || res.EntriesReplayedOK != 1 || res.EntriesStillFailing != 0 {
		t.Fatalf("replay result: got %+v want scanned=1 ok=1 failing=0", res)
	}
	if res.EventsReplayedOK != 1 {
		t.Errorf("events_replayed_ok: got %d want 1", res.EventsReplayedOK)
	}
	if got := readDeadLetterEntries(t, dir); len(got) != 0 {
		t.Errorf("queue should be drained after successful replay; got %d", len(got))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("master received %d batches want 1", len(seen))
	}
	// Replay must go through the live envelope + endpoint, carrying the SAME
	// event_id — that id is what makes the master's ON CONFLICT (event_id) DO
	// NOTHING absorb a re-delivery of something that already landed.
	var got struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(seen[0], &got); err != nil {
		t.Fatalf("replayed body is not the {\"events\":[...]} envelope: %v", err)
	}
	if len(got.Events) != 1 || string(got.Events[0]) != string(original) {
		t.Errorf("replayed payload changed:\n got %s\nwant %s", seen[0], original)
	}
}

// Idempotence evidence: replaying a batch that ALREADY landed re-sends the
// identical event_id, which is the precondition the master's
// `ON CONFLICT (event_id) DO NOTHING` needs to absorb the duplicate. The
// detector mints event_id once (its own CSPRNG) and the proxy forwards the
// payload verbatim, so the id cannot drift between attempts.
func TestComplianceReplay_ReSendsStableEventID(t *testing.T) {
	var mu sync.Mutex
	var seenIDs []string
	var reject atomic.Bool
	reject.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env struct {
			Events []struct {
				EventID string `json:"event_id"`
			} `json:"events"`
		}
		_ = json.Unmarshal(body, &env)
		mu.Lock()
		for _, e := range env.Events {
			seenIDs = append(seenIDs, e.EventID)
		}
		mu.Unlock()
		if reject.Load() {
			// 503: the master got the bytes but could not store them. The proxy
			// cannot know whether the write landed, so it must conserve — and
			// the replay is only safe because the id is stable.
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string][]string{"accepted_ids": {"cev-dup"}})
	}))
	defer srv.Close()

	dir := t.TempDir()
	r := newComplianceReporter(t, dir, srv.URL)

	ev := []byte(`{"event_id":"cev-dup","tenant_id":"t","action_taken":"warn"}`)
	if err := r.UploadComplianceEvents(context.Background(), "team", [][]byte{ev}); err == nil {
		t.Fatal("setup: expected the 503")
	}
	reject.Store(false)
	if _, err := r.ReplayDeadLetter(context.Background()); err != nil {
		t.Fatalf("ReplayDeadLetter: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenIDs) != 2 {
		t.Fatalf("master should have seen the event twice (original + replay); got %v", seenIDs)
	}
	if seenIDs[0] != "cev-dup" || seenIDs[1] != "cev-dup" {
		t.Errorf("event_id drifted across replay: %v — master-side dedup would not catch it", seenIDs)
	}
}

// A retryable failure must ALSO be conserved. This is the one place the
// compliance lane diverges from the usage lane: usage events survive a
// retryable failure in the WAL outbox, compliance events have no WAL, so
// "leave it for the next drain" would mean "lose it".
func TestComplianceUpload_RetryableFailureIsAlsoConserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	dir := t.TempDir()
	r := newComplianceReporter(t, dir, srv.URL)

	if err := r.UploadComplianceEvents(context.Background(), "team",
		[][]byte{[]byte(`{"event_id":"cev-5xx","tenant_id":"t","action_taken":"block"}`)}); err == nil {
		t.Fatal("expected the 502 to be returned")
	}
	entries := readDeadLetterEntries(t, dir)
	if len(entries) != 1 {
		t.Fatalf("a 5xx must conserve the batch (no WAL backs this lane); got %d entries", len(entries))
	}
	if entries[0].Reason != "retryable" || entries[0].ErrorCode != 502 {
		t.Errorf("reason/code: got %q/%d want retryable/502", entries[0].Reason, entries[0].ErrorCode)
	}
}

// Having nowhere to send yet (logged out / team route not synced) is not a
// reason to discard an audit event — a later replay may find a destination.
func TestComplianceUpload_NoRouteIsConserved(t *testing.T) {
	dir := t.TempDir()
	r := newComplianceReporter(t, dir, "http://127.0.0.1:1")

	if err := r.UploadComplianceEvents(context.Background(), "nope",
		[][]byte{[]byte(`{"event_id":"cev-noroute","tenant_id":"t","action_taken":"mask"}`)}); err == nil {
		t.Fatal("expected an error when no route URL is configured (fail-loud)")
	}
	if got := readDeadLetterEntries(t, dir); len(got) != 1 {
		t.Fatalf("event with no destination must be conserved, not dropped; got %d entries", len(got))
	}
}

// Backward compatibility of the on-disk format. A dead_letter.jsonl written by
// a pre-2026-08-10 proxy has NO `kind` field at all; it must keep replaying
// through the usage lane exactly as before.
func TestReplayDeadLetter_LegacyLineWithoutKindStillUsesUsageLane(t *testing.T) {
	var hits atomic.Int64
	var gotPath atomic.Value
	gotPath.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotPath.Store(r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": 1})
	}))
	defer srv.Close()

	dir := t.TempDir()
	r := newComplianceReporter(t, dir, srv.URL)

	// Hand-written legacy line: exactly the fields the old writer emitted.
	legacy := `{"config_hash":"h","reason":"terminal","error_msg":"401","response_body":"","collector_url":"` +
		srv.URL + `/v1/usage-events:batch","proxy_build_id":"b","event_ids":["ev-legacy"],` +
		`"events":[{"event_id":"ev-legacy","org_id":"o","route_source":"team","request_status":"success","request_count":1}],` +
		`"error_code":401,"dead_at":1,"attempt_count":1,"batch_size":1,"schema_version":1}`
	if err := os.WriteFile(filepath.Join(dir, "dead_letter.jsonl"), []byte(legacy+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := r.ReplayDeadLetter(context.Background())
	if err != nil {
		t.Fatalf("ReplayDeadLetter: %v", err)
	}
	if res.EntriesReplayedOK != 1 {
		t.Fatalf("legacy entry must still replay; got %+v", res)
	}
	if p := gotPath.Load().(string); p != "/v1/usage-events:batch" {
		t.Errorf("legacy entry took the wrong lane: posted to %q want /v1/usage-events:batch", p)
	}
}

// A stuck compliance queue must be READABLE — a dead letter nobody can see is
// just a slower silent drop. /admin/audit/status is the existing place an
// operator asks "is anything undelivered here?", so the answer belongs there.
func TestAuditStatus_SurfacesComplianceDeadLetter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"INVALID_JSON","details":"json: unknown field \"trace_id\""}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	r := newComplianceReporter(t, dir, srv.URL)

	_ = r.UploadComplianceEvents(context.Background(), "team", [][]byte{
		[]byte(`{"event_id":"cev-a","tenant_id":"t","action_taken":"block"}`),
		[]byte(`{"event_id":"cev-b","tenant_id":"t","action_taken":"block"}`),
	})

	st := r.AuditStatus()
	if st.Compliance.DeadLetterEntries != 1 {
		t.Errorf("compliance.dead_letter_entries: got %d want 1", st.Compliance.DeadLetterEntries)
	}
	if st.Compliance.DeadLetterEvents != 2 {
		t.Errorf("compliance.dead_letter_events: got %d want 2", st.Compliance.DeadLetterEvents)
	}
	if st.Compliance.LastFailureCode != 400 {
		t.Errorf("compliance.last_failure_code: got %d want 400 (attributable, not just a depth)",
			st.Compliance.LastFailureCode)
	}
	if !strings.Contains(st.Compliance.LastFailureReason, "unknown field") {
		t.Errorf("last_failure_reason must name the cause; got %q", st.Compliance.LastFailureReason)
	}
	if st.Compliance.LastFailureAt == 0 {
		t.Error("last_failure_at should be stamped")
	}
	// Both lanes share the file, so the legacy total counts compliance too.
	if st.DeadLetterCount != 1 {
		t.Errorf("dead_letter_count (all lanes): got %d want 1", st.DeadLetterCount)
	}
}
