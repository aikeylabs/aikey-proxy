package events

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/aikeytime"
)

func TestReporter_ReportAndUpload(t *testing.T) {
	var received atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
			http.Error(w, "bad", 400)
			return
		}
		received.Add(int64(len(req.Events)))
		json.NewEncoder(w).Encode(batchResponse{
			Accepted: len(req.Events),
		})
	}))
	defer srv.Close()

	reporter, err := NewReporter(&ReporterConfig{
		CollectorURL:   srv.URL,
		QueueCapacity:  100,
		WALDir:         t.TempDir(), // WAL is the upload outbox in the new model
		BatchSize:      5,
		UploadInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		reporter.Report(&ReportableEvent{
			EventID:       "e" + string(rune('0'+i)),
			OrgID:         "org1",
			EventTime:     aikeytime.Now(),
			OccurredAt:    aikeytime.Now(),
			RequestStatus: "success",
			RequestCount:  1,
		})
	}

	// Wait for flush interval
	time.Sleep(200 * time.Millisecond)

	reporter.Close()

	if got := received.Load(); got != 3 {
		t.Errorf("expected 3 events received by server, got %d", got)
	}

	m := reporter.Metrics()
	if m.Generated != 3 {
		t.Errorf("generated=%d, want 3", m.Generated)
	}
	if m.Enqueued != 3 {
		t.Errorf("enqueued=%d, want 3", m.Enqueued)
	}
	if m.Dropped != 0 {
		t.Errorf("dropped=%d, want 0", m.Dropped)
	}
}

// TestReporter_PerRouteRouting verifies CollectorRoutes dispatches each
// event to the URL matching its RouteSource, falling back to CollectorURL
// when the route has no specific mapping. Guards the personal/team
// isolation contract added 2026-05-10 (roadmap update file
// 20260510-personal-team-数据隔离与合并显示.md).
func TestReporter_PerRouteRouting(t *testing.T) {
	var personalCount, teamCount, fallbackCount atomic.Int64

	mkServer := func(counter *atomic.Int64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req batchRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad", 400)
				return
			}
			counter.Add(int64(len(req.Events)))
			json.NewEncoder(w).Encode(batchResponse{Accepted: len(req.Events)})
		}))
	}
	personalSrv := mkServer(&personalCount)
	teamSrv := mkServer(&teamCount)
	fallbackSrv := mkServer(&fallbackCount)
	defer personalSrv.Close()
	defer teamSrv.Close()
	defer fallbackSrv.Close()

	reporter, err := NewReporter(&ReporterConfig{
		CollectorURL: fallbackSrv.URL, // catches RouteSource not in map (e.g. "oauth")
		CollectorRoutes: map[string]string{
			"personal": personalSrv.URL,
			"team":     teamSrv.URL,
		},
		QueueCapacity:  100,
		WALDir:         t.TempDir(), // WAL is the upload outbox in the new model
		BatchSize:      5,
		UploadInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	mkEvent := func(id, routeSource string) ReportableEvent {
		return ReportableEvent{
			EventID:       id,
			OrgID:         "org1",
			RouteSource:   routeSource,
			EventTime:     aikeytime.Now(),
			OccurredAt:    aikeytime.Now(),
			RequestStatus: "success",
			RequestCount:  1,
		}
	}
	evP1 := mkEvent("p1", "personal")
	reporter.Report(&evP1)
	evP2 := mkEvent("p2", "personal")
	reporter.Report(&evP2)
	evT1 := mkEvent("t1", "team")
	reporter.Report(&evT1)
	evO1 := mkEvent("o1", "oauth") // fall through to CollectorURL
	reporter.Report(&evO1)

	time.Sleep(200 * time.Millisecond)
	reporter.Close()

	if got := personalCount.Load(); got != 2 {
		t.Errorf("personal collector got %d events, want 2", got)
	}
	if got := teamCount.Load(); got != 1 {
		t.Errorf("team collector got %d events, want 1", got)
	}
	if got := fallbackCount.Load(); got != 1 {
		t.Errorf("fallback (oauth) collector got %d events, want 1", got)
	}
}

// TestReporter_PerRouteIsolation verifies that team upload destination
// being unreachable does NOT silently leak personal events to it (i.e.
// per-event URL grouping holds — no events get sent to the wrong server).
func TestReporter_PerRouteIsolation(t *testing.T) {
	var personalCount atomic.Int64
	personalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		personalCount.Add(int64(len(req.Events)))
		json.NewEncoder(w).Encode(batchResponse{Accepted: len(req.Events)})
	}))
	defer personalSrv.Close()

	// Team URL empty → team events have nowhere to go (dropped at
	// uploadBatch). Personal events still reach their server.
	reporter, err := NewReporter(&ReporterConfig{
		CollectorRoutes: map[string]string{
			"personal": personalSrv.URL,
			"team":     "", // explicitly empty: pre-login state
		},
		QueueCapacity:  100,
		WALDir:         t.TempDir(), // WAL is the upload outbox in the new model
		BatchSize:      5,
		UploadInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	mkEvent := func(id, routeSource string) ReportableEvent {
		return ReportableEvent{
			EventID:       id,
			OrgID:         "org1",
			RouteSource:   routeSource,
			EventTime:     aikeytime.Now(),
			OccurredAt:    aikeytime.Now(),
			RequestStatus: "success",
			RequestCount:  1,
		}
	}
	evP1 := mkEvent("p1", "personal")
	reporter.Report(&evP1)
	evT1 := mkEvent("t1", "team") // dropped — no destination
	reporter.Report(&evT1)

	time.Sleep(200 * time.Millisecond)
	reporter.Close()

	if got := personalCount.Load(); got != 1 {
		t.Errorf("personal collector got %d events, want 1", got)
	}
	m := reporter.Metrics()
	if m.Dropped < 1 {
		t.Errorf("expected at least 1 dropped (team event with no dest), got %d", m.Dropped)
	}
}

// TestReporter_NoDropAllWALd replaces the old TestReporter_DropWhenQueueFull.
// The WAL-as-outbox model has no in-memory queue, so there is no "queue full"
// drop: every reported event is appended to the WAL (the durable buffer) and
// nothing is discarded regardless of upload backpressure. This test pins that
// new contract — Generated == Reported, Dropped == 0, and all events are
// durably on disk for a (possibly offline) later upload.
func TestReporter_NoDropAllWALd(t *testing.T) {
	dir := t.TempDir()
	// No collector URL → upload loop not started; events must still all WAL.
	reporter, err := NewReporter(&ReporterConfig{
		WALDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()

	for i := 0; i < 5; i++ {
		reporter.Report(&ReportableEvent{
			EventID:       "e" + string(rune('0'+i)),
			OrgID:         "org1",
			EventTime:     aikeytime.Now(),
			OccurredAt:    aikeytime.Now(),
			RequestStatus: "success",
			RequestCount:  1,
		})
	}

	m := reporter.Metrics()
	if m.Generated != 5 {
		t.Errorf("generated=%d, want 5", m.Generated)
	}
	if m.Dropped != 0 {
		t.Errorf("dropped=%d, want 0 (WAL buffers, never drops)", m.Dropped)
	}
	// All 5 events must be durably in the WAL.
	entries, err := ReadAllWAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Errorf("WAL has %d entries, want 5 (every event WAL'd)", len(entries))
	}
}

func TestWALWriter_Append(t *testing.T) {
	dir := t.TempDir()
	wal, err := NewWALWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()

	wal.Append(&ReportableEvent{
		EventID:       "e1",
		OrgID:         "org1",
		EventTime:     aikeytime.Now(),
		OccurredAt:    aikeytime.Now(),
		RequestStatus: "success",
		RequestCount:  1,
	})

	wal.Append(&ReportableEvent{
		EventID:       "e2",
		OrgID:         "org1",
		EventTime:     aikeytime.Now(),
		OccurredAt:    aikeytime.Now(),
		RequestStatus: "success",
		RequestCount:  1,
	})

	if wal.AppendFailedTotal() != 0 {
		t.Errorf("unexpected append failures: %d", wal.AppendFailedTotal())
	}
}

// ── 2026-05-11 B1 phase: per-route credential dispatch ────────────────
//
// reporter doUpload now resolves a Credential per-RouteSource group.
// These tests pin the contract a future refactor would have to keep:
//
//   1. A per-route Credential's Bearer() drives the Authorization header
//      for that group; sibling groups get their own credentials.
//   2. Empty per-route credential map → legacy CollectorToken still
//      works (backward compat with pre-B1 deployments).
//   3. Bearer() error from the credential surfaces as a 401-class
//      terminal upload error (event lands in dead-letter, no retry
//      spin against a stale token).
//   4. Credential-free deployments (no per-route + no legacy token) →
//      request goes without Authorization, server decides.

// recordingServer captures the Authorization header from each batch
// POST so per-route routing tests can assert "team's batch carried the
// team credential bearer, not the personal one."
func recordingServer(t *testing.T, counter *atomic.Int64, gotAuth *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		counter.Add(int64(len(req.Events)))
		_ = json.NewEncoder(w).Encode(batchResponse{Accepted: len(req.Events)})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestReporter_PrimaryRouteSource locks the canary's "ride the real route"
// behavior: the probe must pick a credentialed route first (so it authenticates
// like business traffic on cluster), fall to a configured route URL when no
// credential exists (Personal/Trial local collector), and return "" only when
// nothing is wired (legacy CollectorURL fall-through). Regression guard for
// 20260612-compliance-chain-audit-and-lobster-gap.md (canary 401 root cause).
func TestReporter_PrimaryRouteSource(t *testing.T) {
	cases := []struct {
		name  string
		creds map[string]Credential
		urls  map[string]string
		want  string
	}{
		{
			name:  "credentialed team wins (cluster)",
			creds: map[string]Credential{"team": &StaticTokenCredential{Token: "jwt"}},
			urls:  map[string]string{"personal": "http://local", "team": "http://remote"},
			want:  "team",
		},
		{
			name:  "no credential falls to configured route url (personal/trial)",
			creds: nil,
			urls:  map[string]string{"personal": "http://local"},
			want:  "personal",
		},
		{
			name:  "nothing configured returns empty (legacy fall-through)",
			creds: nil,
			urls:  nil,
			want:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewReporter(&ReporterConfig{
				CollectorURL:              "http://legacy",
				CollectorRoutes:           tc.urls,
				CollectorRouteCredentials: tc.creds,
				QueueCapacity:             10,
				WALDir:                    t.TempDir(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := r.PrimaryRouteSource(); got != tc.want {
				t.Fatalf("PrimaryRouteSource() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReporter_PerRouteCredential_DispatchesCorrectBearer(t *testing.T) {
	var personalCount, teamCount atomic.Int64
	var personalAuth, teamAuth atomic.Value
	personalAuth.Store("")
	teamAuth.Store("")

	personalSrv := recordingServer(t, &personalCount, &personalAuth)
	teamSrv := recordingServer(t, &teamCount, &teamAuth)

	reporter, err := NewReporter(&ReporterConfig{
		CollectorRoutes: map[string]string{
			"personal": personalSrv.URL,
			"team":     teamSrv.URL,
		},
		// Legacy token serves as the personal credential (no per-route
		// override). Per-route credential for team is a static "user JWT"
		// stand-in — exercises the same code path RefreshableJWT will use
		// in production.
		CollectorToken: "legacy-svc-token",
		CollectorRouteCredentials: map[string]Credential{
			"team": &StaticTokenCredential{Token: "user-jwt-for-team"},
		},
		QueueCapacity:  100,
		WALDir:         t.TempDir(), // WAL is the upload outbox in the new model
		BatchSize:      5,
		UploadInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	mk := func(id, rs string) ReportableEvent {
		return ReportableEvent{
			EventID: id, OrgID: "o", RouteSource: rs,
			EventTime: aikeytime.Now(), OccurredAt: aikeytime.Now(),
			RequestStatus: "success", RequestCount: 1,
		}
	}
	evP1 := mk("p1", "personal")
	reporter.Report(&evP1)
	evT1 := mk("t1", "team")
	reporter.Report(&evT1)

	time.Sleep(200 * time.Millisecond)
	reporter.Close()

	if personalCount.Load() != 1 || teamCount.Load() != 1 {
		t.Fatalf("counts: personal=%d team=%d (want 1/1)", personalCount.Load(), teamCount.Load())
	}
	if got := personalAuth.Load().(string); got != "Bearer legacy-svc-token" {
		t.Errorf("personal route should fall back to legacy CollectorToken; got %q", got)
	}
	if got := teamAuth.Load().(string); got != "Bearer user-jwt-for-team" {
		t.Errorf("team route should use per-route credential; got %q", got)
	}
}

// Empty per-route map (B1 default until B4 wires user.yaml credentials)
// must keep the legacy single-CollectorToken path working unchanged —
// any reporter v1 deployment that didn't ship per-route credentials must
// continue to upload exactly as before.
func TestReporter_NoPerRouteCredential_FallsBackToLegacyToken(t *testing.T) {
	var count atomic.Int64
	var gotAuth atomic.Value
	gotAuth.Store("")

	srv := recordingServer(t, &count, &gotAuth)

	reporter, err := NewReporter(&ReporterConfig{
		CollectorURL:   srv.URL,
		CollectorToken: "legacy-only",
		// No CollectorRouteCredentials at all.
		QueueCapacity:  100,
		WALDir:         t.TempDir(), // WAL is the upload outbox in the new model
		BatchSize:      5,
		UploadInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	reporter.Report(&ReportableEvent{
		EventID: "e1", OrgID: "o", RouteSource: "team",
		EventTime: aikeytime.Now(), OccurredAt: aikeytime.Now(),
		RequestStatus: "success", RequestCount: 1,
	})
	time.Sleep(200 * time.Millisecond)
	reporter.Close()

	if count.Load() != 1 {
		t.Fatalf("expected 1 event uploaded, got %d", count.Load())
	}
	if got := gotAuth.Load().(string); got != "Bearer legacy-only" {
		t.Errorf("absent per-route credential must fall back to legacy token; got %q", got)
	}
}

// erroringCredential always returns an error from Bearer() — simulates
// "refresh failed; access_token is stale". The reporter must NOT retry
// indefinitely; it must classify as terminal-401 and write to dead
// letter, otherwise a stuck credential would burn the backoff budget on
// every cycle.
type erroringCredential struct {
	msg string
}

func (e *erroringCredential) Bearer(_ context.Context) (string, error) {
	return "", fmt.Errorf("%s", e.msg)
}

func TestReporter_CredentialBearerError_LandsInDeadLetter(t *testing.T) {
	// Set up a collector that would have accepted any payload — but
	// since Bearer() errors, the upload never reaches it.
	var count atomic.Int64
	var gotAuth atomic.Value
	gotAuth.Store("")
	srv := recordingServer(t, &count, &gotAuth)

	dlDir := t.TempDir()
	reporter, err := NewReporter(&ReporterConfig{
		CollectorRoutes: map[string]string{
			"team": srv.URL,
		},
		CollectorRouteCredentials: map[string]Credential{
			"team": &erroringCredential{msg: "refresh failed: HTTP 401 from /auth/refresh"},
		},
		QueueCapacity:  100,
		BatchSize:      5,
		UploadInterval: 50 * time.Millisecond,
		WALDir:         dlDir,
		DBPath:         filepath.Join(dlDir, "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}

	reporter.Report(&ReportableEvent{
		EventID: "t1", OrgID: "o", RouteSource: "team",
		EventTime: aikeytime.Now(), OccurredAt: aikeytime.Now(),
		RequestStatus: "success", RequestCount: 1,
	})

	time.Sleep(300 * time.Millisecond)
	reporter.Close()

	if count.Load() != 0 {
		t.Fatalf("Bearer() error must short-circuit; collector saw %d events", count.Load())
	}

	// Dead letter file should contain one entry with the credential
	// error message in the response body — that's what surfaces to
	// operators triaging "where did my event go".
	dlPath := filepath.Join(dlDir, "dead_letter.jsonl")
	data, err := os.ReadFile(dlPath)
	if err != nil {
		t.Fatalf("dead letter not created: %v", err)
	}
	if !strings.Contains(string(data), "refresh failed") {
		t.Fatalf("dead letter body should carry credential error; got: %s", string(data))
	}
	if !strings.Contains(string(data), "\"event_id\":\"t1\"") &&
		!strings.Contains(string(data), `"event_id":"t1"`) {
		t.Fatalf("dead letter should include the affected event_id; got: %s", string(data))
	}
}

// Mixed batch (personal + team in same flush window) gets per-group
// dispatch — each route's batch carries its own credential. Catches a
// regression where a single shared Authorization header could leak
// across groups.
func TestReporter_MixedBatch_EachGroupGetsOwnBearer(t *testing.T) {
	var pCount, tCount atomic.Int64
	var pAuth, tAuth atomic.Value
	pAuth.Store("")
	tAuth.Store("")

	pSrv := recordingServer(t, &pCount, &pAuth)
	tSrv := recordingServer(t, &tCount, &tAuth)

	reporter, err := NewReporter(&ReporterConfig{
		CollectorRoutes: map[string]string{
			"personal": pSrv.URL,
			"team":     tSrv.URL,
		},
		CollectorRouteCredentials: map[string]Credential{
			"personal": &StaticTokenCredential{Token: "personal-cred"},
			"team":     &StaticTokenCredential{Token: "team-cred"},
		},
		QueueCapacity: 100,
		WALDir:        t.TempDir(), // WAL is the upload outbox in the new model
		// Batch size large enough that a single flush picks up both events
		BatchSize:      10,
		UploadInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	now := aikeytime.Now()
	reporter.Report(&ReportableEvent{
		EventID: "p1", OrgID: "o", RouteSource: "personal",
		EventTime: now, OccurredAt: now,
		RequestStatus: "success", RequestCount: 1,
	})
	reporter.Report(&ReportableEvent{
		EventID: "t1", OrgID: "o", RouteSource: "team",
		EventTime: now, OccurredAt: now,
		RequestStatus: "success", RequestCount: 1,
	})

	time.Sleep(200 * time.Millisecond)
	reporter.Close()

	if pCount.Load() != 1 || tCount.Load() != 1 {
		t.Fatalf("counts: personal=%d team=%d (want 1/1)", pCount.Load(), tCount.Load())
	}
	if got := pAuth.Load().(string); got != "Bearer personal-cred" {
		t.Errorf("personal got %q, want Bearer personal-cred", got)
	}
	if got := tAuth.Load().(string); got != "Bearer team-cred" {
		t.Errorf("team got %q, want Bearer team-cred", got)
	}
}

// ── 2026-05-11 dead-letter replay contract ────────────────────────────
//
// reporter.ReplayDeadLetter() re-reads dead_letter.jsonl, attempts to
// re-deliver each entry using the CURRENT reporter config, and rewrites
// the file with only the still-failing entries. These tests pin the
// behavior that backs `aikey proxy replay-dead-letter`.

// Helper: build a reporter pointed at a stub server, seed dead_letter
// with one or more pre-built entries, then drive ReplayDeadLetter()
// and inspect the result + remaining file contents.
func seedDeadLetter(t *testing.T, dir string, entries ...deadLetterEntry) {
	t.Helper()
	path := filepath.Join(dir, "dead_letter.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("seed dead_letter: %v", err)
	}
	defer f.Close()
	for _, e := range entries {
		buf, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		f.Write(buf)
		f.Write([]byte("\n"))
	}
}

func readDeadLetterEntries(t *testing.T, dir string) []deadLetterEntry {
	t.Helper()
	path := filepath.Join(dir, "dead_letter.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read dead_letter: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	out := make([]deadLetterEntry, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e deadLetterEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("parse line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

// Happy path: 2 entries dead-lettered, collector now accepts them →
// both re-deliver, dead_letter.jsonl ends up empty.
func TestReporter_ReplayDeadLetter_AllReDelivered(t *testing.T) {
	var accepted atomic.Int64
	var auth atomic.Value
	auth.Store("")
	srv := recordingServer(t, &accepted, &auth)

	dir := t.TempDir()
	reporter, err := NewReporter(&ReporterConfig{
		CollectorURL:   srv.URL,
		CollectorToken: "rotated-but-now-correct-token",
		QueueCapacity:  10,
		BatchSize:      5,
		UploadInterval: 50 * time.Millisecond,
		WALDir:         dir,
		DBPath:         filepath.Join(dir, "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()

	// Seed two entries — each carries a 1-event batch.
	seedDeadLetter(t, dir,
		deadLetterEntry{
			DeadAt:    aikeytime.Now(),
			Reason:    "terminal",
			ErrorCode: 401,
			ErrorMsg:  "old token rejected",
			Events:    []ReportableEvent{{EventID: "ev-A", OrgID: "o", RouteSource: "team", EventTime: aikeytime.Now(), OccurredAt: aikeytime.Now(), RequestStatus: "success", RequestCount: 1}},
			EventIDs:  []string{"ev-A"},
		},
		deadLetterEntry{
			DeadAt:    aikeytime.Now(),
			Reason:    "terminal",
			ErrorCode: 401,
			ErrorMsg:  "old token rejected",
			Events:    []ReportableEvent{{EventID: "ev-B", OrgID: "o", RouteSource: "team", EventTime: aikeytime.Now(), OccurredAt: aikeytime.Now(), RequestStatus: "success", RequestCount: 1}},
			EventIDs:  []string{"ev-B"},
		},
	)

	result, err := reporter.ReplayDeadLetter(context.Background())
	if err != nil {
		t.Fatalf("ReplayDeadLetter: %v", err)
	}
	if result.EntriesScanned != 2 || result.EntriesReplayedOK != 2 || result.EntriesStillFailing != 0 {
		t.Fatalf("expected 2/2/0, got %+v", result)
	}
	if result.EventsReplayedOK != 2 {
		t.Errorf("events_replayed_ok: got %d want 2", result.EventsReplayedOK)
	}
	if got := readDeadLetterEntries(t, dir); len(got) != 0 {
		t.Errorf("dead_letter.jsonl should be empty after full re-delivery; got %d entries", len(got))
	}
	if accepted.Load() != 2 {
		t.Errorf("server should have seen 2 events; got %d", accepted.Load())
	}
}

// Mixed path: server returns 401 (collector still rejects), so all
// entries stay in dead-letter. Confirms we don't accidentally drop
// entries that we couldn't re-deliver.
func TestReporter_ReplayDeadLetter_StillFailingStays(t *testing.T) {
	// Server that always 401s — simulates "JWT_SECRET still wrong".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	dir := t.TempDir()
	reporter, err := NewReporter(&ReporterConfig{
		CollectorURL:   srv.URL,
		CollectorToken: "still-wrong",
		QueueCapacity:  10,
		BatchSize:      5,
		UploadInterval: 50 * time.Millisecond,
		WALDir:         dir,
		DBPath:         filepath.Join(dir, "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()

	seedDeadLetter(t, dir,
		deadLetterEntry{
			DeadAt:   aikeytime.Now(),
			Reason:   "terminal",
			Events:   []ReportableEvent{{EventID: "ev-A", OrgID: "o", RouteSource: "team", EventTime: aikeytime.Now(), OccurredAt: aikeytime.Now(), RequestStatus: "success", RequestCount: 1}},
			EventIDs: []string{"ev-A"},
		},
	)

	result, err := reporter.ReplayDeadLetter(context.Background())
	if err != nil {
		t.Fatalf("ReplayDeadLetter: %v", err)
	}
	if result.EntriesReplayedOK != 0 || result.EntriesStillFailing != 1 {
		t.Fatalf("expected 0 ok / 1 still-failing, got %+v", result)
	}
	if got := readDeadLetterEntries(t, dir); len(got) != 1 {
		t.Errorf("entry must stay in file when re-delivery fails; got %d", len(got))
	}
	if !strings.Contains(result.LastError, "401") {
		t.Errorf("last_error should reflect HTTP 401; got %q", result.LastError)
	}
}

// File missing is a benign no-op (operator triggered replay on a
// freshly-installed proxy with no failures yet).
func TestReporter_ReplayDeadLetter_NoFileIsNoOp(t *testing.T) {
	dir := t.TempDir()
	reporter, err := NewReporter(&ReporterConfig{
		CollectorURL:   "http://nope.invalid",
		QueueCapacity:  10,
		BatchSize:      5,
		UploadInterval: 50 * time.Millisecond,
		WALDir:         dir,
		DBPath:         filepath.Join(dir, "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()

	result, err := reporter.ReplayDeadLetter(context.Background())
	if err != nil {
		t.Fatalf("missing file should be no-op, got: %v", err)
	}
	if result.EntriesScanned != 0 {
		t.Errorf("expected 0 entries scanned, got %d", result.EntriesScanned)
	}
}

// Malformed line in dead_letter.jsonl: must not crash; line stays in
// place for operator inspection, valid lines still process normally.
func TestReporter_ReplayDeadLetter_MalformedLineSkipped(t *testing.T) {
	var accepted atomic.Int64
	var auth atomic.Value
	auth.Store("")
	srv := recordingServer(t, &accepted, &auth)

	dir := t.TempDir()
	reporter, err := NewReporter(&ReporterConfig{
		CollectorURL:   srv.URL,
		CollectorToken: "ok",
		QueueCapacity:  10,
		BatchSize:      5,
		UploadInterval: 50 * time.Millisecond,
		WALDir:         dir,
		DBPath:         filepath.Join(dir, "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()

	// Hand-craft mixed file: bad line + valid entry.
	validJSON, _ := json.Marshal(deadLetterEntry{
		DeadAt:   aikeytime.Now(),
		Reason:   "terminal",
		Events:   []ReportableEvent{{EventID: "ev-OK", OrgID: "o", RouteSource: "team", EventTime: aikeytime.Now(), OccurredAt: aikeytime.Now(), RequestStatus: "success", RequestCount: 1}},
		EventIDs: []string{"ev-OK"},
	})
	path := filepath.Join(dir, "dead_letter.jsonl")
	os.WriteFile(path, []byte("{not-json garbage line\n"+string(validJSON)+"\n"), 0o600)

	result, err := reporter.ReplayDeadLetter(context.Background())
	if err != nil {
		t.Fatalf("ReplayDeadLetter: %v", err)
	}
	if result.EntriesReplayedOK != 1 {
		t.Errorf("valid line should re-deliver; got %+v", result)
	}
	// Malformed line MUST stay (operator inspect / repair manually).
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "garbage line") {
		t.Errorf("malformed line should be preserved; file:\n%s", string(data))
	}
	if strings.Contains(string(data), "ev-OK") {
		t.Errorf("re-delivered entry should be removed; file:\n%s", string(data))
	}
}
