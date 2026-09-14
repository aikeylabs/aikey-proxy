package supervisor

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/proxy/asyncscan"
	"github.com/AiKeyLabs/pkg/deepscan"
)

// Which ledger an async result lands in.
//
// 🔴 These run the REAL asyncSubmitFunc → fileAsyncResult → events.Reporter
// chain against two recording ingests, because the defect they guard was a
// flag lost BETWEEN those hops: every piece was routed correctly at submit time
// and still filed as "team" afterwards.
// bugfix: workflow/CI/bugfix/20260913-async-scan-filed-personal-findings-as-team.md

type ingestRecorder struct {
	mu     sync.Mutex
	bodies []string
	srv    *httptest.Server
}

func newIngestRecorder(t *testing.T) *ingestRecorder {
	t.Helper()
	rec := &ingestRecorder{}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/v1/compliance/events" {
			rec.mu.Lock()
			rec.bodies = append(rec.bodies, string(b))
			rec.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted_ids":[]}`))
	}))
	t.Cleanup(rec.srv.Close)
	return rec
}

func (r *ingestRecorder) posts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.bodies...)
}

// fileOne submits one piece through the real lane routing, then files a result
// with a single rule finding in the tail for whatever job the lane produced.
func fileOne(t *testing.T, s *Supervisor, rep *events.Reporter, piece asyncscan.CommittedPiece, traceID string) {
	t.Helper()
	lane := newLaneForTest()
	local := &fakeExec{}
	lane.localSubmit = local.Submit
	if !s.asyncSubmitFunc(lane)(piece, asyncscan.RequestIdentity{TenantID: "org_a", TraceID: traceID, ScopeKey: "au-" + traceID}) {
		t.Fatal("the lane refused the piece")
	}
	if len(local.got) != 1 {
		t.Fatalf("local executor got %d jobs, want 1", len(local.got))
	}
	job := local.got[0]
	s.fileAsyncResult(lane, rep, deepscan.ResultFrame{
		JobID: job.JobID, Status: deepscan.StatusComplete,
		Findings: []deepscan.Finding{{
			Engine: deepscan.EngineRules, Category: "pii", EntityType: "CN_PHONE",
			Severity: "high", Confidence: 90, Start: len(piece.Text) - 11, End: len(piece.Text),
		}},
	})
}

func routingReporter(t *testing.T, team, personal *ingestRecorder) *events.Reporter {
	t.Helper()
	dir := t.TempDir()
	rep, err := events.NewReporter(&events.ReporterConfig{
		CollectorRoutes: map[string]string{"team": team.srv.URL, "personal": personal.srv.URL},
		WALDir:          dir,
		DBPath:          filepath.Join(dir, "events.db"),
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	t.Cleanup(func() { rep.Close() })
	return rep
}

func tailPiece(personal bool) asyncscan.CommittedPiece {
	return asyncscan.CommittedPiece{
		Text: strings.Repeat("x", 40_000) + "13800138000", HeadBytes: 16 << 10,
		Source: "request", Personal: personal,
	}
}

func TestFileAsyncResult_PersonalFindingsGoToTheLocalLedgerOnly(t *testing.T) {
	team, personal := newIngestRecorder(t), newIngestRecorder(t)
	s := &Supervisor{cfg: &config.Config{}}
	fileOne(t, s, routingReporter(t, team, personal), tailPiece(true), "t-personal")

	if got := team.posts(); len(got) != 0 {
		t.Fatalf("a PERSONAL piece's findings were uploaded to the team/master ingest %d time(s): %v", len(got), got)
	}
	got := personal.posts()
	if len(got) != 1 {
		t.Fatalf("the local ledger received %d posts, want 1 — personal findings were lost", len(got))
	}
	if !strings.Contains(got[0], `"t-personal"`) {
		t.Fatalf("local ledger post does not carry the turn's trace id: %s", got[0])
	}
	if strings.Contains(got[0], "scan_coverage") {
		t.Fatalf("local ledger post carries scan_coverage, which the local store cannot hold: %s", got[0])
	}
}

func TestFileAsyncResult_TeamFindingsGoToMasterAndAreMirroredLocally(t *testing.T) {
	team, personal := newIngestRecorder(t), newIngestRecorder(t)
	s := &Supervisor{cfg: &config.Config{}}
	mode := string(asyncscan.TeamAsyncScanLocal)
	s.teamAsyncScan.Store(&mode)
	fileOne(t, s, routingReporter(t, team, personal), tailPiece(false), "t-team")

	if got := team.posts(); len(got) != 1 {
		t.Fatalf("team findings reached the master ingest %d time(s), want 1", len(got))
	}
	got := personal.posts()
	if len(got) != 1 {
		t.Fatalf("team findings were mirrored locally %d time(s), want 1", len(got))
	}
	if !strings.Contains(got[0], `"route_source":"team"`) {
		t.Fatalf("the local mirror is not labelled route_source=team, so the local page cannot tell it apart: %s", got[0])
	}
}

// TestAsyncExecutorChild_ReturnsFindingsToTheProxy — the background detector
// runs in return-events mode, so it never uploads on its own and the proxy stays
// the single filer of what this lane finds.
func TestAsyncExecutorChild_ReturnsFindingsToTheProxy(t *testing.T) {
	s := &Supervisor{cfg: &config.Config{}}
	cfg := s.asyncExecutorChildConfig("/bin/detector", nil)
	found := false
	for _, kv := range cfg.ExtraEnv {
		if kv == "AIKEY_COMPLIANCE_RETURN_EVENTS=1" {
			found = true
		}
		if strings.HasPrefix(kv, "AIKEY_DEEPSCAN_SOCKET=") && kv != "AIKEY_DEEPSCAN_SOCKET=" {
			t.Fatalf("the background detector inherits a deep-scan socket (%q) — content would be scanned twice", kv)
		}
	}
	if !found {
		t.Fatalf("background detector env lacks AIKEY_COMPLIANCE_RETURN_EVENTS=1: %v", cfg.ExtraEnv)
	}
	// And the spawn path uses this config, not a hand-built copy of it.
	if src := readSource(t, "asyncscan_lane.go"); !strings.Contains(src, "cfg := s.asyncExecutorChildConfig(binPath, binArgs)") {
		t.Fatal("asyncExecutorSpawn does not build its child from asyncExecutorChildConfig")
	}
}
