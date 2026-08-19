package events

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// capturedReq records one inbound collector call for assertions.
type capturedReq struct {
	auth string
	raw  string
	body contentBatchRequest
}

// mockContentCollector is an httptest server standing in for the team collector's
// /v1/conversation-records:batch endpoint. status/contiguous are set per test.
type mockContentCollector struct {
	srv        *httptest.Server
	contiguous map[string]int64
	reqs       []capturedReq
	status     int
	mu         sync.Mutex
}

func newMockCollector(t *testing.T, status int, contiguous map[string]int64) *mockContentCollector {
	t.Helper()
	m := &mockContentCollector{status: status, contiguous: contiguous}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/conversation-records:batch" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var req contentBatchRequest
		_ = json.Unmarshal(raw, &req)
		m.mu.Lock()
		m.reqs = append(m.reqs, capturedReq{auth: r.Header.Get("Authorization"), body: req, raw: string(raw)})
		st, cont := m.status, m.contiguous
		m.mu.Unlock()
		if st < 200 || st >= 300 {
			w.WriteHeader(st)
			_, _ = w.Write([]byte(`{"error":"mock failure"}`))
			return
		}
		resp := contentBatchResponse{Accepted: len(req.Records), ContiguousSeq: cont}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockContentCollector) calls() []capturedReq {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]capturedReq, len(m.reqs))
	copy(out, m.reqs)
	return out
}

// seedContentWAL writes seq 1..n for one source, each in its own file (small
// maxBytes forces a roll per entry), and Syncs. Returns the WAL.
func seedContentWAL(t *testing.T, n int) *ContentWAL {
	t.Helper()
	w, err := NewContentWAL(t.TempDir(), 150, 100) // ~1 entry/file, high cap → no eviction
	if err != nil {
		t.Fatalf("new content wal: %v", err)
	}
	for i := int64(1); i <= int64(n); i++ {
		rec := json.RawMessage(fmt.Sprintf(`{"event_id":"ev%02d","pad":"xxxxxxxxxxxxxxxxxxxx"}`, i))
		w.Append("p1", i, rec)
	}
	w.Sync()
	return w
}

func newTestContentReporter(collectorURL string, wal *ContentWAL) *ContentReporter {
	return NewContentReporter(&ContentReporterConfig{
		CollectorURL:    collectorURL,
		Credential:      &StaticTokenCredential{Token: "test-token"},
		ProxyInstanceID: "proxy-1",
		BatchSize:       100,
	}, wal)
}

// Bug-4 regression (2026-06-17): cluster worker nodes have NO per-route team
// Credential; they authenticate the collector with the static CollectorToken
// (cluster service token), exactly as the usage reporter does. Without this
// fallback, cluster-node content uploads hit 401 "invalid or missing service
// token" and conversation capture never persists (form-①/③). Bugfix:
// 2026-06-17-conversation-audit-cluster-content-reporter-collector-token.md
func TestContentReporter_CollectorTokenFallbackWhenNoCredential(t *testing.T) {
	m := newMockCollector(t, http.StatusOK, map[string]int64{"p1": 2})
	wal := seedContentWAL(t, 2)
	r := NewContentReporter(&ContentReporterConfig{
		CollectorURL:    m.srv.URL,
		Credential:      nil, // cluster worker node: no per-route team credential
		CollectorToken:  "cluster-svc-token",
		ProxyInstanceID: "proxy-1",
		BatchSize:       100,
	}, wal)
	r.drainOnce(context.Background(), true)
	calls := m.calls()
	if len(calls) != 1 {
		t.Fatalf("collector calls=%d want 1", len(calls))
	}
	if calls[0].auth != "Bearer cluster-svc-token" {
		t.Fatalf("authorization=%q want %q (CollectorToken fallback)", calls[0].auth, "Bearer cluster-svc-token")
	}
}

// Happy path: all entries upload in one batch with the right shape + bearer; on a
// contiguous response sentSeq and confirmedSeq advance and confirmed files prune
// (current file survives); a second drain is a no-op (no re-upload).
func TestContentReporter_HappyPathUploadsAdvancesPrunes(t *testing.T) {
	m := newMockCollector(t, http.StatusOK, map[string]int64{"p1": 5})
	wal := seedContentWAL(t, 5)
	r := newTestContentReporter(m.srv.URL, wal)

	r.drainOnce(context.Background(), true)

	calls := m.calls()
	if len(calls) != 1 {
		t.Fatalf("collector calls=%d want 1 (all 5 entries fit one batch)", len(calls))
	}
	c := calls[0]
	if c.auth != "Bearer test-token" {
		t.Fatalf("authorization=%q want %q", c.auth, "Bearer test-token")
	}
	if c.body.Source != "aikey-proxy" {
		t.Fatalf("source=%q want aikey-proxy", c.body.Source)
	}
	if c.body.ProxyInstanceID != "proxy-1" {
		t.Fatalf("proxy_instance_id=%q want proxy-1", c.body.ProxyInstanceID)
	}
	if len(c.body.Records) != 5 {
		t.Fatalf("records=%d want 5", len(c.body.Records))
	}
	// SeqAlloc nil → allocated_seq must be omitted from the wire.
	if strings.Contains(c.raw, "allocated_seq") {
		t.Fatalf("allocated_seq present with nil SeqAlloc: %s", c.raw)
	}
	// Record payload forwarded verbatim.
	if !strings.Contains(string(c.body.Records[0]), "ev01") {
		t.Fatalf("first record not forwarded verbatim: %s", c.body.Records[0])
	}

	r.mu.Lock()
	sent, conf := r.sentSeq["p1"], r.confirmedSeq["p1"]
	gate := r.nextUploadAttempt
	r.mu.Unlock()
	if sent != 5 {
		t.Fatalf("sentSeq[p1]=%d want 5", sent)
	}
	if conf != 5 {
		t.Fatalf("confirmedSeq[p1]=%d want 5", conf)
	}
	if !gate.IsZero() {
		t.Fatalf("backoff gate armed after success: %v", gate)
	}

	// Confirmed files pruned; only the current file (seq 5) survives.
	left, _ := ReadAllContentWAL(wal.Dir())
	if len(left) != 1 || left[0].SourceSeq != 5 {
		t.Fatalf("after prune got %d entries want [seq5] (current file survives)", len(left))
	}

	// Second drain: seq5 ≤ sentSeq → skipped, no new upload.
	r.drainOnce(context.Background(), true)
	if got := len(m.calls()); got != 1 {
		t.Fatalf("collector calls=%d after second drain want 1 (already-sent skipped)", got)
	}
}

// Retryable (5xx): cursors stay put (re-sent next pass), backoff gate is armed,
// nothing pruned.
func TestContentReporter_RetryableLeavesCursorsAndArmsBackoff(t *testing.T) {
	m := newMockCollector(t, http.StatusInternalServerError, nil)
	wal := seedContentWAL(t, 5)
	r := newTestContentReporter(m.srv.URL, wal)

	r.drainOnce(context.Background(), true)

	if got := len(m.calls()); got != 1 {
		t.Fatalf("collector calls=%d want 1", got)
	}
	r.mu.Lock()
	sent, conf, fails := r.sentSeq["p1"], r.confirmedSeq["p1"], r.consecutiveFailures
	gate := r.nextUploadAttempt
	r.mu.Unlock()
	if sent != 0 {
		t.Fatalf("sentSeq[p1]=%d want 0 (retryable must not advance)", sent)
	}
	if conf != 0 {
		t.Fatalf("confirmedSeq[p1]=%d want 0", conf)
	}
	if fails == 0 {
		t.Fatalf("consecutiveFailures=0 want >0 after retryable failure")
	}
	if gate.IsZero() {
		t.Fatalf("backoff gate not armed after retryable failure")
	}
	// All entries still present (nothing confirmed → nothing pruned).
	if left, _ := ReadAllContentWAL(wal.Dir()); len(left) != 5 {
		t.Fatalf("entries=%d want 5 (retryable keeps WAL intact)", len(left))
	}
}

// Terminal (4xx, non-429): batch dropped — sentSeq advances so it is not re-sent,
// but no backoff gate (drop is immediate, not a retry) and no prune.
func TestContentReporter_TerminalDropsBatchNoBackoff(t *testing.T) {
	m := newMockCollector(t, http.StatusBadRequest, nil)
	wal := seedContentWAL(t, 3)
	r := newTestContentReporter(m.srv.URL, wal)

	r.drainOnce(context.Background(), true)

	r.mu.Lock()
	sent, conf := r.sentSeq["p1"], r.confirmedSeq["p1"]
	gate := r.nextUploadAttempt
	r.mu.Unlock()
	if sent != 3 {
		t.Fatalf("sentSeq[p1]=%d want 3 (terminal drops → advance past)", sent)
	}
	if conf != 0 {
		t.Fatalf("confirmedSeq[p1]=%d want 0 (terminal never confirms)", conf)
	}
	if !gate.IsZero() {
		t.Fatalf("backoff gate armed on terminal failure: %v (terminal must not arm backoff)", gate)
	}

	// Dropped (sentSeq advanced) → second drain does not re-upload.
	r.drainOnce(context.Background(), true)
	if got := len(m.calls()); got != 1 {
		t.Fatalf("collector calls=%d want 1 (dropped batch not retried)", got)
	}
}

// 429 is retryable (not terminal) even though it is a 4xx — matches the usage
// reporter's classifyUploadError.
func TestContentReporter_TooManyRequestsIsRetryable(t *testing.T) {
	m := newMockCollector(t, http.StatusTooManyRequests, nil)
	wal := seedContentWAL(t, 2)
	r := newTestContentReporter(m.srv.URL, wal)

	r.drainOnce(context.Background(), true)

	r.mu.Lock()
	sent := r.sentSeq["p1"]
	gate := r.nextUploadAttempt
	r.mu.Unlock()
	if sent != 0 {
		t.Fatalf("sentSeq[p1]=%d want 0 (429 is retryable, must not advance)", sent)
	}
	if gate.IsZero() {
		t.Fatalf("backoff gate not armed on 429 (should be retryable)")
	}
}
