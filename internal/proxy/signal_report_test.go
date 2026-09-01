package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/httpx"
)

// signal_report_test.go — covers the I5 emit path's pure + best-effort pieces.
// loop()'s 30s ticker is timing-driven and not deterministically testable, so we
// call post() directly (the loop only batches + invokes it) — see TestSignalPost*.

func TestParseUnifiedUtil5h(t *testing.T) {
	const hdr = "anthropic-ratelimit-unified-5h-utilization"
	tests := []struct {
		name   string
		set    bool
		val    string
		wantV  float64
		wantOK bool
	}{
		{"valid", true, "0.6", 0.6, true},
		{"missing", false, "", 0, false},
		{"malformed", true, "abc", 0, false},
		{"above_one", true, "1.5", 0, false},
		{"negative", true, "-0.1", 0, false},
		{"zero_ok", true, "0", 0, true},
		{"one_ok", true, "1", 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.set {
				h.Set(hdr, tt.val)
			}
			v, ok := parseUnifiedUtil5h(h)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && v != tt.wantV {
				t.Fatalf("v = %v, want %v", v, tt.wantV)
			}
		})
	}
}

func TestEnqueueNilAndEmptyAreSafe(t *testing.T) {
	// nil receiver guard: feature-off reporter must not panic.
	var nilR *signalReporter
	nilR.enqueue("c1", 100, 0.5, nil) // must not panic

	// empty credentialID is dropped — observable via the buffered channel.
	r := &signalReporter{in: make(chan signalSample, 4)}
	r.enqueue("", 100, 0.5, nil)
	if len(r.in) != 0 {
		t.Fatalf("empty credentialID should be dropped, buffered = %d", len(r.in))
	}
	r.enqueue("c1", 100, 0.5, nil)
	if len(r.in) != 1 {
		t.Fatalf("valid sample should be queued, buffered = %d", len(r.in))
	}
}

func TestSignalPostSendsBatch(t *testing.T) {
	type captured struct {
		method      string
		auth        string
		contentType string
		body        []byte
	}
	got := make(chan captured, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got <- captured{req.Method, req.Header.Get("Authorization"), req.Header.Get("Content-Type"), b}
	}))
	defer srv.Close()

	r := newSignalReporter(srv.URL, func(context.Context) (string, error) { return "tok-123", nil }, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporter returned nil")
	}
	r.post([]signalSample{{CredentialID: "c1", TS: 100, Util5h: 0.6}}, nil, nil, nil)

	c := <-got
	if c.method != http.MethodPost {
		t.Errorf("method = %q, want POST", c.method)
	}
	if c.auth != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want %q", c.auth, "Bearer tok-123")
	}
	if c.contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", c.contentType)
	}
	var decoded struct {
		Samples []signalSample `json:"samples"`
	}
	if err := json.Unmarshal(c.body, &decoded); err != nil {
		t.Fatalf("body not valid JSON: %v (raw %s)", err, c.body)
	}
	if len(decoded.Samples) != 1 || decoded.Samples[0] != (signalSample{CredentialID: "c1", TS: 100, Util5h: 0.6}) {
		t.Fatalf("decoded samples = %+v, want one {c1,100,0.6}", decoded.Samples)
	}
}

func TestSignalPostBearerErrorDoesNotPost(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	r := newSignalReporter(srv.URL, func(context.Context) (string, error) {
		return "", io.ErrUnexpectedEOF
	}, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporter returned nil")
	}
	r.post([]signalSample{{CredentialID: "c1", TS: 100, Util5h: 0.6}}, nil, nil, nil) // must not panic

	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("server hit %d times, want 0 (bearer error short-circuits)", n)
	}
}

func TestSignalReporterLoopRetriesTrendAndExposesHealth(t *testing.T) {
	var hits atomic.Int32
	bodies := make(chan []byte, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		bodies <- body
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newSignalReporterEndpoint(srv.URL, "worker-300", func(context.Context) (string, error) { return "tok", nil }, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporterEndpoint returned nil")
	}
	defer r.Close()
	r.enqueue("cred-1", 100, 0.7, nil)

	wakeUntilBody := func() []byte {
		t.Helper()
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case body := <-bodies:
				return body
			case <-tick.C:
				select {
				case r.authWake <- struct{}{}:
				default:
				}
			case <-deadline.C:
				t.Fatal("signal reporter did not flush")
				return nil
			}
		}
	}
	first := wakeUntilBody()
	if !bytes.Contains(first, []byte(`"source_id":"worker-300"`)) || !bytes.Contains(first, []byte(`"credential_id":"cred-1"`)) {
		t.Fatalf("first attempt lost source/sample: %s", first)
	}
	second := wakeUntilBody()
	if string(second) != string(first) {
		t.Fatalf("retry payload changed: first=%s second=%s", first, second)
	}

	deadline := time.Now().Add(time.Second)
	for {
		health := r.healthSnapshot()
		if health.Status == "healthy" && health.PendingSignals == 0 && health.LastSuccessAt > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retry health did not recover: %+v", health)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSignalTrendAccumulatorBoundsUniqueCredentialsAcrossSignalTypes(t *testing.T) {
	a := newSignalTrendAccumulator()
	for i := 0; i < maxPendingSignalCredentials; i++ {
		if !a.addUtil(signalSample{CredentialID: fmt.Sprintf("cred-%d", i)}) {
			t.Fatalf("credential %d was rejected before the bound", i)
		}
	}
	if dropped := a.mergeRate([]rateLimitSample{{CredentialID: "overflow", Count: 1}}); dropped != 1 {
		t.Fatalf("cross-type overflow dropped=%d, want 1", dropped)
	}
	if dropped := a.mergeRate([]rateLimitSample{{CredentialID: "cred-0", Count: 1}}); dropped != 0 {
		t.Fatalf("existing credential update dropped=%d, want 0", dropped)
	}
}

func TestSignalReporterLoopIsolatesRejectedAuthFailureFromTrend(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	bodies := make(chan []byte, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		bodies <- body
		if bytes.Contains(body, []byte(`"auth_failures"`)) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newSignalReporterEndpoint(srv.URL, "worker-1", func(context.Context) (string, error) { return "tok", nil }, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporterEndpoint returned nil")
	}
	defer r.Close()
	r.enqueue("cred-good", 100, 0.5, nil)
	deadline := time.Now().Add(time.Second)
	for len(r.in) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(r.in) > 0 {
		t.Fatal("trend was not consumed into the retry accumulator")
	}
	r.enqueueAuthFailure("cred-bad", "group-1", "seat-1", "fingerprint-1", 401, "token_revoked")

	nextBody := func() []byte {
		t.Helper()
		select {
		case body := <-bodies:
			return body
		case <-time.After(2 * time.Second):
			t.Fatal("signal reporter did not isolate both uploads")
			return nil
		}
	}
	first := nextBody()
	second := nextBody()
	if !bytes.Contains(first, []byte(`"samples"`)) || bytes.Contains(first, []byte(`"auth_failures"`)) {
		t.Fatalf("trend upload was coupled to rejected auth failure: %s", first)
	}
	if !bytes.Contains(second, []byte(`"auth_failures"`)) || bytes.Contains(second, []byte(`"samples"`)) {
		t.Fatalf("auth failure upload was not isolated: %s", second)
	}
	if pending := r.snapshotAuthFailures(); len(pending) != 1 {
		t.Fatalf("rejected auth failure was acknowledged: %+v", pending)
	}
}

func TestEnqueueRevokedNilEmptyAndNonBlocking(t *testing.T) {
	// nil receiver guard: feature-off reporter must not panic.
	var nilR *signalReporter
	nilR.enqueueRevoked("c1", "revoked") // must not panic

	// empty credentialID is dropped; valid one is queued; empty reason defaults.
	r := &signalReporter{revokedIn: make(chan revokedSample, 4)}
	r.enqueueRevoked("", "revoked")
	if len(r.revokedIn) != 0 {
		t.Fatalf("empty credentialID should be dropped, buffered = %d", len(r.revokedIn))
	}
	r.enqueueRevoked("c1", "") // empty reason → defaults to "revoked"
	if len(r.revokedIn) != 1 {
		t.Fatalf("valid revoked should be queued, buffered = %d", len(r.revokedIn))
	}
	if rv := <-r.revokedIn; rv != (revokedSample{CredentialID: "c1", Reason: "revoked"}) {
		t.Fatalf("queued = %+v, want {c1, revoked}", rv)
	}

	// non-blocking: a full buffer drops rather than blocks the forward path.
	full := &signalReporter{revokedIn: make(chan revokedSample, 1)}
	full.enqueueRevoked("c1", "revoked")
	full.enqueueRevoked("c2", "revoked") // buffer full → dropped, must not block
	if len(full.revokedIn) != 1 {
		t.Fatalf("full buffer should drop, buffered = %d", len(full.revokedIn))
	}
}

func TestSignalPostSendsRevoked(t *testing.T) {
	type captured struct {
		method string
		auth   string
		body   []byte
	}
	got := make(chan captured, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got <- captured{req.Method, req.Header.Get("Authorization"), b}
	}))
	defer srv.Close()

	r := newSignalReporter(srv.URL, func(context.Context) (string, error) { return "tok-123", nil }, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporter returned nil")
	}

	// all-revoked batch: body omits "samples" and carries only "revoked".
	r.post(nil, []revokedSample{{CredentialID: "c1", Reason: "revoked"}}, nil, nil)
	c := <-got
	if c.method != http.MethodPost {
		t.Errorf("method = %q, want POST", c.method)
	}
	if c.auth != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want %q", c.auth, "Bearer tok-123")
	}
	if want := `{"revoked":[{"credential_id":"c1","reason":"revoked"}]}`; string(c.body) != want {
		t.Fatalf("body = %s, want %s", c.body, want)
	}

	// mixed batch: both arrays serialize.
	r.post([]signalSample{{CredentialID: "c1", TS: 100, Util5h: 0.6}},
		[]revokedSample{{CredentialID: "c2", Reason: "revoked"}}, nil, nil)
	c = <-got
	var decoded struct {
		Samples []signalSample  `json:"samples"`
		Revoked []revokedSample `json:"revoked"`
	}
	if err := json.Unmarshal(c.body, &decoded); err != nil {
		t.Fatalf("body not valid JSON: %v (raw %s)", err, c.body)
	}
	if len(decoded.Samples) != 1 || decoded.Samples[0] != (signalSample{CredentialID: "c1", TS: 100, Util5h: 0.6}) {
		t.Fatalf("decoded samples = %+v, want one {c1,100,0.6}", decoded.Samples)
	}
	if len(decoded.Revoked) != 1 || decoded.Revoked[0] != (revokedSample{CredentialID: "c2", Reason: "revoked"}) {
		t.Fatalf("decoded revoked = %+v, want one {c2,revoked}", decoded.Revoked)
	}
}

func TestAuthFailureSignalIsVersionedDurableAndRetriedUntilAccepted(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	var hits atomic.Int32
	var bodies [][]byte
	var bodiesMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		bodiesMu.Lock()
		bodies = append(bodies, body)
		bodiesMu.Unlock()
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := &signalReporter{
		url: srv.URL, bearer: func(context.Context) (string, error) { return "svc-token", nil },
		client: httpx.NewSwappableDirect(time.Second), authFailures: make(map[string]authFailureSample),
		authIn: make(chan authFailureSample, 4), authWake: make(chan struct{}, 1), logger: slog.Default(),
	}
	// Missing token version is unsafe: a delayed signal could invalidate a new
	// re-login, so it must not enter the outbox.
	r.enqueueAuthFailure("c1", "g1", "s1", "", 401, "token_revoked")
	if len(r.snapshotAuthFailures()) != 0 {
		t.Fatal("unversioned auth failure entered outbox")
	}
	r.enqueueAuthFailure("c1", "g1", "s1", "fingerprint-1", 401, "token_revoked")
	r.ingestAuthFailures([]authFailureSample{<-r.authIn})
	pending := r.snapshotAuthFailures()
	if len(pending) != 1 || pending[0].TokenFingerprint != "fingerprint-1" {
		t.Fatalf("versioned auth failure not queued: %+v", pending)
	}
	path, err := signalAuthFailurePath()
	if err != nil {
		t.Fatalf("outbox path: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("durable outbox missing: %v", err)
	}

	if r.postAll(nil, nil, pending, nil, nil) {
		t.Fatal("503 upload reported success")
	}
	if len(r.snapshotAuthFailures()) != 1 {
		t.Fatal("failed upload dropped durable auth failure")
	}
	if !r.postAll(nil, nil, pending, nil, nil) {
		t.Fatal("retry upload did not succeed")
	}
	r.acknowledgeAuthFailures(pending)
	if len(r.snapshotAuthFailures()) != 0 {
		t.Fatal("accepted upload remained pending")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("empty outbox file was not removed: %v", err)
	}

	bodiesMu.Lock()
	defer bodiesMu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("upload attempts=%d, want 2", len(bodies))
	}
	var decoded struct {
		AuthFailures []authFailureSample `json:"auth_failures"`
	}
	if err := json.Unmarshal(bodies[1], &decoded); err != nil || len(decoded.AuthFailures) != 1 {
		t.Fatalf("auth failure wire body invalid: err=%v body=%s", err, bodies[1])
	}
	if got := decoded.AuthFailures[0]; got.CredentialID != "c1" || got.OAuthGroupID != "g1" || got.SeatID != "s1" || got.TokenFingerprint != "fingerprint-1" {
		t.Fatalf("auth failure route/version lost on wire: %+v", got)
	}
}

func TestAuthFailureOutboxHydratesOnlyVersionedEntries(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	writer := &signalReporter{
		authFailures: make(map[string]authFailureSample), authIn: make(chan authFailureSample, 1),
		authWake: make(chan struct{}, 1), logger: slog.Default(),
	}
	writer.enqueueAuthFailure("c1", "g1", "s1", "fp-1", 401, "token_revoked")
	writer.ingestAuthFailures([]authFailureSample{<-writer.authIn})

	reader := &signalReporter{authFailures: make(map[string]authFailureSample), logger: slog.Default()}
	reader.hydrateAuthFailures()
	got := reader.snapshotAuthFailures()
	if len(got) != 1 || got[0].TokenFingerprint != "fp-1" {
		t.Fatalf("durable auth failure did not hydrate: %+v", got)
	}
}

func TestAuthFailureBurstDeduplicatesBeforeBoundedWriter(t *testing.T) {
	r := &signalReporter{
		authIn: make(chan authFailureSample, maxPendingAuthFailures),
		health: SignalReportingHealth{Status: "starting"},
	}
	for i := 0; i < 3000; i++ {
		r.enqueueAuthFailure("c1", "g1", "s1", "fp-1", 401, "token_revoked")
	}
	if got := len(r.authIn); got != 1 {
		t.Fatalf("duplicate 401 burst queued=%d records, want one route+token observation", got)
	}
	if got := r.healthSnapshot(); got.DroppedSignals != 0 {
		t.Fatalf("duplicate 401 burst consumed bounded capacity: %+v", got)
	}
}

func TestAuthFailureDeliveryBatches300AndCompactsJournal(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := &signalReporter{
		url: srv.URL, bearer: func(context.Context) (string, error) { return "svc-token", nil },
		client: httpx.NewSwappableDirect(time.Second), logger: slog.Default(),
		authFailures: make(map[string]authFailureSample), authDurable: make(map[string]authFailureSample),
	}
	failures := make([]authFailureSample, 300)
	for i := range failures {
		failures[i] = authFailureSample{
			CredentialID: fmt.Sprintf("credential-%03d", i), OAuthGroupID: "group-1",
			SeatID: fmt.Sprintf("seat-%03d", i), TokenFingerprint: fmt.Sprintf("fp-%03d", i),
			Reason: "token_revoked",
		}
	}
	r.ingestAuthFailures(failures)
	if pending := r.snapshotAuthFailures(); len(pending) != 300 {
		t.Fatalf("journal pending=%d, want 300", len(pending))
	}
	attempted, ok, detail := r.deliverAuthFailures(r.snapshotAuthFailures())
	if !attempted || !ok {
		t.Fatalf("batched auth delivery attempted=%v ok=%v detail=%q", attempted, ok, detail)
	}
	if got, want := hits.Load(), int32(3); got != want {
		t.Fatalf("300 auth failures used %d uploads, want %d bounded batches", got, want)
	}
	if pending := r.snapshotAuthFailures(); len(pending) != 0 {
		t.Fatalf("accepted batch remained pending: %d", len(pending))
	}
	path, _ := r.authFailurePath()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("empty journal was not compacted away: %v", err)
	}
}

func TestAuthFailureTransientOutageMakesOneBoundedAttemptFor300(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	r := &signalReporter{
		url: srv.URL, bearer: func(context.Context) (string, error) { return "svc-token", nil },
		client: httpx.NewSwappableDirect(time.Second), logger: slog.Default(),
		authFailures: make(map[string]authFailureSample), authDurable: make(map[string]authFailureSample),
	}
	failures := make([]authFailureSample, 300)
	for i := range failures {
		failures[i] = authFailureSample{
			CredentialID: fmt.Sprintf("credential-%03d", i), OAuthGroupID: "group-1",
			SeatID: fmt.Sprintf("seat-%03d", i), TokenFingerprint: fmt.Sprintf("fp-%03d", i),
			Reason: "token_revoked",
		}
	}
	r.ingestAuthFailures(failures)
	_, ok, _ := r.deliverAuthFailures(r.snapshotAuthFailures())
	if ok {
		t.Fatal("503 auth delivery reported success")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("Control outage amplified 300 pending failures into %d uploads, want one", got)
	}
	if pending := r.snapshotAuthFailures(); len(pending) != 300 {
		t.Fatalf("transient outage dropped pending failures: %d", len(pending))
	}
}

func TestEnableOrgSignalReporting_UsesClusterServiceEndpointAndToken(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	p := &Proxy{sourceID: "cluster-node-1"}
	p.EnableOrgSignalReporting("https://control.example.test/", "org/cluster", "svc-token")
	defer p.StopSignalReporting()
	if p.signalReporter == nil {
		t.Fatal("cluster signal reporter was not wired")
	}
	if p.signalReporter.sourceID != "cluster-node-1" {
		t.Fatalf("stable signal source=%q, want cluster-node-1", p.signalReporter.sourceID)
	}
	if got, want := p.signalReporter.url, "https://control.example.test/internal/org/org%2Fcluster/signals"; got != want {
		t.Fatalf("cluster signal endpoint=%q want %q", got, want)
	}
	token, err := p.signalReporter.bearer(context.Background())
	if err != nil || token != "svc-token" {
		t.Fatalf("cluster service credential lost: token=%q err=%v", token, err)
	}
}

func TestEnableOrgSignalReporting_PostsObservedResetSnapshotOnShutdown(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	posted := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		posted <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	p := &Proxy{sourceID: "cluster-node-1", poolCooldown: newPoolCooldownStore(), poolObservedResets: newPoolResetStore()}
	p.poolObservedResets.recordRoute("account-1", "credential-1", ObservedWindowResets{FiveHour: 2_000, SevenDay: 8_000})
	p.EnableOrgSignalReporting(srv.URL, "org-1", "svc-token")
	p.StopSignalReporting()

	select {
	case body := <-posted:
		var decoded struct {
			Observed []observedWindowResetSample `json:"observed_window_resets"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		want := observedWindowResetSample{CredentialID: "credential-1", WindowResetAt: 2_000, Window7dResetAt: 8_000}
		if len(decoded.Observed) != 1 || decoded.Observed[0] != want {
			t.Fatalf("Cluster observed reset wire drifted: body=%s decoded=%+v", body, decoded.Observed)
		}
	default:
		t.Fatal("shutdown reconcile did not post Cluster observed reset snapshot")
	}
}

func TestEnableSignalReporting_DoesNotDuplicateMemberPathZResetWriter(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	p := &Proxy{sourceID: "member-proxy", poolCooldown: newPoolCooldownStore(), poolObservedResets: newPoolResetStore()}
	p.EnableSignalReporting("https://control.example.test", func(context.Context) (string, error) { return "jwt", nil })
	defer p.StopSignalReporting()
	if got := p.signalReporter.snapshotObservedWindowResets(); got != nil {
		t.Fatalf("member reporter gained a second Path-Z writer: %+v", got)
	}
}

func TestSignalReportingHealthSnapshotSurfacesMissingWiring(t *testing.T) {
	p := &Proxy{}
	health := p.SignalReportingHealthSnapshot()
	if health == nil || health.Status != "disabled" {
		t.Fatalf("missing reporter must be externally visible, got %+v", health)
	}
}

func TestSignalReportingHealthDropStaysDegradedUntilSuccess(t *testing.T) {
	r := &signalReporter{health: SignalReportingHealth{Status: "starting"}}
	r.recordSignalDrop(1)
	r.recordSignalUpload(false, "signal upload failed")
	if got := r.healthSnapshot(); got.Status != "degraded" || got.DroppedSignals != 1 {
		t.Fatalf("failed retry hid buffer loss: %+v", got)
	}
	r.recordSignalUpload(true, "")
	if got := r.healthSnapshot(); got.Status != "healthy" || got.ConsecutiveFailures != 0 {
		t.Fatalf("successful retry did not recover health: %+v", got)
	}
}

func TestIncrRateLimitNilAndEmpty(t *testing.T) {
	// nil receiver guard: feature-off reporter must not panic.
	var nilR *signalReporter
	nilR.incrRateLimit("c1") // must not panic

	// nil rlCounts map → incrRateLimit must lazy-init, not panic; empty id drops.
	r := &signalReporter{}
	r.incrRateLimit("") // empty credentialID dropped (no lazy-init needed)
	if len(r.snapshotRateLimits()) != 0 {
		t.Fatal("empty credentialID should be dropped")
	}
	r.incrRateLimit("c1") // lazy-inits the map
	if rl := r.snapshotRateLimits(); len(rl) != 1 || rl[0].Count != 1 {
		t.Fatalf("after lazy init = %+v, want one {c1, count 1}", rl)
	}
}

func TestRateLimitCounting(t *testing.T) {
	r := &signalReporter{rlCounts: make(map[string]int)}
	// two 429s + one 403 for c1 → count 3; c2 is never seen → stays absent.
	r.incrRateLimit("c1")
	r.incrRateLimit("c1")
	r.incrRateLimit("c1")
	rl := r.snapshotRateLimits()
	if len(rl) != 1 {
		t.Fatalf("snapshot = %+v, want exactly one entry", rl)
	}
	if rl[0] != (rateLimitSample{CredentialID: "c1", Count: 3, WindowSecs: 30, Risk429Count: 3}) {
		t.Fatalf("snapshot[0] = %+v, want {c1, 3, 30}", rl[0])
	}
}

// TestRateLimitForbiddenSubcount (2026-08-15 方案 c): 403s ride the same
// counter AND a separate forbidden tally, so the master drawer can distinguish
// suspension evidence from ordinary 429 quota rhythm. Both reset together.
func TestRateLimitForbiddenSubcount(t *testing.T) {
	r := &signalReporter{rlCounts: make(map[string]int)}
	r.incrRateLimitHop("c1", false, false) // a 429
	r.incrRateLimitHop("c1", false, true)  // a 403
	r.incrRateLimitHop("c1", true, true)   // a 403 on a fallback hop
	rl := r.snapshotRateLimits()
	if len(rl) != 1 || rl[0].Count != 3 || rl[0].ForbiddenCount != 2 || rl[0].FallbackCount != 1 || rl[0].Risk429Count != 1 {
		t.Fatalf("snapshot = %+v, want {c1 count=3 forbidden=2 fallback=1 risk429=1}", rl)
	}
	// One-window contract: the forbidden tally resets with the flush.
	r.incrRateLimitHop("c1", false, false)
	if rl := r.snapshotRateLimits(); len(rl) != 1 || rl[0].ForbiddenCount != 0 {
		t.Fatalf("forbidden tally leaked across windows: %+v", rl)
	}
}

func TestRateLimitResetAfterFlush(t *testing.T) {
	r := &signalReporter{rlCounts: make(map[string]int)}
	r.incrRateLimit("c1")
	r.incrRateLimit("c1")
	if rl := r.snapshotRateLimits(); len(rl) != 1 || rl[0].Count != 2 {
		t.Fatalf("first window = %+v, want c1 count 2", rl)
	}
	// The next window emits one explicit zero so Master clears the source's
	// previous 403/risk projection; the following idle window is omitted.
	if rl := r.snapshotRateLimits(); len(rl) != 1 || rl[0].CredentialID != "c1" || rl[0].Count != 0 {
		t.Fatalf("after flush snapshot = %+v, want one explicit c1 zero", rl)
	}
	if rl := r.snapshotRateLimits(); rl != nil {
		t.Fatalf("second idle snapshot = %+v, want nil", rl)
	}
	// new increments count up from 0, not from the prior window.
	r.incrRateLimit("c1")
	if rl := r.snapshotRateLimits(); len(rl) != 1 || rl[0].Count != 1 {
		t.Fatalf("second window = %+v, want c1 count 1", rl)
	}
}

func TestRateLimitConcurrent(t *testing.T) {
	// map+mutex concurrency smoke: many goroutines incrementing the same
	// credential must total exactly N*per (run under -race to catch data races).
	r := &signalReporter{rlCounts: make(map[string]int)}
	const goroutines, per = 8, 100
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < per; j++ {
				r.incrRateLimit("c1")
			}
		}()
	}
	wg.Wait()
	rl := r.snapshotRateLimits()
	if len(rl) != 1 || rl[0].Count != goroutines*per {
		t.Fatalf("concurrent count = %+v, want one {c1, %d}", rl, goroutines*per)
	}
}

func TestSignalPostSendsRateLimits(t *testing.T) {
	got := make(chan []byte, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got <- b
	}))
	defer srv.Close()

	r := newSignalReporter(srv.URL, func(context.Context) (string, error) { return "tok-123", nil }, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporter returned nil")
	}

	// rate-limits-only batch: body omits samples + revoked, exact wire contract.
	r.post(nil, nil, []rateLimitSample{{CredentialID: "c1", Count: 3, WindowSecs: 30}}, nil)
	if want := `{"rate_limits":[{"credential_id":"c1","count":3,"window_secs":30,"risk_429_count":0}]}`; string(<-got) != want {
		t.Fatalf("rate-limits-only body mismatch, want %s", want)
	}

	// mixed batch: samples + revoked + rate_limits all serialize.
	r.post([]signalSample{{CredentialID: "c1", TS: 100, Util5h: 0.6}},
		[]revokedSample{{CredentialID: "c2", Reason: "revoked"}},
		[]rateLimitSample{{CredentialID: "c3", Count: 5, WindowSecs: 30}}, nil)
	var decoded struct {
		Samples    []signalSample    `json:"samples"`
		Revoked    []revokedSample   `json:"revoked"`
		RateLimits []rateLimitSample `json:"rate_limits"`
	}
	body := <-got
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body not valid JSON: %v (raw %s)", err, body)
	}
	if len(decoded.Samples) != 1 || decoded.Samples[0] != (signalSample{CredentialID: "c1", TS: 100, Util5h: 0.6}) {
		t.Fatalf("decoded samples = %+v, want one {c1,100,0.6}", decoded.Samples)
	}
	if len(decoded.Revoked) != 1 || decoded.Revoked[0] != (revokedSample{CredentialID: "c2", Reason: "revoked"}) {
		t.Fatalf("decoded revoked = %+v, want one {c2,revoked}", decoded.Revoked)
	}
	if len(decoded.RateLimits) != 1 || decoded.RateLimits[0] != (rateLimitSample{CredentialID: "c3", Count: 5, WindowSecs: 30}) {
		t.Fatalf("decoded rate_limits = %+v, want one {c3,5,30}", decoded.RateLimits)
	}
}

func TestSignalPostSendsWindowStatusSnapshot(t *testing.T) {
	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		got <- body
	}))
	defer srv.Close()

	r := newSignalReporterEndpoint(srv.URL, "worker-1", func(context.Context) (string, error) {
		return "test-token", nil
	}, nil)
	defer func() { _ = r.Close() }()
	windows := []windowStatusSample{{
		CredentialID: "cred-1", WindowStatus: windowStatusExhausted, WindowResetAt: 1_900_000_000,
		Window7dStatus: windowStatusExhausted, Window7dResetAt: 1_900_500_000,
	}}
	if ok, detail := r.uploadAll(nil, nil, nil, nil, nil, nil, windows); !ok {
		t.Fatalf("window status upload failed: %s", detail)
	}
	var decoded struct {
		WindowStatuses []windowStatusSample `json:"window_statuses"`
	}
	if err := json.Unmarshal(<-got, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.WindowStatuses) != 1 || decoded.WindowStatuses[0] != windows[0] {
		t.Fatalf("window status wire drifted: %+v", decoded.WindowStatuses)
	}
}

func TestSignalReporter_WindowSnapshotSuccessIsNotPendingWork(t *testing.T) {
	posted := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		posted <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newSignalReporterEndpoint(srv.URL, "worker-1", func(context.Context) (string, error) {
		return "test-token", nil
	}, nil)
	r.setWindowStatusSource(func() []windowStatusSample {
		return []windowStatusSample{{
			CredentialID: "cred-1", WindowStatus: windowStatusExhausted, WindowResetAt: time.Now().Add(time.Hour).Unix(),
		}}
	})
	if err := r.Close(); err != nil {
		t.Fatalf("close reporter: %v", err)
	}
	select {
	case <-posted:
	default:
		t.Fatal("shutdown flush did not post the live window snapshot")
	}
	if health := r.healthSnapshot(); health.PendingSignals != 0 || health.Status != "healthy" {
		t.Fatalf("successful reconcile snapshot remained pending: %+v", health)
	}
}

func TestIsHardRevoked(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		errType string
		errMsg  string
		want    bool
	}{
		{"401_revoked_msg", 401, "authentication_error", "OAuth token has been revoked", true},
		{"401_revoked_in_type", 401, "token_revoked", "", true},
		{"401_plain_expiry", 401, "authentication_error", "token expired", false},
		{"429_revoked", 429, "", "revoked", false},
		{"200_ok", 200, "", "", false},
		// codex/openai hard-revocation shapes (sub2api-derived, R37 2026-07-04):
		// errMsg is the raw body. token_invalidated has NO "revoked" substring, so
		// the old matcher missed it; the {"detail":"Unauthorized"} form is
		// non-standard (no error envelope at all).
		{"401_codex_token_invalidated", 401, "", `{"error":{"code":"token_invalidated"}}`, true},
		{"401_codex_token_revoked_code", 401, "", `{"error":{"code":"token_revoked"}}`, true},
		{"401_codex_detail_unauthorized", 401, "", `{"detail":"Unauthorized"}`, true},
		// a plain codex 401 (transient / refresh-recoverable) must NOT quarantine.
		{"401_codex_plain", 401, "", `{"error":{"message":"invalid token"}}`, false},
		{"401_generic_unauthorized_word", 401, "", "request was unauthorized, please retry", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHardRevoked(tt.status, tt.errType, tt.errMsg); got != tt.want {
				t.Fatalf("isHardRevoked(%d,%q,%q) = %v, want %v", tt.status, tt.errType, tt.errMsg, got, tt.want)
			}
		})
	}
}

func TestParseUnifiedUtil7d(t *testing.T) {
	const hdr = "anthropic-ratelimit-unified-7d-utilization"
	tests := []struct {
		name   string
		set    bool
		val    string
		wantV  float64
		wantOK bool
	}{
		{"valid", true, "0.42", 0.42, true},
		{"missing", false, "", 0, false},
		{"malformed", true, "xyz", 0, false},
		{"above_one", true, "1.5", 0, false},
		{"negative", true, "-0.1", 0, false},
		{"zero_ok", true, "0", 0, true},
		{"one_ok", true, "1", 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.set {
				h.Set(hdr, tt.val)
			}
			v, ok := parseUnifiedUtil7d(h)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && v != tt.wantV {
				t.Fatalf("v = %v, want %v", v, tt.wantV)
			}
		})
	}
}

func TestSignalSampleUtil7dSerialization(t *testing.T) {
	// both readings present → both serialize, util_7d after util_5h.
	u7d := 0.4
	both, _ := json.Marshal(signalSample{CredentialID: "c1", TS: 100, Util5h: 0.6, Util7d: &u7d})
	if want := `{"credential_id":"c1","ts":100,"util_5h":0.6,"util_7d":0.4}`; string(both) != want {
		t.Fatalf("both = %s, want %s", both, want)
	}
	// 5h-only (no 7d header) → util_7d omitempty drops it, byte-identical to the
	// pre-7d wire format so existing master ingest is unaffected.
	only, _ := json.Marshal(signalSample{CredentialID: "c1", TS: 100, Util5h: 0.6})
	if want := `{"credential_id":"c1","ts":100,"util_5h":0.6}`; string(only) != want {
		t.Fatalf("5h-only = %s, want %s", only, want)
	}
}

func TestConcurrencyPeak(t *testing.T) {
	r := &signalReporter{} // lazy-init path (no maps preallocated)
	// start, start → peak 2; one ends → cur 1; start → cur 2 (peak stays 2).
	d1 := r.trackInflight("c1")
	d2 := r.trackInflight("c1")
	d1()                        // one completes → cur 1
	d3 := r.trackInflight("c1") // back to cur 2
	snap := r.snapshotConcurrency()
	if len(snap) != 1 || snap[0] != (concurrencySample{CredentialID: "c1", Peak: 2}) {
		t.Fatalf("snapshot = %+v, want one {c1, peak 2}", snap)
	}
	// Long-running streams remain visible in every window; otherwise a source
	// would falsely clear concurrency while two requests are still active.
	if snap2 := r.snapshotConcurrency(); len(snap2) != 1 || snap2[0].Peak != 2 {
		t.Fatalf("steady next window = %+v, want c1 peak 2", snap2)
	}
	d2()
	d3() // cur back to 0
	// a fresh request in the new window peaks at 1 (cur started from 0).
	d4 := r.trackInflight("c1")
	if snap3 := r.snapshotConcurrency(); len(snap3) != 1 || snap3[0].Peak != 1 {
		t.Fatalf("new window = %+v, want c1 peak 1", snap3)
	}
	d4()
}

func TestConcurrencyPeakNilAndEmpty(t *testing.T) {
	// nil receiver guard: feature-off reporter must not panic, returns a usable
	// no-op so callers can `defer trackInflight(id)()` unconditionally.
	var nilR *signalReporter
	nilR.trackInflight("c1")() // must not panic

	// empty credentialID → no-op, nothing tracked.
	r := &signalReporter{}
	r.trackInflight("")() // must not panic, no map entry
	if r.snapshotConcurrency() != nil {
		t.Fatal("empty credentialID should track nothing")
	}
}

func TestConcurrencyPeakConcurrent(t *testing.T) {
	// Deterministic peak under real concurrency: all goroutines hold their
	// in-flight slot simultaneously, so the peak is exactly `goroutines`. Run
	// under -race to catch a data race on the inflCur/inflPeak maps.
	r := &signalReporter{}
	const goroutines = 8
	release := make(chan struct{})
	var held, wg sync.WaitGroup
	held.Add(goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			done := r.trackInflight("c1")
			held.Done() // signal "I'm in flight"
			<-release   // hold until every goroutine is concurrently in flight
			done()
		}()
	}
	held.Wait() // all goroutines have incremented → cur == peak == goroutines
	snap := r.snapshotConcurrency()
	close(release)
	wg.Wait()
	if len(snap) != 1 || snap[0] != (concurrencySample{CredentialID: "c1", Peak: goroutines}) {
		t.Fatalf("concurrent peak = %+v, want one {c1, %d}", snap, goroutines)
	}
}

func TestSignalPostSendsConcurrency(t *testing.T) {
	got := make(chan []byte, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got <- b
	}))
	defer srv.Close()

	r := newSignalReporter(srv.URL, func(context.Context) (string, error) { return "tok-123", nil }, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporter returned nil")
	}

	// concurrency-only batch: body omits the other three, exact wire contract.
	r.post(nil, nil, nil, []concurrencySample{{CredentialID: "c1", Peak: 2}})
	if want := `{"concurrency":[{"credential_id":"c1","peak":2}]}`; string(<-got) != want {
		t.Fatalf("concurrency-only body mismatch, want %s", want)
	}

	// mixed all-four batch: samples (with util_7d) + revoked + rate_limits +
	// concurrency all serialize.
	u7d := 0.4
	r.post(
		[]signalSample{{CredentialID: "c1", TS: 100, Util5h: 0.6, Util7d: &u7d}},
		[]revokedSample{{CredentialID: "c2", Reason: "revoked"}},
		[]rateLimitSample{{CredentialID: "c3", Count: 5, WindowSecs: 30}},
		[]concurrencySample{{CredentialID: "c4", Peak: 2}})
	var decoded struct {
		Samples     []signalSample      `json:"samples"`
		Revoked     []revokedSample     `json:"revoked"`
		RateLimits  []rateLimitSample   `json:"rate_limits"`
		Concurrency []concurrencySample `json:"concurrency"`
	}
	body := <-got
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body not valid JSON: %v (raw %s)", err, body)
	}
	if len(decoded.Samples) != 1 || decoded.Samples[0].CredentialID != "c1" || decoded.Samples[0].TS != 100 ||
		decoded.Samples[0].Util5h != 0.6 || decoded.Samples[0].Util7d == nil || *decoded.Samples[0].Util7d != 0.4 {
		t.Fatalf("decoded samples = %+v, want one {c1,100,0.6,0.4}", decoded.Samples)
	}
	if len(decoded.Revoked) != 1 || decoded.Revoked[0] != (revokedSample{CredentialID: "c2", Reason: "revoked"}) {
		t.Fatalf("decoded revoked = %+v, want one {c2,revoked}", decoded.Revoked)
	}
	if len(decoded.RateLimits) != 1 || decoded.RateLimits[0] != (rateLimitSample{CredentialID: "c3", Count: 5, WindowSecs: 30}) {
		t.Fatalf("decoded rate_limits = %+v, want one {c3,5,30}", decoded.RateLimits)
	}
	if len(decoded.Concurrency) != 1 || decoded.Concurrency[0] != (concurrencySample{CredentialID: "c4", Peak: 2}) {
		t.Fatalf("decoded concurrency = %+v, want one {c4,2}", decoded.Concurrency)
	}
}

// TestSignalReporterCloseIdempotentAndNilSafe covers the leak-fix Close contract:
// loop() now returns on <-r.stop (so the per-generation goroutine + ticker don't
// leak across reloads), and Close must be safe to call more than once
// (generation.close paths) and on a nil receiver (feature-off). The concrete risk
// is a double close(r.stop) panic — guarded by stopOnce; this test fails if that
// guard is removed. (loop()'s timing isn't deterministically testable — see the
// file header — so the stop case itself is verified by inspection.)
func TestSignalReporterCloseIdempotentAndNilSafe(t *testing.T) {
	r := newSignalReporter("http://example.invalid", func(context.Context) (string, error) { return "tok", nil }, slog.Default())
	if r == nil {
		t.Fatal("newSignalReporter returned nil")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := r.Close(); err != nil { // idempotent — must not panic on double close
		t.Fatalf("second Close: %v", err)
	}
	var nilR *signalReporter
	if err := nilR.Close(); err != nil { // nil-safe — feature-off passes a nil reporter
		t.Fatalf("nil Close: %v", err)
	}
}
