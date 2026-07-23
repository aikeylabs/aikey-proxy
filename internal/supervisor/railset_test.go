package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// The §2.3 state machine: OK → STALE (3 consecutive failures) → OFFLINE (20),
// any success → OK with counters reset. OFFLINE never stops anything — the
// runner keeps observing (owner decision 2026-07-03: offline-first, no give-up).
// 能红: change the thresholds or the reset-on-success and this goes red.
func TestRailRunner_StateMachineTransitions(t *testing.T) {
	r := &railRunner{spec: railSpec{name: "test_rail"}}
	boom := errors.New("dial tcp: connection refused")

	r.observe(nil)
	if got := r.state; got != railOK {
		t.Fatalf("after success: state=%v want ok", got)
	}
	for i := 0; i < railStaleAfterFailures-1; i++ {
		r.observe(boom)
	}
	if r.state != railOK {
		t.Fatalf("below stale threshold must keep prior state, got %v", r.state)
	}
	r.observe(boom) // 3rd consecutive
	if r.state != railStale {
		t.Fatalf("at %d consecutive failures: state=%v want stale", railStaleAfterFailures, r.state)
	}
	for i := railStaleAfterFailures; i < railOfflineAfterFailures; i++ {
		r.observe(boom)
	}
	if r.state != railOffline {
		t.Fatalf("at %d consecutive failures: state=%v want offline", railOfflineAfterFailures, r.state)
	}
	if r.failures != railOfflineAfterFailures {
		t.Fatalf("failure count=%d want %d", r.failures, railOfflineAfterFailures)
	}
	// Offline is a LABEL: a success at any point recovers fully.
	r.observe(nil)
	if r.state != railOK || r.failures != 0 || r.lastError != "" {
		t.Fatalf("recovery must reset: state=%v failures=%d lastError=%q", r.state, r.failures, r.lastError)
	}
	if r.lastSuccessAt == 0 {
		t.Fatal("recovery must stamp lastSuccessAt")
	}
}

// last_error must carry the underlying cause — the 2026-07-03 incident's
// connection-refused detail was invisible for 7 hours because the old loop
// swallowed it into a bare early return.
func TestRailRunner_LastErrorSurfaced(t *testing.T) {
	r := &railRunner{spec: railSpec{name: "test_rail"}}
	r.observe(fmt.Errorf("GET /accounts/me/routing: %w", errors.New("dial tcp 192.168.0.120:3000: connect: connection refused")))
	if r.lastError == "" || r.state != railInit && r.failures != 1 {
		t.Fatalf("failure must record lastError, got %q", r.lastError)
	}
	if want := "connection refused"; !strings.Contains(r.lastError, want) {
		t.Fatalf("lastError %q must contain %q", r.lastError, want)
	}
}

// /status omits rails that never attempted a cycle (gate never passed): a
// personal install without group VKs renders no control_plane_sync noise.
func TestRailSet_SnapshotOmitsNeverAttempted(t *testing.T) {
	rs := newRailSet(
		railSpec{name: "idle_rail"},
		railSpec{name: "busy_rail"},
	)
	rs.rails[1].observe(errors.New("x"))

	snap := rs.snapshot()
	if _, ok := snap["idle_rail"]; ok {
		t.Fatal("never-attempted rail must be omitted from the snapshot")
	}
	st, ok := snap["busy_rail"]
	if !ok || st.ConsecutiveFailures != 1 || st.State != "init" {
		t.Fatalf("attempted rail must be present with counters: %+v", st)
	}
}

// kickAll must never block, even when nobody is draining the kick channel.
func TestRailSet_KickAllNonBlocking(t *testing.T) {
	rs := newRailSet(railSpec{name: "r1"}, railSpec{name: "r2"})
	done := make(chan struct{})
	go func() {
		rs.kickAll()
		rs.kickAll() // second kick coalesces into the buffered slot
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("kickAll blocked")
	}
}

// A writeback completion wait must observe the result of the exact named cycle,
// not stale last_error/last_success state from an earlier periodic run.
func TestRailSet_KickAndWaitReturnsRequestedCycleResult(t *testing.T) {
	rs := newRailSet(railSpec{name: "other"}, railSpec{name: "group_runtime"})
	wantErr := errors.New("runtime fetch failed")
	go func() {
		ack := <-rs.rails[1].kick
		ack <- railCycleResult{attempted: true, err: wantErr}
		close(ack)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rs.kickAndWait(ctx, "group_runtime"); !errors.Is(err, wantErr) {
		t.Fatalf("kickAndWait error=%v want %v", err, wantErr)
	}
	select {
	case <-rs.rails[0].kick:
		t.Fatal("named kick must not disturb another rail")
	default:
	}
}

func TestRailSet_KickAndWaitRejectsIdleCycle(t *testing.T) {
	rs := newRailSet(railSpec{name: "group_runtime"})
	go func() {
		ack := <-rs.rails[0].kick
		ack <- railCycleResult{}
		close(ack)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := rs.kickAndWait(ctx, "group_runtime")
	if err == nil || !strings.Contains(err.Error(), "readiness gate") {
		t.Fatalf("idle cycle must be explicit, got %v", err)
	}
}

type stubRefreshTokenSource struct {
	token string
	err   error
}

func (s stubRefreshTokenSource) GetPlatformRefreshToken() (string, error) { return s.token, s.err }

// The incident fix in one test: the credential must be REBUILT when the control
// URL changes between cycles — the refresh POST must land on the NEW server,
// not the one baked at first use. 能红: cache the credential without comparing
// builtURL and the second Bearer still hits the old server.
func TestTeamCredentialSource_RebuildsOnURLChange(t *testing.T) {
	mint := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != cliTokenRefreshPath {
				w.WriteHeader(404)
				return
			}
			_, _ = fmt.Fprintf(w, `{"access_token":"tok-from-%s","expires_in":3600}`, name)
		}))
	}
	oldSrv, newSrv := mint("old"), mint("new")
	defer oldSrv.Close()
	defer newSrv.Close()

	src := &teamCredentialSource{}
	vaultStub := stubRefreshTokenSource{token: "refresh-1"}

	b1, err := src.bearer(context.Background(), vaultStub, oldSrv.URL)
	if err != nil || b1 != "tok-from-old" {
		t.Fatalf("first bearer: %q err=%v", b1, err)
	}
	// Control URL drifts (the 2026-07-03 incident: .120 → .121). The very next
	// cycle must mint against the NEW URL — no restart, no reload required.
	b2, err := src.bearer(context.Background(), vaultStub, newSrv.URL)
	if err != nil || b2 != "tok-from-new" {
		t.Fatalf("post-drift bearer: %q err=%v (credential not rebuilt for new URL)", b2, err)
	}
}

// A refresh failure must drop the cached credential so the next cycle rebuilds
// from the current vault + URL (a rotated refresh_token heals in one cycle).
func TestTeamCredentialSource_DropsCredentialOnRefreshFailure(t *testing.T) {
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer fail.Close()
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"tok-recovered","expires_in":3600}`))
	}))
	defer ok.Close()

	src := &teamCredentialSource{}
	if _, err := src.bearer(context.Background(), stubRefreshTokenSource{token: "rt"}, fail.URL); err == nil {
		t.Fatal("401 refresh must surface an error")
	}
	// Same source, working server → rebuilt credential succeeds.
	b, err := src.bearer(context.Background(), stubRefreshTokenSource{token: "rt"}, ok.URL)
	if err != nil || b != "tok-recovered" {
		t.Fatalf("post-failure rebuild: %q err=%v", b, err)
	}
}

// No refresh token in the vault (pre-login) is a countable, visible failure —
// the old loop early-returned FOREVER here with zero logs.
func TestTeamCredentialSource_NoTokenIsAnError(t *testing.T) {
	src := &teamCredentialSource{}
	if _, err := src.bearer(context.Background(), stubRefreshTokenSource{token: ""}, "http://127.0.0.1:1"); err == nil {
		t.Fatal("empty refresh token must be an error, not a silent skip")
	}
	// invalidate() is idempotent and safe on an empty source.
	src.invalidate()
}

// Allocation-engine signals are a control-plane rail, not a usage-collector
// upload. Current installs may have no events.collector_credentials YAML at all;
// the signal reporter must still authenticate from the same vault refresh token
// as group-runtime/routing-override polling.
func TestSignalReportingAuth_UsesTeamRailCredentialWithoutCollectorBundle(t *testing.T) {
	mint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != cliTokenRefreshPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"signal-team-jwt","expires_in":3600}`))
	}))
	defer mint.Close()

	masterURL, bearer := signalReportingAuth(
		mint.URL,
		&teamCredentialSource{},
		stubRefreshTokenSource{token: "vault-refresh-token"},
	)
	if masterURL != mint.URL || bearer == nil {
		t.Fatalf("signal auth not wired: url=%q bearer_nil=%v", masterURL, bearer == nil)
	}
	got, err := bearer(context.Background())
	if err != nil || got != "signal-team-jwt" {
		t.Fatalf("signal bearer=%q err=%v", got, err)
	}
}

func TestSignalReportingAuth_DisabledWithoutControlPlaneInputs(t *testing.T) {
	vault := stubRefreshTokenSource{token: "refresh"}
	if url, bearer := signalReportingAuth("", &teamCredentialSource{}, vault); url != "" || bearer != nil {
		t.Fatalf("empty master URL must disable signal reporter: url=%q bearer_nil=%v", url, bearer == nil)
	}
	if url, bearer := signalReportingAuth("http://master", nil, vault); url != "" || bearer != nil {
		t.Fatalf("nil team credential source must disable signal reporter: url=%q bearer_nil=%v", url, bearer == nil)
	}
}

// The §5.5 sync-health bypass file lifecycle: a rail transitioning into STALE
// writes the file (with failed_since so the reader renders a live duration);
// recovery back to OK removes it — statusline recovery is automatic. Uses the
// same AIKEY_RUN_DIR override as the group-login state file.
func TestWriteSyncHealth_FileLifecycle(t *testing.T) {
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())
	rs := newRailSet(railSpec{name: "routing_override"}, railSpec{name: "group_runtime"})
	boom := errors.New("dial tcp: connection refused")

	// Drive routing_override into STALE via the real observe path.
	transitioned := false
	for i := 0; i < railStaleAfterFailures; i++ {
		transitioned = rs.rails[0].observe(boom)
	}
	if !transitioned {
		t.Fatal("reaching the stale threshold must report a transition")
	}
	rs.writeSyncHealth()

	path, _ := syncHealthPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("degraded rail must write the sync-health file: %v", err)
	}
	var body syncHealthBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("sync-health file must be valid JSON: %v — %s", err, raw)
	}
	entry, ok := body.Rails["routing_override"]
	if !ok || entry.State != "stale" || entry.FailedSince == 0 {
		t.Fatalf("sync-health entry wrong: %+v", body.Rails)
	}
	if _, ok := body.Rails["group_runtime"]; ok {
		t.Fatal("healthy rail must not appear in the sync-health file")
	}
	if body.WrittenAt == 0 {
		t.Fatal("written_at must be stamped")
	}

	// Recovery removes the file.
	if !rs.rails[0].observe(nil) {
		t.Fatal("recovery from stale must report a transition")
	}
	rs.writeSyncHealth()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("all-healthy must remove the sync-health file, stat err=%v", err)
	}
}
