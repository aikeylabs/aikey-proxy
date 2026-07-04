package supervisor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakePoolExchanger stands in for the memory-store broker so the handler's
// session-tracking + writeback chain is testable without a live provider.
type fakePoolExchanger struct {
	authURL    string
	accountID  string
	access     string
	refresh    string
	expiresAt  int64
	externalID string
	identity   string
	submitErr  error
	submitN    int    // # of SubmitCode calls (idempotent-retry assertions)
	forgotN    int    // # of Forget calls (cache-clear-on-success assertions)
	forgotSess string // last Forget sessionID
	forgotAcct string // last Forget accountID
	status     string // LoginStatus result (codex polling leg); "" ⇒ pending
	statusErr  string // LoginStatus provider error text
}

func (f *fakePoolExchanger) StartLogin(_ context.Context, _ string) (string, string, error) {
	return "sess-1", f.authURL, nil
}
func (f *fakePoolExchanger) SubmitCode(_ context.Context, _, _ string) (string, string, string, int64, string, string, error) {
	f.submitN++
	if f.submitErr != nil {
		return "", "", "", 0, "", "", f.submitErr
	}
	return f.accountID, f.access, f.refresh, f.expiresAt, f.externalID, f.identity, nil
}
func (f *fakePoolExchanger) Forget(_ context.Context, sessionID, accountID string) {
	f.forgotN++
	f.forgotSess = sessionID
	f.forgotAcct = accountID
}
func (f *fakePoolExchanger) LoginStatus(_ context.Context, _ string) (string, string, error) {
	if f.status == "" {
		return "pending", "", nil
	}
	return f.status, f.statusErr, nil
}

func newPoolHandler(t *testing.T, ex poolExchanger, masterURL string) *poolLoginHandler {
	t.Helper()
	return &poolLoginHandler{
		ex:        ex,
		masterURL: func() string { return masterURL },
		bearer:    func(context.Context) (string, error) { return "JWT", nil },
		client:    http.DefaultClient,
	}
}

func doJSON(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// TestPoolLogin_EndToEnd: authorize-url binds session→credential; submit-code
// exchanges, then writes the token back to master RW10 with the bound credential_id
// — and the token is NEVER in the submit-code response.
func TestPoolLogin_EndToEnd(t *testing.T) {
	var gotWB memberTokenWriteback
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/accounts/me/oauth-member-token" {
			t.Errorf("unexpected master path %q", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotWB)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer master.Close()

	ex := &fakePoolExchanger{authURL: "https://login", accountID: "acc-x", access: "TOK", refresh: "RT", expiresAt: 42, externalID: "uuid-x", identity: "member@team.com"}
	h := newPoolHandler(t, ex, master.URL)
	h.client = master.Client()

	// 1) authorize-url for credential c1.
	w1 := doJSON(h.authorizeURL, `{"provider":"claude","credential_id":"c1"}`)
	if w1.Code != http.StatusOK {
		t.Fatalf("authorize-url: %d %s", w1.Code, w1.Body.String())
	}
	var sresp struct {
		SessionID    string `json:"session_id"`
		AuthorizeURL string `json:"authorize_url"`
	}
	_ = json.Unmarshal(w1.Body.Bytes(), &sresp)
	if sresp.SessionID != "sess-1" || sresp.AuthorizeURL != "https://login" {
		t.Fatalf("authorize-url resp: %+v", sresp)
	}

	// 2) submit-code with confirm → exchange + writeback.
	w2 := doJSON(h.submitCode, `{"session_id":"sess-1","code":"abc#state","confirm":true}`)
	if w2.Code != http.StatusOK {
		t.Fatalf("submit-code: %d %s", w2.Code, w2.Body.String())
	}
	// writeback carried the SESSION'S credential_id + the exchanged token.
	if gotWB.CredentialID != "c1" || gotWB.AccessToken != "TOK" || gotWB.RefreshToken != "RT" || gotWB.ExpiresAt != 42 || gotWB.ExternalID != "uuid-x" {
		t.Fatalf("writeback wrong: %+v", gotWB)
	}
	// token must NOT be echoed to the caller.
	if strings.Contains(w2.Body.String(), "TOK") || strings.Contains(w2.Body.String(), "RT") {
		t.Fatalf("token leaked into submit-code response: %s", w2.Body.String())
	}
	// the exchanged account's identity (email) IS returned, for display + the
	// team-account mismatch warning (email is not a secret).
	var okResp struct {
		Status   string `json:"status"`
		Identity string `json:"identity"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &okResp)
	if okResp.Identity != "member@team.com" {
		t.Fatalf("submit-code response should carry identity email, got %q", okResp.Identity)
	}
}

// TestPoolLogin_PendingThenConfirm: step 1 (confirm=false) exchanges and returns the
// resolved account for review WITHOUT writing to master; step 2 (confirm=true) writes
// the reviewed token back. Guards the two-step confirm gate (2026-06-30).
func TestPoolLogin_PendingThenConfirm(t *testing.T) {
	var writebacks int32
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&writebacks, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer master.Close()

	ex := &fakePoolExchanger{authURL: "u", accountID: "acc-x", access: "T", identity: "member@team.com"}
	h := newPoolHandler(t, ex, master.URL)
	h.client = master.Client()

	_ = doJSON(h.authorizeURL, `{"provider":"claude","credential_id":"c1"}`)

	// Step 1: no confirm → pending + identity, NO writeback, session kept.
	w1 := doJSON(h.submitCode, `{"session_id":"sess-1","code":"abc#st"}`)
	if w1.Code != http.StatusOK {
		t.Fatalf("step 1 (no confirm) → 200 pending, got %d %s", w1.Code, w1.Body.String())
	}
	var pending struct {
		Status   string `json:"status"`
		Identity string `json:"identity"`
	}
	_ = json.Unmarshal(w1.Body.Bytes(), &pending)
	if pending.Status != "pending" || pending.Identity != "member@team.com" {
		t.Fatalf("step 1 should return pending + identity, got %+v", pending)
	}
	if n := atomic.LoadInt32(&writebacks); n != 0 {
		t.Fatalf("step 1 must NOT write to master, got %d writebacks", n)
	}
	if ex.forgotN != 0 {
		t.Fatalf("step 1 must NOT Forget the session (needed for confirm), got %d", ex.forgotN)
	}

	// Step 2: confirm → writeback lands, session consumed.
	w2 := doJSON(h.submitCode, `{"session_id":"sess-1","code":"abc#st","confirm":true}`)
	if w2.Code != http.StatusOK {
		t.Fatalf("step 2 (confirm) → 200 ok, got %d %s", w2.Code, w2.Body.String())
	}
	if n := atomic.LoadInt32(&writebacks); n != 1 {
		t.Fatalf("step 2 should write exactly once, got %d", n)
	}
	if ex.forgotN != 1 {
		t.Fatalf("step 2 should Forget on success, got %d", ex.forgotN)
	}
}

// TestPoolLogin_RegisterRoutesMounts: RegisterRoutes actually mounts both pool
// endpoints on a real ServeMux and they reach the handler (a missing-field 400,
// not a 404) — verifies the wiring that main.go relies on without starting the
// full proxy.
func TestPoolLogin_RegisterRoutesMounts(t *testing.T) {
	h := newPoolHandler(t, &fakePoolExchanger{authURL: "u"}, "http://unused")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// authorize-url mounted → missing credential_id → 400 (proves reachable).
	r1 := httptest.NewRequest(http.MethodPost, "/oauth/pool/authorize-url", strings.NewReader(`{"provider":"claude"}`))
	w1 := httptest.NewRecorder()
	mux.ServeHTTP(w1, r1)
	if w1.Code == http.StatusNotFound {
		t.Fatal("/oauth/pool/authorize-url not mounted (404)")
	}
	if w1.Code != http.StatusBadRequest {
		t.Fatalf("authorize-url mounted but wrong code: %d", w1.Code)
	}

	// submit-code mounted → unknown session → 400 (proves reachable).
	r2 := httptest.NewRequest(http.MethodPost, "/oauth/pool/submit-code", strings.NewReader(`{"session_id":"x","code":"y"}`))
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, r2)
	if w2.Code == http.StatusNotFound {
		t.Fatal("/oauth/pool/submit-code not mounted (404)")
	}
}

// TestPoolLogin_UnknownSession: submit-code with a session that was never started
// (or already consumed) is rejected — no writeback attempted.
func TestPoolLogin_UnknownSession(t *testing.T) {
	h := newPoolHandler(t, &fakePoolExchanger{}, "http://unused")
	w := doJSON(h.submitCode, `{"session_id":"nope","code":"x"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown session → 400, got %d", w.Code)
	}
}

// TestPoolLogin_MissingCredentialID: authorize-url requires credential_id (which
// account to bind the resulting token to).
func TestPoolLogin_MissingCredentialID(t *testing.T) {
	h := newPoolHandler(t, &fakePoolExchanger{authURL: "u"}, "http://unused")
	if w := doJSON(h.authorizeURL, `{"provider":"claude"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("missing credential_id → 400, got %d", w.Code)
	}
}

// TestPoolLogin_SessionConsumedOnce: a session can't be replayed after success.
func TestPoolLogin_SessionConsumedOnce(t *testing.T) {
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer master.Close()
	ex := &fakePoolExchanger{authURL: "u", accountID: "a", access: "T"}
	h := newPoolHandler(t, ex, master.URL)
	h.client = master.Client()

	_ = doJSON(h.authorizeURL, `{"provider":"claude","credential_id":"c1"}`)
	if w := doJSON(h.submitCode, `{"session_id":"sess-1","code":"x","confirm":true}`); w.Code != http.StatusOK {
		t.Fatalf("first submit: %d", w.Code)
	}
	// replay → session gone → 400.
	if w := doJSON(h.submitCode, `{"session_id":"sess-1","code":"x","confirm":true}`); w.Code != http.StatusBadRequest {
		t.Fatalf("replay should be rejected, got %d", w.Code)
	}
	// success cleared the cached token via Forget (so it doesn't linger in memory).
	if ex.forgotN != 1 || ex.forgotSess != "sess-1" || ex.forgotAcct != "a" {
		t.Fatalf("Forget(sess-1,a) expected once on success, got n=%d sess=%q acct=%q", ex.forgotN, ex.forgotSess, ex.forgotAcct)
	}
}

// TestPoolLogin_WritebackFailureKeepsSessionForRetry: the OAuth code is spent at
// exchange, so a transient master outage during writeback must NOT waste it. The
// handler keeps the session on WRITEBACK_FAILED; the page can re-POST the same
// code#state and — because SubmitCode is idempotent per session — the cached token
// is replayed and lands once master recovers. Forget runs only on the successful
// writeback. 防退化 for the 2026-06-30 idempotent-retry design.
func TestPoolLogin_WritebackFailureKeepsSessionForRetry(t *testing.T) {
	fastBackoff(t) // shrink the writeback retry backoff for the test
	var hits int32
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 503 for the whole first submit (all writebackMaxAttempts), then recover.
		if atomic.AddInt32(&hits, 1) <= int32(writebackMaxAttempts) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer master.Close()

	ex := &fakePoolExchanger{authURL: "u", accountID: "acc-x", access: "TOK"}
	h := newPoolHandler(t, ex, master.URL)
	h.client = master.Client()

	_ = doJSON(h.authorizeURL, `{"provider":"claude","credential_id":"c1"}`)

	// 1) master down for every attempt → WRITEBACK_FAILED, session KEPT, no Forget.
	if w := doJSON(h.submitCode, `{"session_id":"sess-1","code":"abc#st","confirm":true}`); w.Code != http.StatusBadGateway {
		t.Fatalf("first submit (master down) → 502, got %d %s", w.Code, w.Body.String())
	}
	if ex.forgotN != 0 {
		t.Fatalf("Forget must NOT run on writeback failure (got %d)", ex.forgotN)
	}

	// 2) retry same session+code → master recovered → writeback lands, then Forget.
	if w := doJSON(h.submitCode, `{"session_id":"sess-1","code":"abc#st","confirm":true}`); w.Code != http.StatusOK {
		t.Fatalf("retry (master back) → 200, got %d %s", w.Code, w.Body.String())
	}
	if ex.submitN != 2 {
		t.Fatalf("SubmitCode called once per submit; want 2, got %d", ex.submitN)
	}
	if ex.forgotN != 1 || ex.forgotSess != "sess-1" || ex.forgotAcct != "acc-x" {
		t.Fatalf("Forget(sess-1,acc-x) expected once on success, got n=%d sess=%q acct=%q", ex.forgotN, ex.forgotSess, ex.forgotAcct)
	}

	// 3) session consumed on success → a later replay is rejected.
	if w := doJSON(h.submitCode, `{"session_id":"sess-1","code":"abc#st","confirm":true}`); w.Code != http.StatusBadRequest {
		t.Fatalf("post-success replay → 400, got %d", w.Code)
	}
}

// TestPoolLogin_Status: the codex polling leg. Only sessions the pool handler
// started are visible (fail-closed: probing an unknown/personal-broker session id
// → 400), and the response carries status/error text but never token material.
func TestPoolLogin_Status(t *testing.T) {
	ex := &fakePoolExchanger{authURL: "u", accountID: "acc-x", access: "SECRET-TOK"}
	h := newPoolHandler(t, ex, "http://unused")

	_ = doJSON(h.authorizeURL, `{"provider":"codex","credential_id":"c1"}`)

	get := func(sid string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/oauth/pool/status?session_id="+sid, nil)
		w := httptest.NewRecorder()
		h.status(w, r)
		return w
	}

	// Unknown session → 400 (no probing the broker through this handler).
	if w := get("not-ours"); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown session → 400, got %d %s", w.Code, w.Body.String())
	}
	// Missing session_id → 400.
	{
		r := httptest.NewRequest(http.MethodGet, "/oauth/pool/status", nil)
		w := httptest.NewRecorder()
		h.status(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("missing session_id → 400, got %d", w.Code)
		}
	}
	// Pending → {"status":"pending"}.
	if w := get("sess-1"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"pending"`) {
		t.Fatalf("pending status expected, got %d %s", w.Code, w.Body.String())
	}
	// Callback fired → success surfaces, provider error text passes through on
	// failure, and NO token material ever appears in the body.
	ex.status = "success"
	if w := get("sess-1"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"success"`) {
		t.Fatalf("success status expected, got %d %s", w.Code, w.Body.String())
	} else if strings.Contains(w.Body.String(), "SECRET-TOK") {
		t.Fatalf("status body must never contain token material: %s", w.Body.String())
	}
	ex.status, ex.statusErr = "failed", "provider said no"
	if w := get("sess-1"); !strings.Contains(w.Body.String(), "provider said no") {
		t.Fatalf("provider error text should pass through: %s", w.Body.String())
	}
}
