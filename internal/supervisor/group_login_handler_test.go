package supervisor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	submitErr  error
}

func (f *fakePoolExchanger) StartLogin(_ context.Context, _ string) (string, string, error) {
	return "sess-1", f.authURL, nil
}
func (f *fakePoolExchanger) SubmitCode(_ context.Context, _, _ string) (string, string, string, int64, string, error) {
	if f.submitErr != nil {
		return "", "", "", 0, "", f.submitErr
	}
	return f.accountID, f.access, f.refresh, f.expiresAt, f.externalID, nil
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

	ex := &fakePoolExchanger{authURL: "https://login", accountID: "acc-x", access: "TOK", refresh: "RT", expiresAt: 42, externalID: "uuid-x"}
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

	// 2) submit-code → exchange + writeback.
	w2 := doJSON(h.submitCode, `{"session_id":"sess-1","code":"abc#state"}`)
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
	if w := doJSON(h.submitCode, `{"session_id":"sess-1","code":"x"}`); w.Code != http.StatusOK {
		t.Fatalf("first submit: %d", w.Code)
	}
	// replay → session gone → 400.
	if w := doJSON(h.submitCode, `{"session_id":"sess-1","code":"x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("replay should be rejected, got %d", w.Code)
	}
}
