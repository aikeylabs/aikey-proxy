// group_login_handler.go — C10/RW8 (Path α, proxy-orchestrated): the pool login
// endpoints the local contribute page relays to. Unlike the personal broker
// (/oauth/*, vault-backed), the POOL flow exchanges with a MEMORY-store broker so
// the per-member token NEVER lands in the proxy's personal vault, then writes it
// back to master (RW10) over the team JWT — the token is never returned to the
// caller (no Path-β localhost token leak).
//
// Flow:
//
//	POST /oauth/pool/authorize-url {provider, credential_id}
//	    → broker.StartLogin → {session_id, authorize_url}; remember session→credential
//	POST /oauth/pool/submit-code  {session_id, code}
//	    → broker.SubmitCode → read token from memory store
//	    → postMemberToken(master RW10, team JWT, {credential_id, token…})
//	    → {status:"ok"}   (no token in the response)
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	broker "github.com/AiKeyLabs/aikey-auth-broker"
)

// poolSessionTTL bounds how long a started-but-uncompleted pool login session is
// kept. It matches the broker's own login-session TTL (15 min); an authorize-url
// that's never followed by a successful submit-code is reaped on the next
// authorize-url so the session map can't grow unbounded (P2).
const poolSessionTTL = 15 * time.Minute

// poolSession is the value stored per started login: which account it binds to +
// when it started (for TTL reaping).
type poolSession struct {
	credentialID string
	createdAt    time.Time
}

// errNoTeamCredential — no team account-JWT available (not logged in to a team).
var errNoTeamCredential = errors.New("supervisor: no team credential (run aikey login)")

// poolExchanger is the broker surface the pool login needs, abstracted so the
// handler's session-tracking + writeback logic is unit-testable without a live
// provider. brokerPoolExchanger is the production impl (memory-store broker).
type poolExchanger interface {
	// StartLogin begins an OAuth login and returns the session id + authorize URL.
	StartLogin(ctx context.Context, provider string) (sessionID, authURL string, err error)
	// SubmitCode exchanges the pasted code and returns the member's token material
	// for writeback (access/refresh/expiry + the provider account UUID).
	SubmitCode(ctx context.Context, sessionID, code string) (accountID, access, refresh string, expiresAt int64, externalID string, err error)
}

// brokerPoolExchanger wraps a memory-store EmbeddedBroker: SubmitCode reads the
// just-exchanged token back from the memory store (same pattern master uses), so
// nothing is persisted to the proxy vault.
type brokerPoolExchanger struct {
	brk    *broker.EmbeddedBroker
	memTok broker.TokenStore
	memAcc broker.AccountStore
}

func (e *brokerPoolExchanger) StartLogin(ctx context.Context, provider string) (string, string, error) {
	s, err := e.brk.StartLogin(ctx, provider)
	if err != nil {
		return "", "", err
	}
	return s.ID, s.AuthURL, nil
}

func (e *brokerPoolExchanger) SubmitCode(ctx context.Context, sessionID, code string) (string, string, string, int64, string, error) {
	r, err := e.brk.SubmitCode(ctx, sessionID, code)
	if err != nil {
		return "", "", "", 0, "", err
	}
	access, exp, err := e.memTok.GetAccessToken(ctx, r.AccountID)
	if err != nil {
		return "", "", "", 0, "", err
	}
	refresh, _ := e.memTok.GetRefreshToken(ctx, r.AccountID) // optional (Claude 1y has none)
	externalID := ""
	if acct, aerr := e.memAcc.GetByID(ctx, r.AccountID); aerr == nil && acct != nil {
		externalID = acct.ExternalID
	}
	return r.AccountID, access, refresh, exp, externalID, nil
}

// poolLoginHandler serves the pool login endpoints. bearer/masterURL are injected
// (the supervisor wires them from the team credential + control-panel URL) so the
// handler stays testable.
type poolLoginHandler struct {
	ex        poolExchanger
	masterURL func() string
	bearer    func(ctx context.Context) (string, error)
	client    *http.Client
	sessions  sync.Map // sessionID → credentialID (the account being logged into)
}

func (h *poolLoginHandler) authorizeURL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider     string `json:"provider"`
		CredentialID string `json:"credential_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		poolErr(w, http.StatusBadRequest, "BAD_BODY", "invalid request body")
		return
	}
	if req.CredentialID == "" {
		poolErr(w, http.StatusBadRequest, "MISSING_CREDENTIAL_ID", "credential_id is required")
		return
	}
	sid, authURL, err := h.ex.StartLogin(r.Context(), req.Provider)
	if err != nil {
		poolErr(w, http.StatusBadGateway, "LOGIN_START_FAILED", err.Error())
		return
	}
	// Reap expired sessions (P2: bound the map; no background goroutine needed) then
	// bind this session to the account so submit-code writes the token to the right
	// credential (the account the proxy told the member to log into).
	h.sweepExpiredSessions()
	h.sessions.Store(sid, poolSession{credentialID: req.CredentialID, createdAt: time.Now()})
	poolJSON(w, map[string]any{"session_id": sid, "authorize_url": authURL})
}

func (h *poolLoginHandler) submitCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		poolErr(w, http.StatusBadRequest, "BAD_BODY", "invalid request body")
		return
	}
	credAny, ok := h.sessions.Load(req.SessionID)
	if !ok {
		poolErr(w, http.StatusBadRequest, "UNKNOWN_SESSION", "no pool login session for that id")
		return
	}
	sess, ok := credAny.(poolSession)
	if !ok || time.Since(sess.createdAt) > poolSessionTTL {
		h.sessions.Delete(req.SessionID)
		poolErr(w, http.StatusBadRequest, "SESSION_EXPIRED", "pool login session expired; restart the login")
		return
	}
	credentialID := sess.credentialID

	_, access, refresh, exp, externalID, err := h.ex.SubmitCode(r.Context(), req.SessionID, req.Code)
	if err != nil {
		poolErr(w, http.StatusBadGateway, "EXCHANGE_FAILED", err.Error())
		return
	}
	bearer, err := h.bearer(r.Context())
	if err != nil {
		poolErr(w, http.StatusUnauthorized, "NO_TEAM_CREDENTIAL", "not logged in to the team (run aikey login)")
		return
	}
	masterURL := h.masterURL()
	if masterURL == "" {
		poolErr(w, http.StatusServiceUnavailable, "NO_MASTER_URL", "control-panel URL not configured")
		return
	}
	if err := postMemberToken(r.Context(), h.client, masterURL, bearer, memberTokenWriteback{
		CredentialID: credentialID, AccessToken: access, RefreshToken: refresh, ExpiresAt: exp, ExternalID: externalID,
	}); err != nil {
		poolErr(w, http.StatusBadGateway, "WRITEBACK_FAILED", err.Error())
		return
	}
	h.sessions.Delete(req.SessionID) // one-shot: a session completes exactly once
	poolJSON(w, map[string]any{"status": "ok"})
}

// RegisterRoutes mounts the pool login endpoints (server.RouteRegistrar). They
// live alongside the personal broker's /oauth/* routes on the proxy's local mux.
func (h *poolLoginHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /oauth/pool/authorize-url", h.authorizeURL)
	mux.HandleFunc("POST /oauth/pool/submit-code", h.submitCode)
}

// teamBearer returns a fresh team account-JWT Bearer (same credential channel ③
// uses to call master). Errors when not logged in to a team.
func (s *Supervisor) teamBearer(ctx context.Context) (string, error) {
	gen := s.active.Load()
	if gen == nil || gen.vault == nil {
		return "", errNoTeamCredential
	}
	creds := buildCollectorCredentials(s.cfg.Events.CollectorCredentials, gen.vault)
	cred := creds["team"]
	if cred == nil {
		return "", errNoTeamCredential
	}
	return cred.Bearer(ctx)
}

// NewPoolLoginHandler builds the pool login handler with a MEMORY-store broker
// (per-member tokens never touch the proxy vault) + the team bearer / control-panel
// URL closures. The broker reuses the package-global impersonate HTTP client set
// during the personal broker init (Cloudflare bypass). Returns nil if the broker
// dependency isn't available.
func (s *Supervisor) NewPoolLoginHandler() *poolLoginHandler {
	memTok := broker.NewMemoryTokenStore()
	memAcc := broker.NewMemoryAccountStore()
	brk := broker.NewEmbedded(memTok, memAcc)
	return &poolLoginHandler{
		ex:        &brokerPoolExchanger{brk: brk, memTok: memTok, memAcc: memAcc},
		masterURL: readControlPanelURL,
		bearer:    s.teamBearer,
		client:    groupRuntimeHTTPClient,
	}
}

// sweepExpiredSessions deletes login sessions older than poolSessionTTL. Called
// opportunistically on authorize-url so abandoned/failed logins can't accumulate
// (P2) without a dedicated reaper goroutine.
func (h *poolLoginHandler) sweepExpiredSessions() {
	cutoff := time.Now().Add(-poolSessionTTL)
	h.sessions.Range(func(k, v any) bool {
		if s, ok := v.(poolSession); ok && s.createdAt.Before(cutoff) {
			h.sessions.Delete(k)
		}
		return true
	})
}

func poolJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func poolErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	// Mark as an aikey-generated error (mirrors proxy.HeaderAikeyErrorSource /
	// writeJSONError); literal to avoid a supervisor→proxy import. The local web
	// relay keys on this to distinguish aikey errors from upstream pass-throughs.
	w.Header().Set("X-Aikey-Error-Source", code)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
