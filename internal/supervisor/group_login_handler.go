// group_login_handler.go — C10/RW8 (Path α, proxy-orchestrated): the pool login
// endpoints the local contribute page relays to. Unlike the personal broker
// (/oauth/*, vault-backed), the POOL flow exchanges with a MEMORY-store broker so
// the per-member token NEVER lands in the proxy's personal vault, then writes it
// back to master (RW10) over the team JWT — the token is never returned to the
// caller (no Path-β localhost token leak).
//
// Flow:
//
//	POST /oauth/pool/authorize-url {credential_id}
//	    → master login-context → broker.StartLogin(canonical provider)
//	    → {session_id, authorize_url, flow}; bind session→credential/group/account/provider
//	POST /oauth/pool/submit-code  {session_id, code}
//	    → broker.SubmitCode → read token from memory store
//	    → postMemberToken(master RW10, team JWT, {credential_id, token…})
//	    → targeted group_runtime sync → {status:"ok", sync_status} (no token)
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	broker "github.com/AiKeyLabs/aikey-auth-broker"
)

// poolSessionTTL bounds how long a started-but-uncompleted pool login session is
// kept. It matches the broker's own login-session TTL (15 min); an authorize-url
// that's never followed by a successful submit-code is reaped on the next
// authorize-url so the session map can't grow unbounded (P2).
const poolSessionTTL = 15 * time.Minute

// The credential is already durable on master before this wait begins. Keep
// the request bounded: on timeout/failure the rail keeps its normal retry loop
// and the caller gets an explicit pending state instead of a failed login.
const poolLoginRuntimeSyncTimeout = 12 * time.Second

// poolSession is the value stored per started login: which account it binds to +
// when it started (for TTL reaping).
type poolSession struct {
	credentialID     string
	oauthGroupID     string
	accountID        string
	providerCode     string
	protocolType     string
	expectedIdentity string
	externalID       string
	flow             string
	createdAt        time.Time
}

// errNoTeamCredential — no team account-JWT available (not logged in to a team).
var errNoTeamCredential = errors.New("supervisor: no team credential (run aikey login)")

// poolExchanger is the broker surface the pool login needs, abstracted so the
// handler's session-tracking + writeback logic is unit-testable without a live
// provider. brokerPoolExchanger is the production impl (memory-store broker).
type poolExchanger interface {
	// StartLogin begins an OAuth login and returns the session id + authorize URL.
	StartLogin(ctx context.Context, profile poolProviderProfile) (sessionID, authURL string, err error)
	// SubmitCode exchanges the pasted code and returns the member's token material
	// for writeback (access/refresh/expiry + the provider account UUID) plus the
	// exchanged account's identity (email) for display / mismatch-warning. It is
	// IDEMPOTENT per session: a second call for an already-exchanged session replays
	// the cached token instead of re-spending the one-shot code (so a retry after a
	// failed writeback doesn't force the member to re-login).
	SubmitCode(ctx context.Context, sessionID, code string) (accountID, access, refresh string, expiresAt int64, externalID, identity string, err error)
	// Forget clears the cached exchange result (token + broker session) once the
	// token has been durably written back to master, so it doesn't linger in memory.
	Forget(ctx context.Context, sessionID, accountID string)
	// LoginStatus reports a login session's progress (pending/success/failed/
	// expired + provider error text). Codex's auth_code flow completes via the
	// broker's localhost:1455 callback — the page can't paste a code, it POLLS
	// this until the callback fires, then submit-code replays the cached exchange
	// (empty code, idempotent). NO token material in the result.
	LoginStatus(ctx context.Context, sessionID string) (status, errText string, err error)
}

// brokerPoolExchanger wraps a memory-store EmbeddedBroker: SubmitCode reads the
// just-exchanged token back from the memory store (same pattern master uses), so
// nothing is persisted to the proxy vault.
type brokerPoolExchanger struct {
	brk    *broker.EmbeddedBroker
	memTok broker.TokenStore
	memAcc broker.AccountStore
}

func (e *brokerPoolExchanger) StartLogin(ctx context.Context, profile poolProviderProfile) (string, string, error) {
	var (
		s   *broker.LoginSession
		err error
	)
	if profile.config != nil {
		s, err = e.brk.StartLoginWithConfig(ctx, *profile.config)
	} else {
		s, err = e.brk.StartLogin(ctx, profile.broker)
	}
	if err != nil {
		return "", "", err
	}
	return s.ID, s.AuthURL, nil
}

func (e *brokerPoolExchanger) SubmitCode(ctx context.Context, sessionID, code string) (string, string, string, int64, string, string, error) {
	r, err := e.brk.SubmitCode(ctx, sessionID, code)
	if err != nil {
		return "", "", "", 0, "", "", err
	}
	access, exp, err := e.memTok.GetAccessToken(ctx, r.AccountID)
	if err != nil {
		return "", "", "", 0, "", "", err
	}
	refresh, _ := e.memTok.GetRefreshToken(ctx, r.AccountID) // optional; stored master-only and never refreshed for Anthropic
	externalID := ""
	if acct, aerr := e.memAcc.GetByID(ctx, r.AccountID); aerr == nil && acct != nil {
		externalID = acct.ExternalID
	}
	// DisplayIdentity is the exchanged account's email (ExtractIdentity.Email) — used
	// for display + the team-account mismatch warning, never for the token itself.
	return r.AccountID, access, refresh, exp, externalID, r.DisplayIdentity, nil
}

// Forget removes the just-completed login's token from the memory store and its
// broker session, so the per-member token doesn't sit in proxy memory past the
// successful writeback. Memory-store deletes ignore ctx, but it's threaded through
// for interface symmetry.
func (e *brokerPoolExchanger) Forget(ctx context.Context, sessionID, accountID string) {
	_ = e.memTok.DeleteTokens(ctx, accountID)
	e.brk.ForgetSession(sessionID)
}

func (e *brokerPoolExchanger) LoginStatus(ctx context.Context, sessionID string) (string, string, error) {
	s, err := e.brk.GetLoginStatus(ctx, sessionID)
	if err != nil {
		return "", "", err
	}
	return s.Status, s.Error, nil
}

// poolLoginHandler serves the pool login endpoints. bearer/masterURL are injected
// (the supervisor wires them from the team credential + control-panel URL) so the
// handler stays testable.
type poolLoginHandler struct {
	ex                   poolExchanger
	sessionKeyExchange   func(ctx context.Context, loginCtx poolLoginContext, opts broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error)
	sessionKeyNodeEgress func() (string, error)
	masterURL            func() string
	bearer               func(ctx context.Context) (string, error)
	client               *http.Client
	resolveContext       func(ctx context.Context, credentialID string) (poolLoginContext, error) // tests; nil=master
	syncAfterWriteback   func(ctx context.Context) error                                          // nil only in focused tests
	sessions             sync.Map                                                                 // sessionID → immutable credential/provider/group binding
	sessionKeyPending    sync.Map                                                                 // operationID → *poolSessionKeyPending (token held only until writeback)
	sessionKeyOpsMu      sync.Mutex
	sessionKeyOps        map[string]*poolSessionKeyOperation // short-lived per-operation locks; protects idempotent exchange/writeback
}

type poolSessionKeyPending struct {
	loginCtx  poolLoginContext
	token     *broker.SessionKeyToken
	createdAt time.Time
	expiresAt int64
}

type poolSessionKeyOperation struct {
	mu   sync.Mutex
	refs int
}

type poolProviderProfile struct {
	broker string
	flow   string
	config *broker.ProviderConfig
}

func poolProviderFor(loginCtx poolLoginContext) (poolProviderProfile, bool) {
	switch strings.ToLower(strings.TrimSpace(loginCtx.ProviderCode)) {
	case "anthropic":
		return poolProviderProfile{broker: "claude", flow: "setup_token"}, true
	case "openai":
		return poolProviderProfile{broker: "codex", flow: "auth_code"}, true
	case "mock":
		if loginCtx.OAuthAuthorizeURL == "" || loginCtx.OAuthTokenURL == "" {
			return poolProviderProfile{}, false
		}
		switch strings.ToLower(strings.TrimSpace(loginCtx.ProtocolType)) {
		case "anthropic":
			if strings.TrimSpace(loginCtx.OAuthContext) == "" {
				return poolProviderProfile{}, false
			}
			cfg := broker.ClaudeConfig
			cfg.Code = "mock:anthropic"
			cfg.DisplayName = "Mock Provider (Anthropic)"
			cfg.ProviderCode = "mock"
			cfg.ProtocolType = "anthropic"
			cfg.IdentityProvider = "claude"
			cfg.AuthorizeURL = loginCtx.OAuthAuthorizeURL
			cfg.TokenURL = loginCtx.OAuthTokenURL
			cfg.RequireTLSImpersonation = false
			cfg.ExtraAuthorizeParams = cloneStringMap(cfg.ExtraAuthorizeParams)
			cfg.ExtraAuthorizeParams["credential_id"] = loginCtx.CredentialID
			cfg.ExtraAuthorizeParams["login_hint"] = loginCtx.ExpectedIdentity
			cfg.ExtraAuthorizeParams["oauth_context"] = loginCtx.OAuthContext
			return poolProviderProfile{broker: cfg.Code, flow: "setup_token", config: &cfg}, true
		case "openai_compatible":
			if strings.TrimSpace(loginCtx.OAuthContext) == "" {
				return poolProviderProfile{}, false
			}
			cfg := broker.CodexConfig
			cfg.Code = "mock:openai_compatible"
			cfg.DisplayName = "Mock Provider (OpenAI/Codex)"
			cfg.ProviderCode = "mock"
			cfg.ProtocolType = "openai_compatible"
			cfg.IdentityProvider = "codex"
			cfg.AuthorizeURL = loginCtx.OAuthAuthorizeURL
			cfg.TokenURL = loginCtx.OAuthTokenURL
			cfg.ExtraAuthorizeParams = cloneStringMap(cfg.ExtraAuthorizeParams)
			cfg.ExtraAuthorizeParams["credential_id"] = loginCtx.CredentialID
			cfg.ExtraAuthorizeParams["login_hint"] = loginCtx.ExpectedIdentity
			cfg.ExtraAuthorizeParams["oauth_context"] = loginCtx.OAuthContext
			return poolProviderProfile{broker: cfg.Code, flow: "auth_code", config: &cfg}, true
		default:
			return poolProviderProfile{}, false
		}
	default:
		return poolProviderProfile{}, false
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (h *poolLoginHandler) authorizeURL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider     string `json:"provider"`
		CredentialID string `json:"credential_id"`
		Namespace    string `json:"namespace,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		poolErr(w, http.StatusBadRequest, "BAD_BODY", "invalid request body")
		return
	}
	if req.CredentialID == "" {
		poolErr(w, http.StatusBadRequest, "MISSING_CREDENTIAL_ID", "credential_id is required")
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
	var loginCtx poolLoginContext
	if h.resolveContext != nil {
		loginCtx, err = h.resolveContext(r.Context(), req.CredentialID)
	} else {
		loginCtx, err = fetchPoolLoginContext(r.Context(), h.writebackClientFn()(), masterURL, bearer, req.CredentialID)
	}
	if err != nil {
		status := http.StatusBadGateway
		var httpErr *poolLoginContextHTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 {
			status = httpErr.StatusCode
		}
		poolErr(w, status, "LOGIN_CONTEXT_UNAVAILABLE", err.Error())
		return
	}
	profile, supported := poolProviderFor(loginCtx)
	if !supported {
		poolErr(w, http.StatusUnprocessableEntity, "LOGIN_PROVIDER_UNSUPPORTED",
			"this account's provider is not supported by the local pool-login broker: "+loginCtx.ProviderCode)
		return
	}
	if profile.config != nil {
		namespace, valid := normalizeMockNamespace(req.Namespace)
		if !valid {
			poolErr(w, http.StatusBadRequest, "INVALID_NAMESPACE", "namespace must be 1-64 ASCII letters, digits, '.', '_', '-' or ':'")
			return
		}
		cfg := *profile.config
		cfg.ExtraAuthorizeParams = cloneStringMap(cfg.ExtraAuthorizeParams)
		cfg.ExtraAuthorizeParams["namespace"] = namespace
		profile.config = &cfg
	}
	if req.Provider != "" && !strings.EqualFold(req.Provider, profile.broker) {
		slog.Warn("broker.pool.client_provider_ignored",
			"credential_id", req.CredentialID, "client_provider", req.Provider,
			"bound_provider", loginCtx.ProviderCode)
	}
	sid, authURL, err := h.ex.StartLogin(r.Context(), profile)
	if err != nil {
		poolErr(w, http.StatusBadGateway, "LOGIN_START_FAILED", err.Error())
		return
	}
	// Reap expired sessions (P2: bound the map; no background goroutine needed) then
	// bind this session to the account so submit-code writes the token to the right
	// credential (the account the proxy told the member to log into).
	h.sweepExpiredSessions()
	h.sessions.Store(sid, poolSession{
		credentialID: loginCtx.CredentialID, oauthGroupID: loginCtx.OauthGroupID,
		accountID: loginCtx.AccountID, providerCode: loginCtx.ProviderCode,
		protocolType:     loginCtx.ProtocolType,
		expectedIdentity: loginCtx.ExpectedIdentity, externalID: loginCtx.ExternalID,
		flow: profile.flow, createdAt: time.Now(),
	})
	poolJSON(w, map[string]any{
		"session_id": sid, "authorize_url": authURL, "provider_code": loginCtx.ProviderCode,
		"flow": profile.flow, "expected_identity": loginCtx.ExpectedIdentity,
	})
}

func normalizeMockNamespace(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		value = "manual"
	}
	if len(value) > 64 {
		return "", false
	}
	for _, c := range value {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == ':' {
			continue
		}
		return "", false
	}
	return value, true
}

func (h *poolLoginHandler) submitCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Code      string `json:"code"`
		// Confirm gates the WRITEBACK. false (step 1) = exchange only + return the
		// resolved account for review; true (step 2) = write the reviewed token back.
		Confirm bool `json:"confirm"`
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

	accountID, access, refresh, exp, externalID, identity, err := h.ex.SubmitCode(r.Context(), req.SessionID, req.Code)
	if err != nil {
		// Surface the provider exchange failure (CLAUDE.md 失败要显眼). err carries
		// the wrapped upstream response (e.g. `[http_403] {provider body}`), which is
		// the only place to see WHY the OAuth provider rejected the code.
		slog.Warn("broker.pool.exchange_failed",
			"error", err.Error(), "session_id", req.SessionID, "credential_id", credentialID)
		poolErr(w, http.StatusBadGateway, "EXCHANGE_FAILED", err.Error())
		return
	}

	// Step 1 (confirm=false): the code is exchanged and the resolved account returned
	// for the member to review — but NOTHING is written to master yet. The token is
	// held in the memory store (idempotent replay) and the session kept, so the
	// follow-up confirm call replays it WITHOUT re-spending the one-shot code. If the
	// member never confirms, the 15-min session TTL reaps the held token.
	if !req.Confirm {
		poolJSON(w, map[string]any{
			"status": "pending", "identity": identity,
			"expected_identity": sess.expectedIdentity, "provider_code": sess.providerCode,
		})
		return
	}

	// Step 2 (confirm=true): write the reviewed token back to master.
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
	if err := postMemberToken(r.Context(), h.writebackClientFn(), masterURL, bearer, memberTokenWriteback{
		CredentialID: credentialID, AccessToken: access, RefreshToken: refresh, ExpiresAt: exp,
		ExternalID: externalID, ProviderCode: sess.providerCode, ProtocolType: sess.protocolType,
		OauthGroupID: sess.oauthGroupID, AccountID: sess.accountID, Identity: identity,
	}); err != nil {
		// DELIBERATELY keep the session (do NOT delete here): the code was already
		// spent, so the member must be able to retry just the writeback. SubmitCode is
		// idempotent per session — a re-submit replays the cached token instead of
		// re-exchanging — so the page can re-POST the same code#state once master is
		// reachable, and this token lands without a fresh login. The session is reaped
		// by poolSessionTTL (15 min) if the member gives up.
		slog.Warn("broker.pool.writeback_failed",
			"error", err.Error(), "credential_id", credentialID)
		poolErr(w, http.StatusBadGateway, "WRITEBACK_FAILED", err.Error())
		return
	}

	// Make the just-written member token available to the data path immediately.
	// This targets only group_runtime: a global reload would disturb unrelated
	// rails and still would not prove that this credential reached the runtime.
	syncStatus := "ok"
	syncError := ""
	if h.syncAfterWriteback != nil {
		syncCtx, cancel := context.WithTimeout(r.Context(), poolLoginRuntimeSyncTimeout)
		err = h.syncAfterWriteback(syncCtx)
		cancel()
		if err != nil {
			syncStatus = "pending"
			syncError = err.Error()
			slog.Warn("broker.pool.runtime_sync_pending",
				"error", syncError, "credential_id", credentialID,
				"oauth_group_id", sess.oauthGroupID, "account_id", sess.accountID)
		}
	}
	// Durably on master now: drop the proxy-side binding AND the broker's cached token
	// (Forget) so the per-member token doesn't linger in proxy memory. One-shot done.
	h.sessions.Delete(req.SessionID)
	h.ex.Forget(r.Context(), req.SessionID, accountID)
	// Return the exchanged account's identity (email) — NOT the token — so the page
	// shows which Claude account was actually logged into and can warn (yellow) if it
	// doesn't match the team account this slot expects. Email is not a secret (already
	// shown as the account identity); the token still never leaves the proxy.
	resp := map[string]any{"status": "ok", "identity": identity, "sync_status": syncStatus}
	if syncError != "" {
		resp["sync_error"] = syncError
	}
	poolJSON(w, resp)
}

// status serves GET /oauth/pool/status?session_id=<id> — the codex (auth_code)
// pool login's polling leg. The browser can't paste a code for codex (OpenAI
// redirects to the broker's own localhost:1455 callback, which exchanges
// in-place), so the page polls here until the session flips to success, then
// calls submit-code with an EMPTY code — the broker's idempotent replay returns
// the cached exchange without re-spending anything. Only sessions this handler
// started are visible (fail-closed vs probing the personal broker's sessions);
// the response carries status + provider error text, never token material.
func (h *poolLoginHandler) status(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("session_id")
	if sid == "" {
		poolErr(w, http.StatusBadRequest, "MISSING_SESSION_ID", "session_id query param is required")
		return
	}
	sessAny, ok := h.sessions.Load(sid)
	if !ok {
		poolErr(w, http.StatusBadRequest, "UNKNOWN_SESSION", "no pool login session for that id")
		return
	}
	if sess, ok := sessAny.(poolSession); !ok || time.Since(sess.createdAt) > poolSessionTTL {
		h.sessions.Delete(sid)
		poolErr(w, http.StatusBadRequest, "SESSION_EXPIRED", "pool login session expired; restart the login")
		return
	}
	status, errText, err := h.ex.LoginStatus(r.Context(), sid)
	if err != nil {
		poolErr(w, http.StatusBadGateway, "STATUS_FAILED", err.Error())
		return
	}
	resp := map[string]any{"status": status}
	if errText != "" {
		resp["error_detail"] = errText
	}
	poolJSON(w, resp)
}

// RegisterRoutes mounts the pool login endpoints (server.RouteRegistrar). They
// live alongside the personal broker's /oauth/* routes on the proxy's local mux.
func (h *poolLoginHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /oauth/pool/authorize-url", h.authorizeURL)
	mux.HandleFunc("POST /oauth/pool/submit-code", h.submitCode)
	mux.HandleFunc("GET /oauth/pool/status", h.status)
	mux.HandleFunc("POST /oauth/pool/session-key", h.sessionKey)
	mux.HandleFunc("GET /oauth/pool/session-key/capabilities", h.sessionKeyCapabilities)
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
// URL closures. Session-key exchange creates isolated Chrome-impersonating
// clients with the selected credential's explicit effective egress; it does not
// reuse the process-global browser-OAuth client or its implicit proxy state.
func (s *Supervisor) NewPoolLoginHandler(nodeEgress func() string) *poolLoginHandler {
	memTok := broker.NewMemoryTokenStore()
	memAcc := broker.NewMemoryAccountStore()
	brk := broker.NewEmbedded(memTok, memAcc)
	return &poolLoginHandler{
		ex:                 &brokerPoolExchanger{brk: brk, memTok: memTok, memAcc: memAcc},
		sessionKeyExchange: exchangePoolSessionKey,
		sessionKeyNodeEgress: func() (string, error) {
			if nodeEgress == nil {
				return "", errors.New("node egress proxy is unavailable")
			}
			resolved := strings.TrimSpace(nodeEgress())
			if resolved == "" {
				return "", errors.New("node egress proxy is unavailable")
			}
			return resolved, nil
		},
		masterURL: readControlPanelURL,
		bearer:    s.teamBearer,
		syncAfterWriteback: func(ctx context.Context) error {
			if s.railset == nil {
				return errors.New("group runtime sync rail is not initialized")
			}
			return s.railset.kickAndWait(ctx, "group_runtime")
		},
		// client left nil in production ⇒ writebackClientFn() resolves the LIVE
		// swappable groupRuntimeClient each retry, so a network-change rebuild
		// heals the writeback. Tests inject a fixed h.client (see writebackClientFn).
	}
}

// writebackClientFn returns the *http.Client provider postMemberToken re-resolves
// every retry. When h.client is set (tests inject a fixed httptest client) it
// wins; otherwise production uses the live swappable control-plane client so a
// mid-flight rebuild (selfheal) takes effect on the next attempt.
func (h *poolLoginHandler) writebackClientFn() func() *http.Client {
	if h.client != nil {
		c := h.client
		return func() *http.Client { return c }
	}
	return groupRuntimeClient
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

func poolErrWithMeta(w http.ResponseWriter, status int, code, msg, operationID string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Aikey-Error-Source", code)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":        map[string]string{"code": code, "message": msg},
		"operation_id": operationID,
	})
}
