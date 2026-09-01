// group_session_key_handler.go isolates the desktop Provider Session Key
// flow from the existing browser OAuth flow while preserving the same account
// binding, token writeback, and runtime synchronization boundaries.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"runtime"
	"strings"
	"time"

	broker "github.com/AiKeyLabs/aikey-auth-broker"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

type poolSessionKeyAdapter func(context.Context, poolLoginContext, broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error)

type poolSessionKeyAdapterKey struct {
	providerCode string
	protocolType string
}

var poolSessionKeyAdapters = map[poolSessionKeyAdapterKey]poolSessionKeyAdapter{
	{providerCode: "anthropic", protocolType: "anthropic"}: func(ctx context.Context, _ poolLoginContext, opts broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error) {
		return broker.ExchangeClaudeSessionKey(ctx, opts)
	},
	{providerCode: "openai", protocolType: "openai_compatible"}: func(ctx context.Context, _ poolLoginContext, opts broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error) {
		return broker.ExchangeCodexSessionKey(ctx, opts)
	},
	{providerCode: "mock", protocolType: "anthropic"}: func(ctx context.Context, loginCtx poolLoginContext, opts broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error) {
		return broker.ExchangeMockSessionKey(ctx, broker.MockSessionKeyExchangeOptions{
			SessionKey: opts.SessionKey,
			ProxyURL:   opts.ProxyURL,
			TokenURL:   loginCtx.OAuthTokenURL,
		})
	},
	{providerCode: "mock", protocolType: "openai_compatible"}: func(ctx context.Context, loginCtx poolLoginContext, opts broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error) {
		return broker.ExchangeMockCodexSessionKey(ctx, broker.MockSessionKeyExchangeOptions{
			SessionKey: opts.SessionKey,
			ProxyURL:   opts.ProxyURL,
			TokenURL:   loginCtx.OAuthTokenURL,
		})
	},
}

func poolSessionKeyAdapterFor(loginCtx poolLoginContext) (poolSessionKeyAdapter, bool) {
	provider := strings.ToLower(strings.TrimSpace(loginCtx.ProviderCode))
	protocol := strings.ToLower(strings.TrimSpace(loginCtx.ProtocolType))
	adapter, ok := poolSessionKeyAdapters[poolSessionKeyAdapterKey{providerCode: provider, protocolType: protocol}]
	if !ok || (provider == "mock" && strings.TrimSpace(loginCtx.OAuthTokenURL) == "") {
		return nil, false
	}
	return adapter, true
}

func poolSessionKeyProviderSupported(loginCtx poolLoginContext) bool {
	_, ok := poolSessionKeyAdapterFor(loginCtx)
	return ok
}

// exchangePoolSessionKey is the sole provider dispatch for this login use case.
// The authoritative login context comes from Master; the browser never chooses
// an endpoint or provider. Mock credentials use their resident token endpoint;
// real Session Keys enter only their provider's fixed broker implementation.
func exchangePoolSessionKey(ctx context.Context, loginCtx poolLoginContext, opts broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error) {
	adapter, ok := poolSessionKeyAdapterFor(loginCtx)
	if !ok {
		return nil, &broker.OAuthError{
			Code:    broker.ErrCodeSessionKeyProviderUnsupported,
			Message: "Session Key sign-in is not supported for this account provider.",
			Hint:    "Choose a supported Anthropic or OpenAI-compatible OAuth account.",
		}
	}
	return adapter(ctx, loginCtx, opts)
}

// sessionKey signs a supported pool account in without opening a browser. It
// uses the same review/writeback/runtime-sync semantics as submitCode, but the
// authorization input is exchanged in-process by aikey-auth-broker on Windows or macOS.
// Token material is never serialized to this HTTP response.
func (h *poolLoginHandler) sessionKey(w http.ResponseWriter, r *http.Request) {
	trace := observability.ExtractOrCreate(r)
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var req struct {
		CredentialID string `json:"credential_id"`
		SessionKey   string `json:"session_key,omitempty"`
		OperationID  string `json:"operation_id"`
		Confirm      bool   `json:"confirm"`
		Cancel       bool   `json:"cancel"`
		// IdentityMismatchConfirmed is the member's explicit second acknowledgement
		// for a cross-account Session Key (拍板 2026-09-01, supersedes the 08-27
		// fail-closed rule for THIS member entry). Ignored unless Confirm is set and
		// the pending operation is actually mismatched.
		IdentityMismatchConfirmed bool `json:"identity_mismatch_confirmed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		poolErr(w, http.StatusBadRequest, "BAD_BODY", "invalid or oversized request body")
		return
	}
	if req.CredentialID == "" {
		poolErr(w, http.StatusBadRequest, "MISSING_CREDENTIAL_ID", "credential_id is required")
		return
	}
	if !validPoolOperationID(req.OperationID) {
		poolErr(w, http.StatusBadRequest, "INVALID_OPERATION_ID", "operation_id must be 16-64 ASCII letters, digits, '-', or '_'")
		return
	}
	op := h.acquireSessionKeyOperation(req.OperationID)
	defer h.releaseSessionKeyOperation(req.OperationID, op)
	h.sweepExpiredSessionKeyOperations()

	pendingAny, hasPending := h.sessionKeyPending.Load(req.OperationID)
	var pending *poolSessionKeyPending
	if hasPending {
		pending, _ = pendingAny.(*poolSessionKeyPending)
		if pending == nil || pending.loginCtx.CredentialID != req.CredentialID || time.Since(pending.createdAt) > poolSessionTTL {
			h.forgetSessionKeyOperation(req.OperationID, pending)
			poolErr(w, http.StatusBadRequest, "SESSION_EXPIRED", "session key login operation expired; restart the login")
			return
		}
	} else {
		if req.Confirm || req.Cancel {
			poolErr(w, http.StatusBadRequest, "UNKNOWN_OPERATION", "no session key login operation for that id")
			return
		}
		if h.sessionKeyExchange == nil {
			poolErr(w, http.StatusServiceUnavailable, broker.ErrCodeSessionKeyPlatformUnsupported, "session key sign-in is unavailable on this installation")
			return
		}
		bearer, masterURL, loginCtx, err := h.resolvePoolLogin(r.Context(), req.CredentialID)
		_ = bearer // The authoritative context is fetched now; a fresh bearer is resolved again at writeback.
		_ = masterURL
		if err != nil {
			h.writePoolLoginResolveError(w, err)
			return
		}
		if !poolSessionKeyProviderSupported(loginCtx) {
			poolErr(w, http.StatusUnprocessableEntity, broker.ErrCodeSessionKeyProviderUnsupported, "session key sign-in is supported only for configured Anthropic or OpenAI-compatible OAuth accounts")
			return
		}
		// The Master login context carries the authoritative account override or
		// group default. Empty falls back to this device's node/system proxy. Do
		// not require a managed-VK runtime row: login may correctly precede VK
		// issuance, and creating a fake VK would split the routing truth source.
		egressURL := strings.TrimSpace(loginCtx.EffectiveEgressURL)
		if egressURL == "" && h.sessionKeyNodeEgress != nil {
			egressURL, err = h.sessionKeyNodeEgress()
			if err != nil {
				poolErr(w, http.StatusConflict, broker.ErrCodeSessionKeyEgressUnavailable,
					"No device egress proxy is available for this account. Configure the account, OAuth group, or desktop node upstream proxy, then try again.")
				return
			}
		}
		if strings.TrimSpace(egressURL) == "" {
			poolErr(w, http.StatusConflict, broker.ErrCodeSessionKeyEgressUnavailable,
				"No effective egress proxy is configured. Configure the account, OAuth group, or desktop node upstream proxy, then try again.")
			return
		}
		token, err := h.sessionKeyExchange(r.Context(), loginCtx, broker.SessionKeyExchangeOptions{SessionKey: req.SessionKey, ProxyURL: egressURL})
		if err != nil {
			code, message := poolSessionKeyError(err)
			slog.Warn("Session key exchange failed",
				"event.name", observability.EventProxyPoolSessionKeyExchangeFailed,
				"error.code", code, "credential_id", req.CredentialID,
				"request_id", trace.RequestID, "trace_id", trace.TraceID, "span_id", trace.SpanID)
			poolErr(w, poolSessionKeyHTTPStatus(code), code, message)
			return
		}
		identityMismatch := !sessionKeyIdentityMatches(loginCtx, token.Identity)
		if identityMismatch {
			// spec: R-oauth-token-mint-12.S1 不匹配成为待确认审阅态，零写入
			// Cross-account Session Key (拍板 2026-09-01, supersedes the 2026-08-27
			// immediate fail-closed): the exchange result stays a SHORT-LIVED pending
			// operation and the member must explicitly acknowledge the mismatch on
			// confirm. Safe because the v3.1 mint model writeback is SEAT-scoped
			// (R-oauth-token-mint-9.S1): the token + its ACTUAL provider account id
			// land on the member's own seat row only — the shared account row,
			// its identity (email/external_id), and other members are untouched.
			// The runtime rail prefers the seat row's provider_account_id, so the
			// injected upstream identity always matches this token.
			// 变更记录: 技术实现/update/20260901-SessionKey跨账号登录-确认后绑定本人seat行.md
			slog.Warn("Session key identity does not match the selected account; awaiting explicit member confirmation",
				"event.name", observability.EventProxyPoolSessionKeyIdentityMismatch,
				"error.code", broker.ErrCodeSessionKeyIdentityMismatch, "credential_id", req.CredentialID,
				"request_id", trace.RequestID, "trace_id", trace.TraceID, "span_id", trace.SpanID)
		}
		exchangedAt := time.Now()
		pending = &poolSessionKeyPending{
			loginCtx:         loginCtx,
			token:            token,
			identityMismatch: identityMismatch,
			createdAt:        exchangedAt,
			expiresAt:        exchangedAt.Unix() + token.ExpiresIn,
		}
		// Codex auto-renewal (方案 20260818, default-on): retain the session key
		// for the confirm writeback so master can re-exchange it before the
		// access token expires. Codex protocol only — Claude session keys are
		// deliberately NOT retained (owner ruling: Claude 只做 7 天到期预警).
		if strings.EqualFold(loginCtx.ProtocolType, "openai_compatible") {
			pending.sessionKey = req.SessionKey
			if !token.SessionExpiresAt.IsZero() {
				pending.sessionExpiresAt = token.SessionExpiresAt.Unix()
			}
		}
		h.sessionKeyPending.Store(req.OperationID, pending)
		h.scheduleSessionKeyExpiry(req.OperationID, pending)
	}
	if req.Cancel {
		h.forgetSessionKeyOperation(req.OperationID, pending)
		poolJSON(w, map[string]any{"status": "canceled", "operation_id": req.OperationID})
		return
	}

	identity := pending.token.Identity.Email
	if !req.Confirm {
		poolJSON(w, map[string]any{
			"status": "pending", "operation_id": req.OperationID,
			"identity": identity, "expected_identity": pending.loginCtx.ExpectedIdentity,
			"provider_code":     pending.loginCtx.ProviderCode,
			"identity_mismatch": pending.identityMismatch,
		})
		return
	}
	if pending.identityMismatch && !req.IdentityMismatchConfirmed {
		// spec: R-oauth-token-mint-12.S2 普通 confirm 不能一键写入跨账号 token
		// Confirm without the explicit mismatch acknowledgement: keep the pending
		// operation (the member can re-confirm with the acknowledgement or cancel);
		// nothing is written. An accidental one-click confirm can never bind a
		// cross-account token.
		poolErrWithMeta(w, http.StatusConflict, broker.ErrCodeSessionKeyIdentityMismatch,
			"The Session Key belongs to a different account. Re-confirm with the mismatch acknowledgement to bind it to your seat, or cancel.", req.OperationID)
		return
	}

	bearer, err := h.bearer(r.Context())
	if err != nil {
		poolErrWithMeta(w, http.StatusUnauthorized, "NO_TEAM_CREDENTIAL", "not logged in to the team (run aikey login)", req.OperationID)
		return
	}
	masterURL := h.masterURL()
	if masterURL == "" {
		poolErrWithMeta(w, http.StatusServiceUnavailable, "NO_MASTER_URL", "control-panel URL not configured", req.OperationID)
		return
	}
	ctx := pending.loginCtx
	if err := postMemberToken(r.Context(), h.writebackClientFn(), masterURL, bearer, memberTokenWriteback{
		CredentialID: ctx.CredentialID, AccessToken: pending.token.AccessToken,
		RefreshToken: pending.token.RefreshToken, ExpiresAt: pending.expiresAt,
		RenewalCredential: pending.sessionKey, RenewalExpiresAt: pending.sessionExpiresAt,
		ExternalID: pending.token.Identity.ExternalID, ProviderCode: ctx.ProviderCode,
		ProtocolType: ctx.ProtocolType, OauthGroupID: ctx.OauthGroupID,
		AccountID: ctx.AccountID, Identity: identity, IdentityMismatch: pending.identityMismatch,
	}); err != nil {
		slog.Warn("Session key token writeback failed",
			"event.name", observability.EventProxyPoolSessionKeyWritebackFailed,
			"error.code", observability.ErrCodeProxyPoolSessionKeyWritebackFailed, "credential_id", ctx.CredentialID, "error", err.Error(),
			"request_id", trace.RequestID, "trace_id", trace.TraceID, "span_id", trace.SpanID)
		poolErrWithMeta(w, http.StatusBadGateway, "WRITEBACK_FAILED", err.Error(), req.OperationID)
		return
	}

	syncStatus, syncError := h.syncPoolRuntime(r.Context(), ctx, trace)
	h.forgetSessionKeyOperation(req.OperationID, pending)
	resp := map[string]any{
		"status": "ok", "identity": identity, "sync_status": syncStatus,
		"identity_mismatch": pending.identityMismatch,
	}
	if syncError != "" {
		resp["sync_error"] = syncError
	}
	poolJSON(w, resp)
}

// sessionKeyCapabilities is an external health signal for installers and E2E.
// It performs no provider request and exposes no account data. A healthy local
// service on an unsupported host deliberately reports available=false.
func (h *poolLoginHandler) sessionKeyCapabilities(w http.ResponseWriter, _ *http.Request) {
	available := broker.SupportsSessionKeyPlatform(runtime.GOOS) && h.sessionKeyExchange != nil
	reason := ""
	if !available {
		reason = broker.ErrCodeSessionKeyPlatformUnsupported
	}
	poolJSON(w, map[string]any{
		"status": "ok", "available": available, "platform": runtime.GOOS,
		"browser_required": false, "refresh_supported": false, "reason_code": reason,
	})
}

func (h *poolLoginHandler) resolvePoolLogin(ctx context.Context, credentialID string) (bearer, masterURL string, loginCtx poolLoginContext, err error) {
	bearer, err = h.bearer(ctx)
	if err != nil {
		return "", "", poolLoginContext{}, errNoTeamCredential
	}
	masterURL = h.masterURL()
	if masterURL == "" {
		return bearer, "", poolLoginContext{}, errors.New("control-panel URL not configured")
	}
	if h.resolveContext != nil {
		loginCtx, err = h.resolveContext(ctx, credentialID)
		return bearer, masterURL, loginCtx, err
	}
	loginCtx, err = fetchPoolLoginContext(ctx, h.writebackClientFn()(), masterURL, bearer, credentialID)
	return bearer, masterURL, loginCtx, err
}

func (h *poolLoginHandler) writePoolLoginResolveError(w http.ResponseWriter, err error) {
	if errors.Is(err, errNoTeamCredential) {
		poolErr(w, http.StatusUnauthorized, "NO_TEAM_CREDENTIAL", "not logged in to the team (run aikey login)")
		return
	}
	status := http.StatusBadGateway
	code := "LOGIN_CONTEXT_UNAVAILABLE"
	if err.Error() == "control-panel URL not configured" {
		status, code = http.StatusServiceUnavailable, "NO_MASTER_URL"
	}
	var httpErr *poolLoginContextHTTPError
	if errors.As(err, &httpErr) && httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 {
		status = httpErr.StatusCode
	}
	poolErr(w, status, code, err.Error())
}

func (h *poolLoginHandler) syncPoolRuntime(ctx context.Context, loginCtx poolLoginContext, trace observability.TraceContext) (status, detail string) {
	if h.syncAfterWriteback == nil {
		return "ok", ""
	}
	syncCtx, cancel := context.WithTimeout(ctx, poolLoginRuntimeSyncTimeout)
	err := h.syncAfterWriteback(syncCtx)
	cancel()
	if err == nil {
		return "ok", ""
	}
	slog.Warn("Session key runtime sync is pending",
		"event.name", observability.EventProxyPoolSessionKeyRuntimeSyncPending,
		"error.code", observability.ErrCodeProxyPoolSessionKeyRuntimeSyncPending, "error", err.Error(),
		"credential_id", loginCtx.CredentialID, "oauth_group_id", loginCtx.OauthGroupID, "account_id", loginCtx.AccountID,
		"request_id", trace.RequestID, "trace_id", trace.TraceID, "span_id", trace.SpanID)
	return "pending", err.Error()
}

func validPoolOperationID(value string) bool {
	if len(value) < 16 || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func poolSessionKeyError(err error) (code, message string) {
	var oauthErr *broker.OAuthError
	if errors.As(err, &oauthErr) {
		message = oauthErr.Message
		if oauthErr.Hint != "" {
			message += " " + oauthErr.Hint
		}
		return oauthErr.Code, message
	}
	return broker.ErrCodeLoginFailed, "Session Key sign-in failed. Check the desktop egress proxy and try again with a fresh provider Session Key."
}

func poolSessionKeyHTTPStatus(code string) int {
	switch code {
	case broker.ErrCodeSessionKeyFormatInvalid:
		return http.StatusBadRequest
	case broker.ErrCodeSessionKeyInvalid:
		return http.StatusUnauthorized
	case broker.ErrCodeSessionKeyNotAuthorized:
		return http.StatusForbidden
	case broker.ErrCodeSessionKeyPlatformUnsupported, broker.ErrCodeSessionKeyEgressUnsupported:
		return http.StatusUnprocessableEntity
	case broker.ErrCodeSessionKeyEgressUnavailable:
		return http.StatusConflict
	case broker.ErrCodeSessionKeyIdentityMismatch:
		return http.StatusConflict
	default:
		return http.StatusBadGateway
	}
}

func sessionKeyIdentityMatches(loginCtx poolLoginContext, identity broker.IdentityInfo) bool {
	expectedExternalID := strings.TrimSpace(loginCtx.ExternalID)
	if expectedExternalID != "" {
		return expectedExternalID == strings.TrimSpace(identity.ExternalID)
	}
	expectedEmail := strings.TrimSpace(loginCtx.ExpectedIdentity)
	if expectedEmail == "" {
		// spec: R-oauth-token-mint-12.S5 期望身份为空 = 首登，proxy 不得比 Master 严
		// No expected identity at all: a newly provisioned pool row awaiting its
		// first login. Master's own writeback matcher (membertoken.identityMismatch)
		// accepts this and C5-backfills the identity, so the proxy must not be
		// stricter — a 409 here made first logins impossible (08-27 评审 P1,
		// aligned 2026-09-01).
		// bugfix: workflow/CI/bugfix/2026-09-01-sessionkey-cross-account-login-blocked.md
		return true
	}
	actualEmail := strings.TrimSpace(identity.Email)
	return actualEmail != "" && strings.EqualFold(expectedEmail, actualEmail)
}

// acquireSessionKeyOperation keeps one mutex per in-flight operation. The
// reference count prevents deleting a mutex while another retry is already
// waiting on it, which would otherwise allow a third request to exchange the
// same session key concurrently through a newly-created mutex.
func (h *poolLoginHandler) acquireSessionKeyOperation(operationID string) *poolSessionKeyOperation {
	h.sessionKeyOpsMu.Lock()
	if h.sessionKeyOps == nil {
		h.sessionKeyOps = make(map[string]*poolSessionKeyOperation)
	}
	op := h.sessionKeyOps[operationID]
	if op == nil {
		op = &poolSessionKeyOperation{}
		h.sessionKeyOps[operationID] = op
	}
	op.refs++
	h.sessionKeyOpsMu.Unlock()
	op.mu.Lock()
	return op
}

func (h *poolLoginHandler) releaseSessionKeyOperation(operationID string, op *poolSessionKeyOperation) {
	op.mu.Unlock()
	h.sessionKeyOpsMu.Lock()
	op.refs--
	if op.refs == 0 {
		if _, pending := h.sessionKeyPending.Load(operationID); !pending {
			delete(h.sessionKeyOps, operationID)
		}
	}
	h.sessionKeyOpsMu.Unlock()
}

func (h *poolLoginHandler) forgetSessionKeyOperation(operationID string, pending *poolSessionKeyPending) {
	if pending != nil && pending.token != nil {
		pending.token.AccessToken = ""
		pending.token.RefreshToken = ""
	}
	if pending != nil {
		pending.sessionKey = ""
	}
	h.sessionKeyPending.Delete(operationID)
}

func (h *poolLoginHandler) sweepExpiredSessionKeyOperations() {
	cutoff := time.Now().Add(-poolSessionTTL)
	h.sessionKeyPending.Range(func(key, value any) bool {
		pending, ok := value.(*poolSessionKeyPending)
		if !ok || pending.createdAt.Before(cutoff) {
			operationID, valid := key.(string)
			if !valid {
				h.sessionKeyPending.Delete(key)
				return true
			}
			h.forgetSessionKeyOperation(operationID, pending)
			h.sessionKeyOpsMu.Lock()
			if op := h.sessionKeyOps[operationID]; op != nil && op.refs == 0 {
				delete(h.sessionKeyOps, operationID)
			}
			h.sessionKeyOpsMu.Unlock()
		}
		return true
	})
}

// scheduleSessionKeyExpiry guarantees a held token is cleared after the TTL
// even if the user closes the page and no later request arrives to run the lazy
// sweep. The operation lock serializes expiry with a concurrent confirm/retry.
func (h *poolLoginHandler) scheduleSessionKeyExpiry(operationID string, pending *poolSessionKeyPending) {
	delay := time.Until(pending.createdAt.Add(poolSessionTTL))
	if delay < 0 {
		delay = 0
	}
	time.AfterFunc(delay, func() {
		op := h.acquireSessionKeyOperation(operationID)
		defer h.releaseSessionKeyOperation(operationID, op)
		current, ok := h.sessionKeyPending.Load(operationID)
		if !ok || current != pending || time.Since(pending.createdAt) < poolSessionTTL {
			return
		}
		h.forgetSessionKeyOperation(operationID, pending)
	})
}
