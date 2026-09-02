package supervisor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	broker "github.com/AiKeyLabs/aikey-auth-broker"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// fakePoolExchanger stands in for the memory-store broker so the handler's
// session-tracking + writeback chain is testable without a live provider.
type fakePoolExchanger struct {
	authURL         string
	accountID       string
	access          string
	refresh         string
	expiresAt       int64
	externalID      string
	identity        string
	submitErr       error
	submitN         int    // # of SubmitCode calls (idempotent-retry assertions)
	forgotN         int    // # of Forget calls (cache-clear-on-success assertions)
	forgotSess      string // last Forget sessionID
	forgotAcct      string // last Forget accountID
	status          string // LoginStatus result (codex polling leg); "" ⇒ pending
	statusErr       string // LoginStatus provider error text
	startedProvider string
	startedProfile  poolProviderProfile
}

func (f *fakePoolExchanger) StartLogin(_ context.Context, profile poolProviderProfile) (string, string, error) {
	f.startedProvider = profile.broker
	f.startedProfile = profile
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
		sessionKeyNodeEgress: func() (string, error) {
			return "http://127.0.0.1:10808", nil
		},
		resolveContext: func(_ context.Context, credentialID string) (poolLoginContext, error) {
			return poolLoginContext{
				CredentialID: credentialID, OauthGroupID: "g1", AccountID: "account-" + credentialID,
				ProviderCode: "anthropic", ProtocolType: "anthropic", ExpectedIdentity: "member@team.com",
			}, nil
		},
	}
}

func TestPoolSessionKeyProviderSupportedUsesCredentialProtocol(t *testing.T) {
	for _, tt := range []struct {
		name string
		ctx  poolLoginContext
		want bool
	}{
		{name: "anthropic", ctx: poolLoginContext{ProviderCode: "anthropic", ProtocolType: "anthropic"}, want: true},
		{name: "openai codex", ctx: poolLoginContext{ProviderCode: "openai", ProtocolType: "openai_compatible"}, want: true},
		{name: "mock anthropic", ctx: poolLoginContext{ProviderCode: "mock", ProtocolType: "anthropic", OAuthTokenURL: "http://127.0.0.1/oauth/anthropic/token"}, want: true},
		{name: "mock missing endpoint", ctx: poolLoginContext{ProviderCode: "mock", ProtocolType: "anthropic"}, want: false},
		{name: "mock codex", ctx: poolLoginContext{ProviderCode: "mock", ProtocolType: "openai_compatible", OAuthTokenURL: "http://127.0.0.1/oauth/openai_compatible/token"}, want: true},
		{name: "mock codex missing endpoint", ctx: poolLoginContext{ProviderCode: "mock", ProtocolType: "openai_compatible"}, want: false},
		{name: "unknown brand", ctx: poolLoginContext{ProviderCode: "other", ProtocolType: "anthropic"}, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := poolSessionKeyProviderSupported(tt.ctx); got != tt.want {
				t.Fatalf("poolSessionKeyProviderSupported(%+v)=%t want %t", tt.ctx, got, tt.want)
			}
		})
	}
}

func TestExchangePoolSessionKeyUsesResidentMockCodexContext(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(map[string]any{
		"exp":                            time.Now().Add(time.Hour).Unix(),
		"https://api.openai.com/profile": map[string]any{"email": "mock-codex@example.test"},
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "cred-mock-codex",
			"chatgpt_plan_type":  "mock",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	accessToken := header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".fixture"
	var sawExchange, sawVerify bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/openai_compatible/token":
			sawExchange = true
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected mock Codex exchange method: %s", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("grant_type") != "session_key" || !strings.HasPrefix(r.Form.Get("session_key"), "mock-chatgpt-session-") {
				t.Fatalf("unexpected mock Codex grant: %v", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": accessToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/openai/v1/responses":
			sawVerify = true
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+accessToken {
				t.Fatalf("unexpected mock Codex verification request: %s auth=%t", r.Method, r.Header.Get("Authorization") != "")
			}
			_, _ = io.WriteString(w, `{"status":"completed"}`)
		default:
			t.Fatalf("unexpected mock Codex request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer provider.Close()

	token, err := exchangePoolSessionKey(context.Background(), poolLoginContext{
		ProviderCode: "mock", ProtocolType: "openai_compatible",
		OAuthTokenURL: provider.URL + "/oauth/openai_compatible/token",
	}, broker.SessionKeyExchangeOptions{
		SessionKey: "mock-chatgpt-session-fixture-value-long-enough",
		ProxyURL:   "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("mock Codex Session Key exchange: %v", err)
	}
	if token.AccessToken != accessToken || token.RefreshToken != "" ||
		token.Identity.ExternalID != "cred-mock-codex" || token.Identity.Email != "mock-codex@example.test" {
		t.Fatalf("unexpected mock Codex token metadata: %+v", token)
	}
	// spec: R-sessionkey-login-safety-1.S1 success must close BOTH provider
	// legs; a dispatch regression to the exchange-only capability would skip
	// the verification leg and stay green without this assertion.
	if !sawExchange || !sawVerify {
		t.Fatalf("atomic mock Codex login missed a provider leg: exchange=%t verify=%t", sawExchange, sawVerify)
	}
}

func TestExchangePoolSessionKeyUsesResidentMockProviderContext(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/anthropic/token" || r.Method != http.MethodPost {
			t.Fatalf("unexpected mock provider request: %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.Form.Get("grant_type") != "session_key" ||
			r.Form.Get("session_key") != "sk-ant-sid02-mock-fixture-value-long-enough" ||
			r.Form.Get("expires_in") != "31536000" {
			t.Fatalf("unexpected mock provider grant: %v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"MOCK-ACCESS","refresh_token":"MOCK-REFRESH","token_type":"Bearer","expires_in":31536000,"scope":"user:inference","account":{"uuid":"cred-mock","email_address":"mock@example.test"},"organization":{"uuid":"mock-org","name":"AiKey Mock Organization"}}`)
	}))
	defer provider.Close()

	token, err := exchangePoolSessionKey(context.Background(), poolLoginContext{
		ProviderCode: "mock", ProtocolType: "anthropic",
		OAuthTokenURL: provider.URL + "/oauth/anthropic/token",
	}, broker.SessionKeyExchangeOptions{
		SessionKey: "sk-ant-sid02-mock-fixture-value-long-enough",
		ProxyURL:   "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("mock Session Key exchange: %v", err)
	}
	if token.AccessToken != "MOCK-ACCESS" || token.Identity.ExternalID != "cred-mock" || token.Identity.Email != "mock@example.test" {
		t.Fatalf("unexpected exchanged token metadata: %+v", token)
	}
}

// A real Anthropic credential must enter the fixed Claude exchanger, never the
// resident Mock Provider adapter. An invalid proxy shape makes the official
// exchanger stop before network I/O and gives this dispatch test a hermetic
// assertion surface.
func TestExchangePoolSessionKeyRoutesRealAnthropicToClaudeExchanger(t *testing.T) {
	_, err := exchangePoolSessionKey(context.Background(), poolLoginContext{
		ProviderCode: "anthropic", ProtocolType: "anthropic",
	}, broker.SessionKeyExchangeOptions{
		SessionKey: "sk-ant-sid02-real-shaped-fixture-value-long-enough",
		ProxyURL:   "ftp://proxy.invalid:21",
	})
	var oauthErr *broker.OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != broker.ErrCodeSessionKeyEgressUnsupported {
		t.Fatalf("real Anthropic account did not enter the Claude exchanger: %v", err)
	}
	if strings.Contains(oauthErr.Message, "Mock Provider") {
		t.Fatalf("real Anthropic account entered the Mock Provider adapter: %v", err)
	}
}

func TestExchangePoolSessionKeyRoutesRealOpenAIToCodexExchanger(t *testing.T) {
	_, err := exchangePoolSessionKey(context.Background(), poolLoginContext{
		ProviderCode: "openai", ProtocolType: "openai_compatible",
	}, broker.SessionKeyExchangeOptions{
		SessionKey: "opaque-chatgpt-session-token-value-0123456789",
		ProxyURL:   "ftp://proxy.invalid:21",
	})
	var oauthErr *broker.OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != broker.ErrCodeSessionKeyEgressUnsupported {
		t.Fatalf("real OpenAI account did not enter the Codex exchanger: %v", err)
	}
	if strings.Contains(oauthErr.Message, "Mock Provider") {
		t.Fatalf("real OpenAI account entered the Mock Provider adapter: %v", err)
	}
}

// spec: R-sessionkey-login-safety-1.S1 the Codex routes may only wire the
// atomic exchange-and-verify broker capabilities. The real chatgpt.com verify
// leg cannot be exercised hermetically, so this fence asserts function
// identity on the dispatch table itself — an exchange-only entry would let an
// unverified bearer reach member pending/writeback.
func TestPoolSessionKeyRoutes_CodexRoutesAreAtomic(t *testing.T) {
	codex := poolSessionKeyRoutes[poolSessionKeyAdapterKey{providerCode: "openai", protocolType: "openai_compatible"}]
	if codex.exchange == nil || reflect.ValueOf(codex.exchange).Pointer() !=
		reflect.ValueOf(broker.ExchangeAndVerifyCodexSessionKey).Pointer() {
		t.Fatal("openai/openai_compatible route bypasses the atomic Codex login capability")
	}
	mockCodex := poolSessionKeyRoutes[poolSessionKeyAdapterKey{providerCode: "mock", protocolType: "openai_compatible"}]
	if mockCodex.mockExchange == nil || reflect.ValueOf(mockCodex.mockExchange).Pointer() !=
		reflect.ValueOf(broker.ExchangeAndVerifyMockCodexSessionKey).Pointer() {
		t.Fatal("mock/openai_compatible route bypasses the atomic Codex login capability")
	}
}

func TestPoolSessionKey_RefusesMissingEffectiveEgressBeforeExchange(t *testing.T) {
	h := newPoolHandler(t, &fakePoolExchanger{}, "http://unused")
	var exchanges atomic.Int32
	h.sessionKeyNodeEgress = func() (string, error) { return "", nil }
	h.sessionKeyExchange = func(context.Context, poolLoginContext, broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error) {
		exchanges.Add(1)
		return nil, errors.New("must not run")
	}
	w := doJSON(h.sessionKey, `{"credential_id":"c1","session_key":"sk-ant-sid02-fixture-value-long-enough","operation_id":"proxyrequired1234567890"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), broker.ErrCodeSessionKeyEgressUnavailable) {
		t.Fatalf("missing egress: %d %s", w.Code, w.Body.String())
	}
	if exchanges.Load() != 0 {
		t.Fatalf("provider exchange ran without an effective proxy: %d", exchanges.Load())
	}
}

func TestPoolSessionKey_UsesMasterEffectiveEgressWithoutLocalVKRuntime(t *testing.T) {
	h := newPoolHandler(t, &fakePoolExchanger{}, "http://unused")
	h.resolveContext = func(_ context.Context, credentialID string) (poolLoginContext, error) {
		return poolLoginContext{
			CredentialID: credentialID, OauthGroupID: "group-without-local-vk", AccountID: "account-1",
			ProviderCode: "anthropic", ProtocolType: "anthropic", ExpectedIdentity: "member@team.com",
			EffectiveEgressURL: "socks5://account.example:1080",
		}, nil
	}
	var fallbackCalls atomic.Int32
	h.sessionKeyNodeEgress = func() (string, error) {
		fallbackCalls.Add(1)
		return "", errors.New("local VK runtime must not be required")
	}
	var gotProxy string
	h.sessionKeyExchange = func(_ context.Context, _ poolLoginContext, opts broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error) {
		gotProxy = opts.ProxyURL
		return &broker.SessionKeyToken{AccessToken: "ACCESS", ExpiresIn: 60, Identity: broker.IdentityInfo{Email: "member@team.com"}}, nil
	}

	w := doJSON(h.sessionKey, `{"credential_id":"c1","session_key":"sk-ant-sid02-fixture-value-long-enough","operation_id":"masteregress1234567890"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"pending"`) {
		t.Fatalf("master effective egress login: %d %s", w.Code, w.Body.String())
	}
	if gotProxy != "socks5://account.example:1080" || fallbackCalls.Load() != 0 {
		t.Fatalf("egress=%q fallback_calls=%d", gotProxy, fallbackCalls.Load())
	}
}

func TestPoolSessionKey_PendingConfirmWritesOnceWithoutTokenLeak(t *testing.T) {
	var gotWB memberTokenWriteback
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotWB); err != nil {
			t.Fatalf("decode writeback: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer master.Close()

	h := newPoolHandler(t, &fakePoolExchanger{}, master.URL)
	h.client = master.Client()
	var exchanges atomic.Int32
	exchangedAt := time.Now().Unix()
	h.sessionKeyExchange = func(_ context.Context, _ poolLoginContext, opts broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error) {
		exchanges.Add(1)
		if opts.SessionKey != "sk-ant-sid02-fixture-value-long-enough" || opts.ProxyURL != "http://127.0.0.1:10808" {
			t.Fatalf("wrong exchanger input: session=%q proxy=%q", opts.SessionKey, opts.ProxyURL)
		}
		return &broker.SessionKeyToken{
			AccessToken: "ACCESS-SECRET", RefreshToken: "REFRESH-SECRET", TokenType: "Bearer",
			ExpiresIn: 3600, Scope: "user:inference",
			Identity: broker.IdentityInfo{Email: "member@team.com", ExternalID: "claude-user", OrgUUID: "org-1"},
		}, nil
	}
	h.sessionKeyNodeEgress = func() (string, error) { return "http://127.0.0.1:10808", nil }

	const operationID = "0123456789abcdef0123456789abcdef"
	w1 := doJSON(h.sessionKey, `{"credential_id":"c1","session_key":"sk-ant-sid02-fixture-value-long-enough","operation_id":"`+operationID+`"}`)
	if w1.Code != http.StatusOK || !strings.Contains(w1.Body.String(), `"status":"pending"`) {
		t.Fatalf("exchange: %d %s", w1.Code, w1.Body.String())
	}
	if strings.Contains(w1.Body.String(), "ACCESS-SECRET") || strings.Contains(w1.Body.String(), "REFRESH-SECRET") {
		t.Fatalf("pending response leaked token: %s", w1.Body.String())
	}

	w2 := doJSON(h.sessionKey, `{"credential_id":"c1","operation_id":"`+operationID+`","confirm":true}`)
	if w2.Code != http.StatusOK || !strings.Contains(w2.Body.String(), `"status":"ok"`) {
		t.Fatalf("confirm: %d %s", w2.Code, w2.Body.String())
	}
	if exchanges.Load() != 1 {
		t.Fatalf("confirm must reuse held token, exchanges=%d", exchanges.Load())
	}
	if gotWB.AccessToken != "ACCESS-SECRET" || gotWB.RefreshToken != "REFRESH-SECRET" || gotWB.Identity != "member@team.com" {
		t.Fatalf("wrong writeback: %+v", gotWB)
	}
	if gotWB.ExpiresAt < exchangedAt+3599 || gotWB.ExpiresAt > exchangedAt+3601 {
		t.Fatalf("expiry must be based on exchange time, got %d near %d", gotWB.ExpiresAt, exchangedAt+3600)
	}
	if strings.Contains(w2.Body.String(), "ACCESS-SECRET") || strings.Contains(w2.Body.String(), "REFRESH-SECRET") {
		t.Fatalf("confirm response leaked token: %s", w2.Body.String())
	}
}

func TestPoolSessionKey_SweepRemovesExpiredTokenAndOperationLock(t *testing.T) {
	h := newPoolHandler(t, &fakePoolExchanger{}, "http://unused")
	const operationID = "expiredoperation1234567890"
	pending := &poolSessionKeyPending{
		token:     &broker.SessionKeyToken{AccessToken: "ACCESS-SECRET", RefreshToken: "REFRESH-SECRET"},
		createdAt: time.Now().Add(-poolSessionTTL - time.Second),
	}
	h.sessionKeyPending.Store(operationID, pending)
	h.sessionKeyOps = map[string]*poolSessionKeyOperation{operationID: {}}

	h.sweepExpiredSessionKeyOperations()

	if _, ok := h.sessionKeyPending.Load(operationID); ok {
		t.Fatal("expired pending token was not removed")
	}
	if pending.token.AccessToken != "" || pending.token.RefreshToken != "" {
		t.Fatal("expired pending token strings were not cleared")
	}
	if _, ok := h.sessionKeyOps[operationID]; ok {
		t.Fatal("expired operation lock was not removed")
	}
}

func TestPoolSessionKey_ScheduledExpiryClearsAbandonedToken(t *testing.T) {
	h := newPoolHandler(t, &fakePoolExchanger{}, "http://unused")
	const operationID = "scheduledexpiry1234567890"
	pending := &poolSessionKeyPending{
		token:     &broker.SessionKeyToken{AccessToken: "ACCESS-SECRET", RefreshToken: "REFRESH-SECRET"},
		createdAt: time.Now().Add(-poolSessionTTL),
	}
	h.sessionKeyPending.Store(operationID, pending)
	h.scheduleSessionKeyExpiry(operationID, pending)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, ok := h.sessionKeyPending.Load(operationID); !ok {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := h.sessionKeyPending.Load(operationID); ok {
		t.Fatal("scheduled expiry did not remove the abandoned token")
	}
	if pending.token.AccessToken != "" || pending.token.RefreshToken != "" {
		t.Fatal("scheduled expiry did not clear token strings")
	}
}

func TestPoolSessionKey_WritebackRetryDoesNotReexchange(t *testing.T) {
	fastBackoff(t)
	logs := captureJSONLogs(t)
	var hits atomic.Int32
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) <= int32(writebackMaxAttempts) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer master.Close()

	h := newPoolHandler(t, &fakePoolExchanger{}, master.URL)
	h.client = master.Client()
	var exchanges atomic.Int32
	h.sessionKeyExchange = func(context.Context, poolLoginContext, broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error) {
		exchanges.Add(1)
		return &broker.SessionKeyToken{AccessToken: "SECRET-WRITEBACK-TOKEN", ExpiresIn: 3600, Identity: broker.IdentityInfo{Email: "member@team.com"}}, nil
	}
	const operationID = "fedcba9876543210fedcba9876543210"
	if w := doJSON(h.sessionKey, `{"credential_id":"c1","session_key":"sk-ant-sid02-fixture-value-long-enough","operation_id":"`+operationID+`"}`); w.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(h.sessionKey, `{"credential_id":"c1","operation_id":"`+operationID+`","confirm":true}`); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "WRITEBACK_FAILED") {
		t.Fatalf("first confirm: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(h.sessionKey, `{"credential_id":"c1","operation_id":"`+operationID+`","confirm":true}`); w.Code != http.StatusOK {
		t.Fatalf("retry confirm: %d %s", w.Code, w.Body.String())
	}
	if exchanges.Load() != 1 {
		t.Fatalf("writeback retry re-exchanged provider token: %d", exchanges.Load())
	}
	assertStructuredWarning(t, logs.String(), observability.EventProxyPoolSessionKeyWritebackFailed, observability.ErrCodeProxyPoolSessionKeyWritebackFailed)
	if strings.Contains(logs.String(), "SECRET-WRITEBACK-TOKEN") {
		t.Fatal("writeback warning leaked token material")
	}
}

func TestPoolSessionKey_RuntimeSyncWarningCarriesStableContract(t *testing.T) {
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer master.Close()

	h := newPoolHandler(t, &fakePoolExchanger{}, master.URL)
	h.client = master.Client()
	h.sessionKeyExchange = func(context.Context, poolLoginContext, broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error) {
		return &broker.SessionKeyToken{AccessToken: "SECRET-RUNTIME-SYNC-TOKEN", ExpiresIn: 3600, Identity: broker.IdentityInfo{Email: "member@team.com"}}, nil
	}
	h.syncAfterWriteback = func(context.Context) error { return errors.New("runtime sync fixture failed") }

	const operationID = "runtimewarnings1234567890abcdef"
	if w := doJSON(h.sessionKey, `{"credential_id":"c1","session_key":"sk-ant-sid02-fixture-value-long-enough","operation_id":"`+operationID+`"}`); w.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", w.Code, w.Body.String())
	}

	logs := captureJSONLogs(t)
	r := httptest.NewRequest(http.MethodPost, "/oauth/pool/session-key", strings.NewReader(`{"credential_id":"c1","operation_id":"`+operationID+`","confirm":true}`))
	r.Header.Set("traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	r.Header.Set("x-request-id", "req-session-key-runtime-sync")
	w := httptest.NewRecorder()
	h.sessionKey(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"sync_status":"pending"`) {
		t.Fatalf("durable login with pending sync: %d %s", w.Code, w.Body.String())
	}
	logText := logs.String()
	assertStructuredWarning(t, logText, observability.EventProxyPoolSessionKeyRuntimeSyncPending, observability.ErrCodeProxyPoolSessionKeyRuntimeSyncPending)
	for _, want := range []string{
		`"request_id":"req-session-key-runtime-sync"`,
		`"trace_id":"0123456789abcdef0123456789abcdef"`,
		`"span_id":"`,
	} {
		if !strings.Contains(logText, want) {
			t.Fatalf("runtime-sync warning missing %s: %s", want, logText)
		}
	}
	if strings.Contains(logText, "SECRET-RUNTIME-SYNC-TOKEN") {
		t.Fatal("runtime-sync warning leaked token material")
	}
}

func TestPoolSessionKey_CancelZerosAndRemovesPendingToken(t *testing.T) {
	h := newPoolHandler(t, &fakePoolExchanger{}, "http://unused")
	h.sessionKeyExchange = func(context.Context, poolLoginContext, broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error) {
		return &broker.SessionKeyToken{AccessToken: "T", RefreshToken: "R", ExpiresIn: 3600, Identity: broker.IdentityInfo{Email: "member@team.com"}}, nil
	}
	const operationID = "aaaabbbbccccddddeeeeffff00001111"
	if w := doJSON(h.sessionKey, `{"credential_id":"c1","session_key":"sk-ant-sid02-fixture-value-long-enough","operation_id":"`+operationID+`"}`); w.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", w.Code, w.Body.String())
	}
	pendingAny, _ := h.sessionKeyPending.Load(operationID)
	pending := pendingAny.(*poolSessionKeyPending)
	if w := doJSON(h.sessionKey, `{"credential_id":"c1","operation_id":"`+operationID+`","cancel":true}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "canceled") {
		t.Fatalf("cancel: %d %s", w.Code, w.Body.String())
	}
	if pending.token.AccessToken != "" || pending.token.RefreshToken != "" {
		t.Fatal("cancel must zero held token material")
	}
	if _, ok := h.sessionKeyPending.Load(operationID); ok {
		t.Fatal("cancel must remove pending operation")
	}
}

// TestPoolSessionKey_IdentityMismatchRequiresExplicitAcknowledgement pins the
// 2026-09-01 拍板 (supersedes the 2026-08-27 immediate fail-closed): a
// cross-account Session Key becomes a reviewable pending operation; an ordinary
// confirm still refuses; only the explicit identity_mismatch_confirmed
// acknowledgement writes back — carrying identity_mismatch=true and the ACTUAL
// provider account id so master binds the member's own seat row only.
// spec: R-oauth-token-mint-12.S1 (Step 1) / .S2 (Step 2) / .S3 (Step 3)
func TestPoolSessionKey_IdentityMismatchRequiresExplicitAcknowledgement(t *testing.T) {
	var (
		gotWB      memberTokenWriteback
		writebacks atomic.Int32
	)
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writebacks.Add(1)
		if err := json.NewDecoder(r.Body).Decode(&gotWB); err != nil {
			t.Fatalf("decode writeback: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer master.Close()

	h := newPoolHandler(t, &fakePoolExchanger{}, master.URL)
	h.client = master.Client()
	token := &broker.SessionKeyToken{
		AccessToken: "ACCESS-SECRET", RefreshToken: "REFRESH-SECRET", ExpiresIn: 3600,
		Identity: broker.IdentityInfo{Email: "wrong@team.com", ExternalID: "wrong-uuid"},
	}
	h.resolveContext = func(_ context.Context, credentialID string) (poolLoginContext, error) {
		return poolLoginContext{
			CredentialID: credentialID, OauthGroupID: "g1", AccountID: "a1",
			ProviderCode: "anthropic", ProtocolType: "anthropic",
			ExpectedIdentity: "member@team.com", ExternalID: "expected-uuid",
		}, nil
	}
	h.sessionKeyExchange = func(context.Context, poolLoginContext, broker.SessionKeyExchangeOptions) (*broker.SessionKeyToken, error) {
		return token, nil
	}
	const operationID = "99998888777766665555444433332222"

	// Step 1: exchange → reviewable pending with the mismatch surfaced, zero writeback.
	w := doJSON(h.sessionKey, `{"credential_id":"c1","session_key":"sk-ant-sid02-fixture-value-long-enough","operation_id":"`+operationID+`"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"identity_mismatch":true`) {
		t.Fatalf("mismatch review state: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "ACCESS-SECRET") || strings.Contains(w.Body.String(), "REFRESH-SECRET") {
		t.Fatal("token material leaked into the review response")
	}
	if _, ok := h.sessionKeyPending.Load(operationID); !ok {
		t.Fatal("mismatch must create a confirmable pending operation")
	}
	if writebacks.Load() != 0 {
		t.Fatalf("review step must not write to master, got %d", writebacks.Load())
	}

	// Step 2: ordinary confirm WITHOUT the acknowledgement → refused, pending kept.
	w = doJSON(h.sessionKey, `{"credential_id":"c1","operation_id":"`+operationID+`","confirm":true}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), broker.ErrCodeSessionKeyIdentityMismatch) {
		t.Fatalf("unacknowledged confirm: %d %s", w.Code, w.Body.String())
	}
	if _, ok := h.sessionKeyPending.Load(operationID); !ok {
		t.Fatal("unacknowledged confirm must keep the pending operation for re-confirm/cancel")
	}
	if writebacks.Load() != 0 {
		t.Fatalf("unacknowledged confirm must not write to master, got %d", writebacks.Load())
	}

	// Step 3: explicit acknowledgement → exactly one writeback with the mismatch
	// declared and the ACTUAL identity (master stores it on the seat row).
	w = doJSON(h.sessionKey, `{"credential_id":"c1","operation_id":"`+operationID+`","confirm":true,"identity_mismatch_confirmed":true}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"identity_mismatch":true`) {
		t.Fatalf("acknowledged confirm: %d %s", w.Code, w.Body.String())
	}
	if writebacks.Load() != 1 {
		t.Fatalf("acknowledged confirm must write exactly once, got %d", writebacks.Load())
	}
	if !gotWB.IdentityMismatch || gotWB.ExternalID != "wrong-uuid" || gotWB.Identity != "wrong@team.com" {
		t.Fatalf("writeback must declare the mismatch with the actual identity: %+v", gotWB)
	}
	if gotWB.AccessToken != "ACCESS-SECRET" {
		t.Fatalf("writeback must carry the exchanged token: %+v", gotWB)
	}
	if _, ok := h.sessionKeyPending.Load(operationID); ok {
		t.Fatal("completed operation must be forgotten")
	}
}

func TestPoolBrowserOAuth_IdentityMismatchFailsClosedWithoutWriteback(t *testing.T) {
	ex := &fakePoolExchanger{
		accountID: "provider-account", access: "ACCESS", refresh: "REFRESH", expiresAt: 100,
		externalID: "wrong-uuid", identity: "wrong@team.com",
	}
	h := newPoolHandler(t, ex, "http://master.invalid")
	h.sessions.Store("sess-1", poolSession{
		credentialID: "c1", oauthGroupID: "g1", accountID: "a1",
		providerCode: "anthropic", protocolType: "anthropic",
		expectedIdentity: "member@team.com", externalID: "expected-uuid", createdAt: time.Now(),
	})
	w := doJSON(h.submitCode, `{"session_id":"sess-1","code":"one-shot-code","confirm":false}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), broker.ErrCodeSessionKeyIdentityMismatch) {
		t.Fatalf("browser mismatch: %d %s", w.Code, w.Body.String())
	}
	if ex.forgotN != 1 || ex.forgotSess != "sess-1" || ex.forgotAcct != "provider-account" {
		t.Fatalf("mismatched browser token not consumed: %+v", ex)
	}
	if _, ok := h.sessions.Load("sess-1"); ok {
		t.Fatal("mismatched browser session remained confirmable")
	}
}

func TestSessionKeyIdentityMatches_FailsClosedWithoutExpectedIdentity(t *testing.T) {
	// spec: R-oauth-token-mint-12.S5 期望身份为空 = 首登，proxy 不得比 Master 严
	// 2026-09-01 alignment with master's membertoken.identityMismatch: a pool row
	// with NO expected identity at all is a first login — master accepts it and
	// C5-backfills, so the proxy must not 409 it (08-27 评审 P1).
	if !sessionKeyIdentityMatches(poolLoginContext{}, broker.IdentityInfo{Email: "member@team.com", ExternalID: "claude-user"}) {
		t.Fatal("first login onto an identity-less account must pass for master-side backfill")
	}
	if sessionKeyIdentityMatches(
		poolLoginContext{ExternalID: "expected-uuid", ExpectedIdentity: "member@team.com"},
		broker.IdentityInfo{Email: "member@team.com"},
	) {
		t.Fatal("a stable external ID must not fall back to email when the exchanged ID is absent")
	}
	if !sessionKeyIdentityMatches(
		poolLoginContext{ExpectedIdentity: "Member@Team.com"},
		broker.IdentityInfo{Email: "member@team.com"},
	) {
		t.Fatal("email-only identity should match case-insensitively")
	}
}

func doJSON(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func captureJSONLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	old := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &logs
}

func assertStructuredWarning(t *testing.T, logText, eventName, errorCode string) {
	t.Helper()
	for _, want := range []string{
		`"level":"WARN"`,
		`"event.name":"` + eventName + `"`,
		`"error.code":"` + errorCode + `"`,
		`"request_id":"`,
		`"trace_id":"`,
		`"span_id":"`,
	} {
		if !strings.Contains(logText, want) {
			t.Fatalf("structured warning missing %s: %s", want, logText)
		}
	}
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
	if gotWB.CredentialID != "c1" || gotWB.AccessToken != "TOK" || gotWB.RefreshToken != "RT" || gotWB.ExpiresAt != 42 || gotWB.ExternalID != "uuid-x" || gotWB.ProviderCode != "anthropic" || gotWB.OauthGroupID != "g1" || gotWB.AccountID != "account-c1" || gotWB.Identity != "member@team.com" {
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

// The client/provider display value is never authoritative. The credential's
// master binding selects both broker provider and flow at session creation.
func TestPoolLogin_AuthorizeUsesServerBindingNotClientProvider(t *testing.T) {
	ex := &fakePoolExchanger{authURL: "https://login"}
	h := newPoolHandler(t, ex, "https://master.invalid")
	h.resolveContext = func(_ context.Context, credentialID string) (poolLoginContext, error) {
		return poolLoginContext{
			CredentialID: credentialID, OauthGroupID: "g-openai", AccountID: "a-openai",
			ProviderCode: "openai", ExpectedIdentity: "codex@team.com",
		}, nil
	}

	w := doJSON(h.authorizeURL, `{"provider":"claude","credential_id":"c-openai"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	if ex.startedProvider != "codex" {
		t.Fatalf("server-bound openai must start codex, client claude must be ignored; got %q", ex.startedProvider)
	}
	var got struct {
		ProviderCode     string `json:"provider_code"`
		Flow             string `json:"flow"`
		ExpectedIdentity string `json:"expected_identity"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.ProviderCode != "openai" || got.Flow != "auth_code" || got.ExpectedIdentity != "codex@team.com" {
		t.Fatalf("server login context not returned intact: %+v", got)
	}
}

func TestPoolProviderFor_MockUsesCredentialProtocolAndMasterEndpoints(t *testing.T) {
	tests := []struct {
		name              string
		protocol          string
		wantFlow          string
		wantIdentity      string
		wantImpersonation bool
	}{
		{name: "anthropic", protocol: "anthropic", wantFlow: "setup_token", wantIdentity: "claude"},
		{name: "codex", protocol: "openai_compatible", wantFlow: "auth_code", wantIdentity: "codex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := poolLoginContext{
				CredentialID: "cred-1", ProviderCode: "mock", ProtocolType: tt.protocol,
				OAuthAuthorizeURL: "https://master.example/mock-provider/oauth/" + tt.protocol + "/authorize",
				OAuthTokenURL:     "https://master.example/mock-provider/oauth/" + tt.protocol + "/token",
				OAuthContext:      "signed-context",
				ExpectedIdentity:  "member@example.test",
			}
			profile, ok := poolProviderFor(ctx)
			if !ok || profile.config == nil {
				t.Fatalf("mock %s must resolve to a session-scoped broker config: %+v", tt.protocol, profile)
			}
			if profile.flow != tt.wantFlow || profile.config.IdentityProvider != tt.wantIdentity {
				t.Fatalf("wrong mock profile: flow=%q identity=%q", profile.flow, profile.config.IdentityProvider)
			}
			if profile.config.ProviderCode != "mock" || profile.config.ProtocolType != tt.protocol {
				t.Fatalf("OAuth profile collapsed account axes: provider=%q protocol=%q",
					profile.config.ProviderCode, profile.config.ProtocolType)
			}
			if profile.config.AuthorizeURL != ctx.OAuthAuthorizeURL || profile.config.TokenURL != ctx.OAuthTokenURL {
				t.Fatalf("master endpoints not preserved: %+v", profile.config)
			}
			if profile.config.ExtraAuthorizeParams["credential_id"] != "cred-1" || profile.config.ExtraAuthorizeParams["login_hint"] != "member@example.test" {
				t.Fatalf("credential binding missing from authorize params: %+v", profile.config.ExtraAuthorizeParams)
			}
			if profile.config.ExtraAuthorizeParams["oauth_context"] != "signed-context" {
				t.Fatalf("signed Master context missing from authorize params: %+v", profile.config.ExtraAuthorizeParams)
			}
			if tt.protocol == "anthropic" && profile.config.RequireTLSImpersonation {
				t.Fatal("the internal mock endpoint must not use Anthropic TLS impersonation")
			}
		})
	}

	for _, bad := range []poolLoginContext{
		{ProviderCode: "mock", ProtocolType: "anthropic"},
		{ProviderCode: "mock", ProtocolType: "unknown", OAuthAuthorizeURL: "https://a", OAuthTokenURL: "https://t"},
	} {
		if _, ok := poolProviderFor(bad); ok {
			t.Fatalf("ambiguous mock binding must fail closed: %+v", bad)
		}
	}
}

func TestPoolLogin_MockNamespaceIsSessionScoped(t *testing.T) {
	ex := &fakePoolExchanger{authURL: "https://login"}
	h := newPoolHandler(t, ex, "https://master.invalid")
	h.resolveContext = func(_ context.Context, credentialID string) (poolLoginContext, error) {
		return poolLoginContext{
			CredentialID: credentialID, OauthGroupID: "g-mock", AccountID: "a-mock",
			ProviderCode: "mock", ProtocolType: "anthropic", ExpectedIdentity: "mock@example.test",
			OAuthAuthorizeURL: "https://master.example/mock-provider/oauth/anthropic/authorize",
			OAuthTokenURL:     "https://master.example/mock-provider/oauth/anthropic/token",
			OAuthContext:      "signed-context",
		}, nil
	}
	w := doJSON(h.authorizeURL, `{"credential_id":"c-mock","namespace":"ci:run-1"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	if ex.startedProfile.config == nil || ex.startedProfile.config.ExtraAuthorizeParams["namespace"] != "ci:run-1" {
		t.Fatalf("namespace was not frozen into the Mock OAuth session: %+v", ex.startedProfile)
	}

	w = doJSON(h.authorizeURL, `{"credential_id":"c-mock","namespace":"bad/scope"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "INVALID_NAMESPACE") {
		t.Fatalf("invalid namespace must fail before broker start: %d %s", w.Code, w.Body.String())
	}
}

func TestPoolLogin_AuthorizeSurfacesMasterContextConflict(t *testing.T) {
	h := newPoolHandler(t, &fakePoolExchanger{authURL: "https://login"}, "https://master.invalid")
	h.resolveContext = func(context.Context, string) (poolLoginContext, error) {
		return poolLoginContext{}, &poolLoginContextHTTPError{
			StatusCode: http.StatusConflict,
			Detail:     `{"error":"BIZ_OAUTH_LOGIN_CONTEXT_UNAVAILABLE"}`,
		}
	}
	w := doJSON(h.authorizeURL, `{"credential_id":"c1"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "BIZ_OAUTH_LOGIN_CONTEXT_UNAVAILABLE") {
		t.Fatalf("master login-context conflict must stay visible, got %d %s", w.Code, w.Body.String())
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

// Once master has accepted the token, a runtime-sync failure is not allowed to
// turn the completed OAuth login into a retry loop. It is returned as an
// explicit pending state while the normal rail keeps retrying in background.
func TestPoolLogin_RuntimeSyncFailureIsVisibleButNonBlocking(t *testing.T) {
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
	h.syncAfterWriteback = func(context.Context) error {
		if atomic.LoadInt32(&writebacks) != 1 {
			t.Fatal("runtime sync ran before the token was durable on master")
		}
		return errors.New("group runtime fetch failed")
	}

	_ = doJSON(h.authorizeURL, `{"credential_id":"c1"}`)
	w := doJSON(h.submitCode, `{"session_id":"sess-1","code":"abc#st","confirm":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("durable login must stay successful, got %d %s", w.Code, w.Body.String())
	}
	var got struct {
		Status     string `json:"status"`
		SyncStatus string `json:"sync_status"`
		SyncError  string `json:"sync_error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Status != "ok" || got.SyncStatus != "pending" || !strings.Contains(got.SyncError, "runtime fetch failed") {
		t.Fatalf("pending sync must be explicit without failing login: %+v", got)
	}
	if ex.forgotN != 1 {
		t.Fatalf("durable login session must be consumed despite pending sync, got forgot=%d", ex.forgotN)
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
