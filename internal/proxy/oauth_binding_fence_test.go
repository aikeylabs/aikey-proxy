package proxy

// Characterization (fence) tests for the OAuth-via-binding path through
// handlePathPrefixRoute. These pin the EXACT current behavior of:
//
//   - happy path: binding.KeySourceType="personal_oauth_account" →
//     broker.EnsureFresh → ResolveCredential → oauthInject → 200
//   - broker absent (proxy started without OAuth wired) → 503 OAUTH_NOT_AVAILABLE
//   - EnsureFresh fails (refresh token expired / revoked) → 401 OAUTH_TOKEN_EXPIRED
//   - ResolveCredential fails (broker found the account but couldn't
//     decrypt) → 503 OAUTH_RESOLVE_FAILED
//   - Codex BaseURL override: when canonicalCode=openai, BaseURL forced
//     to https://chatgpt.com/backend-api/codex regardless of route.BaseURL
//
// Why this file exists separately: AKL-207 plans to refactor
// `handlePathPrefixRoute` and extract a shared credential resolver that
// apppipe/pipeline.go can also call. The existing test file covers team
// + personal binding paths but NOT OAuth, leaving the highest-risk
// branch unfenced. These tests provide the safety net for the refactor —
// they MUST pass before AKL-207 lands and MUST still pass after.
//
// What the refactor must preserve (and these tests prove):
//   - Exact response status codes (401 / 503 / 200)
//   - Exact error codes (OAUTH_NOT_AVAILABLE / OAUTH_TOKEN_EXPIRED / OAUTH_RESOLVE_FAILED)
//   - Codex's quirky BaseURL override (production-critical: Claude Code
//     team uses it daily)
//   - oauthInject side-effect on request headers (Bearer + identity)

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// ── capturingTransport — observes outbound URL without leaving localhost ─

// capturingTransport implements http.RoundTripper. It captures the URL the
// proxy *attempted to dial* and short-circuits with a synthetic 200 so the
// test never hits the network. Fence tests use the captured URL to assert
// the BaseURL the proxy chose — the most precise way to pin the Codex
// override and similar production-critical quirks without flakiness from
// real network conditions.
//
// Why not redirect to httptest.NewServer: redirection masks BaseURL choice
// (proxy "hits the upstream" regardless of what it picked). Capture +
// assert is the right semantics for fence tests of BaseURL selection.
type capturingTransport struct {
	host string
	url  string
}

func (c *capturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.host = req.URL.Host
	c.url = req.URL.String()
	// Synthetic 200 — body shape mirrors a minimal upstream response so
	// the proxy's downstream usage extractor doesn't WARN on shape mismatch.
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(
			`{"id":"msg","type":"message","content":[{"type":"text","text":"ok"}],"model":"c","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)),
		Request: req,
	}, nil
}

// ── mockOAuthBroker — minimal OAuthBroker implementation for fence tests ──

type mockOAuthBroker struct {
	// ensureFreshErr / resolveErr — if set, the corresponding broker method
	// returns this error. nil = success path.
	ensureFreshErr error
	resolveErr     error
	// resolveCred — the credential returned by ResolveCredential on success.
	// Provider field must match the canonicalCode the test exercises so
	// oauthInject(r, cred, canonicalCode) dispatches to the correct
	// per-provider injector.
	resolveCred *OAuthCredential
	// statusErr / status — return shape for GetAccountStatus. Tests
	// rarely exercise GetAccountStatus directly (it's for the probe path,
	// not the binding path), so defaults are fine.
	statusErr error
	status    string
}

func (m *mockOAuthBroker) EnsureFresh(ctx context.Context, accountID string) error {
	return m.ensureFreshErr
}

func (m *mockOAuthBroker) ResolveCredential(ctx context.Context, accountID string) (*OAuthCredential, error) {
	if m.resolveErr != nil {
		return nil, m.resolveErr
	}
	if m.resolveCred == nil {
		return &OAuthCredential{AccessToken: "default-tok", AccountID: accountID, Provider: "anthropic"}, nil
	}
	return m.resolveCred, nil
}

func (m *mockOAuthBroker) GetAccountStatus(ctx context.Context, accountID string) (string, error) {
	if m.statusErr != nil {
		return "", m.statusErr
	}
	return m.status, nil
}

// ── Fence test 1: OAuth happy path ──────────────────────────────────────────

// Pins: binding.KeySourceType="personal_oauth_account" → broker invoked →
// outbound request targets api.anthropic.com (default OAuth BaseURL) +
// Authorization: Bearer header set (not x-api-key) + path stripped to
// /v1/messages. This is the dominant Claude Pro path; if the AKL-207
// refactor breaks this, every Claude Pro user breaks.
func TestFence_OAuthBinding_HappyPath(t *testing.T) {
	av := &mockActiveVault{
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "personal_oauth_account",
				KeySourceRef:  "session_oauth-acct-1",
			},
		},
		activeTeamKeys: map[string]*vault.ManagedKey{
			// Sentinel: OAuth binding path MUST take precedence over team
			// key for the same provider. If the refactor accidentally
			// fell through to team key resolution, this team key would
			// be picked and our captured Host wouldn't be api.anthropic.com.
			"anthropic": {
				VirtualKeyID: "should-not-be-used",
				ProviderCode: "anthropic",
				BaseURL:      "http://team-key-wrongly-used.invalid",
				PlaintextKey: "sk-team-WRONG",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)
	p.SetBroker(&mockOAuthBroker{
		resolveCred: &OAuthCredential{
			AccessToken: "oauth-bearer-real",
			AccountID:   "session_oauth-acct-1",
			Provider:    "anthropic",
			ExternalID:  "claude-pro-uuid",
			Identity:    "user@example.com",
		},
	})
	transport := &capturingTransport{}
	p.SetTransport(transport)

	body := `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	// Outbound URL: must be api.anthropic.com (the providerDefaultBaseURL
	// for anthropic). If team-key path was wrongly picked, this would be
	// "team-key-wrongly-used.invalid".
	if transport.host != "api.anthropic.com" {
		t.Errorf("outbound Host = %q, want api.anthropic.com (OAuth binding path must use providerDefaultBaseURL, not team key BaseURL)", transport.host)
	}
	// Path: provider prefix stripped (/anthropic prefix → /v1/messages).
	// injectClaudeOAuth appends `?beta=true` query so we check Contains
	// not HasSuffix. The beta param is pinned by oauth_inject_test.go's
	// TestInjectClaudeOAuth_BetaQueryParam — required by Anthropic OAuth.
	if !strings.Contains(transport.url, "/v1/messages") {
		t.Errorf("outbound URL = %q, want path /v1/messages (provider prefix should be stripped)", transport.url)
	}
	// Request headers (mutated by oauthInject before forwarding):
	// Authorization: Bearer <token>, x-api-key removed.
	auth := req.Header.Get("Authorization")
	apiKey := req.Header.Get("x-api-key")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Errorf("Authorization = %q, want Bearer prefix (oauthInject must set Authorization for anthropic OAuth)", auth)
	}
	if apiKey != "" {
		t.Errorf("x-api-key should be stripped on OAuth path, got %q", apiKey)
	}
	// Response status: the synthetic transport returns 200.
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
}

// ── Fence test 2: broker not wired → 503 OAUTH_NOT_AVAILABLE ────────────────

// Pins: production safety guard. Proxy starting without OAuth broker
// (older edition / config mishap) must NOT silently fall through to
// fetching the access token "somehow" — must return a precise 503 so the
// operator sees what's missing.
func TestFence_OAuthBinding_NoBrokerReturns503(t *testing.T) {
	av := &mockActiveVault{
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "personal_oauth_account",
				KeySourceRef:  "session_acct",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)
	// Deliberately NOT setting broker — p.broker stays nil.

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d — body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "OAUTH_NOT_AVAILABLE") {
		t.Errorf("expected error.code OAUTH_NOT_AVAILABLE, got: %s", w.Body.String())
	}
}

// ── Fence test 3: EnsureFresh fails → 401 OAUTH_TOKEN_EXPIRED ──────────────

// Pins: when the refresh token expired or was revoked upstream, the user
// MUST see a 401 with a precise error code that the CLI's `aikey auth
// login` re-auth flow can detect. Sliding to a 500 would mask the
// "re-auth required" signal and confuse the user.
func TestFence_OAuthBinding_EnsureFreshFailReturns401(t *testing.T) {
	av := &mockActiveVault{
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "personal_oauth_account",
				KeySourceRef:  "session_expired",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)
	p.SetBroker(&mockOAuthBroker{
		ensureFreshErr: errFenceTokenExpired,
	})

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d — body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "OAUTH_TOKEN_EXPIRED") {
		t.Errorf("expected error.code OAUTH_TOKEN_EXPIRED, got: %s", w.Body.String())
	}
	// Message should include the re-auth command so users can self-recover.
	if !strings.Contains(w.Body.String(), "aikey auth login") {
		t.Errorf("error message should suggest `aikey auth login`, got: %s", w.Body.String())
	}
}

// ── Fence test 4: ResolveCredential fails → 503 OAUTH_RESOLVE_FAILED ───────

// Pins: broker recognized the account but couldn't return a credential
// (vault decryption failure, account in unexpected state). Should NOT
// silently fall through to team/personal — return 503 so ops can
// investigate the broker's internal state.
func TestFence_OAuthBinding_ResolveFailReturns503(t *testing.T) {
	av := &mockActiveVault{
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "personal_oauth_account",
				KeySourceRef:  "session_unresolvable",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)
	p.SetBroker(&mockOAuthBroker{
		// EnsureFresh succeeds, but ResolveCredential fails — covers the
		// "stale broker cache / decryption error" path.
		resolveErr: errFenceResolveFail,
	})

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d — body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "OAUTH_RESOLVE_FAILED") {
		t.Errorf("expected error.code OAUTH_RESOLVE_FAILED, got: %s", w.Body.String())
	}
}

// ── Fence test 5: Codex BaseURL override (canonicalCode=openai only) ───────

// Pins the production-critical quirk: Codex OAuth (canonicalCode=openai
// with a personal_oauth_account binding) routes to chatgpt.com's
// /backend-api/codex endpoint, NOT api.openai.com/v1. This is because
// Codex uses the Responses API at a separate origin. If the refactor
// loses this override, every Codex user hits a 404 from OpenAI.
//
// Why this is brittle and important: the override is a single line
// inside handlePathPrefixRoute (`if canonicalCode == "openai" {
// baseURL = "https://chatgpt.com/backend-api/codex" }`). It has no
// separate function — easy to miss when extracting a helper.
func TestFence_OAuthBinding_OpenAICodexBaseURLOverride(t *testing.T) {
	av := &mockActiveVault{
		providerBindings: map[string]*vault.ProviderBinding{
			"openai": {
				ProviderCode:  "openai",
				KeySourceType: "personal_oauth_account",
				KeySourceRef:  "session_codex",
			},
		},
		// Sentinel: provide a team key BaseURL that, if (wrongly) picked,
		// would show up as the outbound Host. The Codex override MUST
		// supersede it.
		activeTeamKeys: map[string]*vault.ManagedKey{
			"openai": {
				VirtualKeyID: "should-not-be-reached",
				ProviderCode: "openai",
				ProtocolType: "openai",
				BaseURL:      "http://team-key-wrongly-used.invalid",
				PlaintextKey: "sk-wrong",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)
	p.SetBroker(&mockOAuthBroker{
		resolveCred: &OAuthCredential{
			AccessToken: "codex-oauth-bearer",
			AccountID:   "session_codex",
			Provider:    "openai",
		},
	})
	transport := &capturingTransport{}
	p.SetTransport(transport)

	// Codex OAuth speaks the RESPONSES API — that is the whole reason its upstream
	// is chatgpt.com/backend-api/codex rather than api.openai.com/v1. This fence
	// originally drove the request with /chat/completions, which silently encoded
	// the 2026-07-13 bug (a Chat-Completions client's path appended to an upstream
	// that doesn't serve it → ChatGPT's edge replies "invalid x-api-key"). The
	// dialect gate now rejects that shape before forwarding, so the fence drives
	// the dialect codex actually speaks; its ASSERTION (the Codex base-URL override
	// must beat the team key's BaseURL) is unchanged and still the point.
	req := httptest.NewRequest(http.MethodPost, "/openai/v1/responses",
		strings.NewReader(`{"model":"gpt-4o","input":"hi"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	// The fence: outbound Host MUST be chatgpt.com (Codex override),
	// NOT api.openai.com (default) and NOT the bogus team-key invalid host.
	if transport.host != "chatgpt.com" {
		t.Errorf("outbound Host = %q, want chatgpt.com (Codex BaseURL override for canonicalCode=openai + OAuth binding)", transport.host)
	}
	// Path must include /backend-api/codex (the Codex API path under chatgpt.com).
	if !strings.Contains(transport.url, "/backend-api/codex") {
		t.Errorf("outbound URL = %q, want /backend-api/codex prefix (Codex API path)", transport.url)
	}
	_ = w // synthetic 200 from capturingTransport — response shape not asserted here
}

// ── Test errors ─────────────────────────────────────────────────────────────

var (
	errFenceTokenExpired = &fenceError{msg: "refresh token expired"}
	errFenceResolveFail  = &fenceError{msg: "could not decrypt access_token"}
)

type fenceError struct{ msg string }

func (e *fenceError) Error() string { return e.msg }
