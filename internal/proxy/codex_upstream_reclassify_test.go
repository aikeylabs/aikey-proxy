package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// scriptedTransport answers every request with one canned upstream response.
// Separate from capturingTransport on purpose: that helper is shared by nine
// released fences and always answers 200; widening it would change what those
// fences exercise.
type scriptedTransport struct {
	status  int
	body    string
	headers http.Header
	calls   int
}

func (s *scriptedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.calls++
	if req.Body != nil {
		_, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	h := http.Header{"Content-Type": []string{"application/json"}}
	for k, v := range s.headers {
		h[k] = v
	}
	return &http.Response{
		StatusCode: s.status,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Request:    req,
	}, nil
}

// The exact body the ChatGPT Codex backend returned on 2026-09-10 for a model
// it does not serve (spike cells M04s/M04n, both the streaming and the
// non-streaming leg; results/20260910T061800Z.tsv).
const codexModelUnsupportedBody = `{"detail":"The 'gpt-5.4-mini' model is not supported when using Codex with a ChatGPT account."}`

func TestCodexUpstreamReclassify_RuleTable(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantCode string
	}{
		{name: "measured model-unsupported body", status: 400, body: codexModelUnsupportedBody, wantCode: "OAUTH_MODEL_UNSUPPORTED"},
		{name: "same reason, another model", status: 400,
			body:     `{"detail":"The 'gpt-4o' model is not supported when using Codex with a ChatGPT account."}`,
			wantCode: "OAUTH_MODEL_UNSUPPORTED"},
		{name: "a genuine client error stays verbatim", status: 400,
			body: `{"detail":"Invalid value for 'input': expected a list."}`, wantCode: ""},
		{name: "a shape violation stays verbatim (the request leg owns those)", status: 400,
			body: `{"detail":"Input must be a list"}`, wantCode: ""},
		{name: "not a 400", status: 429, body: codexModelUnsupportedBody, wantCode: ""},
		{name: "empty body", status: 400, body: ``, wantCode: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := codexUpstream400Code(tc.status, []byte(tc.body)); got != tc.wantCode {
				t.Fatalf("codexUpstream400Code = %q, want %q", got, tc.wantCode)
			}
		})
	}
}

// A model the Codex backend does not serve must not reach the client as 400:
// 400 is outside every relay's retry range (tokenhub's own default is
// "1xx, 3xx, 4xx except 400/408, 5xx except 504/524"; production runs
// 100-199,300-399,401-599), so the fallback chain dies on it even when another
// channel carries the model. Measured 2026-09-10 on the live pool: gpt-5.4-mini
// answered 400 on BOTH the streaming and the non-streaming leg and all 13 cells
// stayed on use_channel=["3"], never reaching the third-party channel that
// carries the same model.
//
// spec: R-tokenhub-pool-fallback-7 池自身服务不了的请求 MUST NOT 以 400 出现
func TestCodexUpstream400_ModelUnsupportedBecomes422OnEveryLane(t *testing.T) {
	t.Run("personal OAuth lane", func(t *testing.T) {
		w, transport := servePersonalCodexWithUpstream(t, 400, codexModelUnsupportedBody)
		assertReclassified(t, w, transport)
	})
	t.Run("group (pool) lane", func(t *testing.T) {
		w, transport := serveGroupCodexWithUpstream(t, 400, codexModelUnsupportedBody)
		assertReclassified(t, w, transport)
	})
}

func assertReclassified(t *testing.T, w *httptest.ResponseRecorder, transport *scriptedTransport) {
	t.Helper()
	if transport.calls == 0 {
		t.Fatal("the upstream was never dialed — this fence must exercise the response leg, not a pre-dial gate")
	}
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; a 400 here is what breaks the relay's fallback chain. body=%s", w.Code, w.Body.String())
	}
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("response is not an aikey error envelope: %v body=%s", err, w.Body.String())
	}
	if env.Error.Code != "OAUTH_MODEL_UNSUPPORTED" {
		t.Fatalf("error.code = %q, want OAUTH_MODEL_UNSUPPORTED", env.Error.Code)
	}
	if !strings.Contains(env.Error.Message, "not supported when using Codex") {
		t.Fatalf("the upstream's own reason must survive so an operator can see WHY: %q", env.Error.Message)
	}
	if got := w.Header().Get(HeaderAikeyUpstreamStatus); got != "400" {
		t.Fatalf("%s = %q, want 400 — the original status must stay traceable", HeaderAikeyUpstreamStatus, got)
	}
	if got := w.Header().Get(HeaderAikeyErrorSource); got != "OAUTH_MODEL_UNSUPPORTED" {
		t.Fatalf("%s = %q — a re-labeled status must be marked as aikey-produced", HeaderAikeyErrorSource, got)
	}
}

// R-tokenhub-pool-fallback-7 BUT NOT: a real client error is still the client's
// problem. Relabelling it would make every relay retry a request that cannot
// succeed anywhere, turning one fast 400 into four slow ones.
func TestCodexUpstream400_UnrelatedClientErrorStaysVerbatim(t *testing.T) {
	const body = `{"detail":"Invalid value for 'input': expected a list."}`
	w, transport := servePersonalCodexWithUpstream(t, 400, body)
	if transport.calls == 0 {
		t.Fatal("upstream never dialed")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (verbatim)", w.Code)
	}
	if w.Body.String() != body {
		t.Fatalf("body must be byte-identical (protocol transparency):\n got %s\nwant %s", w.Body.String(), body)
	}
	if w.Header().Get(HeaderAikeyUpstreamStatus) != "" {
		t.Fatalf("%s must be absent when nothing was re-labeled", HeaderAikeyUpstreamStatus)
	}
}

// The marker is set only where the resolver knows the request is Codex-bound.
// An Anthropic OAuth credential answering the very same body keeps its 400:
// this table is derived from ChatGPT Codex backend behavior and says nothing
// about other upstreams. Same personal-lane fixture as the positive case, only
// the provider axis changes — a regression that marked every OAuth lane as
// Codex-bound fails here and nowhere else.
func TestCodexUpstream400_NotReclassifiedForAnthropicOAuth(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	av := &mockActiveVault{providerBindings: map[string]*vault.ProviderBinding{"anthropic": {
		ProviderCode: "anthropic", KeySourceType: "personal_oauth_account", KeySourceRef: "session_claude",
	}}}
	p := setupTestProxyWithActive(t, av)
	p.SetBroker(&mockOAuthBroker{resolveCred: &OAuthCredential{
		AccessToken: "claude-oauth-bearer", AccountID: "session_claude", Provider: "anthropic",
	}})
	transport := &scriptedTransport{status: 400, body: codexModelUnsupportedBody}
	p.SetTransport(transport)

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)
	if transport.calls == 0 {
		t.Fatalf("upstream never dialed (status=%d body=%s)", w.Code, w.Body.String())
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: the Codex rule table must not judge a non-Codex upstream", w.Code)
	}
	if w.Header().Get(HeaderAikeyUpstreamStatus) != "" {
		t.Fatalf("%s must be absent on a lane that was never marked Codex-bound", HeaderAikeyUpstreamStatus)
	}
}

// servePersonalCodexWithUpstream drives the personal codex OAuth lane (vault
// provider binding) with a scripted upstream response.
func servePersonalCodexWithUpstream(t *testing.T, status int, body string) (*httptest.ResponseRecorder, *scriptedTransport) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	av := &mockActiveVault{providerBindings: map[string]*vault.ProviderBinding{"openai": {
		ProviderCode: "openai", KeySourceType: "personal_oauth_account", KeySourceRef: "session_codex",
	}}}
	p := setupTestProxyWithActive(t, av)
	p.SetBroker(&mockOAuthBroker{resolveCred: &OAuthCredential{
		AccessToken: "codex-oauth-bearer", AccountID: "session_codex", Provider: "openai",
	}})
	transport := &scriptedTransport{status: status, body: body}
	p.SetTransport(transport)

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/responses",
		strings.NewReader(`{"model":"gpt-5.4-mini","input":[{"role":"user","content":"hi"}],"stream":true,"store":false}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)
	return w, transport
}

// serveGroupOAuthWithUpstream drives the pool lane — the one that actually faces
// tokenhub — with a scripted upstream response. The provider axis is a parameter
// so the Codex lane and a non-Codex lane share one fixture and differ only where
// the claim differs.
func serveGroupOAuthWithUpstream(t *testing.T, providerCode, protocolType, path, reqBody string, status int, body string) (*httptest.ResponseRecorder, *scriptedTransport) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-pool", ProviderCode: providerCode, ProtocolType: protocolType}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-pool": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ProviderCode: providerCode, ProtocolType: protocolType,
			ExpiresAt: 9_000_000_000,
		}, "pool-oauth-token"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp-pool", ProtocolType: protocolType, RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-pool",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_poolgroup": route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	transport := &scriptedTransport{status: status, body: body}
	p.SetTransport(transport)

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_poolgroup")
	w := httptest.NewRecorder()
	p.Handle(w, req)
	return w, transport
}

func serveGroupCodexWithUpstream(t *testing.T, status int, body string) (*httptest.ResponseRecorder, *scriptedTransport) {
	t.Helper()
	return serveGroupOAuthWithUpstream(t, "openai", "openai_compatible", "/responses",
		`{"model":"gpt-5.4-mini","input":[{"role":"user","content":"hi"}],"stream":true,"store":false}`,
		status, body)
}
