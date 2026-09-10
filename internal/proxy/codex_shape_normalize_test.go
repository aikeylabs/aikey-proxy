package proxy

// Fences for the Codex request-shape normalizer (codex_shape_normalize.go).
// Every case names the spike cell it mirrors
// (workflow/CI/research/codex-shape-matrix-2026-09/results/20260910T021253Z.tsv).
//
// spec: R-tokenhub-pool-fallback-7.S1 非 Codex 形状的请求不得以 400 断掉兜底链

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func TestNormalizeCodexBody_RuleTable(t *testing.T) {
	cases := []struct {
		name        string
		cell        string
		in          string
		wantChanges []string
		check       func(t *testing.T, out map[string]json.RawMessage)
	}{
		{"string input → one user message (S01)", "S01",
			`{"model":"m","input":"hi","instructions":"x","stream":true,"store":false}`,
			[]string{"input"},
			func(t *testing.T, out map[string]json.RawMessage) {
				want := `[{"content":[{"text":"hi","type":"input_text"}],"role":"user"}]`
				if string(out["input"]) != want {
					t.Fatalf("input = %s, want %s", out["input"], want)
				}
			}},
		{"store true → false (S08)", "S08",
			`{"model":"m","input":[],"stream":true,"store":true}`,
			[]string{"store"}, nil},
		{"store absent → false (S09)", "S09",
			`{"model":"m","input":[],"stream":true}`,
			[]string{"store"}, nil},
		{"max_output_tokens stripped (S10)", "S10",
			`{"model":"m","input":[],"stream":true,"store":false,"max_output_tokens":32}`,
			[]string{"strip:max_output_tokens"}, nil},
		{"temperature stripped (S11)", "S11",
			`{"model":"m","input":[],"stream":true,"store":false,"temperature":0.2}`,
			[]string{"strip:temperature"}, nil},
		{"truncation stripped (S16)", "S16",
			`{"model":"m","input":[],"stream":true,"store":false,"truncation":"auto"}`,
			[]string{"strip:truncation"}, nil},
		{"metadata stripped, user kept (S17)", "S17",
			`{"model":"m","input":[],"stream":true,"store":false,"user":"u","metadata":{"k":"v"}}`,
			[]string{"strip:metadata"},
			func(t *testing.T, out map[string]json.RawMessage) {
				if _, ok := out["user"]; !ok {
					t.Fatal("user must be kept: it was never rejected on the real backend")
				}
			}},
		{"worst case: string input + no store + stream:false (S20) — stream untouched", "S20",
			`{"model":"m","input":"hi","stream":false}`,
			[]string{"input", "store"},
			func(t *testing.T, out map[string]json.RawMessage) {
				if string(out["stream"]) != "false" {
					t.Fatalf("stream must be left alone until tasks.md 8⑤ lands: %s", out["stream"])
				}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, changes := normalizeCodexBody([]byte(c.in))
			if strings.Join(changes, ",") != strings.Join(c.wantChanges, ",") {
				t.Fatalf("[%s] changes = %v, want %v", c.cell, changes, c.wantChanges)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(out, &fields); err != nil {
				t.Fatalf("[%s] output is not JSON: %v (%s)", c.cell, err, out)
			}
			if string(fields["store"]) != "false" {
				t.Fatalf("[%s] store must always end up false: %s", c.cell, fields["store"])
			}
			for _, name := range codexUnsupportedParams {
				if _, present := fields[name]; present {
					t.Fatalf("[%s] unsupported parameter %s survived", c.cell, name)
				}
			}
			if c.check != nil {
				c.check(t, fields)
			}
		})
	}
}

// Shapes the backend accepts must pass through byte-for-byte (B0, S02, S04,
// S05, S12–S15, S18, S19) — a normalizer that re-serializes what it did not
// change would silently reorder keys and defeat every "untouched" assertion.
func TestNormalizeCodexBody_AcceptedShapesUntouched(t *testing.T) {
	for _, in := range []string{
		`{"model":"m","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}],"instructions":"x","stream":true,"store":false}`,
		`{"model":"m","input":[{"role":"user","content":"hi"}],"stream":true,"store":false}`,
		`{"model":"m","input":[],"instructions":"","stream":true,"store":false}`,
		`{"model":"m","input":[],"stream":true,"store":false,"tools":[{"type":"function","name":"ping"}],"tool_choice":"auto"}`,
		`{"model":"m","input":[],"stream":true,"store":false,"reasoning":{"effort":"low"},"text":{"format":{"type":"text"}},"include":["reasoning.encrypted_content"],"prompt_cache_key":"k","parallel_tool_calls":false}`,
		`not json at all`,
		`[1,2,3]`,
	} {
		out, changes := normalizeCodexBody([]byte(in))
		if len(changes) != 0 || !bytes.Equal(out, []byte(in)) {
			t.Fatalf("accepted shape was rewritten: changes=%v out=%s in=%s", changes, out, in)
		}
	}
}

func TestNormalizeCodexRequest_OnlyResponsesPOST(t *testing.T) {
	body := `{"model":"m","input":"hi"}`
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/chat/completions"},
		{http.MethodGet, "/responses"},
		{http.MethodPost, "/models"},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(body))
		r2 := normalizeCodexRequest(r)
		if got := codexNormalizationsFromContext(r2.Context()); len(got) != 0 {
			t.Fatalf("%s %s must not be normalized: %v", tc.method, tc.path, got)
		}
		raw, _ := io.ReadAll(r2.Body)
		if string(raw) != body {
			t.Fatalf("%s %s body altered: %s", tc.method, tc.path, raw)
		}
	}
	// Both lanes' path shapes are covered: /v1/responses (personal) and
	// /responses (group lane, already stripped).
	for _, path := range []string{"/v1/responses", "/responses", "/responses/"} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Content-Length", "26")
		r2 := normalizeCodexRequest(r)
		if got := strings.Join(codexNormalizationsFromContext(r2.Context()), ","); got != "input,store" {
			t.Fatalf("%s: normalizations = %q, want input,store", path, got)
		}
		raw, _ := io.ReadAll(r2.Body)
		if r2.ContentLength != int64(len(raw)) || r2.Header.Get("Content-Length") != "" || r2.GetBody == nil {
			t.Fatalf("%s: length bookkeeping drifted: ContentLength=%d body=%d header=%q GetBody=%v",
				path, r2.ContentLength, len(raw), r2.Header.Get("Content-Length"), r2.GetBody != nil)
		}
		again, _ := r2.GetBody()
		if b, _ := io.ReadAll(again); !bytes.Equal(b, raw) {
			t.Fatalf("%s: GetBody does not replay the rewritten body", path)
		}
	}
}

func TestReportCodexNormalization_HeaderOnlyWhenRewritten(t *testing.T) {
	clean := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"input":[],"store":false}`))
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Request: normalizeCodexRequest(clean)}
	reportCodexNormalization(resp)
	if resp.Header.Get(HeaderAikeyNormalized) != "" {
		t.Fatalf("no rewrite must mean no header, got %q", resp.Header.Get(HeaderAikeyNormalized))
	}
	dirty := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(`{"input":"hi","temperature":1}`))
	resp = &http.Response{StatusCode: 200, Header: http.Header{}, Request: normalizeCodexRequest(dirty)}
	reportCodexNormalization(resp)
	if got := resp.Header.Get(HeaderAikeyNormalized); got != "input,store,strip:temperature" {
		t.Fatalf("X-Aikey-Normalized = %q", got)
	}
}

// Every OAuth codex dispatch lane runs the normalizer, because every lane goes
// through resolveOAuthUpstream — the one exit for "this request is bound for
// the Codex backend". Same three lanes TestFence_CodexOAuthDispatchLanesUseSharedSetup
// pins for the base-URL override; a lane that bypassed the shared resolver would
// fail here first.
func TestCodexNormalization_AppliesOnEveryPersonalOAuthLane(t *testing.T) {
	cases := []struct {
		name       string
		token      string
		tier1Route bool
		binding    bool
	}{
		{name: "tier1 registry token", token: "aikey_personal_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", tier1Route: true},
		{name: "tier2 connectivity probe", token: "aikey_probe_session_codex_probe"},
		{name: "vault provider binding", binding: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			av := &mockActiveVault{}
			if tc.binding {
				av.providerBindings = map[string]*vault.ProviderBinding{"openai": {
					ProviderCode: "openai", KeySourceType: "personal_oauth_account", KeySourceRef: "session_codex",
				}}
			}
			p := setupTestProxyWithActive(t, av)
			p.SetBroker(&mockOAuthBroker{resolveCred: &OAuthCredential{
				AccessToken: "codex-oauth-bearer", AccountID: "session_codex", Provider: "openai",
			}})
			if tc.tier1Route {
				p.registry.Merge(map[string]*vkeys.ResolvedRoute{tc.token: {
					VirtualKeyID: "oauth:session_codex_tier1",
					Provider:     "openai", ProviderCode: "openai", ProtocolType: "openai_compatible",
					BaseURL: "https://api.openai.com/v1", KeyAlias: oauthSentinelKey,
					AccountID: "session_codex_tier1", RouteSource: "oauth",
				}})
			}
			transport := &capturingTransport{}
			p.SetTransport(transport)

			req := httptest.NewRequest(http.MethodPost, "/openai/v1/responses",
				strings.NewReader(`{"model":"gpt-5","input":"hi","stream":true,"temperature":0.2}`))
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			p.Handle(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			var sent map[string]json.RawMessage
			if err := json.Unmarshal(transport.body, &sent); err != nil {
				t.Fatalf("outbound body is not JSON: %v (%s)", err, transport.body)
			}
			if !jsonRawStartsWith(sent["input"], '[') || string(sent["store"]) != "false" {
				t.Fatalf("outbound body not normalized: %s", transport.body)
			}
			if _, present := sent["temperature"]; present {
				t.Fatalf("temperature reached the Codex backend: %s", transport.body)
			}
			if got := w.Header().Get(HeaderAikeyNormalized); got != "input,store,strip:temperature" {
				t.Fatalf("X-Aikey-Normalized = %q — the client must be able to see what was rewritten", got)
			}
		})
	}
}

// The group (pool) lane resolves the Codex upstream per attempt through the same
// resolver; the rewrite must land on the bytes the transport actually sends.
func TestCodexNormalization_AppliesOnGroupLane(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-codex", ProviderCode: "openai", ProtocolType: "openai_compatible"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-codex": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ProviderCode: "openai", ProtocolType: "openai_compatible",
			ExpiresAt: 9_000_000_000,
		}, "codex-oauth-token"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp-codex", ProtocolType: "openai_compatible", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-codex",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_codexgroup": route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	transport := &capturingTransport{}
	p.SetTransport(transport)

	req := httptest.NewRequest(http.MethodPost, "/responses",
		strings.NewReader(`{"model":"gpt-5-codex","input":"hi","stream":true,"metadata":{"k":"v"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_codexgroup")
	w := httptest.NewRecorder()
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(transport.body, &sent); err != nil {
		t.Fatalf("outbound body is not JSON: %v (%s)", err, transport.body)
	}
	if !jsonRawStartsWith(sent["input"], '[') || string(sent["store"]) != "false" {
		t.Fatalf("group-lane outbound body not normalized: %s", transport.body)
	}
	if _, present := sent["metadata"]; present {
		t.Fatalf("metadata reached the Codex backend on the group lane: %s", transport.body)
	}
	if got := w.Header().Get(HeaderAikeyNormalized); got != "input,store,strip:metadata" {
		t.Fatalf("X-Aikey-Normalized = %q", got)
	}
}

// The Resident Mock Provider simulating the Codex upstream (provider "mock",
// protocol openai_compatible → persona "openai") speaks the same dialect and,
// in strict mode, enforces the same shape rules — so the normalizer must key on
// the PERSONA, not the canonical provider code. Found the hard way: the first
// hermetic relay leg (tokenhub → ingress → worker → strict Mock) came back
// "400 Input must be a list" because only the canonical "openai" branch
// normalized (2026-09-10).
func TestCodexNormalization_AppliesToMockCodexPersona(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	key := grKey()
	refs := []vkeys.GroupAccountRef{{AccountID: "acc-mock-codex", ProviderCode: "mock", ProtocolType: "openai_compatible"}}
	mat := map[string]vkeys.GroupRuntimeAccount{
		"acc-mock-codex": encMat(t, key, vkeys.GroupRuntimeAccount{
			CredentialType: "oauth_account", ProviderCode: "mock", ProtocolType: "openai_compatible",
			BaseURL: "http://127.0.0.1:9/openai", ExpiresAt: 9_000_000_000,
		}, "mock-oauth-token"),
	}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-grp-mock-codex", ProtocolType: "openai_compatible", RouteSource: "team",
		SeatID: "seat-1", OauthGroupID: "grp-mock-codex",
		GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
	}
	p := setupTestProxy(t, "http://unused.invalid")
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_mockcodex": route})
	p.SetGroupKeyProvider(fakeGroupKey{k: key})
	transport := &capturingTransport{}
	p.SetTransport(transport)

	req := httptest.NewRequest(http.MethodPost, "/responses",
		strings.NewReader(`{"model":"gpt-5-codex","input":"hi","stream":true,"temperature":0.2}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aikey_team_mockcodex")
	w := httptest.NewRecorder()
	p.Handle(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(transport.body, &sent); err != nil {
		t.Fatalf("outbound body is not JSON: %v (%s)", err, transport.body)
	}
	if !jsonRawStartsWith(sent["input"], '[') || string(sent["store"]) != "false" {
		t.Fatalf("mock-codex persona outbound body not normalized: %s", transport.body)
	}
	if _, present := sent["temperature"]; present {
		t.Fatalf("temperature reached the (mock) Codex backend: %s", transport.body)
	}
	if got := w.Header().Get(HeaderAikeyNormalized); got != "input,store,strip:temperature" {
		t.Fatalf("X-Aikey-Normalized = %q", got)
	}
}

// Chat Completions on a codex OAuth credential cannot be served (the backend
// only speaks the Responses API). The answer used to be 400, which no relay
// retries; it is now 422 — still a client-visible refusal for a direct SDK
// (no automatic retry), but inside an external relay's retry range so it can
// fall back to a provider that does speak Chat Completions. The code is
// unchanged: OAUTH_RESPONSES_ONLY. User ruling 2026-09-10 (proposal 拍板点 8 ③).
func TestCodexChatCompletions_Answers422OnEveryLane(t *testing.T) {
	personal := []struct {
		name       string
		token      string
		tier1Route bool
	}{
		{name: "tier1 registry token", token: "aikey_personal_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", tier1Route: true},
		{name: "tier2 connectivity probe", token: "aikey_probe_session_codex_probe"},
	}
	for _, tc := range personal {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			p := setupTestProxyWithActive(t, &mockActiveVault{})
			p.SetBroker(&mockOAuthBroker{resolveCred: &OAuthCredential{
				AccessToken: "codex-oauth-bearer", AccountID: "session_codex", Provider: "openai",
			}})
			if tc.tier1Route {
				p.registry.Merge(map[string]*vkeys.ResolvedRoute{tc.token: {
					VirtualKeyID: "oauth:session_codex_tier1",
					Provider:     "openai", ProviderCode: "openai", ProtocolType: "openai_compatible",
					BaseURL: "https://api.openai.com/v1", KeyAlias: oauthSentinelKey,
					AccountID: "session_codex_tier1", RouteSource: "oauth",
				}})
			}
			p.SetTransport(&capturingTransport{})
			req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions",
				strings.NewReader(`{"model":"gpt-5","messages":[{"role":"user","content":"hi"}]}`))
			req.Header.Set("Authorization", "Bearer "+tc.token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			p.Handle(w, req)
			assertResponsesOnly422(t, w)
		})
	}
	t.Run("group lane", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		key := grKey()
		refs := []vkeys.GroupAccountRef{{AccountID: "acc-codex", ProviderCode: "openai", ProtocolType: "openai_compatible"}}
		mat := map[string]vkeys.GroupRuntimeAccount{
			"acc-codex": encMat(t, key, vkeys.GroupRuntimeAccount{
				CredentialType: "oauth_account", ProviderCode: "openai", ProtocolType: "openai_compatible",
				ExpiresAt: 9_000_000_000,
			}, "codex-oauth-token"),
		}
		route := &vkeys.ResolvedRoute{
			VirtualKeyID: "vk-grp-codex", ProtocolType: "openai_compatible", RouteSource: "team",
			SeatID: "seat-1", OauthGroupID: "grp-codex",
			GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
		}
		p := setupTestProxy(t, "http://unused.invalid")
		p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_codexgroup": route})
		p.SetGroupKeyProvider(fakeGroupKey{k: key})
		p.SetTransport(&capturingTransport{})
		req := httptest.NewRequest(http.MethodPost, "/chat/completions",
			strings.NewReader(`{"model":"gpt-5-codex","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer aikey_team_codexgroup")
		w := httptest.NewRecorder()
		p.Handle(w, req)
		assertResponsesOnly422(t, w)
	})
}

func assertResponsesOnly422(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (inside a relay's 401-599 retry range, outside SDK auto-retry); body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"OAUTH_RESPONSES_ONLY"`) {
		t.Fatalf("code must stay OAUTH_RESPONSES_ONLY (no new error code): %s", w.Body.String())
	}
}

func TestOAuthUpstreamRejectsShape_NonStreamOnly(t *testing.T) {
	mk := func(method, path, body string) *http.Request {
		return httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if r := oauthUpstreamRejectsShape("openai", mk(http.MethodPost, "/responses", `{"input":[],"stream":true}`)); r != "" {
		t.Fatalf("stream:true must pass: %q", r)
	}
	for _, body := range []string{`{"input":[],"stream":false}`, `{"input":[]}`, `{"input":"hi","stream":"true"}`} {
		if r := oauthUpstreamRejectsShape("openai", mk(http.MethodPost, "/v1/responses", body)); r == "" {
			t.Fatalf("non-stream body must be refused: %s", body)
		}
	}
	// Not our gate: other personas, other paths (the path gate owns chat), non-JSON.
	if r := oauthUpstreamRejectsShape("anthropic", mk(http.MethodPost, "/responses", `{"stream":false}`)); r != "" {
		t.Fatalf("anthropic persona must not be gated: %q", r)
	}
	if r := oauthUpstreamRejectsShape("openai", mk(http.MethodPost, "/chat/completions", `{"stream":false}`)); r != "" {
		t.Fatalf("chat path belongs to the path gate: %q", r)
	}
	if r := oauthUpstreamRejectsShape("openai", mk(http.MethodPost, "/responses", `not json`)); r != "" {
		t.Fatalf("non-JSON must be left to the upstream: %q", r)
	}
	// Body restored byte-for-byte after the peek.
	req := mk(http.MethodPost, "/responses", `{"input":[],"stream":false}`)
	_ = oauthUpstreamRejectsShape("openai", req)
	if raw, _ := io.ReadAll(req.Body); string(raw) != `{"input":[],"stream":false}` {
		t.Fatalf("body not restored: %s", raw)
	}
}

// A non-streaming Responses request on a codex OAuth credential is refused
// pre-dial with 422 OAUTH_CODEX_SHAPE_UNSUPPORTED on every lane — never
// forwarded (the backend would answer 400, which no relay retries).
// 2026-09-10 止血 for the availability gap G-TPF-9; the full fix (SSE→JSON
// reassembly) is tasks.md 8⑤.
func TestCodexNonStream_Answers422OnEveryLane(t *testing.T) {
	assert422 := func(t *testing.T, w *httptest.ResponseRecorder, transport *capturingTransport) {
		t.Helper()
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"OAUTH_CODEX_SHAPE_UNSUPPORTED"`) {
			t.Fatalf("code must be OAUTH_CODEX_SHAPE_UNSUPPORTED: %s", w.Body.String())
		}
		if transport.url != "" {
			t.Fatalf("non-stream request must be refused pre-dial, but reached %s", transport.url)
		}
	}
	body := `{"model":"gpt-5","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}],"stream":false,"store":false}`
	personal := []struct {
		name       string
		token      string
		tier1Route bool
		binding    bool
	}{
		{name: "tier1 registry token", token: "aikey_personal_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", tier1Route: true},
		{name: "tier2 connectivity probe", token: "aikey_probe_session_codex_probe"},
		{name: "vault provider binding", binding: true},
	}
	for _, tc := range personal {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			av := &mockActiveVault{}
			if tc.binding {
				av.providerBindings = map[string]*vault.ProviderBinding{"openai": {
					ProviderCode: "openai", KeySourceType: "personal_oauth_account", KeySourceRef: "session_codex",
				}}
			}
			p := setupTestProxyWithActive(t, av)
			p.SetBroker(&mockOAuthBroker{resolveCred: &OAuthCredential{
				AccessToken: "codex-oauth-bearer", AccountID: "session_codex", Provider: "openai",
			}})
			if tc.tier1Route {
				p.registry.Merge(map[string]*vkeys.ResolvedRoute{tc.token: {
					VirtualKeyID: "oauth:session_codex_tier1",
					Provider:     "openai", ProviderCode: "openai", ProtocolType: "openai_compatible",
					BaseURL: "https://api.openai.com/v1", KeyAlias: oauthSentinelKey,
					AccountID: "session_codex_tier1", RouteSource: "oauth",
				}})
			}
			transport := &capturingTransport{}
			p.SetTransport(transport)
			req := httptest.NewRequest(http.MethodPost, "/openai/v1/responses", strings.NewReader(body))
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			p.Handle(w, req)
			assert422(t, w, transport)
		})
	}
	for _, lane := range []struct{ name, provider, base string }{
		{"group lane (openai)", "openai", ""},
		{"group lane (mock codex persona)", "mock", "http://127.0.0.1:9/openai"},
	} {
		t.Run(lane.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			key := grKey()
			refs := []vkeys.GroupAccountRef{{AccountID: "acc-1", ProviderCode: lane.provider, ProtocolType: "openai_compatible"}}
			mat := map[string]vkeys.GroupRuntimeAccount{
				"acc-1": encMat(t, key, vkeys.GroupRuntimeAccount{
					CredentialType: "oauth_account", ProviderCode: lane.provider, ProtocolType: "openai_compatible",
					BaseURL: lane.base, ExpiresAt: 9_000_000_000,
				}, "oauth-token"),
			}
			route := &vkeys.ResolvedRoute{
				VirtualKeyID: "vk-grp", ProtocolType: "openai_compatible", RouteSource: "team",
				SeatID: "seat-1", OauthGroupID: "grp-1",
				GroupAccounts: mustJSON(t, refs), GroupRuntime: mustJSON(t, mat),
			}
			p := setupTestProxy(t, "http://unused.invalid")
			p.registry.Merge(map[string]*vkeys.ResolvedRoute{"aikey_team_nonstream": route})
			p.SetGroupKeyProvider(fakeGroupKey{k: key})
			transport := &capturingTransport{}
			p.SetTransport(transport)
			req := httptest.NewRequest(http.MethodPost, "/responses", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer aikey_team_nonstream")
			w := httptest.NewRecorder()
			p.Handle(w, req)
			assert422(t, w, transport)
		})
	}
}
