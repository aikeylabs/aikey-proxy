package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// mockVault implements VaultGetter for testing.
type mockVault struct {
	secrets map[string]string
}

func (m *mockVault) GetSecret(alias string) (string, error) {
	s, ok := m.secrets[alias]
	if !ok {
		return "", fmt.Errorf("not found: %s", alias)
	}
	return s, nil
}

// mockEventStore satisfies events.Store interface for collector.
type mockEventStore struct{}

func (m *mockEventStore) Insert(_ []events.UsageEvent) error { return nil }
func (m *mockEventStore) QueryStats() (map[string]int64, map[string]int64, error) {
	return nil, nil, nil
}
func (m *mockEventStore) Close() error { return nil }

func setupTestProxy(t *testing.T, upstreamURL string) *Proxy {
	t.Helper()
	return setupTestProxyWithStore(t, upstreamURL, &mockEventStore{})
}

// setupTestProxyWithStore creates a Proxy wired to a custom EventInserter,
// useful for tests that need to capture and assert on recorded events.
func setupTestProxyWithStore(t *testing.T, upstreamURL string, store events.EventInserter) *Proxy {
	t.Helper()

	// Per-test run-dir isolation (2026-07-04). TestMain sandboxes AIKEY_RUN_DIR to
	// ONE package-wide temp dir; the pool cooldown store persists to + hydrates from
	// pool-cooldown.json under it (survive-restart, oauth_pool_cooldown.go). Sharing
	// that one file across tests means a test that cools an account (acc-1, …) leaks
	// it to every later test whose proxy hydrates the same file — so group_serve
	// tests passed in isolation but failed together (cooled accounts → NO_CANDIDATES /
	// ALL_UNUSABLE instead of the expected outcome). Giving each constructed proxy its
	// OWN run dir makes every test hydrate an EMPTY cooldown file. This is the SINGLE
	// construction point for all proxy tests (setupTestProxy delegates here), so one
	// t.Setenv covers group + window + fallback tests. Single-proxy tests that read
	// AIKEY_RUN_DIR later (group-login-required.json) stay consistent — t.Setenv holds
	// for the whole test. Restart-survival is covered separately by the persist tests,
	// which build the store directly (not via this helper).
	t.Setenv("AIKEY_RUN_DIR", t.TempDir())

	v := &mockVault{
		secrets: map[string]string{
			"openai:test":    "sk-real-openai-key-123",
			"anthropic:test": "sk-ant-real-key-456",
		},
	}

	// Stage C-2.c: Registry.Load (taking []config.VirtualKeyConfig) was
	// removed alongside VirtualKeyConfig itself. Tests now seed routes
	// directly via Merge, matching the production path where vault is
	// the only source of routes.
	registry := vkeys.NewRegistry()
	registry.Merge(map[string]*vkeys.ResolvedRoute{
		"aikey_team_openai_test": {
			VirtualKeyID: "vk_openai",
			Provider:     "openai",
			BaseURL:      upstreamURL,
			KeyAlias:     "openai:test",
			ProtocolType: "openai",
			RouteSource:  "personal_byok", // historical label kept for test parity
		},
		"aikey_team_anthropic_test": {
			VirtualKeyID:  "vk_anthropic",
			Provider:      "anthropic",
			BaseURL:       upstreamURL,
			KeyAlias:      "anthropic:test",
			AllowedModels: []string{"claude-sonnet-4-5-20250929"},
			ProtocolType:  "anthropic",
			RouteSource:   "personal_byok",
		},
	})

	providers := provider.NewRegistry()
	// batchSize=1 + short flush so events are immediately visible in tests.
	collector := events.NewCollector(store, 1, 5*time.Millisecond)
	t.Cleanup(func() { collector.Close() })

	return New(v, registry, providers, collector, context.Background())
}

func TestProxy_OpenAI_KeyReplacement(t *testing.T) {
	var receivedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"chatcmpl-test","choices":[{"message":{"content":"hello"}}]}`))
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer aikey_team_openai_test")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	resp := w.Result()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(respBody))
	}

	if receivedAuth != "Bearer sk-real-openai-key-123" {
		t.Fatalf("upstream should receive real key, got %q", receivedAuth)
	}
}

func TestProxy_Anthropic_KeyReplacement(t *testing.T) {
	var receivedAPIKey string
	var receivedVersion string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAPIKey = r.Header.Get("x-api-key")
		receivedVersion = r.Header.Get("anthropic-version")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"type":"message","content":[{"type":"text","text":"hello"}]}`))
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)

	body := `{"model":"claude-sonnet-4-5-20250929","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	req.Header.Set("x-api-key", "aikey_team_anthropic_test")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if receivedAPIKey != "sk-ant-real-key-456" { //nolint:gosec // test fixture, not a real credential
		t.Fatalf("upstream should receive real Anthropic key, got %q", receivedAPIKey)
	}
	if receivedVersion == "" {
		t.Fatal("anthropic-version header should be set")
	}
}

func TestProxy_MissingVirtualKey(t *testing.T) {
	p := setupTestProxy(t, "http://unused")

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	var errResp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "TOKEN_MISSING" {
		t.Fatalf("expected TOKEN_MISSING, got %q", errResp.Error.Code)
	}
}

func TestProxy_InvalidVirtualKey(t *testing.T) {
	p := setupTestProxy(t, "http://unused")

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer aikey_team_nonexistent")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestProxy_ForbiddenModel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)

	body := `{"model":"claude-opus-4-20250514","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	req.Header.Set("x-api-key", "aikey_team_anthropic_test")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestProxy_StreamingResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected flusher")
		}
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n"))
		flusher.Flush()
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n"))
		flusher.Flush()
		w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer aikey_team_openai_test")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	respBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBody), "Hello") {
		t.Fatalf("expected 'Hello' in streaming response, got %q", string(respBody))
	}
	if !strings.Contains(string(respBody), "[DONE]") {
		t.Fatalf("expected '[DONE]' in streaming response, got %q", string(respBody))
	}
}

func TestExtractVirtualKey_Bearer(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Bearer aikey_team_abc123")

	if token := extractVirtualKey(req); token != "aikey_team_abc123" {
		t.Fatalf("expected aikey_team_abc123, got %q", token)
	}
}

func TestExtractVirtualKey_XAPIKey(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("x-api-key", "aikey_team_def456")

	if token := extractVirtualKey(req); token != "aikey_team_def456" {
		t.Fatalf("expected aikey_team_def456, got %q", token)
	}
}

func TestExtractVirtualKey_RealKeyIgnored(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Bearer sk-real-key-123")

	if token := extractVirtualKey(req); token != "" {
		t.Fatalf("real keys should be ignored, got %q", token)
	}
}

func TestExtractVirtualKey_NoKey(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	if token := extractVirtualKey(req); token != "" {
		t.Fatalf("expected empty, got %q", token)
	}
}

// ---- Token recording integration tests -------------------------------------

// TestProxy_NonStreaming_RecordsTokens verifies that a non-streaming response
// is parsed for token usage and a UsageEvent is recorded with correct counts.
func TestProxy_NonStreaming_RecordsTokens_OpenAI(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"id": "chatcmpl-test",
			"choices": [{"message": {"content": "hello"}}],
			"usage": {"prompt_tokens": 12, "completion_tokens": 34, "total_tokens": 46}
		}`))
	}))
	defer upstream.Close()

	store := newCapturingStore()
	p := setupTestProxyWithStore(t, upstream.URL, store)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer aikey_team_openai_test")
	req.Header.Set("Content-Type", "application/json")

	p.Handle(httptest.NewRecorder(), req)

	ev := store.waitEvent(t, 2*time.Second)
	if ev.InputTokens != 12 {
		t.Errorf("InputTokens = %d, want 12", ev.InputTokens)
	}
	if ev.OutputTokens != 34 {
		t.Errorf("OutputTokens = %d, want 34", ev.OutputTokens)
	}
	if ev.IsStreaming {
		t.Error("IsStreaming should be false for non-streaming request")
	}
	if ev.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", ev.StatusCode)
	}
}

func TestProxy_NonStreaming_RecordsTokens_Anthropic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"type": "message",
			"content": [{"type": "text", "text": "hello"}],
			"usage": {"input_tokens": 8, "output_tokens": 20}
		}`))
	}))
	defer upstream.Close()

	store := newCapturingStore()
	p := setupTestProxyWithStore(t, upstream.URL, store)

	body := `{"model":"claude-sonnet-4-5-20250929","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	req.Header.Set("x-api-key", "aikey_team_anthropic_test")
	req.Header.Set("Content-Type", "application/json")

	p.Handle(httptest.NewRecorder(), req)

	ev := store.waitEvent(t, 2*time.Second)
	if ev.InputTokens != 8 {
		t.Errorf("InputTokens = %d, want 8", ev.InputTokens)
	}
	if ev.OutputTokens != 20 {
		t.Errorf("OutputTokens = %d, want 20", ev.OutputTokens)
	}
}

// TestProxy_Streaming_RecordsTokens verifies that a streaming SSE response
// is parsed for token usage via streamDrainer and a UsageEvent is recorded
// with the correct counts once the stream ends.
func TestProxy_Streaming_RecordsTokens_Anthropic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		chunks := []string{
			`data: {"type":"message_start","message":{"usage":{"input_tokens":6,"output_tokens":0}}}`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`,
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":18}}`,
			"data: [DONE]",
		}
		for _, c := range chunks {
			w.Write([]byte(c + "\n\n"))
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	store := newCapturingStore()
	p := setupTestProxyWithStore(t, upstream.URL, store)

	body := `{"model":"claude-sonnet-4-5-20250929","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	req.Header.Set("x-api-key", "aikey_team_anthropic_test")
	req.Header.Set("Content-Type", "application/json")

	p.Handle(httptest.NewRecorder(), req)

	ev := store.waitEvent(t, 3*time.Second)
	if ev.InputTokens != 6 {
		t.Errorf("InputTokens = %d, want 6", ev.InputTokens)
	}
	if ev.OutputTokens != 18 {
		t.Errorf("OutputTokens = %d, want 18", ev.OutputTokens)
	}
	if !ev.IsStreaming {
		t.Error("IsStreaming should be true")
	}
}

// TestProxy_ErrorResponse_NoTokens verifies that error responses are recorded
// with zero tokens and the correct error type.
func TestProxy_ErrorResponse_NoTokens(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(429)
		w.Write([]byte(`{"error":{"type":"rate_limit_error","message":"rate limited"}}`))
	}))
	defer upstream.Close()

	store := newCapturingStore()
	p := setupTestProxyWithStore(t, upstream.URL, store)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer aikey_team_openai_test")
	req.Header.Set("Content-Type", "application/json")

	p.Handle(httptest.NewRecorder(), req)

	ev := store.waitEvent(t, 2*time.Second)
	if ev.InputTokens != 0 || ev.OutputTokens != 0 {
		t.Errorf("error response should have no tokens, got (%d,%d)", ev.InputTokens, ev.OutputTokens)
	}
	if ev.StatusCode != 429 {
		t.Errorf("StatusCode = %d, want 429", ev.StatusCode)
	}
	if ev.ErrorType == "" {
		t.Error("ErrorType should be set for error responses")
	}
}

// ── extractProviderFromPath unit tests ───────────────────────────────────────

func TestExtractProviderFromPath(t *testing.T) {
	tests := []struct {
		path             string
		wantProvider     string
		wantStrippedPath string
	}{
		{"/anthropic/v1/messages", "anthropic", "/v1/messages"},
		{"/openai/v1/chat/completions", "openai", "/v1/chat/completions"},
		{"/deepseek/v1/chat/completions", "deepseek", "/v1/chat/completions"},
		{"/kimi/v1/chat/completions", "kimi", "/v1/chat/completions"},
		{"/moonshot/v1/chat/completions", "moonshot", "/v1/chat/completions"},
		{"/google/v1/models", "google", "/v1/models"},
		{"/anthropic", "anthropic", ""},
		{"/v1/messages", "", ""},
		{"/anthropicX/v1", "", ""},
		{"/", "", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			gotProvider, gotStripped := extractProviderFromPath(tt.path)
			if gotProvider != tt.wantProvider {
				t.Errorf("provider = %q, want %q", gotProvider, tt.wantProvider)
			}
			if gotStripped != tt.wantStrippedPath {
				t.Errorf("stripped = %q, want %q", gotStripped, tt.wantStrippedPath)
			}
		})
	}
}

// ── Path-prefix routing integration tests ────────────────────────────────────

// mockActiveVault implements both VaultGetter and ActiveKeyReader for testing.
type mockActiveVault struct {
	secrets          map[string]string
	activeKeyConfig  *vault.ActiveKeyConfig
	activeTeamKeys   map[string]*vault.ManagedKey      // keyed by lowercase provider code
	providerBindings map[string]*vault.ProviderBinding // keyed by lowercase provider code (default profile)
	// App-pipeline-specific fields (AKL-207). nil values are fine; the App
	// pipeline methods return nil/nil for the no-op case which equals
	// "no app registered" / "no scope binding" — graceful.
	appRecord   *vault.AppRecord
	appBindings map[string]*vault.ProviderBinding // keyed by `<profileID>|<providerCode>`
	// Mode B / Mode C alias lookup (2026-05-23, credential-mode-architecture
	// SPEC §1.1.B + §1.1.C). nil keeps GetAliasCredential returning
	// "not found" so legacy tests (mode A flows) need no changes.
	aliasCreds      map[string]*vault.AliasCredential // keyed by alias name
	personalAlias   string
	personalText    string
	personalProv    string
	personalBaseURL string
}

func TestSelectTokenBinding_UsesClientRouteToChooseExactMockBinding(t *testing.T) {
	anthropic := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-mock", ProviderCode: "mock", ProtocolType: "anthropic", CredentialID: "cred-a",
	}
	openai := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-mock", ProviderCode: "mock", ProtocolType: "openai_compatible", CredentialID: "cred-o",
	}
	container := &vkeys.ResolvedRoute{VirtualKeyID: "vk-mock", Bindings: []*vkeys.ResolvedRoute{anthropic, openai}}
	reader := &mockActiveVault{providerBindings: map[string]*vault.ProviderBinding{
		"anthropic": {
			ClientRoute: "anthropic", ProviderCode: "mock", ProtocolType: "anthropic",
			KeySourceType: "managed_virtual_key", KeySourceRef: "vk-mock",
		},
	}}
	p := &Proxy{activeReader: reader}

	got, err := p.selectTokenBinding(container, "anthropic", "anthropic")
	if err != nil {
		t.Fatalf("selectTokenBinding: %v", err)
	}
	if got.ProviderCode != "mock" || got.ProtocolType != "anthropic" || got.CredentialID != "cred-a" {
		t.Fatalf("selected %+v, want exact mock+anthropic binding", got)
	}

	got, err = p.selectTokenBinding(container, "openai", "openai_compatible")
	if err != nil {
		t.Fatalf("unique protocol fallback: %v", err)
	}
	if got.CredentialID != "cred-o" {
		t.Fatalf("selected credential=%q, want cred-o", got.CredentialID)
	}
}

func TestSelectTokenBinding_RejectsAmbiguousSameProtocolBindings(t *testing.T) {
	container := &vkeys.ResolvedRoute{
		VirtualKeyID: "vk-ambiguous",
		Bindings: []*vkeys.ResolvedRoute{
			{VirtualKeyID: "vk-ambiguous", ProviderCode: "openai", ProtocolType: "openai_compatible"},
			{VirtualKeyID: "vk-ambiguous", ProviderCode: "mock", ProtocolType: "openai_compatible"},
		},
	}
	p := &Proxy{}
	if _, err := p.selectTokenBinding(container, "openai", "openai_compatible"); err == nil {
		t.Fatal("ambiguous same-protocol token must fail until aikey use selects an exact binding")
	}
}

func (m *mockActiveVault) GetSecret(alias string) (string, error) {
	s, ok := m.secrets[alias]
	if !ok {
		return "", fmt.Errorf("not found: %s", alias)
	}
	return s, nil
}

func (m *mockActiveVault) GetActiveKeyConfig() (*vault.ActiveKeyConfig, error) {
	return m.activeKeyConfig, nil
}

func (m *mockActiveVault) GetActiveTeamKeyByProvider(providerCode, protocolType string) (*vault.ManagedKey, error) {
	if m.activeTeamKeys == nil {
		return nil, nil
	}
	mk, ok := m.activeTeamKeys[strings.ToLower(providerCode)]
	if !ok {
		return nil, nil
	}
	if protocolType != "" && !strings.EqualFold(mk.ProtocolType, protocolType) {
		return nil, nil
	}
	return mk, nil
}

func (m *mockActiveVault) GetPersonalKeyByAlias(alias string) (string, string, string, error) {
	if alias == m.personalAlias {
		return m.personalText, m.personalProv, m.personalBaseURL, nil
	}
	return "", "", "", fmt.Errorf("personal key %q not found", alias)
}

func (m *mockActiveVault) GetTeamKeyByID(virtualKeyID, targetProviderCode, protocolType string) (*vault.ManagedKey, error) {
	// Exact axes never fall through to another binding. A fully unspecified
	// lookup retains the deterministic legacy single-binding fallback.
	var fallback *vault.ManagedKey
	for _, mk := range m.activeTeamKeys {
		if mk.VirtualKeyID != virtualKeyID {
			continue
		}
		if targetProviderCode != "" && strings.EqualFold(mk.ProviderCode, targetProviderCode) &&
			(protocolType == "" || strings.EqualFold(mk.ProtocolType, protocolType)) {
			return mk, nil
		}
		if fallback == nil {
			fallback = mk
		}
	}
	if targetProviderCode == "" && protocolType == "" {
		return fallback, nil
	}
	return nil, nil
}

func (m *mockActiveVault) GetProviderBinding(providerCode string) (*vault.ProviderBinding, error) {
	// v1.0.2: mock returns nil by default to exercise the legacy fallback path.
	// Tests that want to exercise binding-based routing can set providerBindings.
	if m.providerBindings == nil {
		return nil, nil
	}
	b, ok := m.providerBindings[strings.ToLower(providerCode)]
	if !ok {
		return nil, nil
	}
	return b, nil
}

// GetProviderBindingWithScope satisfies apppipe.VaultReader. Tests setting
// `appBindings["app:<slug>|<provider>"] = ...` exercise the App pipeline's
// isolated-mode resolution; setting `appBindings["default|<provider>"] = ...`
// covers follow-active mode. Falls back to the legacy `providerBindings` map
// when scope == "default" so existing fixtures don't need to migrate.
func (m *mockActiveVault) GetProviderBindingWithScope(profileID, providerCode string) (*vault.ProviderBinding, error) {
	if m.appBindings != nil {
		if b, ok := m.appBindings[profileID+"|"+strings.ToLower(providerCode)]; ok {
			return b, nil
		}
	}
	// Backstop: default profile reuses the existing field so legacy
	// fixtures don't have to populate appBindings.
	if profileID == "default" && m.providerBindings != nil {
		if b, ok := m.providerBindings[strings.ToLower(providerCode)]; ok {
			return b, nil
		}
	}
	return nil, nil
}

// GetAppRecord satisfies apppipe.VaultReader. Tests set m.appRecord to the
// metadata they want apppipe.Resolve to read; multi-app tests can build
// distinct mocks per slug.
func (m *mockActiveVault) GetAppRecord(slug string) (*vault.AppRecord, error) {
	if m.appRecord == nil {
		return nil, nil
	}
	if m.appRecord.Slug != slug {
		return nil, nil
	}
	return m.appRecord, nil
}

// GetAliasCredential satisfies apppipe.VaultReader + probepipe.VaultReader.
// Added 2026-05-23 for mode B / mode C. Tests that exercise either pipeline
// populate m.aliasCreds keyed by alias name; the default zero-value map
// returns nil → "alias not found" so unrelated tests (mode A flows) keep
// passing without further setup.
func (m *mockActiveVault) GetAliasCredential(name string) (*vault.AliasCredential, error) {
	if m.aliasCreds == nil {
		return nil, nil
	}
	return m.aliasCreds[name], nil
}

func setupTestProxyWithActive(t *testing.T, av *mockActiveVault) *Proxy {
	t.Helper()
	prov := provider.NewRegistry()
	coll := events.NewCollector(&mockEventStore{}, 1, 5*time.Millisecond)
	t.Cleanup(func() { coll.Close() })
	reg := vkeys.NewRegistry()
	return New(av, reg, prov, coll, context.Background())
}

func TestHandlePathPrefix_NoActiveReader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Plain mockVault does not implement ActiveKeyReader → path-prefix routing disabled.
	p := setupTestProxy(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ACTIVE_KEY_NOT_SUPPORTED") {
		t.Errorf("expected ACTIVE_KEY_NOT_SUPPORTED, got: %s", w.Body.String())
	}
}

func TestHandlePathPrefix_TeamKey(t *testing.T) {
	var capturedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"msg","type":"message","content":[],"model":"claude-3","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	av := &mockActiveVault{
		activeTeamKeys: map[string]*vault.ManagedKey{
			"anthropic": {
				VirtualKeyID:     "test",
				ProviderCode:     "anthropic",
				ProtocolType:     "anthropic",
				BaseURL:          upstream.URL,
				PlaintextKey:     "sk-ant-test",
				ProviderBaseURLs: map[string]string{"anthropic": upstream.URL},
			},
		},
	}
	p := setupTestProxyWithActive(t, av)

	body := `{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if capturedPath != "/v1/messages" {
		t.Errorf("upstream path = %q, want /v1/messages", capturedPath)
	}
}

func TestHandlePathPrefix_NoActiveKey(t *testing.T) {
	av := &mockActiveVault{
		activeTeamKeys:  map[string]*vault.ManagedKey{},
		activeKeyConfig: nil,
	}
	p := setupTestProxyWithActive(t, av)

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "NO_ACTIVE_KEY") {
		t.Errorf("expected NO_ACTIVE_KEY, got: %s", w.Body.String())
	}
}

func TestHandlePathPrefix_ProviderBaseURLUsed(t *testing.T) {
	// Verifies that ProviderBaseURLs takes precedence over BaseURL for the specific provider.
	var capturedPath string
	upstreamAnthropicCustom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"m","type":"message","content":[],"model":"c","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstreamAnthropicCustom.Close()

	// BaseURL points to a different server; ProviderBaseURLs["anthropic"] points to our test server.
	av := &mockActiveVault{
		activeTeamKeys: map[string]*vault.ManagedKey{
			"anthropic": {
				VirtualKeyID:     "multi",
				ProviderCode:     "anthropic",
				ProtocolType:     "anthropic",
				BaseURL:          "http://wrong-server.invalid",
				PlaintextKey:     "sk-ant-real",
				ProviderBaseURLs: map[string]string{"anthropic": upstreamAnthropicCustom.URL},
			},
		},
	}
	p := setupTestProxyWithActive(t, av)

	body := `{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"max_tokens":5}`
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if capturedPath != "/v1/messages" {
		t.Errorf("upstream path = %q, want /v1/messages", capturedPath)
	}
}

// ── v1.0.2: Provider binding-based routing tests ─────────────────────────────

func TestHandlePathPrefix_BindingPersonalKey(t *testing.T) {
	var capturedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"m","type":"message","content":[],"model":"c","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	av := &mockActiveVault{
		activeKeyConfig: nil,
		activeTeamKeys:  map[string]*vault.ManagedKey{},
		personalAlias:   "my-claude",
		personalText:    "sk-ant-binding-test",
		personalProv:    "anthropic",
		personalBaseURL: upstream.URL,
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "personal",
				KeySourceRef:  "my-claude",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)

	body2 := `{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(body2))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if capturedAuth != "sk-ant-binding-test" {
		t.Errorf("upstream x-api-key = %q, want sk-ant-binding-test", capturedAuth)
	}
}

// ── aikey_probe_ sentinel tests (2026-04-22) ──────────────────────
//
// Why this whole cluster: Stage 3 of the connectivity-probe-through-proxy
// fix introduced a sentinel bearer so `aikey test <alias>` and the shell
// wrapper preflight can probe a specific personal key without the CLI
// touching the vault. Before this, personal-key probes decrypted in the
// CLI (prompting for master password) — unacceptable for a preflight that
// runs before every `claude` / `codex` invocation. The tests below pin
// the contract so a future regression that silently falls back to the
// active-binding resolver fails fast.

func TestHandlePathPrefix_PersonalAliasSentinel(t *testing.T) {
	var capturedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	av := &mockActiveVault{
		personalAlias:   "my-claude",
		personalText:    "sk-ant-from-vault",
		personalProv:    "anthropic",
		personalBaseURL: upstream.URL,
		// No providerBindings / activeTeamKeys — proves the sentinel does NOT
		// depend on any active binding having been set up. This is the
		// "wrapper preflight before the user has activated anything" case.
	}
	p := setupTestProxyWithActive(t, av)

	req := httptest.NewRequest(http.MethodGet, "/anthropic/v1/models", nil)
	req.Header.Set("Authorization", "Bearer aikey_probe_my-claude")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if capturedAuth != "sk-ant-from-vault" {
		t.Errorf("upstream x-api-key = %q, want sk-ant-from-vault "+
			"(proxy should decrypt the personal alias and inject the real key)",
			capturedAuth)
	}
}

func TestHandlePathPrefix_PersonalAliasSentinel_NotActive(t *testing.T) {
	// Regression guard for the 2026-04-22 caveat: before this sentinel,
	// probing an inactive personal key fell through to "active binding
	// lookup" and inadvertently exercised the active one. The sentinel
	// must test EXACTLY the alias named, regardless of what's active.
	var capturedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	av := &mockActiveVault{
		personalAlias:   "inactive-key",
		personalText:    "sk-ant-inactive",
		personalProv:    "anthropic",
		personalBaseURL: upstream.URL,
		// Active binding points at a DIFFERENT alias/team key — this is
		// what the fallback resolver would pick. The sentinel must ignore it.
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "personal",
				KeySourceRef:  "some-other-active-alias",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)

	req := httptest.NewRequest(http.MethodGet, "/anthropic/v1/models", nil)
	req.Header.Set("Authorization", "Bearer aikey_probe_inactive-key")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if capturedAuth != "sk-ant-inactive" {
		t.Errorf("upstream x-api-key = %q, want sk-ant-inactive "+
			"(sentinel must test the NAMED alias, not whichever is active)",
			capturedAuth)
	}
}

func TestHandlePathPrefix_PersonalAliasSentinel_UnknownAlias(t *testing.T) {
	av := &mockActiveVault{
		personalAlias: "only-this-one",
		personalText:  "sk-real",
		personalProv:  "anthropic",
	}
	p := setupTestProxyWithActive(t, av)

	req := httptest.NewRequest(http.MethodGet, "/anthropic/v1/models", nil)
	req.Header.Set("Authorization", "Bearer aikey_probe_nonexistent")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for unknown alias, got %d — body: %s",
			w.Code, w.Body.String())
	}
	// Body must hint at the fix so a preflight wrapper can surface it.
	if body := w.Body.String(); !strings.Contains(body, "aikey list") {
		t.Errorf("error body should point user at `aikey list`, got: %s", body)
	}
}

func TestHandlePathPrefix_PersonalAliasSentinel_EmptySuffix(t *testing.T) {
	av := &mockActiveVault{
		personalAlias: "any",
		personalText:  "sk",
		personalProv:  "anthropic",
	}
	p := setupTestProxyWithActive(t, av)

	req := httptest.NewRequest(http.MethodGet, "/anthropic/v1/models", nil)
	// Trailing-underscore-only sentinel: malformed caller.
	req.Header.Set("Authorization", "Bearer aikey_probe_")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for empty alias suffix, got %d", w.Code)
	}
}

func TestHandlePathPrefix_BindingTeamKey(t *testing.T) {
	var capturedPath2 string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath2 = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"m","type":"message","content":[],"model":"c","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	av := &mockActiveVault{
		activeKeyConfig: nil,
		activeTeamKeys: map[string]*vault.ManagedKey{
			"anthropic": {
				VirtualKeyID:     "vk_team_abc",
				ProviderCode:     "anthropic",
				ProtocolType:     "anthropic",
				BaseURL:          upstream.URL,
				PlaintextKey:     "sk-ant-team-real",
				ProviderBaseURLs: map[string]string{"anthropic": upstream.URL},
			},
		},
		providerBindings: map[string]*vault.ProviderBinding{
			"anthropic": {
				ProviderCode:  "anthropic",
				KeySourceType: "team",
				KeySourceRef:  "vk_team_abc",
			},
		},
	}
	p := setupTestProxyWithActive(t, av)

	body2 := `{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(body2))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if capturedPath2 != "/v1/messages" {
		t.Errorf("upstream path = %q, want /v1/messages", capturedPath2)
	}
}

func TestHandlePathPrefix_BindingFallsBackToLegacy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"m","type":"message","content":[],"model":"c","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer upstream.Close()

	av := &mockActiveVault{
		providerBindings: nil, // no bindings — should use legacy path
		activeTeamKeys: map[string]*vault.ManagedKey{
			"anthropic": {
				VirtualKeyID:     "vk_legacy",
				ProviderCode:     "anthropic",
				ProtocolType:     "anthropic",
				BaseURL:          upstream.URL,
				PlaintextKey:     "sk-ant-legacy",
				ProviderBaseURLs: map[string]string{"anthropic": upstream.URL},
			},
		},
	}
	p := setupTestProxyWithActive(t, av)

	body2 := `{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(body2))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// extractModel + Kimi session extraction contract tests.
//
// Why: extractModel is the single body-once-read step that feeds both the
// model allowlist check and the downstream session_id stash. Regressing
// either extraction breaks feature correctness silently (turn aggregation
// uses the wrong session, statusline shows wrong model). These tests pin
// the current contract so a future refactor doesn't quietly drop either.
// ---------------------------------------------------------------------------

func TestExtractModel_StashesModelAndKimiSession(t *testing.T) {
	body := []byte(`{"model":"kimi-k2.5","messages":[{"role":"user","content":"hi"}],"prompt_cache_key":"sess-abc-123","stream":true}`)
	req := httptest.NewRequest(http.MethodPost, "/kimi/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	model := extractModel(req)

	if model != "kimi-k2.5" {
		t.Fatalf("model return = %q, want kimi-k2.5", model)
	}
	if got := req.Header.Get("x-aikey-model"); got != "kimi-k2.5" {
		t.Errorf("x-aikey-model header = %q, want kimi-k2.5", got)
	}
	if got := req.Header.Get("x-aikey-kimi-session"); got != "sess-abc-123" {
		t.Errorf("x-aikey-kimi-session header = %q, want sess-abc-123", got)
	}

	// Critical: body must be re-buffered so upstream forwarding works. Read
	// it again and assert we see the original bytes.
	rebuffered, _ := io.ReadAll(req.Body)
	if !bytes.Equal(rebuffered, body) {
		t.Errorf("body not re-buffered; got %q", rebuffered)
	}
}

func TestExtractModel_NoPromptCacheKey_LeavesKimiHeaderUnset(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", bytes.NewReader(body))

	extractModel(req)

	if got := req.Header.Get("x-aikey-kimi-session"); got != "" {
		t.Errorf("x-aikey-kimi-session should be empty for non-Kimi body, got %q", got)
	}
	if got := req.Header.Get("x-aikey-model"); got != "claude-sonnet-4-6" {
		t.Errorf("x-aikey-model = %q, want claude-sonnet-4-6", got)
	}
}

func TestExtractModel_StreamingRequest_StillExtractsKimiSession(t *testing.T) {
	// Regression guard for third-party review round 3 Finding 1 —
	// streaming requests must still pick up prompt_cache_key from body
	// (extractModel runs at serveRoute entry before any streaming split).
	body := []byte(`{"stream":true,"model":"kimi-k2.5","prompt_cache_key":"streaming-sess-xyz"}`)
	req := httptest.NewRequest(http.MethodPost, "/kimi/v1/chat/completions", bytes.NewReader(body))

	extractModel(req)

	if got := req.Header.Get("x-aikey-kimi-session"); got != "streaming-sess-xyz" {
		t.Fatalf("streaming request lost prompt_cache_key: header = %q", got)
	}
}

// resolveSessionID was rewritten 2026-05-26 to delegate to the
// sessionid package's config-driven extractor (session-fingerprint.yaml). The
// tests below are smoke tests at the wrapper layer — they verify the
// proxy correctly hands req/protocol/provider to the extractor and
// the resulting session_id matches what the WAL would record. Pure
// rule-correctness tests live in sessionid/matcher_test.go.
//
// Signature change: was (http.Header, providerCode); is (*http.Request,
// protocolType, providerCode). Callers in pipelines.go / forward_and_resolve.go
// updated in lockstep. See design + plan docs:
//   roadmap20260320/技术实现/阶段5-丰富生态/20260526-Performance页会话维度与下钻设计.md

func makeReqWithHeaders(h http.Header) *http.Request {
	req := httptest.NewRequest("POST", "https://example.com/v1/messages", strings.NewReader(""))
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return req
}

func TestResolveSessionID_ClaudeHeaderWins(t *testing.T) {
	// Claude header is the authoritative source on anthropic protocol.
	// Even with an X-Aikey-Kimi-Session stash present (a body-parsed
	// hint that's only meaningful for kimi routes), Claude wins on
	// anthropic because the yaml's anthropic rule does NOT include
	// the Kimi stash header — protocol scoping prevents cross-pollution.
	h := http.Header{}
	h.Set("X-Claude-Code-Session-Id", "claude-sess-1")
	h.Set("x-aikey-kimi-session", "kimi-sess-should-lose")
	req := makeReqWithHeaders(h)
	if got := resolveSessionID(req, "anthropic", "anthropic"); got != "claude-sess-1" {
		t.Errorf("want Claude header to win on anthropic protocol, got %q", got)
	}
}

func TestResolveSessionID_KimiFallback(t *testing.T) {
	// Kimi protocol: the X-Aikey-Kimi-Session header (stashed by
	// extractModel from body's prompt_cache_key) is the canonical
	// session source per yaml's openai_compatible/kimi_code rule.
	h := http.Header{}
	h.Set("x-aikey-kimi-session", "kimi-sess-only")
	req := makeReqWithHeaders(h)
	if got := resolveSessionID(req, "openai_compatible", "kimi_code"); got != "kimi-sess-only" {
		t.Errorf("want kimi stash header to provide session, got %q", got)
	}
}

func TestResolveSessionID_BothMissing(t *testing.T) {
	req := makeReqWithHeaders(http.Header{})
	if got := resolveSessionID(req, "openai_compatible", "kimi_code"); got != "" {
		t.Errorf("want empty for no headers, got %q", got)
	}
}

// Regression guard for review finding #3 (2026-04-20), preserved across
// the 2026-05-26 sessionid refactor: if a non-Kimi provider's body
// happens to carry `prompt_cache_key` (and extractModel still stamps
// x-aikey-kimi-session regardless of provider), the WAL event MUST NOT
// surface that value — `prompt_cache_key` is Kimi-specific semantics.
//
// The yaml achieves this via protocol scoping: only the kimi_code /
// moonshot / kimi rules list X-Aikey-Kimi-Session as a source.
// Anthropic / OpenAI rules don't, so the stash is invisible there.
func TestResolveSessionID_NonKimiProviderIgnoresKimiHeader(t *testing.T) {
	h := http.Header{}
	h.Set("x-aikey-kimi-session", "looks-like-session-but-not-kimi")

	cases := []struct {
		protocol string
		provider string
	}{
		{"anthropic", "anthropic"},
		{"openai", "openai"},
		{"some_future_protocol", "generic"},
		{"", ""},
	}
	for _, c := range cases {
		req := makeReqWithHeaders(h)
		if got := resolveSessionID(req, c.protocol, c.provider); got != "" {
			t.Errorf("protocol=%q provider=%q: x-aikey-kimi-session must NOT leak (got %q) — "+
				"yaml scoping should restrict this header to kimi routes only",
				c.protocol, c.provider, got)
		}
	}
}

// ---------------------------------------------------------------------------
// extractModel body-size semantics (simplified 2026-04-21 from the prior
// streaming-prefix design):
//   - Huge bodies (> extractBodyHardLimit) must be skipped entirely so we
//     never OOM on multimodal payloads (review finding #1).
//   - All other bodies — including "fields at the tail after a huge
//     messages array" shape that Kimi 1.36 uses — must be fully parsed
//     so we pick up `model` and `prompt_cache_key` regardless of where
//     they sit in the JSON.
//   - Body replay must always survive so upstream still sees the full
//     payload unchanged.
// ---------------------------------------------------------------------------

func TestExtractModel_HugeBody_SkipsParsingAndLeavesBodyAlone(t *testing.T) {
	// Simulate a multimodal payload just past the hard limit: body contents
	// are irrelevant since we're testing the size fence. We lie about
	// ContentLength (> hard limit) which is enough to trigger the guard.
	body := []byte(`{"model":"kimi-k2.5","messages":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/kimi/v1/chat/completions", bytes.NewReader(body))
	req.ContentLength = extractBodyHardLimit + 1

	model := extractModel(req)

	if model != "" {
		t.Errorf("huge body: want empty model (parsing skipped), got %q", model)
	}
	if got := req.Header.Get("x-aikey-model"); got != "" {
		t.Errorf("huge body: x-aikey-model should be unset, got %q", got)
	}
	if got := req.Header.Get("x-aikey-kimi-session"); got != "" {
		t.Errorf("huge body: x-aikey-kimi-session should be unset, got %q", got)
	}
	// Body must pass through untouched for upstream.
	rebuffered, _ := io.ReadAll(req.Body)
	if !bytes.Equal(rebuffered, body) {
		t.Errorf("huge body: body mutated; got %q", rebuffered)
	}
}

// Regression guard for 2026-04-21 bug: Kimi 1.36.0 serializes `messages`
// as the first top-level field (huge system prompt + tools + history) and
// `prompt_cache_key` only after it. An earlier streaming-prefix design
// that only scanned the first 16 KB missed the session id, so every Kimi
// turn landed in WAL with empty session_id and the receipt hook never
// fired. This test pins the "fields-after-messages" shape and verifies
// the simplified full-buffer path captures both fields regardless of
// body size up to the hard limit.
func TestExtractModel_KimiShape_FieldsAfterLargeMessagesArray(t *testing.T) {
	var payload bytes.Buffer
	// Kimi body shape: messages FIRST (big), model + prompt_cache_key LAST.
	payload.WriteString(`{"messages":[`)
	// Fill the messages array with ~50 KB of content — bigger than any
	// reasonable prefix-scan window, smaller than the hard limit.
	for i := 0; i < 200; i++ {
		if i > 0 {
			payload.WriteByte(',')
		}
		payload.WriteString(`{"role":"user","content":"`)
		payload.WriteString(strings.Repeat("x", 250))
		payload.WriteString(`"}`)
	}
	payload.WriteString(`],"model":"kimi-k2.5","prompt_cache_key":"tail-sess-z"}`)
	bodyBytes := payload.Bytes()
	if len(bodyBytes) < 32*1024 {
		t.Fatalf("fixture too small — the whole point is to dwarf any prefix window; got %d bytes", len(bodyBytes))
	}

	req := httptest.NewRequest(http.MethodPost, "/kimi/v1/chat/completions",
		bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))

	model := extractModel(req)

	if model != "kimi-k2.5" {
		t.Errorf("Kimi shape: want model=kimi-k2.5, got %q — has the full-buffer path been replaced with a prefix scanner again?", model)
	}
	if got := req.Header.Get("x-aikey-kimi-session"); got != "tail-sess-z" {
		t.Errorf("Kimi shape: want session=tail-sess-z, got %q — prompt_cache_key at body tail must still be captured", got)
	}

	rebuffered, _ := io.ReadAll(req.Body)
	if !bytes.Equal(rebuffered, bodyBytes) {
		t.Errorf("Kimi shape: body replay mismatch; len(got)=%d, len(want)=%d",
			len(rebuffered), len(bodyBytes))
	}
}
