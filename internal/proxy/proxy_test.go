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

	"github.com/AiKeyLabs/aikey-proxy/internal/config"
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

func (m *mockEventStore) Insert(_ []events.UsageEvent) error                              { return nil }
func (m *mockEventStore) QueryStats() (map[string]int64, map[string]int64, error) { return nil, nil, nil }
func (m *mockEventStore) Close() error                                             { return nil }

func setupTestProxy(t *testing.T, upstreamURL string) *Proxy {
	t.Helper()
	return setupTestProxyWithStore(t, upstreamURL, &mockEventStore{})
}

// setupTestProxyWithStore creates a Proxy wired to a custom EventInserter,
// useful for tests that need to capture and assert on recorded events.
func setupTestProxyWithStore(t *testing.T, upstreamURL string, store events.EventInserter) *Proxy {
	t.Helper()

	v := &mockVault{
		secrets: map[string]string{
			"openai:test":    "sk-real-openai-key-123",
			"anthropic:test": "sk-ant-real-key-456",
		},
	}

	registry := vkeys.NewRegistry()
	registry.Load([]config.VirtualKeyConfig{
		{
			ID:       "vk_openai",
			Token:    "aikey_vk_openai_test",
			Provider: "openai",
			BaseURL:  upstreamURL,
			KeyAlias: "openai:test",
		},
		{
			ID:            "vk_anthropic",
			Token:         "aikey_vk_anthropic_test",
			Provider:      "anthropic",
			BaseURL:       upstreamURL,
			KeyAlias:      "anthropic:test",
			AllowedModels: []string{"claude-sonnet-4-5-20250929"},
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
	req.Header.Set("Authorization", "Bearer aikey_vk_openai_test")
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
	req.Header.Set("x-api-key", "aikey_vk_anthropic_test")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if receivedAPIKey != "sk-ant-real-key-456" {
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
	req.Header.Set("Authorization", "Bearer aikey_vk_nonexistent")

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
	req.Header.Set("x-api-key", "aikey_vk_anthropic_test")
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
	req.Header.Set("Authorization", "Bearer aikey_vk_openai_test")
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
	req.Header.Set("Authorization", "Bearer aikey_vk_abc123")

	if token := extractVirtualKey(req); token != "aikey_vk_abc123" {
		t.Fatalf("expected aikey_vk_abc123, got %q", token)
	}
}

func TestExtractVirtualKey_XAPIKey(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("x-api-key", "aikey_vk_def456")

	if token := extractVirtualKey(req); token != "aikey_vk_def456" {
		t.Fatalf("expected aikey_vk_def456, got %q", token)
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
	req.Header.Set("Authorization", "Bearer aikey_vk_openai_test")
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
	req.Header.Set("x-api-key", "aikey_vk_anthropic_test")
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
	req.Header.Set("x-api-key", "aikey_vk_anthropic_test")
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
	req.Header.Set("Authorization", "Bearer aikey_vk_openai_test")
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
	activeTeamKeys   map[string]*vault.ManagedKey // keyed by lowercase provider code
	personalAlias    string
	personalText     string
	personalProv     string
	personalBaseURL  string
	providerBindings map[string]*vault.ProviderBinding // keyed by lowercase provider code
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

func (m *mockActiveVault) GetActiveTeamKeyByProvider(providerCode string) (*vault.ManagedKey, error) {
	if m.activeTeamKeys == nil {
		return nil, nil
	}
	mk, ok := m.activeTeamKeys[strings.ToLower(providerCode)]
	if !ok {
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

func (m *mockActiveVault) GetTeamKeyByID(virtualKeyID string) (*vault.ManagedKey, error) {
	// Search all team keys for the specific ID.
	for _, mk := range m.activeTeamKeys {
		if mk.VirtualKeyID == virtualKeyID {
			return mk, nil
		}
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
				VirtualKeyID:     "aikey_vk_test",
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
				VirtualKeyID:     "aikey_vk_multi",
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

func TestResolveSessionID_ClaudeHeaderWins(t *testing.T) {
	// Claude header wins across ALL providers — it's Claude-specific and
	// can't be forged by other SDKs. Pass providerCode="kimi" here to
	// prove the gate doesn't accidentally short-circuit the Claude path.
	h := http.Header{}
	h.Set("X-Claude-Code-Session-Id", "claude-sess-1")
	h.Set("x-aikey-kimi-session", "kimi-sess-should-lose")
	if got := resolveSessionID(h, "kimi"); got != "claude-sess-1" {
		t.Errorf("want Claude header to win, got %q", got)
	}
}

func TestResolveSessionID_KimiFallback(t *testing.T) {
	h := http.Header{}
	h.Set("x-aikey-kimi-session", "kimi-sess-only")
	if got := resolveSessionID(h, "kimi"); got != "kimi-sess-only" {
		t.Errorf("want kimi fallback, got %q", got)
	}
}

func TestResolveSessionID_BothMissing(t *testing.T) {
	if got := resolveSessionID(http.Header{}, "kimi"); got != "" {
		t.Errorf("want empty for no headers, got %q", got)
	}
}

// Regression guard for review finding #3 (2026-04-20): if a non-Kimi
// provider's body happens to carry `prompt_cache_key` (and extractModel
// stamps x-aikey-kimi-session regardless of provider, which it does),
// resolveSessionID MUST NOT surface that value to the WAL event — it's
// Kimi-specific semantics, applying it to Anthropic / OpenAI / Generic
// events would be silent data pollution.
func TestResolveSessionID_NonKimiProviderIgnoresKimiHeader(t *testing.T) {
	h := http.Header{}
	h.Set("x-aikey-kimi-session", "looks-like-session-but-not-kimi")

	for _, provider := range []string{"anthropic", "openai", "generic", ""} {
		if got := resolveSessionID(h, provider); got != "" {
			t.Errorf("provider=%q: x-aikey-kimi-session must NOT leak (got %q) — "+
				"gate should restrict this header to kimi routes only",
				provider, got)
		}
	}
}

// ---------------------------------------------------------------------------
// F1c regression: extractModel performance/safety under large bodies.
//   - Huge bodies (> extractBodyHardLimit) must be skipped entirely so we
//     never OOM on multimodal payloads.
//   - Mid-sized bodies (> extractPrefixScan, <= hard limit) must extract
//     top-level fields via the streaming path without materialising the
//     full body in memory.
//   - Body replay must survive both paths so upstream still sees the full
//     payload unchanged.
// ---------------------------------------------------------------------------

func TestExtractModel_HugeBody_SkipsParsingAndLeavesBodyAlone(t *testing.T) {
	// Simulate a multimodal payload just past the hard limit: huge JSON
	// array of strings. We don't actually construct 4MB here — we lie
	// about ContentLength, which is enough to trigger the guard.
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

func TestExtractModel_LargeBody_StreamScansPrefix(t *testing.T) {
	// Build a body whose top-level `model` and `prompt_cache_key` sit at
	// the front, followed by a large `messages` array that exceeds
	// extractPrefixScan. Streaming path should find both fields without
	// materialising the large array.
	var payload bytes.Buffer
	payload.WriteString(`{"model":"kimi-k2.5","prompt_cache_key":"large-sess-9","messages":[`)
	// ~20 KB of filler strings in the messages array, pushing total body
	// past the 16 KB prefix scan limit.
	for i := 0; i < 200; i++ {
		if i > 0 {
			payload.WriteByte(',')
		}
		payload.WriteString(`{"role":"user","content":"`)
		payload.WriteString(strings.Repeat("x", 100))
		payload.WriteString(`"}`)
	}
	payload.WriteString(`]}`)
	bodyBytes := payload.Bytes()
	if len(bodyBytes) <= extractPrefixScan {
		t.Fatalf("test fixture too small — want > %d bytes, got %d",
			extractPrefixScan, len(bodyBytes))
	}

	req := httptest.NewRequest(http.MethodPost, "/kimi/v1/chat/completions",
		bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))

	model := extractModel(req)

	if model != "kimi-k2.5" {
		t.Errorf("large body: want model=kimi-k2.5, got %q", model)
	}
	if got := req.Header.Get("x-aikey-kimi-session"); got != "large-sess-9" {
		t.Errorf("large body: want session=large-sess-9, got %q", got)
	}

	// Critical: body replay. Upstream must see every byte.
	rebuffered, _ := io.ReadAll(req.Body)
	if !bytes.Equal(rebuffered, bodyBytes) {
		t.Errorf("large body: replay mismatch; len(got)=%d, len(want)=%d",
			len(rebuffered), len(bodyBytes))
	}
}

func TestScanTopLevelStringFields_SkipsNestedValues(t *testing.T) {
	// Direct unit test of the token-stream skipper: a deeply nested
	// object before `model` must not break extraction, and the function
	// must not allocate memory proportional to the nested value.
	body := `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],"model":"m1","prompt_cache_key":"s1"}`
	m, s := scanTopLevelStringFields(strings.NewReader(body), "model", "prompt_cache_key")
	if m != "m1" || s != "s1" {
		t.Errorf("want (m1,s1), got (%q,%q)", m, s)
	}
}

func TestScanTopLevelStringFields_EarlyExitAfterBothFound(t *testing.T) {
	// If model + prompt_cache_key both appear before other fields, the
	// scanner must stop — later junk (even malformed JSON) shouldn't
	// matter. This is the load-bearing optimisation for huge-messages
	// payloads.
	body := `{"model":"m","prompt_cache_key":"s","junk":`
	m, s := scanTopLevelStringFields(strings.NewReader(body), "model", "prompt_cache_key")
	if m != "m" || s != "s" {
		t.Errorf("early exit failed: (%q,%q)", m, s)
	}
}

func TestScanTopLevelStringFields_NonObjectReturnsEmpty(t *testing.T) {
	// Body that isn't a JSON object (array, scalar, garbage) returns
	// empty strings — no panic, no partial state.
	cases := []string{`[]`, `"just a string"`, `42`, `not json at all`, ``}
	for _, c := range cases {
		m, s := scanTopLevelStringFields(strings.NewReader(c), "model", "prompt_cache_key")
		if m != "" || s != "" {
			t.Errorf("input %q: want empty, got (%q,%q)", c, m, s)
		}
	}
}
