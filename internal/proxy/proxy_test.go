package proxy

import (
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
	secrets         map[string]string
	activeKeyConfig *vault.ActiveKeyConfig
	activeTeamKeys  map[string]*vault.ManagedKey // keyed by lowercase provider code
	personalAlias   string
	personalText    string
	personalProv    string
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
		return m.personalText, m.personalProv, "", nil
	}
	return "", "", "", fmt.Errorf("personal key %q not found", alias)
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
