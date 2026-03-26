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
	collector := events.NewCollector(&mockEventStore{}, 100, 5*time.Second)
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
