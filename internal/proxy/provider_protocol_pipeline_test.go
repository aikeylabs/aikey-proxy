package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
)

// These integration cases pin the four independent routing axes at the two
// pipelines that previously collapsed Provider into Protocol:
//
//	client route -> real provider -> wire protocol -> credential
//
// A Mock credential is intentionally used because its Provider (mock) can
// never be mistaken for an adapter name. The request must still select the
// anthropic/openai adapter from ProtocolType while preserving the Mock runtime
// base URL and Mock provider attribution.
func TestAppPipeline_PreservesProviderAndUsesProtocolAdapter(t *testing.T) {
	tests := []struct {
		name             string
		slug             string
		clientRoute      string
		protocolType     string
		requestPath      string
		requestBody      string
		runtimePrefix    string
		wantUpstreamPath string
		wantAuthHeader   string
		upstreamResponse string
	}{
		{
			name:             "Mock Anthropic selected through OpenAI-wire app",
			slug:             "mock-anthropic-app",
			clientRoute:      "anthropic",
			protocolType:     "anthropic",
			requestPath:      "/apps/mock-anthropic-app/v1/chat/completions",
			requestBody:      `{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"hi"}]}`,
			runtimePrefix:    "/anthropic",
			wantUpstreamPath: "/anthropic/v1/messages",
			wantAuthHeader:   "X-Api-Key",
			upstreamResponse: `{"id":"msg_mock","type":"message","role":"assistant","model":"claude-3-5-sonnet-20241022","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`,
		},
		{
			name:             "Mock OpenAI direct app",
			slug:             "mock-openai-app",
			clientRoute:      "openai",
			protocolType:     "openai_compatible",
			requestPath:      "/apps/mock-openai-app/v1/chat/completions",
			requestBody:      `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`,
			runtimePrefix:    "/openai",
			wantUpstreamPath: "/openai/v1/chat/completions",
			wantAuthHeader:   "Authorization",
			upstreamResponse: `{"id":"chatcmpl_mock","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath, gotAuth string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotAuth = r.Header.Get(tt.wantAuthHeader)
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.upstreamResponse))
			}))
			defer upstream.Close()

			av := newAppPipelineTestVault(tt.slug, []string{tt.clientRoute}, "mock-secret", upstream.URL+tt.runtimePrefix)
			binding := &vault.ProviderBinding{
				ClientRoute:   tt.clientRoute,
				ProviderCode:  "mock",
				ProtocolType:  tt.protocolType,
				KeySourceType: "personal",
				KeySourceRef:  "app-test-key",
			}
			av.appBindings["app:"+tt.slug+"|"+tt.clientRoute] = binding
			av.personalProv = "mock"

			p := setupTestProxyWithActive(t, av)
			seedAppRouteInProxy(p, tt.slug)
			req := httptest.NewRequest(http.MethodPost, tt.requestPath, strings.NewReader(tt.requestBody))
			req.Header.Set("Authorization", "Bearer "+testAppBearer)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			p.Handle(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status=%d, want 200; body=%s", w.Code, w.Body.String())
			}
			if gotPath != tt.wantUpstreamPath {
				t.Errorf("upstream path=%q, want %q", gotPath, tt.wantUpstreamPath)
			}
			wantAuth := "mock-secret"
			if tt.wantAuthHeader == "Authorization" {
				wantAuth = "Bearer mock-secret"
			}
			if gotAuth != wantAuth {
				t.Errorf("%s=%q, want %q", tt.wantAuthHeader, gotAuth, wantAuth)
			}
			if binding.ProviderCode != "mock" {
				t.Errorf("shared binding ProviderCode mutated to %q, want mock", binding.ProviderCode)
			}
		})
	}
}

func TestProbePipeline_PreservesProviderAndUsesProtocolAdapter(t *testing.T) {
	tests := []struct {
		name             string
		alias            string
		protocolType     string
		requestPath      string
		requestBody      string
		runtimePrefix    string
		wantUpstreamPath string
		wantAuthHeader   string
	}{
		{
			name:             "Mock Anthropic probe",
			alias:            "mock-anthropic",
			protocolType:     "anthropic",
			requestPath:      "/probe/mock-anthropic/v1/messages",
			requestBody:      `{"model":"claude-3-5-sonnet-20241022","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`,
			runtimePrefix:    "/anthropic",
			wantUpstreamPath: "/anthropic/v1/messages",
			wantAuthHeader:   "X-Api-Key",
		},
		{
			name:             "Mock OpenAI probe",
			alias:            "mock-openai",
			protocolType:     "openai_compatible",
			requestPath:      "/probe/mock-openai/v1/chat/completions",
			requestBody:      `{"model":"gpt-4o","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`,
			runtimePrefix:    "/openai",
			wantUpstreamPath: "/openai/v1/chat/completions",
			wantAuthHeader:   "Authorization",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath, gotAuth string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotAuth = r.Header.Get(tt.wantAuthHeader)
				w.Header().Set("Content-Type", "application/json")
				if tt.protocolType == "anthropic" {
					_, _ = w.Write([]byte(`{"id":"msg_probe","type":"message","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
					return
				}
				_, _ = w.Write([]byte(`{"id":"chatcmpl_probe","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
			}))
			defer upstream.Close()

			binding := &vault.ProviderBinding{
				ProviderCode:  "mock",
				ProtocolType:  tt.protocolType,
				KeySourceType: "personal",
				KeySourceRef:  tt.alias,
			}
			av := &mockActiveVault{
				aliasCreds: map[string]*vault.AliasCredential{
					tt.alias: {Binding: binding, Status: "active", AliasKind: "personal"},
				},
				personalAlias:   tt.alias,
				personalText:    "mock-secret",
				personalProv:    "mock",
				personalBaseURL: upstream.URL + tt.runtimePrefix,
			}
			p := setupTestProxyWithActive(t, av)
			req := httptest.NewRequest(http.MethodPost, tt.requestPath, strings.NewReader(tt.requestBody))
			req.Header.Set("Authorization", "Bearer aikey_app_internal_degrade_detector_v1")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			p.Handle(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status=%d, want 200; body=%s", w.Code, w.Body.String())
			}
			if gotPath != tt.wantUpstreamPath {
				t.Errorf("upstream path=%q, want %q", gotPath, tt.wantUpstreamPath)
			}
			wantAuth := "mock-secret"
			if tt.wantAuthHeader == "Authorization" {
				wantAuth = "Bearer mock-secret"
			}
			if gotAuth != wantAuth {
				t.Errorf("%s=%q, want %q", tt.wantAuthHeader, gotAuth, wantAuth)
			}
			if binding.ProviderCode != "mock" {
				t.Errorf("shared binding ProviderCode mutated to %q, want mock", binding.ProviderCode)
			}
		})
	}
}
