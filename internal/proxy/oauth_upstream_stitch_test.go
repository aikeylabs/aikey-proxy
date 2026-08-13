package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

func TestStitchOAuthRequestURL_OneProviderTableRule(t *testing.T) {
	tests := []struct {
		name       string
		provider   string
		protocol   string
		baseURL    string
		requestURL string
		wantURL    string
	}{
		{"Anthropic root", "anthropic", "anthropic", "https://api.anthropic.com", "http://proxy.test/v1/messages?beta=true", "https://api.anthropic.com/v1/messages?beta=true"},
		{"Anthropic effective", "anthropic", "anthropic", "https://api.anthropic.com/v1", "http://proxy.test/v1/messages?beta=true", "https://api.anthropic.com/v1/messages?beta=true"},
		{"Anthropic custom gateway effective", "anthropic", "anthropic", "https://gateway.example.test/api/anthropic/v1", "http://proxy.test/v1/messages", "https://gateway.example.test/api/anthropic/v1/messages"},
		{"Kimi coding", "kimi_code", "openai_compatible", "https://api.kimi.com/coding/v1", "http://proxy.test/v1/chat/completions", "https://api.kimi.com/coding/v1/chat/completions"},
		{"GLM Anthropic", "zhipu", "anthropic", "https://open.bigmodel.cn/api/anthropic/v1", "http://proxy.test/v1/messages", "https://open.bigmodel.cn/api/anthropic/v1/messages"},
		{"Mock runtime rail", "mock", "anthropic", "http://mock.test:3000/mock-provider/anthropic", "http://proxy.test/v1/messages", "http://mock.test:3000/mock-provider/anthropic/v1/messages"},
		{"Codex backend", "openai", "openai_compatible", "https://chatgpt.com/backend-api/codex", "http://proxy.test/responses", "https://chatgpt.com/backend-api/codex/responses"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.requestURL, nil)
			route := &vkeys.ResolvedRoute{
				Provider: tt.provider, ProviderCode: tt.provider,
				ProtocolType: tt.protocol, BaseURL: tt.baseURL,
			}
			if err := stitchOAuthRequestURL(req, route); err != nil {
				t.Fatalf("stitch OAuth request: %v", err)
			}
			if got := req.URL.String(); got != tt.wantURL {
				t.Fatalf("URL = %q, want %q", got, tt.wantURL)
			}
		})
	}
}
