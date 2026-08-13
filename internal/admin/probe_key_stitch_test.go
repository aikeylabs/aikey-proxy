package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Health checks receive the same effective/custom BaseURL shape that users see
// elsewhere. Exact outgoing paths must therefore be composed by the shared
// provider-route Stitch contract, not by trimming only /v1 and appending a
// second hard-coded version.
func TestProbeKey_UsesProviderRouteStitchForEveryVersionShape(t *testing.T) {
	tests := []struct {
		name         string
		provider     string
		protocol     string
		baseSuffix   string
		wantPath     string
		wantKeyQuery bool
	}{
		{name: "Anthropic v1", provider: "anthropic", protocol: "anthropic", baseSuffix: "/v1", wantPath: "/v1/messages"},
		{name: "Google v1beta", provider: "google", protocol: "gemini", baseSuffix: "/v1beta", wantPath: "/v1beta/models/gemini-1.5-flash:generateContent", wantKeyQuery: true},
		{name: "Doubao v3", provider: "doubao", protocol: "openai_compatible", baseSuffix: "/api/v3", wantPath: "/api/v3/chat/completions"},
		{name: "Kimi nested v1", provider: "kimi_code", protocol: "openai_compatible", baseSuffix: "/coding/v1", wantPath: "/coding/v1/chat/completions"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath, gotKey string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotKey = r.URL.Query().Get("key")
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			status, err := probeKey(context.Background(), upstream.Client(), &KeyCheckTarget{
				Provider: tt.provider,
				Protocol: tt.protocol,
				BaseURL:  upstream.URL + tt.baseSuffix,
				APIKey:   "health-test-key",
			})
			if err != nil {
				t.Fatalf("probeKey: %v", err)
			}
			if status != http.StatusOK {
				t.Fatalf("status=%d, want 200", status)
			}
			if gotPath != tt.wantPath {
				t.Errorf("outbound path=%q, want %q", gotPath, tt.wantPath)
			}
			if tt.wantKeyQuery && gotKey != "health-test-key" {
				t.Errorf("Google key query missing")
			}
		})
	}
}
