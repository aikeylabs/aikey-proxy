package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// P1d (R-C): metadata attribution flips to the truthful upstream vendor.
func TestTruthfulProviderCode(t *testing.T) {
	cases := []struct {
		baseURL, declared, want string
	}{
		{"https://open.bigmodel.cn/api/anthropic", "anthropic", "zhipu"}, // the fix
		{"https://open.bigmodel.cn/api/coding/paas/v4", "anthropic", "zhipu"},
		{"https://api.anthropic.com", "anthropic", "anthropic"}, // no-op
		{"https://api.kimi.com/coding/v1", "kimi_code", "kimi_code"},
		{"https://third-party.example/v1", "custom", "custom"}, // unknown host → unchanged
		{"", "anthropic", "anthropic"},                         // no base_url → unchanged
	}
	for _, c := range cases {
		if got := truthfulProviderCode(c.baseURL, c.declared); got != c.want {
			t.Errorf("truthfulProviderCode(%q,%q) = %q, want %q", c.baseURL, c.declared, got, c.want)
		}
	}
}

// TestBuildBaseEvent_GLMAttributedToZhipu: end-to-end, a GLM-anthropic route
// whose ProviderCode was normalized to zhipu records event.Provider=zhipu.
func TestBuildBaseEvent_GLMAttributedToZhipu(t *testing.T) {
	p := &Proxy{}
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", nil)
	resp := &http.Response{StatusCode: 200}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "team:vk",
		ProviderCode: truthfulProviderCode("https://open.bigmodel.cn/api/anthropic", "anthropic"),
		ProtocolType: "anthropic",
	}
	ev := p.buildBaseEvent(req, resp, time.Now(), route, false)
	if ev.Provider != "zhipu" {
		t.Errorf("event.Provider = %q, want zhipu (metadata attribution fix)", ev.Provider)
	}
}

// P1d (R-C, design D-10 refined): isProviderCompatible must allow a binding
// whose real upstream endpoint speaks the SAME wire protocol the path prefix
// implies (GLM zhipu binding on the /anthropic path), while still rejecting a
// genuine cross-protocol mismatch.
func TestIsProviderCompatible_CrossProviderSameProtocol(t *testing.T) {
	cases := []struct {
		name          string
		providerCode  string
		baseURL       string
		canonicalPath string // path-prefix provider
		protocol      string
		want          bool
	}{
		{
			name:         "same provider (existing)",
			providerCode: "anthropic", baseURL: "https://api.anthropic.com",
			canonicalPath: "anthropic", protocol: "anthropic", want: true,
		},
		{
			name:         "zhipu binding on anthropic path (GLM anthropic endpoint)",
			providerCode: "zhipu", baseURL: "https://open.bigmodel.cn/api/anthropic",
			canonicalPath: "anthropic", protocol: "anthropic", want: true, // same wire protocol → compatible
		},
		{
			name:         "zhipu binding on openai path (GLM coding endpoint)",
			providerCode: "zhipu", baseURL: "https://open.bigmodel.cn/api/coding/paas/v4",
			canonicalPath: "openai", protocol: "openai_compatible", want: true, // both openai_compatible
		},
		{
			name:         "zhipu anthropic endpoint on openai path — cross-protocol, reject",
			providerCode: "zhipu", baseURL: "https://open.bigmodel.cn/api/anthropic",
			canonicalPath: "openai", protocol: "openai_compatible", want: false, // anthropic != openai_compatible
		},
		{
			name:         "openai binding on anthropic path — cross-protocol, reject",
			providerCode: "openai", baseURL: "https://api.openai.com",
			canonicalPath: "anthropic", protocol: "anthropic", want: false,
		},
		{
			name:         "no base_url falls back to strict provider match",
			providerCode: "zhipu", baseURL: "",
			canonicalPath: "anthropic", protocol: "anthropic", want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			route := &vkeys.ResolvedRoute{ProviderCode: c.providerCode, BaseURL: c.baseURL}
			if got := isProviderCompatible(route, c.canonicalPath, c.protocol); got != c.want {
				t.Errorf("isProviderCompatible(%s@%s, path=%s) = %v, want %v",
					c.providerCode, c.baseURL, c.canonicalPath, got, c.want)
			}
		})
	}
}
