package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
)

// 2026-05-08 Kimi 双平台拆分 — `usage_events.provider` canonical 写入回归测试。
//
// 评审反馈期间发现的连带 bug (workflow/CI/bugfix/2026-05-08-events-provider-
// uses-url-prefix-not-canonical.md):
//
// pre-fix `buildBaseEvent` 用 `route.Provider` (URL 前缀,e.g. "kimi" deprecated
// alias) 写 events.provider 字段。post-Kimi-split 同一条 vault entry
// (provider_code='kimi_code') 经 deprecated `/kimi/v1` vs canonical
// `/kimi_code/v1` 两条路径访问会写入两个不同 provider 字符串,用量聚合分裂。
//
// 修复后用 `route.ProviderCode` (canonical) 优先,`route.Provider` 兜底。
// 下面的测试锁定:
//   - canonical ProviderCode 优先于 URL-prefix Provider
//   - ProviderCode 缺失时优雅退回 Provider (不写空字符串)

func TestBuildBaseEvent_PrefersCanonicalProviderCode(t *testing.T) {
	// 模拟 /kimi/v1 路径下的请求:Provider 是 URL 前缀 "kimi" (deprecated),
	// ProviderCode 是 canonical "kimi_code" (proxy 在 path-prefix routing
	// 时填入)。事件应该记录 canonical "kimi_code" 而非 "kimi"。
	p := &Proxy{}
	req := httptest.NewRequest(http.MethodPost, "/kimi/v1/chat/completions", nil)
	resp := &http.Response{StatusCode: 200}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "personal:my-key",
		Provider:     "kimi",      // URL 前缀(deprecated alias)
		ProviderCode: "kimi_code", // canonical
		ProtocolType: "openai_compatible",
	}

	ev := p.buildBaseEvent(req, resp, time.Now(), route, false)

	if ev.Provider != "kimi_code" {
		t.Errorf("buildBaseEvent.Provider = %q, want %q (canonical from ProviderCode)",
			ev.Provider, "kimi_code")
	}
}

func TestBuildBaseEvent_FallbackToProviderWhenProviderCodeEmpty(t *testing.T) {
	// 防御:pre-2026-05-08 fixture 或 route_builders bug 可能让 ProviderCode
	// 为空字符串。此时退回 Provider,避免写空 provider 字段污染聚合查询。
	p := &Proxy{}
	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	resp := &http.Response{StatusCode: 200}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "personal:my-key",
		Provider:     "openai",
		ProviderCode: "", // 故意留空模拟 fixture
		ProtocolType: "openai_compatible",
	}

	ev := p.buildBaseEvent(req, resp, time.Now(), route, false)

	if ev.Provider != "openai" {
		t.Errorf("buildBaseEvent.Provider = %q, want fallback %q", ev.Provider, "openai")
	}
}

func TestBuildBaseEvent_MoonshotPathStaysAsMoonshot(t *testing.T) {
	// /moonshot/v1 路径:Provider="moonshot", ProviderCode="moonshot",两者
	// 一致都是 canonical。事件记录 "moonshot" 而非任何混淆形态。
	p := &Proxy{}
	req := httptest.NewRequest(http.MethodPost, "/moonshot/v1/chat/completions", nil)
	resp := &http.Response{StatusCode: 200}
	route := &vkeys.ResolvedRoute{
		VirtualKeyID: "personal:my-moonshot-key",
		Provider:     "moonshot",
		ProviderCode: "moonshot",
		ProtocolType: "openai_compatible",
	}

	ev := p.buildBaseEvent(req, resp, time.Now(), route, false)

	if ev.Provider != "moonshot" {
		t.Errorf("buildBaseEvent.Provider = %q, want %q", ev.Provider, "moonshot")
	}
}
