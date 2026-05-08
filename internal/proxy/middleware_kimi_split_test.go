package proxy

import "testing"

// 2026-05-08 Kimi 双平台拆分回归断言 (review feedback fix #1, #4)
//
// 评审反馈发现的 bug:
//   [高] #1: handlePathPrefixRoute 走 protocolType 查 adapter 没问题,但 legacy
//        /v1 token-based flow (proxy.go:291) 用 route.Provider (= provider_code,
//        post-split 是 "kimi_code" / "moonshot") 查 adapter,registry 只注册了
//        "kimi" 不识别新码 → 502 PROVIDER_ERROR。
//   [中] #4: providerCanonicalCode("kimi") 必须归一化到 "kimi_code"。否则
//        OAuth binding 写入 vault 是 "kimi",proxy GetProviderBinding lookup
//        URL canonical "kimi_code" 时找不到。
//
// 这两个 bug 都是字面值比较类的硬编码,单元测试可以直接断言。

func TestProviderCanonicalCode_KimiResolvesToKimiCode(t *testing.T) {
	// 'kimi' 是 deprecated alias,canonical 形态是 'kimi_code'。让 vault binding
	// (写时归一化) 与 proxy GetProviderBinding lookup (读时归一化) 在新旧
	// path-prefix / 老 vault 数据 / 新 vault 数据之间都匹配。
	got := providerCanonicalCode("kimi")
	if got != "kimi_code" {
		t.Errorf("providerCanonicalCode(\"kimi\") = %q, want %q", got, "kimi_code")
	}
}

func TestProviderCanonicalCode_KimiCodeStaysCanonical(t *testing.T) {
	if got := providerCanonicalCode("kimi_code"); got != "kimi_code" {
		t.Errorf("providerCanonicalCode(\"kimi_code\") = %q, want unchanged", got)
	}
}

func TestProviderCanonicalCode_MoonshotStaysCanonical(t *testing.T) {
	if got := providerCanonicalCode("moonshot"); got != "moonshot" {
		t.Errorf("providerCanonicalCode(\"moonshot\") = %q, want unchanged", got)
	}
}

func TestProviderDefaultBaseURL_KimiCode(t *testing.T) {
	// kimi_code 是新 canonical,upstream api.kimi.com/coding。
	got := providerDefaultBaseURL("kimi_code")
	want := "https://api.kimi.com/coding"
	if got != want {
		t.Errorf("providerDefaultBaseURL(\"kimi_code\") = %q, want %q", got, want)
	}
}

func TestProviderDefaultBaseURL_Moonshot(t *testing.T) {
	// Moonshot 应路由到 api.moonshot.cn (修 pre-split 共用 case 错误指向
	// Kimi Code endpoint 的 bug)。
	got := providerDefaultBaseURL("moonshot")
	want := "https://api.moonshot.cn"
	if got != want {
		t.Errorf("providerDefaultBaseURL(\"moonshot\") = %q, want %q", got, want)
	}
}

func TestProviderDefaultBaseURL_KimiDeprecatedAlias(t *testing.T) {
	// 'kimi' 仍兼容旧 shell hook env vars 路径前缀,upstream 与 kimi_code 一致。
	got := providerDefaultBaseURL("kimi")
	want := "https://api.kimi.com/coding"
	if got != want {
		t.Errorf("providerDefaultBaseURL(\"kimi\") = %q, want %q", got, want)
	}
}

func TestExtractProviderFromPath_KimiCodePathRecognized(t *testing.T) {
	// /kimi_code/v1/... 必须被识别为 path-prefix route (review feedback fix
	// 防退化:若 known list 漏掉 kimi_code,新路径会落 fallback 走 token-based
	// 处理,直接 token_missing 401)。
	provider, stripped := extractProviderFromPath("/kimi_code/v1/chat/completions")
	if provider != "kimi_code" {
		t.Errorf("extractProviderFromPath kimi_code: provider = %q, want kimi_code", provider)
	}
	if stripped != "/v1/chat/completions" {
		t.Errorf("extractProviderFromPath kimi_code: stripped = %q, want /v1/chat/completions", stripped)
	}
}

func TestExtractProviderFromPath_MoonshotPathRecognized(t *testing.T) {
	provider, stripped := extractProviderFromPath("/moonshot/v1/chat/completions")
	if provider != "moonshot" {
		t.Errorf("extractProviderFromPath moonshot: provider = %q", provider)
	}
	if stripped != "/v1/chat/completions" {
		t.Errorf("extractProviderFromPath moonshot: stripped = %q", stripped)
	}
}

func TestExtractProviderFromPath_KimiDeprecatedPathStillWorks(t *testing.T) {
	// 老 shell hook 写入的 KIMI_BASE_URL=...:27200/kimi/v1 必须继续工作。
	provider, _ := extractProviderFromPath("/kimi/v1/chat/completions")
	if provider != "kimi_code" && provider != "kimi" {
		// 'kimi' 命中后 canonicalize → "kimi_code"。known list 只要含 'kimi'
		// 就 OK,后续 canonical 步骤会归一化。
		t.Errorf("extractProviderFromPath /kimi/v1: provider = %q, want kimi or kimi_code", provider)
	}
}
