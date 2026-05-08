package admin

import "testing"

// 2026-05-08 Kimi 双平台拆分 review feedback (medium): probeModelForProtocol
// 此前接收 t.Protocol (= "openai" / "openai_compatible" 等 wire-protocol),
// 而 kimi_code / moonshot 的 model selection 应该按 provider_code 分流。
// supervisor.go::providerProtocol 把 kimi_code/moonshot 都归到 "openai"
// protocol → 永远命中 fallback gpt-4o-mini → api.kimi.com 探针被 reject。
//
// 修复后调用方 (admin/handlers.go:391) 改用 t.Provider 调用此函数,
// 所以下面这些断言锁定 provider-code-based 模型映射:

func TestProbeModelForProvider_KimiCode(t *testing.T) {
	got := probeModelForProtocol("kimi_code")
	want := "kimi-k2.5"
	if got != want {
		t.Errorf("probeModelForProtocol(\"kimi_code\") = %q, want %q (Kimi Code 用自家 model)",
			got, want)
	}
}

func TestProbeModelForProvider_Moonshot(t *testing.T) {
	got := probeModelForProtocol("moonshot")
	want := "moonshot-v1-8k"
	if got != want {
		t.Errorf("probeModelForProtocol(\"moonshot\") = %q, want %q (Moonshot 平台 model)",
			got, want)
	}
}

func TestProbeModelForProvider_KimiDeprecatedAlias(t *testing.T) {
	// 'kimi' deprecated alias 仍兼容老 vault 数据,与 kimi_code 同 model。
	got := probeModelForProtocol("kimi")
	want := "kimi-k2.5"
	if got != want {
		t.Errorf("probeModelForProtocol(\"kimi\") = %q, want %q", got, want)
	}
}

func TestProbeModelForProvider_DeepseekStillKeysOnProtocol(t *testing.T) {
	// 防退化:deepseek 仍然命中专用 case (deepseek-chat),不掉到 fallback。
	got := probeModelForProtocol("deepseek")
	want := "deepseek-chat"
	if got != want {
		t.Errorf("probeModelForProtocol(\"deepseek\") = %q, want %q", got, want)
	}
}

func TestProbeModelForProvider_UnknownFallsbackToGpt4o(t *testing.T) {
	// 未知 provider 仍 fallback gpt-4o-mini (大多数 OpenAI-compat gateway 都识别)。
	got := probeModelForProtocol("some-new-aggregator-i-havent-seen")
	want := "gpt-4o-mini"
	if got != want {
		t.Errorf("probeModelForProtocol unknown = %q, want fallback %q", got, want)
	}
}
