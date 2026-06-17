package proxy

import (
	"strings"
	"testing"
)

// TestHistoryLeakFix_FullScanCoversHistory 是 2026-06-16 "历史漏扫"修复的围栏测试。
//
// 根因(lobster 远程 debug 实证):增量扫描 extractLatestUserContent 只取最新一条
// user turn,跳过历史。用户先说含敏感词的话、再追问不含的 → 敏感词进了历史,而
// 增量扫描不再扫它 → 原文每轮透传给模型。
//
// 修复:applyInboundFilter 改用 extractFilterableContent(全量,覆盖 system +
// 全部 messages[].content)。本测试断言:全量抽取能把历史里的敏感词作为 piece
// 提取出来(会被送去 detector 扫),而旧的增量抽取会漏掉它(留作对照)。
func TestHistoryLeakFix_UserScanCoversHistorySkipsAssistantSystem(t *testing.T) {
	// system 含敏感S(admin);历史 user 含敏感A;assistant(返回内容)含敏感B;最新 user。
	body := []byte(`{"model":"claude","system":"守则含敏感S","messages":[` +
		`{"role":"user","content":"敏感A 你认识他吗"},` + // 历史用户输入(漏点所在)
		`{"role":"assistant","content":"敏感B 我知道"},` + // 模型返回内容
		`{"role":"user","content":"他是谁"}` + // 最新 user
		`]}`)

	pieces, _, ok := extractUserContent(body)
	if !ok {
		t.Fatal("extractUserContent ok=false")
	}
	// 必须覆盖历史 USER 输入 + 最新 user(修历史漏扫)
	if !hfHasPiece(pieces, "敏感A") {
		t.Errorf("修复失效:漏了历史用户输入'敏感A';pieces=%v", hfTexts(pieces))
	}
	if !hfHasPiece(pieces, "他是谁") {
		t.Errorf("漏了最新 user '他是谁';pieces=%v", hfTexts(pieces))
	}
	// 不扫 assistant(返回内容)+ system(admin 指令)
	if hfHasPiece(pieces, "敏感B") {
		t.Error("不该扫 assistant 返回内容'敏感B'(入站合规不 mask 模型返回)")
	}
	if hfHasPiece(pieces, "敏感S") {
		t.Error("不该扫 system prompt'敏感S'(mask admin 指令会污染 agent)")
	}
	t.Logf("✅ user-only 抽取=%v(覆盖历史用户输入+最新;跳过 assistant 返回 + system)", hfTexts(pieces))
}

func hfHasPiece(ps []contentPiece, sub string) bool {
	for _, p := range ps {
		if strings.Contains(p.text, sub) {
			return true
		}
	}
	return false
}

func hfTexts(ps []contentPiece) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.text)
	}
	return out
}
