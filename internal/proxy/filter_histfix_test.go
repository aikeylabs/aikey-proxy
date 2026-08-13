package proxy

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHistoryLeakFix_FullScanCoversHistory 是 2026-06-16 "历史漏扫"修复的围栏测试。
//
// 根因(lobster 远程 debug 实证):增量扫描 extractLatestUserContent 只取最新一条
// user turn,跳过历史。用户先说含敏感词的话、再追问不含的 → 敏感词进了历史,而
// 增量扫描不再扫它 → 原文每轮透传给模型。
//
// 修复:applyInboundFilter 改用 extractUserContent(覆盖全部会话角色消息)。本测试
// 断言:抽取能把历史里的敏感词作为 piece 提取出来(会被送去 detector 扫)。
//
// 2026-08-08 P4(占位符还原方案 §3.4)修订:assistant 从"必须跳过"改为"默认必须扫"。
// 原因是响应侧还原把原文交回客户端,下一轮该原文以 assistant 身份重发 —— 跳过它
// 等于 mask 只在首轮有效(方案 §2.2)。system 仍必须跳过(mask admin 指令会污染 agent)。
func TestHistoryLeakFix_ScanCoversHistoryAndAssistantSkipsSystem(t *testing.T) {
	// system 含敏感S(admin);历史 user 含敏感A;assistant(上轮还原后的原文)含敏感B;最新 user。
	body := []byte(`{"model":"claude","system":"守则含敏感S","messages":[` +
		`{"role":"user","content":"敏感A 你认识他吗"},` + // 历史用户输入(2026-06-16 漏点)
		`{"role":"assistant","content":"敏感B 我知道"},` + // 上轮还原后的原文(2026-08-08 漏点)
		`{"role":"user","content":"他是谁"}` + // 最新 user
		`]}`)

	pieces, _, ok := extractUserContent(body, nil) // nil = 默认策略 {user, assistant}
	if !ok {
		t.Fatal("extractUserContent ok=false")
	}
	// 必须覆盖历史 USER 输入 + 最新 user(修 2026-06-16 历史漏扫)
	if !hfHasPiece(pieces, "敏感A") {
		t.Errorf("修复失效:漏了历史用户输入'敏感A';pieces=%v", hfTexts(pieces))
	}
	if !hfHasPiece(pieces, "他是谁") {
		t.Errorf("漏了最新 user '他是谁';pieces=%v", hfTexts(pieces))
	}
	// 必须覆盖 assistant 历史(修 2026-08-08 还原泄漏)
	if !hfHasPiece(pieces, "敏感B") {
		t.Errorf("修复失效:漏了 assistant 历史'敏感B' —— 还原后的原文会从这里明文回上游;pieces=%v", hfTexts(pieces))
	}
	// system(admin 指令)仍然不扫
	if hfHasPiece(pieces, "敏感S") {
		t.Error("不该扫 system prompt'敏感S'(mask admin 指令会污染 agent)")
	}
	t.Logf("✅ 抽取=%v(覆盖历史 user + assistant + 最新;跳过 system)", hfTexts(pieces))
}

// TestScanRolePolicy_SkipSetAndFailSafe 锁住角色策略的三条语义:
//  1. 策略内的已知角色 → 扫;
//  2. 策略外的已知角色 → 跳(system 必须在这一档);
//  3. 未知/缺失角色 → **一律扫**(fail-safe,绝不静默漏扫真实输入)。
//
// 第 3 条是把"跳过列表"翻成"允许列表"时最容易丢的性质:如果实现成纯 allow-list,
// 一个我们没见过的客户端角色(如 "human")会被静默跳过 → 漏扫。
func TestScanRolePolicy_SkipSetAndFailSafe(t *testing.T) {
	cases := []struct {
		roles scanRoleSet
		role  string
		want  bool
		why   string
	}{
		{nil, "user", true, "默认策略含 user"},
		{nil, "assistant", true, "默认策略含 assistant(P4)"},
		{nil, "system", false, "默认不扫 admin 指令"},
		{nil, "developer", false, "OpenAI 的 system 等价角色同样不扫"},
		{nil, "tool", false, "工具输出本期不扫(可配置放开)"},
		{nil, "function", false, "OpenAI legacy 工具输出同上"},
		{nil, "", true, "缺失角色 → fail-safe 扫"},
		{nil, "human", true, "未知角色 → fail-safe 扫(绝不静默漏扫)"},
		{nil, "ASSISTANT", true, "大小写归一"},
		{nil, "  user  ", true, "空白归一"},
		{scanRoleSet{"user": {}}, "assistant", false, "显式收窄后 assistant 不扫(能红用例依赖这一条)"},
		{scanRoleSet{"user": {}}, "human", true, "收窄不影响未知角色的 fail-safe"},
		{scanRoleSet{"user": {}, "assistant": {}, "tool": {}}, "tool", true, "可扩展到 tool"},
	}
	for _, c := range cases {
		if got := c.roles.scans(c.role); got != c.want {
			t.Errorf("scans(%q) with %v = %v, want %v —— %s", c.role, c.roles.list(), got, c.want, c.why)
		}
	}
}

// TestNewScanRoleSet_RejectsUnknownAndNeverScansNothing:配置解析必须
// (a) 归一化、(b) 报告非法项(不静默丢弃)、(c) 全非法时回落默认而不是"什么都不扫"。
func TestNewScanRoleSet_RejectsUnknownAndNeverScansNothing(t *testing.T) {
	set, rejected := newScanRoleSet([]string{" User ", "ASSISTANT", "tool"})
	if len(rejected) != 0 {
		t.Errorf("合法角色被拒:%v", rejected)
	}
	if got := set.list(); len(got) != 3 || got[0] != "assistant" || got[1] != "tool" || got[2] != "user" {
		t.Errorf("归一化结果=%v,want [assistant tool user]", got)
	}

	set, rejected = newScanRoleSet([]string{"user", "bogus"})
	if len(rejected) != 1 || rejected[0] != "bogus" {
		t.Errorf("非法角色必须被报告(供 WARN),got %v", rejected)
	}
	if got := set.list(); len(got) != 1 || got[0] != "user" {
		t.Errorf("合法项仍应生效,got %v", got)
	}

	// 全非法 → 回落默认(而不是空集=什么都不扫)。
	set, rejected = newScanRoleSet([]string{"bogus", " "})
	if len(rejected) != 1 {
		t.Errorf("want 1 rejected, got %v", rejected)
	}
	if set != nil {
		t.Errorf("全非法应回落默认(nil),got %v", set)
	}
	if !set.scans("assistant") {
		t.Error("回落后必须仍扫 assistant —— 配置写错绝不能把脱敏关掉")
	}
}

// TestRestoreLeakFix_AssistantHistoryMaskedOutbound 是 P4 的**能红**围栏(方案 §2.2)。
//
// 场景:第 1 轮用户发了地址 → 出站被打成 {{ADDR_1}} → 响应侧还原,用户/客户端历史里
// 存的是**原文**。第 2 轮客户端把整段历史重发,那条原文现在位于 **assistant** 消息里。
// 若 assistant 不在扫描角色集合中,它就明文回到上游 —— mask 只在首轮有效。
//
// 能红设计:同一条请求跑两遍。默认策略必须**不含**原文;把 assistant 从角色集合里
// 去掉后必须**含有**原文。第二个断言存在的意义是证明第一个断言测的是真实行为,
// 而不是一个恒真断言(比如 hook 恰好把什么都打码了)。
func TestRestoreLeakFix_AssistantHistoryMaskedOutbound(t *testing.T) {
	// 上一轮被还原回客户端的原文,这一轮以 assistant 身份重发。
	const restored = "北京市朝阳区建国路9001号"

	send := func(roles []string) string {
		p := &Proxy{filterHook: &contentAwareHook{maskFor: restored}}
		if roles != nil {
			p.SetFilterScanRoles(roles)
		}
		r := newReq(`{"messages":[` +
			`{"role":"user","content":"帮我改写这段话"},` +
			`{"role":"assistant","content":"好的,已记录 ` + restored + ` 这个地址"},` +
			`{"role":"user","content":"再短一点"}` +
			`]}`)
		r.Header.Set("X-Claude-Code-Session-Id", "restore-leak-fence")
		if !p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "",
			resolveSessionID(r, "anthropic", "anthropic"), "", discardLogger()) {
			t.Fatal("请求被 block,用例前提不成立")
		}
		return readReqBody(t, r)
	}

	// ① 默认策略(user+assistant):assistant 历史里的原文必须被脱敏后才出站。
	withAssistant := send(nil)
	if strings.Contains(withAssistant, restored) {
		t.Errorf("还原泄漏未修:assistant 历史里的原文明文出站了\n出站 body=%s", withAssistant)
	}
	if !strings.Contains(withAssistant, "[MASKED]") {
		t.Errorf("assistant 历史应被打码,出站 body=%s", withAssistant)
	}

	// ② 能红对照:把 assistant 从角色集合里去掉 → 泄漏必须重现。若这里不再泄漏,
	//    说明 ① 的绿是假绿(它并不是靠 assistant 扫描拿到的)。
	userOnly := send([]string{"user"})
	if !strings.Contains(userOnly, restored) {
		t.Fatalf("能红对照失效:去掉 assistant 角色后原文竟然仍被脱敏 —— ①的断言并未验证 assistant 扫描\n出站 body=%s", userOnly)
	}
	t.Logf("✅ 能红成立:roles=[user assistant] 原文被脱敏;roles=[user] 原文泄漏(%q 出现在出站 body)", restored)
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
