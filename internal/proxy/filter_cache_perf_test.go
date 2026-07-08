package proxy

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// TestFilterCache_PerfDetectCallReduction 量化缓存对 "detector 真扫次数"(=最贵的那部分,
// 每条 ~1–200ms)的削减。模拟 Claude Code / OpenClaw 的真实行为:**每轮 +1 条新 user
// 消息、历史全量重发**。用真实 applyInboundFilter + 真实缓存 + 计数 hook,对比
// 无缓存 / window=5 / window=50。
//
// 关键观测点(run -v 看表):window < 单请求消息数 时,LRU 顺序扫描会 thrash —— working-set
// 超过容量且顺序访问是 LRU 的经典退化,命中率掉到接近 0、几乎每轮全量重扫。这决定了
// window 默认值能不能撑住长对话。
func TestFilterCache_PerfDetectCallReduction(t *testing.T) {
	// measure 返回跑完 turns 轮对话后 detector 被真正调用的累计次数(越少越好)。
	measure := func(turns, window int, cacheOn bool) int {
		hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}
		p := &Proxy{filterHook: hook}
		if cacheOn {
			p.SetFilterCacheEnabled(true, window)
		}
		for turn := 1; turn <= turns; turn++ {
			parts := make([]string, 0, turn)
			for i := 1; i <= turn; i++ {
				parts = append(parts, fmt.Sprintf(`{"role":"user","content":"user message number %d"}`, i))
			}
			r := newReq(`{"messages":[` + strings.Join(parts, ",") + `]}`)
			r.Header.Set("X-Claude-Code-Session-Id", "perf-sess") // 固定 session → 命中同一桶
			p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", discardLogger())
		}
		return hook.called
	}

	t.Logf("增长型对话(每轮 +1 新消息、历史全量重发)累计 detector 真扫次数(越少越好):")
	t.Logf("%-6s | %-8s | %-22s | %-22s", "轮数", "无缓存", "window=5", "window=50")
	for _, turns := range []int{5, 10, 20, 50} {
		noCache := measure(turns, 0, false)
		w5 := measure(turns, 5, true)
		w50 := measure(turns, 50, true)
		save := func(v int) float64 { return 100 * float64(noCache-v) / float64(noCache) }
		t.Logf("%-6d | %-8d | %-5d (省 %3.0f%%)        | %-5d (省 %3.0f%%)",
			turns, noCache, w5, save(w5), w50, save(w50))
	}

	// 断言 thrash 的存在(防止以后有人"优化"掉这个观测):window=5 在 20 轮对话下,
	// 真扫次数应该远高于"理想的每条扫一次"(=20),证明 window<历史长度时缓存基本失效。
	idealOncePerMsg := 20
	w5at20 := measure(20, 5, true)
	if w5at20 <= idealOncePerMsg*2 {
		t.Errorf("预期 window=5 在 20 轮下 thrash(真扫 >> %d),实测 %d —— 若此断言失败说明淘汰行为变了,复核",
			idealOncePerMsg, w5at20)
	}
	// 对照:window 足够大(50)时应接近理想(每条扫一次 = 20)。
	if w50at20 := measure(20, 50, true); w50at20 != idealOncePerMsg {
		t.Errorf("预期 window=50 在 20 轮下每条只扫一次=%d,实测 %d", idealOncePerMsg, w50at20)
	}
}

// TestFilterCache_LoopCoversAllNotJustTail 锁住"循环必须覆盖请求里全部 user 消息",
// 不能限制成"只循环最后 N 条"(用户 2026-06-16 提议"循环20次")。否则靠前的历史消息
// 不被处理 → 保持客户端原文 → 裸发漏检(= 本次修的那个 bug)。构造 30 条对话、敏感词
// 在第 1 条(远超任何"最后 20 条"的尾窗),断言它仍被 mask。
func TestFilterCache_LoopCoversAllNotJustTail(t *testing.T) {
	hook := &contentAwareHook{maskFor: "SECRET"} // 命中即整段替换成 [MASKED]
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 128)

	parts := []string{`{"role":"user","content":"SECRET-at-the-very-first-turn"}`}
	for i := 2; i <= 30; i++ {
		parts = append(parts, fmt.Sprintf(`{"role":"user","content":"benign message %d"}`, i))
	}
	r := newReq(`{"messages":[` + strings.Join(parts, ",") + `]}`)
	r.Header.Set("X-Claude-Code-Session-Id", "loop-cover-sess")
	p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", discardLogger())

	body := readReqBody(t, r)
	if strings.Contains(body, "SECRET-at-the-very-first-turn") {
		t.Error("第1条(远在'最后20条'之外)敏感词裸发 —— 循环必须覆盖全部 user 消息,不能限制尾部 N 条")
	}
	if !strings.Contains(body, "[MASKED]") {
		t.Error("第1条敏感消息应被打码(证明循环处理到了它,而非只处理尾部)")
	}
}

// BenchmarkFilterCache_FullStorageWarmTurn 测量"全量存(window≥消息数)+ 循环全部消息"
// 在缓存全命中下处理一轮 50 条历史的开销 —— 证明"循环全部"并不贵(老消息都是 µs 级缓存
// 命中、不碰 detector),从而说明"只循环末尾 5 条"省不下什么,却会让其余 45 条不打码漏发。
func BenchmarkFilterCache_FullStorageWarmTurn(b *testing.B) {
	const msgs = 50
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 64) // 全量存:window ≥ 消息数 → 全命中、无 thrash

	parts := make([]string, msgs)
	for i := 0; i < msgs; i++ {
		parts[i] = fmt.Sprintf(`{"role":"user","content":"user message number %d"}`, i)
	}
	body := `{"messages":[` + strings.Join(parts, ",") + `]}`

	warm := newReq(body)
	warm.Header.Set("X-Claude-Code-Session-Id", "bench-sess")
	p.applyInboundFilter(httptest.NewRecorder(), warm, "m", "personal", "", "", "", "", discardLogger())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := newReq(body)
		r.Header.Set("X-Claude-Code-Session-Id", "bench-sess")
		p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", discardLogger())
	}
}
