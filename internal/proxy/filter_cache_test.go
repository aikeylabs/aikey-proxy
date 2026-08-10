package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// TestFilterCache_HistoryReuse 是第二步缓存的核心断言:多轮对话里,历史中逐字未变
// 的消息命中缓存、不再重扫;只有新增消息才调 detector。证明缓存把全量扫的"每轮重扫
// 历史"降回 O(新增)。
func TestFilterCache_HistoryReuse(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	// 第1轮:messages=[A] → 扫 A
	r1 := newReq(`{"messages":[{"role":"user","content":"A"}]}`)
	p.applyInboundFilter(httptest.NewRecorder(), r1, "m", "personal", "", "", "", "", "", discardLogger())
	if hook.called != 1 {
		t.Fatalf("turn1: Detect called %d, want 1", hook.called)
	}

	// 第2轮:messages=[A(历史 user), x(assistant), B(user)] → A 命中缓存不重扫;
	// assistant x 首次出现要扫(P4 起 assistant 纳入扫描范围);新 user B 要扫。
	r2 := newReq(`{"messages":[{"role":"user","content":"A"},{"role":"assistant","content":"x"},{"role":"user","content":"B"}]}`)
	p.applyInboundFilter(httptest.NewRecorder(), r2, "m", "personal", "", "", "", "", "", discardLogger())
	if hook.called != 3 { // 1(A) + 1(assistant x, 首次) + 1(B);A 命中缓存
		t.Errorf("turn2: Detect 累计 %d, want 3(A 命中缓存;assistant x 与 B 首次各扫一次)", hook.called)
	}

	// 第3轮:再追加一条新 user C。此时 A 与 assistant x 都已在缓存里 → 只扫 C。
	// 这一步是 P4 性能论证的核心:assistant 历史跨轮逐字不变,只在**首次出现**付一次
	// detector 调用,之后与 user 历史同样是 O(1) 缓存命中 —— 增量是常数不是每轮翻倍。
	r3 := newReq(`{"messages":[{"role":"user","content":"A"},{"role":"assistant","content":"x"},{"role":"user","content":"B"},{"role":"assistant","content":"y"},{"role":"user","content":"C"}]}`)
	p.applyInboundFilter(httptest.NewRecorder(), r3, "m", "personal", "", "", "", "", "", discardLogger())
	if hook.called != 5 { // +1(assistant y 首次) +1(C 首次);A/x/B 全命中
		t.Errorf("turn3: Detect 累计 %d, want 5(A/x/B 命中缓存,只扫新增的 y 与 C)", hook.called)
	}
}

// 缓存关闭(filterCache nil)→ 同内容每次都扫(无状态全量扫,INV-6)。
func TestFilterCache_Disabled_AlwaysScans(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}
	p := &Proxy{filterHook: hook} // 不调 SetFilterCacheEnabled → 缓存关闭
	for i := 0; i < 2; i++ {
		r := newReq(`{"messages":[{"role":"user","content":"A"}]}`)
		p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", "", discardLogger())
	}
	if hook.called != 2 {
		t.Errorf("缓存关闭:Detect called %d, want 2(不应缓存)", hook.called)
	}
}

// 命中缓存时,已打码的判定被正确复用(第2次同内容仍 masked、且不重扫)。
func TestFilterCache_MaskVerdictReused(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionMask, MutatedPayload: []byte("[X]")}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	r1 := newReq(`{"messages":[{"role":"user","content":"secret"}]}`)
	p.applyInboundFilter(httptest.NewRecorder(), r1, "m", "personal", "", "", "", "", "", discardLogger())
	r2 := newReq(`{"messages":[{"role":"user","content":"secret"}]}`)
	p.applyInboundFilter(httptest.NewRecorder(), r2, "m", "personal", "", "", "", "", "", discardLogger())

	if hook.called != 1 {
		t.Errorf("Detect called %d, want 1(第2次应命中缓存)", hook.called)
	}
	if got := readReqBody(t, r2); !strings.Contains(got, "[X]") {
		t.Errorf("缓存命中后没有复用打码:%s", got)
	}
}

// degraded(超时/fail-open)判定绝不缓存,否则会把"没扫成"误记为 allow、下轮放行(INV-2)。
func TestFilterCache_DegradedNotCached(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow, Degraded: true}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)
	for i := 0; i < 2; i++ {
		r := newReq(`{"messages":[{"role":"user","content":"A"}]}`)
		p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", "", discardLogger())
	}
	if hook.called != 2 {
		t.Errorf("degraded 被缓存了?Detect called %d, want 2(degraded 不可缓存)", hook.called)
	}
}

// degraded(detector 超时/不可用 → fail-open)时:该请求【原文放行】—— 不拦截、不遮蔽、
// 不套用 MutatedPayload。锁住 fail-open 语义("宁可个别漏检也不卡业务"那一侧),也是
// token-cache 分析里"超时裸发原文"那条的守卫:未来误改成"degraded 就拦截"或"degraded 也
// 按 MutatedPayload 改写"都会被它挡住。
func TestFilterCache_DegradedForwardsOriginalUnmasked(t *testing.T) {
	const sensitive = "my key sk-secret-123 keep safe"
	// detector 没扫成(超时)→ fail-open allow;即便捎带了 MutatedPayload,degraded/allow
	// 路径也必须忽略它、放行原文。
	hook := &stubHook{resp: &apphook.Response{
		Action:         apphook.ActionAllow,
		Degraded:       true,
		MutatedPayload: []byte("[SHOULD-BE-IGNORED]"),
	}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	r := newReq(`{"messages":[{"role":"user","content":"` + sensitive + `"}]}`)
	proceed := p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", "", discardLogger())

	if !proceed {
		t.Fatal("degraded 必须放行(fail-open):不拦截用户请求")
	}
	body := readReqBody(t, r)
	if !strings.Contains(body, sensitive) {
		t.Errorf("degraded 必须原文放行(不遮蔽):内容被改写了 → %s", body)
	}
	if strings.Contains(body, "[SHOULD-BE-IGNORED]") {
		t.Errorf("degraded/allow 路径不该套用 MutatedPayload → %s", body)
	}
}

// LRU 容量淘汰 + TTL 过期(用注入时钟)。
func TestLRUMaskCache_TTLAndEviction(t *testing.T) {
	c := newLRUMaskCache(2, 10*time.Second)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	c.Put("k1", maskVerdict{action: apphook.ActionAllow})
	c.Put("k2", maskVerdict{action: apphook.ActionMask, maskedHead: "m"})
	if _, ok := c.Get("k1"); !ok { // Get 把 k1 提到 MRU
		t.Fatal("k1 应在")
	}
	c.Put("k3", maskVerdict{}) // 超容量 → 淘汰 LRU(此刻 k2 最久未用)
	if _, ok := c.Get("k2"); ok {
		t.Error("k2 应被 LRU 淘汰")
	}
	if _, ok := c.Get("k1"); !ok {
		t.Error("k1 应存活(刚被 Get 过,是 MRU)")
	}
	now = now.Add(11 * time.Second) // 越过 TTL
	if _, ok := c.Get("k1"); ok {
		t.Error("k1 应因 TTL 过期")
	}
}

// 滑动续期(用户 2026-06-17 对齐 Claude 5min prompt cache:命中即续期):窗口内每次 Get
// 刷新空闲计时 → 活跃条目永不过期;只有"停顿 > TTL"才过期。固定TTL(写入后即计时)会在此
// 失败 —— 这正是之前 257s 间隔 miss 的根因(60s 固定过期)。
func TestLRUMaskCache_SlidingRefreshesOnUse(t *testing.T) {
	c := newLRUMaskCache(4, 10*time.Second)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	c.Put("k", maskVerdict{action: apphook.ActionAllow})

	// 每 8s 访问一次(<10s TTL),连访 3 次跨 24s(远超 10s)→ 续期、始终存活。
	for i := 1; i <= 3; i++ {
		now = now.Add(8 * time.Second)
		if _, ok := c.Get("k"); !ok {
			t.Fatalf("第 %d 次访问(间隔 8s<10s TTL)应续期存活;固定 TTL 会在此 miss", i)
		}
	}
	// 停顿 11s(>TTL)→ 过期。
	now = now.Add(11 * time.Second)
	if _, ok := c.Get("k"); ok {
		t.Error("停顿 11s>10s TTL 应过期")
	}
}

// scope 优先级:已解析 sessionID > metadata.user_id > VK > global,且绝不返回空(防串桶)。
func TestCacheScope_Priority(t *testing.T) {
	withUID := map[string]any{"metadata": map[string]any{"user_id": "u1"}}

	if got := cacheScope("sess1", withUID, "vk1"); got != "s:sess1" {
		t.Errorf("session 应优先:got %s", got)
	}
	if got := cacheScope("", withUID, "vk1"); got != "u:u1" {
		t.Errorf("user_id 次之:got %s", got)
	}
	if got := cacheScope("", map[string]any{}, "vk1"); got != "vk:vk1" {
		t.Errorf("VK 兜底:got %s", got)
	}
	if got := cacheScope("", map[string]any{}, ""); got != "global" {
		t.Errorf("global 最后:got %s", got)
	}
}

// 2026-08-08 跨 provider 会话作用域:scope 的会话来源必须是 sessionid fingerprint 表
// (resolveSessionID),而不是"只认 X-Claude-Code-Session-Id"那条硬编码。逐 provider 断言
// 修复前会退化成同一个桶的那几类客户端现在各自拿到会话级 scope。
func TestCacheScope_CrossProviderSessionSources(t *testing.T) {
	// 修复前:只有这一行(anthropic + Claude 专有 header)能进会话桶。
	rClaude := httptest.NewRequest("POST", "/v1/messages", http.NoBody)
	rClaude.Header.Set("X-Claude-Code-Session-Id", "claude-sess")
	if got := cacheScope(resolveSessionID(rClaude, "anthropic", "anthropic"), nil, "vk1"); got != "s:claude-sess" {
		t.Errorf("anthropic header 场景应与修复前同作用域,got %s want s:claude-sess", got)
	}

	// 修复前:kimi 的会话在 body(prompt_cache_key),header 取不到 → 落 vk:/global 共桶。
	rKimi := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"kimi-k2","prompt_cache_key":"kimi-sess","messages":[]}`))
	if got := cacheScope(resolveSessionID(rKimi, "openai_compatible", "kimi_code"), nil, "vk1"); got != "s:kimi-sess" {
		t.Errorf("kimi body 会话字段应进会话桶(修复前是 vk1 共桶),got %s", got)
	}

	// 同理 openai 的 conversation_id。
	rOpenAI := httptest.NewRequest("POST", "/v1/responses",
		strings.NewReader(`{"model":"gpt-x","conversation_id":"oai-sess"}`))
	if got := cacheScope(resolveSessionID(rOpenAI, "openai", "openai"), nil, "vk1"); got != "s:oai-sess" {
		t.Errorf("openai conversation_id 应进会话桶,got %s", got)
	}

	// 通用约定 header(cursor / cline / 第三方 Agent 走 common_fallback)。
	rAgent := httptest.NewRequest("POST", "/v1/chat/completions", http.NoBody)
	rAgent.Header.Set("X-Aikey-Session-Id", "agent-sess")
	if got := cacheScope(resolveSessionID(rAgent, "openai_compatible", "some_new_provider"), nil, "vk1"); got != "s:agent-sess" {
		t.Errorf("X-Aikey-Session-Id 通用兜底应进会话桶,got %s", got)
	}

	// 取不到任何会话来源 → fallback 链行为不变(user_id → vk → global)。
	rNone := httptest.NewRequest("POST", "/v1/chat/completions", http.NoBody)
	empty := resolveSessionID(rNone, "openai_compatible", "zhipu")
	if empty != "" {
		t.Fatalf("前提:无任何会话来源时 resolveSessionID 应为空,got %q", empty)
	}
	if got := cacheScope(empty, map[string]any{"metadata": map[string]any{"user_id": "u9"}}, "vk1"); got != "u:u9" {
		t.Errorf("Extract 空 → fallback 链不变(user_id 优先于 vk),got %s", got)
	}
	if got := cacheScope(empty, nil, "vk1"); got != "vk:vk1" {
		t.Errorf("Extract 空 + 无 user_id → vk 兜底,got %s", got)
	}
}

// window 默认值(用户 2026-06-16 全量存决策:128,避免长对话 thrash):
// SetFilterCacheEnabled 传 0/负 → 回落默认。
func TestFilterCache_DefaultWindow(t *testing.T) {
	if defaultMaskCacheWindow != 1000 {
		t.Fatalf("默认 window 常量应为 1000(全量存,带上限), got %d", defaultMaskCacheWindow)
	}
	if defaultMaxSessions != 200 {
		t.Fatalf("默认 maxSessions 应为 200, got %d", defaultMaxSessions)
	}
	p := &Proxy{filterHook: &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}}
	p.SetFilterCacheEnabled(true, 0) // 0 → 回落默认
	smc, ok := p.filterCache.(*sessionMaskCache)
	if !ok {
		t.Fatalf("filterCache 应是 *sessionMaskCache, got %T", p.filterCache)
	}
	if smc.window != defaultMaskCacheWindow {
		t.Errorf("window=0 应回落默认 %d, got %d", defaultMaskCacheWindow, smc.window)
	}
}

// 同一请求里多条「逐字相同」的 user 消息(用户 2026-06-16 P3):靠前那条 miss→真扫→
// 回填,靠后那条命中复用;两条都各自按自己的位置写回打码(各有独立 setText 闭包,
// filter_content.go:159/178)。即「倒数第二 miss、倒数第一 hit,但两条都要被正确 mask」。
func TestFilterCache_DuplicateMessagesInOneRequest(t *testing.T) {
	hook := &contentAwareHook{maskFor: "secret"} // 命中即整段替换成 [MASKED]
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	// 两条逐字相同的敏感消息一起发
	r := newReq(`{"messages":[{"role":"user","content":"secret"},{"role":"user","content":"secret"}]}`)
	p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", "", "", "", discardLogger())

	body := readReqBody(t, r)
	if strings.Contains(body, "secret") {
		t.Errorf("重复消息有漏网:body 仍含原文 secret:%s", body)
	}
	if n := strings.Count(body, "[MASKED]"); n != 2 {
		t.Errorf("两条相同消息都应各自打码:[MASKED] 出现 %d 次, want 2", n)
	}
	if hook.called != 1 { // 靠前 miss 真扫一次;靠后命中复用,不再真扫
		t.Errorf("相同内容应只真扫一次:Detect called %d, want 1(靠前 miss、靠后 hit)", hook.called)
	}
}

// 两级有界缓存:per-session 窗口淘汰 + 跨会话隔离(不能串)+ session 级 LRU 整桶淘汰。
// 直接对应用户 2026-06-16 设计:KEY=sessionID、value=最近 N 条 hash、不同 session 不串。
func TestSessionMaskCache_WindowIsolationAndSessionLRU(t *testing.T) {
	mk := func(tag string) maskVerdict { return maskVerdict{action: apphook.ActionMask, maskedHead: tag} }

	// 1) per-session 窗口:window=2,同会话写 3 个 key → 最久未用的被淘汰。
	c := newSessionMaskCache(8, 2, time.Hour) // maxSessions=8, window=2
	c.Put("A", "k1", mk("v1"))
	c.Put("A", "k2", mk("v2"))
	if _, ok := c.Get("A", "k1"); !ok { // Get 把 k1 提为 MRU
		t.Fatal("A/k1 应在(窗口内)")
	}
	c.Put("A", "k3", mk("v3")) // 窗口=2 满 → 淘汰 LRU(此刻 k2 最久未用)
	if _, ok := c.Get("A", "k2"); ok {
		t.Error("A/k2 应被窗口淘汰(window=2)")
	}
	if _, ok := c.Get("A", "k1"); !ok {
		t.Error("A/k1 应存活(刚 Get 过=MRU)")
	}

	// 2) 跨会话隔离:B 用与 A 相同的 key 也读不到 A 的判定,且各写各的不互相覆盖。
	if _, ok := c.Get("B", "k1"); ok {
		t.Error("不能串:B 不应看到 A 的 k1")
	}
	c.Put("B", "k1", mk("B-v1"))
	if bv, ok := c.Get("B", "k1"); !ok || bv.maskedHead != "B-v1" {
		t.Errorf("B/k1 应是 B 自己的值:%+v ok=%v", bv, ok)
	}
	if av, _ := c.Get("A", "k1"); av.maskedHead != "v1" {
		t.Errorf("A/k1 不应被 B 覆盖:got %q(两桶应独立)", av.maskedHead)
	}

	// 3) session 级 LRU:maxSessions=2,写第 3 个 session → 最久未用的整桶淘汰。
	c2 := newSessionMaskCache(2, 5, time.Hour)
	c2.Put("S1", "x", mk("x"))
	c2.Put("S2", "x", mk("x"))
	if _, ok := c2.Get("S1", "x"); !ok { // S1 提为 MRU,S2 变 LRU
		t.Fatal("S1 应在")
	}
	c2.Put("S3", "x", mk("x")) // 超 maxSessions=2 → 淘汰 LRU session(S2)
	if _, ok := c2.Get("S2", "x"); ok {
		t.Error("S2 整桶应被 session 级 LRU 淘汰")
	}
	if _, ok := c2.Get("S1", "x"); !ok {
		t.Error("S1 应存活(刚 Get=MRU)")
	}
	if _, ok := c2.Get("S3", "x"); !ok {
		t.Error("S3 应在(刚写入)")
	}
}
