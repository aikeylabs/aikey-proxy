// filter_cache_session_scope_test.go — 合规缓存作用域接入跨 provider 会话表的围栏
// (2026-08-08 Q3,用户拍板)。
//
// 背景:cacheScope 原来只认 X-Claude-Code-Session-Id(Claude Code CLI 专有 header),
// 于是 kimi / codex / cursor / cline 等非 Claude 客户端全都降级到 metadata.user_id /
// vk / global 桶 —— 同一 VK 下的不同会话共用一个桶,"不能串"(INV-3)退化成租户级隔离。
// 修复:复用调用方 resolveSessionID()(sessionid fingerprint 表,单一真相源)的结果。
//
// 这里锁三件事:①anthropic 场景不回归;②kimi/openai 现在拿到会话级隔离(跨会话不串);
// ③会话来源在 body 里时,body 仍可被合规链完整重复消费(可重入)。
package proxy

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// kimiBody 构造一条会话 id 在 BODY 里(prompt_cache_key)的 kimi 请求体 —— 也就是修复前
// 拿不到会话作用域的那一类客户端。
func kimiBody(session, content string) string {
	return fmt.Sprintf(`{"model":"kimi-k2","prompt_cache_key":%q,"messages":[{"role":"user","content":%q}]}`,
		session, content)
}

// TestFilterCache_KimiBodySessionScopesAndIsolates:kimi(会话 id 在 body)两个不同会话
// 发【逐字相同】的内容,必须各自真扫、不互相命中(修复前两者都落 vk/global 同一个桶,
// 第二个会话会命中第一个会话的判定 —— 跨会话串)。同会话重发则命中缓存。
func TestFilterCache_KimiBodySessionScopesAndIsolates(t *testing.T) {
	hook := &contentAwareHook{maskFor: "secret"}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 50)

	send := func(session string) string {
		r := newReq(kimiBody(session, "my secret note"))
		// 生产同一条链:route 解析出的 (protocol, provider) 交给 sessionid fingerprint 表。
		sess := resolveSessionID(r, "openai_compatible", "kimi_code")
		if sess != session {
			t.Fatalf("前提失败:kimi body 会话未被解析出来,got %q want %q", sess, session)
		}
		p.applyInboundFilter(httptest.NewRecorder(), r, "kimi-k2", "team", "org1", "vk1", "seat1",
			sess, discardLogger())
		return readReqBody(t, r)
	}

	out1 := send("kimi-sess-A")
	if hook.called != 1 {
		t.Fatalf("会话A首发应真扫一次,got %d", hook.called)
	}
	if strings.Contains(out1, "secret") {
		t.Fatalf("会话A的敏感内容应被打码:%s", out1)
	}

	send("kimi-sess-A") // 同会话同内容 → 命中缓存
	if hook.called != 1 {
		t.Errorf("同会话同内容应命中缓存(不重扫),累计 called=%d want 1", hook.called)
	}

	out3 := send("kimi-sess-B") // 不同会话同内容 → 必须重扫(不能串)
	if hook.called != 2 {
		t.Errorf("跨会话串了!会话B复用了会话A的判定:累计 called=%d want 2 —— 修复前 kimi 会落同一个 vk 桶", hook.called)
	}
	if strings.Contains(out3, "secret") {
		t.Fatalf("会话B的敏感内容也必须被打码:%s", out3)
	}
}

// TestFilterCache_SessionScopeBeatsSharedVK:同一个 VK(共享池)下的两个会话,内容相同
// 也不共享判定。这是修复要解决的核心退化 —— 修复前非 Claude 客户端只有 vk 粒度。
func TestFilterCache_SessionScopeBeatsSharedVK(t *testing.T) {
	h := &contentAwareHook{maskFor: "zzz"} // 内容不含 zzz → allow 判定,同样会入缓存
	p := &Proxy{filterHook: h}
	p.SetFilterCacheEnabled(true, 50)

	send := func(sess string) {
		r := newReq(`{"messages":[{"role":"user","content":"same text under one vk"}]}`)
		p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org1", "shared-vk", "seat1",
			sess, discardLogger())
	}
	send("sess-1")
	send("sess-2")
	if h.called != 2 {
		t.Errorf("同一 VK 下两个会话必须各自扫:called=%d want 2(会话作用域优先于 vk)", h.called)
	}
	send("sess-1") // 回到会话1 → 命中它自己的桶
	if h.called != 2 {
		t.Errorf("会话1 重发应命中自己的缓存:called=%d want 2", h.called)
	}
}

// TestFilterCache_BodyReentrantAfterSessionExtraction:会话 id 在 body 里时,
// resolveSessionID 会读一次 body(sessionid.parseBodyJSON);它必须把 body 复原,
// 否则紧随其后的合规过滤链读到空 body → 整条请求静默不过滤(fail-open 漏检)。
// 这条围栏按生产顺序(先 resolveSessionID 再 applyInboundFilter)断言:
// ①合规链仍看到全部内容并打码;②转发出去的 body 仍是完整合法 JSON、非会话字段无损。
func TestFilterCache_BodyReentrantAfterSessionExtraction(t *testing.T) {
	h := &contentAwareHook{maskFor: "secret"}
	p := &Proxy{filterHook: h}
	p.SetFilterCacheEnabled(true, 50)

	body := `{"model":"kimi-k2","prompt_cache_key":"reentrant-sess","temperature":0.7,` +
		`"messages":[{"role":"user","content":"first secret line"},{"role":"user","content":"second plain line"}]}`
	r := newReq(body)

	sess := resolveSessionID(r, "openai_compatible", "kimi_code") // 读 body 的那一步
	if sess != "reentrant-sess" {
		t.Fatalf("前提:会话应从 body 解析出来,got %q", sess)
	}
	if !p.applyInboundFilter(httptest.NewRecorder(), r, "kimi-k2", "team", "org1", "vk1", "seat1",
		sess, discardLogger()) {
		t.Fatal("mask 判定不应拦截请求")
	}
	if h.called != 2 {
		t.Fatalf("body 未复原 → 合规链没看到内容!扫描片段数 called=%d want 2(两条 user 消息)", h.called)
	}
	out := readReqBody(t, r)
	if strings.Contains(out, "first secret line") {
		t.Errorf("敏感内容未打码(body 可能被会话提取截断):%s", out)
	}
	if !strings.Contains(out, "[MASKED]") || !strings.Contains(out, "second plain line") {
		t.Errorf("转发 body 内容不完整:%s", out)
	}
	// 非会话字段必须无损透传(证明只是重放了同一份字节,没有丢字段)。
	for _, must := range []string{`"temperature":0.7`, `"prompt_cache_key":"reentrant-sess"`, `"model":"kimi-k2"`} {
		if !strings.Contains(out, must) {
			t.Errorf("转发 body 丢了字段 %s:%s", must, out)
		}
	}
}

// TestFilterCache_BodyReentrantWhenSessionExtractionSkipped:body 超过 sessionid 的
// body_max_bytes(64KB)时 parseBodyJSON 直接放弃解析 —— 那条路径也必须原样保留 body,
// 否则大 prompt 请求会整条不过滤。断言:会话取不到(落 vk 桶)但内容仍被扫描 + 打码。
func TestFilterCache_BodyReentrantWhenSessionExtractionSkipped(t *testing.T) {
	h := &contentAwareHook{maskFor: "secret"}
	p := &Proxy{filterHook: h}
	p.SetFilterCacheEnabled(true, 50)

	filler := strings.Repeat("padding text ", 6000) // > 64KB,超过 body_max_bytes
	body := fmt.Sprintf(`{"model":"kimi-k2","prompt_cache_key":"too-big-sess","messages":[`+
		`{"role":"user","content":%q},{"role":"user","content":"tail secret piece"}]}`, filler)
	r := newReq(body)
	if len(body) <= 65536 {
		t.Fatalf("前提:body 需超过 sessionid body_max_bytes(65536),实际 %d", len(body))
	}

	sess := resolveSessionID(r, "openai_compatible", "kimi_code")
	if sess != "" {
		t.Fatalf("前提:超限 body 应放弃会话解析(返回空),got %q", sess)
	}
	if !p.applyInboundFilter(httptest.NewRecorder(), r, "kimi-k2", "team", "org1", "vk1", "seat1",
		sess, discardLogger()) {
		t.Fatal("不应拦截")
	}
	if h.called != 2 {
		t.Fatalf("超限 body 分支未复原 body → 合规链漏扫!called=%d want 2", h.called)
	}
	out := readReqBody(t, r)
	if strings.Contains(out, "tail secret piece") {
		t.Errorf("超限 body 里的敏感片段漏发:%s", out)
	}
	if !strings.Contains(out, "padding text") {
		t.Errorf("转发 body 丢了正文:%.120s", out)
	}
}
