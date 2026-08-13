package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// filter_cache_block_test.go — 合规缓存安全修复回归套件(用户拍板 2026-08-08):
// block(ActionBlock)判定【不入缓存】,每次都必须按最新策略重新走 detector 判定。
//
// WHY(隐患溯源):缓存命中回放不调 detector;若 block 入缓存,则管理员放宽策略 / in-place
// pack swap(不 bump detectorVersion)后,陈旧 block 仍持续 403,且 sliding TTL 命中续期
// 近乎永久 —— 放宽后无法立即生效。block 走拒绝路径不转发上游,缓存省下的一次 detector
// 调用收益可忽略,ROI 为负。mask/warn/allow 保持缓存不变(它们转发上游、复用收益实在)。
// 关联:filter_dispatch.go 写侧(Put 前排除 ActionBlock)+ 读侧(Get 后排除 ActionBlock)。

// contentAwareBlockHook blocks any piece whose payload contains blockFor, else
// allows. Lets a test drive the block path with DIFFERENT content per turn
// (edit-retry) while counting real detector calls.
type contentAwareBlockHook struct {
	blockFor string
	called   int
}

func (h *contentAwareBlockHook) Name() string { return "content-aware-block" }
func (h *contentAwareBlockHook) Detect(_ context.Context, req *apphook.Request) *apphook.Response {
	h.called++
	if strings.Contains(string(req.Payload), h.blockFor) {
		return &apphook.Response{Action: apphook.ActionBlock, Reason: "high-risk content blocked"}
	}
	return &apphook.Response{Action: apphook.ActionAllow}
}
func (h *contentAwareBlockHook) Status() *apphook.Status { return &apphook.Status{Healthy: true} }

// 核心断言:原样重试 + block —— 内容逐字不变、第一次 block 403,第二次【同内容】请求
// detector 被再次调用(called=2),而不是缓存直接 403。这是本次修复的断言核心:block
// 判定不入缓存 → 每轮按最新策略重判。
func TestFilterCache_BlockNotCached_SameContentRescans(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionBlock, Reason: "leak"}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	const body = `{"messages":[{"role":"user","content":"leak-me"}]}`

	// 第1次:block → 403、不放行。
	w1 := httptest.NewRecorder()
	if proceed := p.applyInboundFilter(w1, newReq(body), "m", "personal", "", "", "", "", "", discardLogger()); proceed {
		t.Fatal("turn1: block 必须不放行(proceed=false)")
	}
	if w1.Code != http.StatusForbidden {
		t.Fatalf("turn1: 期望 403, got %d", w1.Code)
	}
	if hook.called != 1 {
		t.Fatalf("turn1: detector 应被调用 1 次, got %d", hook.called)
	}

	// 第2次:同内容 → 必须再次走 detector(不是缓存直接 403)。
	w2 := httptest.NewRecorder()
	if proceed := p.applyInboundFilter(w2, newReq(body), "m", "personal", "", "", "", "", "", discardLogger()); proceed {
		t.Fatal("turn2: block 仍必须不放行")
	}
	if w2.Code != http.StatusForbidden {
		t.Fatalf("turn2: 期望 403, got %d", w2.Code)
	}
	if hook.called != 2 {
		t.Errorf("核心断言失败:block 被缓存了 —— 第2次同内容 detector 未被重新调用(called=%d, want 2)。"+
			"若为 1 说明命中缓存直接 403,放宽策略后无法立即生效", hook.called)
	}
}

// block 判定后,缓存里【没有】该 verdict —— 直接查缓存状态证明(不是靠第二次 miss 间接推断)。
// scope/key 复算方式与 dispatch 完全一致:scope=global(无 header/uid/vk)、detectorVer=""
// (stubHook.Status().Version 为空)、hash=head 的 sha256。
func TestFilterCache_BlockLeavesNoCacheEntry(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionBlock, Reason: "leak"}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	const content = "leak-me"
	p.applyInboundFilter(httptest.NewRecorder(),
		newReq(`{"messages":[{"role":"user","content":"`+content+`"}]}`),
		"m", "personal", "", "", "", "", "", discardLogger())

	smc, ok := p.filterCache.(*sessionMaskCache)
	if !ok {
		t.Fatalf("filterCache 应是 *sessionMaskCache, got %T", p.filterCache)
	}
	// dispatch 里 detectorVer = hook.Status().Version(此处空串),ckey = ver|hash(head)。
	key := cacheKey(hook.Status().Version, hashHead(content))
	if v, hit := smc.Get("global", key); hit {
		t.Errorf("block 判定不应写入缓存,但查到条目:action=%d", v.action)
	}
}

// 读侧守卫:即便缓存里【残留】了历史 block verdict(手工 Put 模拟进程内 pre-fix 污染 /
// 写侧未来回归),读取时也必须当作 miss、落到真扫重判,而不是回放陈旧拒绝。
func TestFilterCache_ReadSideSkipsPollutedBlock(t *testing.T) {
	// detector 现在对同内容返回 Allow(模拟管理员已放宽策略)。
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	const content = "was-blocked-now-allowed"
	// 手工把一条陈旧 block verdict 塞进缓存(scope/key 与 dispatch 复算一致)。
	smc := p.filterCache.(*sessionMaskCache)
	key := cacheKey(hook.Status().Version, hashHead(content))
	smc.Put("global", key, maskVerdict{action: apphook.ActionBlock, reason: "stale block"})

	// 同内容请求:读侧守卫应跳过陈旧 block → 真扫 → 按最新策略 Allow 放行。
	w := httptest.NewRecorder()
	proceed := p.applyInboundFilter(w, newReq(`{"messages":[{"role":"user","content":"`+content+`"}]}`),
		"m", "personal", "", "", "", "", "", discardLogger())
	if !proceed {
		t.Fatal("读侧守卫失败:陈旧 block verdict 被回放,请求被 403(应重判为 Allow 放行)")
	}
	if hook.called != 1 {
		t.Errorf("读侧守卫失败:陈旧 block 命中缓存直接返回,detector 未被重判调用(called=%d, want 1)", hook.called)
	}
}

// 编辑重试 + mask:内容改了 → hash 变 → 不命中 → detector 再调用。证明 hash 键天然区分编辑,
// 与 block 修复无关但锁住"缓存不会把改过的内容误当历史复用"。
func TestFilterCache_EditedContentMask_Rescans(t *testing.T) {
	hook := &contentAwareHook{maskFor: "secret"} // 含 secret 即打码
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	p.applyInboundFilter(httptest.NewRecorder(),
		newReq(`{"messages":[{"role":"user","content":"secret-A"}]}`),
		"m", "personal", "", "", "", "", "", discardLogger())
	if hook.called != 1 {
		t.Fatalf("turn1: called %d, want 1", hook.called)
	}
	// 编辑内容(仍含 secret,仍会 mask,但 hash 变)→ 不命中 → 重扫。
	p.applyInboundFilter(httptest.NewRecorder(),
		newReq(`{"messages":[{"role":"user","content":"secret-B"}]}`),
		"m", "personal", "", "", "", "", "", discardLogger())
	if hook.called != 2 {
		t.Errorf("编辑后 hash 变应重扫:called %d, want 2", hook.called)
	}
}

// 编辑重试 + block:内容改了 → 不命中 → 重判(本就不命中,确认 block 编辑路径每次真扫、每次 403)。
func TestFilterCache_EditedContentBlock_Rescans(t *testing.T) {
	hook := &contentAwareBlockHook{blockFor: "leak"}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	w1 := httptest.NewRecorder()
	p.applyInboundFilter(w1, newReq(`{"messages":[{"role":"user","content":"leak-A"}]}`),
		"m", "personal", "", "", "", "", "", discardLogger())
	if w1.Code != http.StatusForbidden || hook.called != 1 {
		t.Fatalf("turn1: code=%d called=%d, want 403 & 1", w1.Code, hook.called)
	}
	w2 := httptest.NewRecorder()
	p.applyInboundFilter(w2, newReq(`{"messages":[{"role":"user","content":"leak-B"}]}`),
		"m", "personal", "", "", "", "", "", discardLogger())
	if w2.Code != http.StatusForbidden || hook.called != 2 {
		t.Errorf("turn2: 编辑后仍 block 且重扫:code=%d called=%d, want 403 & 2", w2.Code, hook.called)
	}
}

// 回归:warn 判定仍被缓存(非 block action 缓存行为逐字不变)。第二次同内容命中缓存、
// detector 不再调用。防止本次 block 修复误伤 warn/mask/allow 的缓存复用。
func TestFilterCache_WarnStillCached(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionWarn, Reason: "soft"}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	const body = `{"messages":[{"role":"user","content":"borderline"}]}`
	for i := 0; i < 2; i++ {
		p.applyInboundFilter(httptest.NewRecorder(), newReq(body), "m", "personal", "", "", "", "", "", discardLogger())
	}
	if hook.called != 1 {
		t.Errorf("回归:warn 应仍被缓存,第2次应命中:called %d, want 1(block 修复不得误伤 warn)", hook.called)
	}
}
