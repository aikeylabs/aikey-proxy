// filter_audit_unit_identity_test.go — 审计单元身份必须由内容派生,不得寄生在缓存上
// (2026-09-08,用户拍板)。
//
// 守的规则:R-compliance-filter-scope-2「审计单元 = "一个会话内的一段违规内容",
// 不是"每个请求"」(workflow/CI/requirements/2026-06-04-compliance-filter-direction-and-scope.md)。
//
// 这一组围栏补的是 2026-08-08 那三条(filter_cache_audit_replay_test.go)漏掉的另一半:
// 它们全部断言**缓存命中**路径,而重复审计行恰恰只在**缓存未命中**时产生。
//
//	命中 → 回放缓存里的同一条事件 → 同一 id → 下游 ON CONFLICT 吸收  ← 老围栏守这条
//	未命中 → detector 真扫 → CSPRNG 铸新 id → 下游吸收不了 → 多一行  ← 没人守,就是本次的 BUG
//
// 所以下面每个用例的 stub 都**模拟真实 detector 的行为:每次被调用都换一个新 event_id**。
// 只有这样,"id 稳定"才是被 proxy 的派生逻辑保证的,而不是被 stub 的常量假装出来的。
//
// 能红方式:删掉 filter_dispatch.go 里的 `ev = injectEventID(ev, auditUnitID(...))` 一行,
// 本文件 4 个用例全红(实测记录见 bugfix 文档「能红实证」段)。
package proxy

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// cspringHook 模拟真实 detector:每次 Detect 都铸一个新的随机 event_id
// (ai-compliance-detector/cmd/detector/main.go 的 newEventID 是 CSPRNG)。
// 这正是"重扫产生重复审计行"的源头,围栏必须把它复现出来才有意义。
type csprngHook struct {
	called int
}

func (h *csprngHook) Name() string { return "csprng-stub" }
func (h *csprngHook) Status() *apphook.Status {
	return &apphook.Status{Healthy: true, Version: "stub-v1"}
}
func (h *csprngHook) Close() error { return nil }
func (h *csprngHook) Detect(ctx context.Context, req *apphook.Request) *apphook.Response {
	h.called++
	return &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte("[X]"),
		// 每轮不同的 id —— 与生产 detector 行为一致。
		Event: []byte(fmt.Sprintf(
			`{"event_id":"detector-random-%d","tenant_id":"","action_taken":"mask"}`, h.called)),
	}
}

// auditProxy 造一台装了合规 hook + 真 Reporter 的 proxy,团队路由指向假 master。
func auditProxy(t *testing.T, hook apphook.Hook, cacheOn bool) (*Proxy, <-chan []map[string]any) {
	t.Helper()
	srv, sink := complianceSink(t)
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(cacheOn, 50)
	p.SetReporter(teamReporter(t, srv.URL), "inst-1", "v-test", "cfg-1", 0, "")
	return p, sink
}

func auditSendTurn(t *testing.T, p *Proxy, sessionID, content string) {
	t.Helper()
	r := newReq(fmt.Sprintf(`{"messages":[{"role":"user","content":%q}]}`, content))
	p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org-9", "vk-7", "seat-3",
		sessionID, "", discardLogger())
}

func auditEventIDOf(t *testing.T, evs []map[string]any) string {
	t.Helper()
	if len(evs) != 1 {
		t.Fatalf("期望恰好 1 条审计事件,got %d", len(evs))
	}
	id, _ := evs[0]["event_id"].(string)
	if id == "" {
		t.Fatalf("审计事件没有 event_id:%v", evs[0])
	}
	return id
}

// TestAuditUnit_RescanAfterCacheLossKeepsSameID —— 本次修复的核心断言。
//
// 场景 = 生产里最常见的那条:proxy/detector 重启、规则包热切、LRU 淘汰、1h TTL 到期,
// 任意一条都会让缓存整体失效;客户端下一轮照常把整段历史重发,于是**同一段违规内容
// 被第二次真扫**。修复前 detector 铸新 id → 下游 ON CONFLICT 认不出来 → 审计里多一行
// 对应同一个违规,长对话里放大成几十上百行(2026-08-08 明确否决过的形态)。
func TestAuditUnit_RescanAfterCacheLossKeepsSameID(t *testing.T) {
	hook := &csprngHook{}
	p, sink := auditProxy(t, hook, true)

	auditSendTurn(t, p, "sess-42", "violating content")
	firstID := auditEventIDOf(t, waitEvents(t, sink, "第1轮(真扫)"))

	// 模拟缓存失效:重启 / 淘汰 / TTL / pack 热切 / SUSPEND —— 对本断言等价。
	p.SetFilterCacheEnabled(true, 50)

	auditSendTurn(t, p, "sess-42", "violating content")
	secondID := auditEventIDOf(t, waitEvents(t, sink, "第2轮(缓存失效后重扫)"))

	if hook.called != 2 {
		t.Fatalf("前提不成立:第2轮应该是真扫(缓存已失效),got called=%d", hook.called)
	}
	if !strings.HasPrefix(firstID, "au_") {
		t.Errorf("审计事件 id 不是 proxy 派生的审计单元 id(%q)—— detector 的 CSPRNG id 漏了出去", firstID)
	}
	if firstID != secondID {
		t.Errorf("同一会话内的同一段内容重扫后换了审计单元 id:\n  第1轮 %s\n  第2轮 %s\n"+
			"→ 下游按 event_id 幂等,id 一变就是审计里多一行,违反 R-compliance-filter-scope-2"+
			"「审计单元 = 一个会话内的一段违规内容」", firstID, secondID)
	}
}

// TestAuditUnit_StableWhenVerdictCacheDisabled —— 缓存**根本没开**时同样成立。
//
// WHY 单列一条:修复的整个要点就是"审计正确性不能寄生在缓存上"。缓存被 fail-safe
// SUSPEND(detector 说不清自己的规则集)时每片都真扫,恰恰是最容易产生重复行的状态。
// 如果内容身份仍然只在 cache != nil 分支里算,这条必红。
func TestAuditUnit_StableWhenVerdictCacheDisabled(t *testing.T) {
	hook := &csprngHook{}
	p, sink := auditProxy(t, hook, false) // cache == nil

	auditSendTurn(t, p, "sess-42", "violating content")
	firstID := auditEventIDOf(t, waitEvents(t, sink, "第1轮(无缓存)"))
	auditSendTurn(t, p, "sess-42", "violating content")
	secondID := auditEventIDOf(t, waitEvents(t, sink, "第2轮(无缓存)"))

	if hook.called != 2 {
		t.Fatalf("前提不成立:关掉缓存后每轮都该真扫,got called=%d", hook.called)
	}
	if firstID != secondID {
		t.Errorf("缓存关闭时审计单元 id 不稳定(%s vs %s)—— 说明内容身份仍然只在缓存分支里算,"+
			"审计正确性依旧寄生在缓存上", firstID, secondID)
	}
}

// TestAuditUnit_DifferentSessionsGetDifferentIDs —— 去重不能跨会话吞掉。
//
// 规则原文是「一个会话**内**的一段违规内容」:两个人(或同一个人的两个会话)各自说了
// 同一句违规内容,那是两个审计单元、两行记录。派生 id 里带会话作用域就是为了这个;
// 如果只按内容派生,第二个会话的违规会被静默吞掉 —— 那是漏记,比重复更严重。
func TestAuditUnit_DifferentSessionsGetDifferentIDs(t *testing.T) {
	hook := &csprngHook{}
	p, sink := auditProxy(t, hook, true)

	auditSendTurn(t, p, "sess-A", "violating content")
	idA := auditEventIDOf(t, waitEvents(t, sink, "会话 A"))
	auditSendTurn(t, p, "sess-B", "violating content")
	idB := auditEventIDOf(t, waitEvents(t, sink, "会话 B"))

	if idA == idB {
		t.Errorf("两个会话的同一段内容拿到了同一个审计单元 id(%s)—— 下游会把第二个会话的"+
			"违规当重复吞掉,变成漏记", idA)
	}
}

// TestAuditUnit_UnchangedByRulesetEpoch —— 管理员改规则包不得让历史重记一遍。
//
// 用户拍板 2026-09-08:派生 id **不含** contentVersion。含了的话,管理员编辑一次规则包
// 就会让所有活跃会话的全部历史违规重新落一遍账 —— 那是同一个洪水换了个触发器。
// 判定本身变没变由事件自带的 detector/content 版本字段承载,不靠多记一行。
//
// 🔴 这条必须走**生产链路**驱动真实的 epoch 变化,不能只对 auditUnitID 做纯函数断言。
// 初版就是那么写的(断签名 + 断不同内容不同 id),实测**假绿**:把 contentVer 用一个包级
// 变量折进派生(最自然的真实写法,不改签名),那版测试照样绿。围栏要按「概念有几个出口」写,
// 不是按「我刚改了哪几行」写。
func TestAuditUnit_UnchangedByRulesetEpoch(t *testing.T) {
	hook := &epochHook{csprngHook: csprngHook{}, epoch: "pack-epoch-v1"}
	p, sink := auditProxy(t, hook, true)

	auditSendTurn(t, p, "sess-42", "violating content")
	firstID := auditEventIDOf(t, waitEvents(t, sink, "第1轮(pack v1)"))

	// 管理员在控制台编辑规则包 → detector 原地热切 ruleset → epoch 变。
	// cacheKey 含 contentVer,所以缓存条目立刻不可达 → 下一轮必然真扫。
	hook.epoch = "pack-epoch-v2"

	auditSendTurn(t, p, "sess-42", "violating content")
	secondID := auditEventIDOf(t, waitEvents(t, sink, "第2轮(pack v2)"))

	if hook.called != 2 {
		t.Fatalf("前提不成立:epoch 变化后该条目应失效、第2轮必须真扫,got called=%d", hook.called)
	}
	if firstID != secondID {
		t.Errorf("规则集版本变化让审计单元换了 id:\n  v1 %s\n  v2 %s\n"+
			"→ 管理员编辑一次规则包,所有活跃会话的全部历史违规会重新落一遍账。"+
			"这是同一个洪水换了个触发器,正是 2026-09-08 拍板要避免的。"+
			"判定变没变由事件自带的 detector/content 版本字段承载,不靠多记一行。", firstID, secondID)
	}
}

// epochHook 在 csprngHook 之上实现 apphook.ContentVersioned,让用例能驱动
// "管理员热切规则包"这件事(epoch 变 → cacheKey 变 → 缓存条目不可达 → 真扫)。
type epochHook struct {
	csprngHook
	epoch string
}

func (h *epochHook) ContentVersion() (string, bool) { return h.epoch, true }
