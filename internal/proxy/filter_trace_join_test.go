// filter_trace_join_test.go — 合规事件 ↔ 对话轮次关联键(trace_id)的围栏
// (2026-08-09 F1a,用户拍板方案 A)。
//
// # 背景:为什么需要这组围栏
//
// 审计页要给每轮内容加"眼睛"看被打码前的原文。原方案想用 compliance 事件的
// event_id 去 join conversation_records —— 这个前提是错的:
//
//   - compliance event_id 在 detector 子进程用它自己的 CSPRNG 生成(newEventID)
//   - conversation 轮次 event_id 是 proxy 的 W3C trace id
//
// 两个毫不相干的 id 空间,join 恒为空。审计页 2026-07-08 引入的 `?event=` 深链因此
// 从来没生效过 —— 它是照着一句写错的代码注释写的死代码。
//
// 定案:proxy 给 compliance 事件盖上本轮 trace_id,前端据此 join。这里的围栏钉死三件
// 事,任何一件退化都必须变红:
//
//	①同源  —— 盖给 compliance 的 trace_id,和 conversation observer 落库用的
//	          EventID,必须是同一个值。这是 join 成立的唯一前提。
//	②N:1  —— 一轮对话产生 N 条 compliance 事件(每命中一个 content piece 一条),
//	          它们必须共享同一个 trace_id;对话侧只有 1 条记录。
//	③兜底  —— 没有 observer context 时不许伪造 trace id(ExtractOrCreate 不幂等,
//	          伪造出来的 id join 不到任何东西,比空更糟),字段必须整个缺席。
//
// 全链路走生产代码:真 applyInboundFilter → 真 events.Reporter → httptest 假 master;
// 对话侧走真 conversation_audit.Observer。不 mock 上报路径。
package proxy

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observer/conversation_audit"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"
)

// traceJoinSink 收集 conversation_audit 落库的记录,用来断言 join 的另一半。
type traceJoinSink struct {
	recs []*conversation_audit.ConversationRecord
}

func (s *traceJoinSink) Submit(r *conversation_audit.ConversationRecord) { s.recs = append(s.recs, r) }

// TestTraceJoin_ComplianceEventAndConversationTurnShareTheKey 是 F1a 的核心断言:
// 同一次请求,compliance 事件盖的 trace_id 必须等于 conversation 记录的 EventID。
//
// 这个测试刻意把两条链路都跑真的:同一个 *observer.RequestContext 既喂给
// conversation_audit.Observer(它落 EventID),又通过 route.ObserverContext 喂给
// traceIDForAudit(它出 compliance 的 trace_id)。断言二者相等 = join 一定成立。
//
// 能红验证:把 filter_dispatch.go 里 injectTraceID 那一层去掉,或者让
// traceIDForAudit 返回新铸的 id,本用例立刻红。
func TestTraceJoin_ComplianceEventAndConversationTurnShareTheKey(t *testing.T) {
	const wantTrace = "4bf92f3577b34da6a3ce929d0e0e4736"

	srv, sink := complianceSink(t)

	// 一轮对话命中 1 个 piece → detector 返回 1 条事件。
	hook := &stubHook{resp: &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte("[MASKED]"),
		Event:          []byte(`{"event_id":"evt-detector-csprng","tenant_id":"","action_taken":"mask"}`),
	}}
	p := &Proxy{filterHook: hook}
	p.SetReporter(teamReporter(t, srv.URL), "inst-1", "v-test", "cfg-1", 0, "")

	// 生产链路里这一个 RequestContext 会同时被 NotifyStart 交给 conversation
	// observer、并挂到 route.ObserverContext 上 —— 这里如实复现这个"同一个指针"。
	obsReqCtx := &observer.RequestContext{
		ProtocolFamily: "anthropic",
		RequestBody:    []byte(`{"model":"claude-x","messages":[{"role":"user","content":"my secret is 4111111111111111"}]}`),
		TraceID:        wantTrace,
		OrgID:          "org-9",
		SeatID:         "seat-3",
		SessionID:      "sess-42",
		ProviderID:     "anthropic",
		StartedAt:      time.Unix(1_700_000_000, 0),
	}
	route := &vkeys.ResolvedRoute{ObserverContext: obsReqCtx}

	// ---- 链路 A:compliance 事件侧 ----
	traceID := traceIDForAudit(route)
	if traceID != wantTrace {
		t.Fatalf("traceIDForAudit 没有从 route.ObserverContext 取到本轮 trace id:got %q want %q", traceID, wantTrace)
	}
	r := newReq(`{"messages":[{"role":"user","content":"my secret is 4111111111111111"}]}`)
	p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org-9", "vk-7", "seat-3",
		"sess-42", traceID, discardLogger())

	evs := waitEvents(t, sink, "compliance 上报")
	if len(evs) != 1 {
		t.Fatalf("应上报 1 条合规事件,got %d", len(evs))
	}
	gotTrace, ok := evs[0]["trace_id"].(string)
	if !ok || gotTrace == "" {
		t.Fatalf("合规事件没有携带 trace_id(审计页无法 join 到原文轮次):%#v", evs[0])
	}

	// ---- 链路 B:对话轮次侧(真 observer) ----
	enabled := true
	cs := &traceJoinSink{}
	obs := conversation_audit.New(conversation_audit.Config{
		Sink:     cs,
		Enabled:  func() bool { return enabled },
		MaxBytes: func() int { return 0 },
	})
	obs.OnRequestStart(context.Background(), obsReqCtx)
	obs.OnSSEEvent(context.Background(), obsReqCtx, "content_block_delta",
		[]byte(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"ok"}}`))
	obs.OnSSEEvent(context.Background(), obsReqCtx, "message_stop", []byte(`{"type":"message_stop"}`))
	obs.OnRequestEnd(context.Background(), obsReqCtx, 1234)

	if len(cs.recs) != 1 {
		t.Fatalf("一轮对话应落 1 条 conversation 记录,got %d", len(cs.recs))
	}

	// ---- join 断言:两侧的键必须相等 ----
	if gotTrace != cs.recs[0].EventID {
		t.Fatalf("关联键不同源 → 审计页 join 不到原文:\n  compliance.trace_id        = %q\n  conversation_records.event_id = %q",
			gotTrace, cs.recs[0].EventID)
	}

	// 反向钉死那条被订正的错误注释:detector 铸的 event_id 恰恰 join 不到轮次。
	if evs[0]["event_id"] == cs.recs[0].EventID {
		t.Fatalf("compliance event_id 竟然等于 conversation event_id —— 若真如此说明 id 生成链路变了,本围栏的前提(以及 trace_id 的必要性)需要重新评估")
	}
}

// TestTraceJoin_AllEventsOfOneTurnShareOneTrace 钉死 N:1 基数。
//
// 一轮请求里有多段命中内容时,proxy 在 per-piece 循环里 append 多条事件;它们属于
// 同一轮对话,必须全部携带同一个 trace_id。否则前端按 trace_id 聚合时,同一轮会被拆成
// 多轮,或者部分事件失去原文入口。
func TestTraceJoin_AllEventsOfOneTurnShareOneTrace(t *testing.T) {
	const wantTrace = "0af7651916cd43dd8448eb211c80319c"

	srv, sink := complianceSink(t)
	hook := &stubHook{resp: &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte("[MASKED]"),
		Event:          []byte(`{"event_id":"evt-per-piece","tenant_id":"","action_taken":"mask"}`),
	}}
	p := &Proxy{filterHook: hook}
	p.SetReporter(teamReporter(t, srv.URL), "inst-1", "v-test", "cfg-1", 0, "")

	// 三段 user content → 三次 Detect → 三条事件,同一轮。
	body := `{"messages":[
		{"role":"user","content":"leak one 4111111111111111"},
		{"role":"user","content":"leak two 4222222222222222"},
		{"role":"user","content":"leak three 4333333333333333"}
	]}`
	p.applyInboundFilter(httptest.NewRecorder(), newReq(body), "m", "team", "org-9", "vk-7", "seat-3",
		"sess-42", wantTrace, discardLogger())

	evs := waitEvents(t, sink, "多段命中上报")
	if len(evs) < 2 {
		t.Fatalf("本用例需要一轮产生多条事件才能验证 N:1,got %d 条 —— 若 piece 提取规则变了请调整语料", len(evs))
	}
	for i, e := range evs {
		got, _ := e["trace_id"].(string)
		if got != wantTrace {
			t.Fatalf("第 %d 条事件的 trace_id=%q,与本轮 %q 不一致 → 同一轮被拆成多轮", i, got, wantTrace)
		}
	}
}

// TestTraceJoin_NoObserverContextStampsNothing 钉死兜底语义。
//
// 没有 observer context(没有任何 observer 激活)时也就没有 conversation 记录可 join。
// 此时必须让 trace_id 字段整个缺席,而不是塞一个新铸的 id:
// observability.ExtractOrCreate 不幂等,没有 traceparent 头就现铸一个随机 trace,
// 那样得到的键 join 不到任何行,却看起来像有效关联 —— 静默错误比空值危险得多。
//
// 这同时是 master 侧向后兼容的对侧保证:老 proxy 不发该字段,master 必须能收。
func TestTraceJoin_NoObserverContextStampsNothing(t *testing.T) {
	if got := traceIDForAudit(nil); got != "" {
		t.Fatalf("route=nil 时应返回空 trace,got %q", got)
	}
	if got := traceIDForAudit(&vkeys.ResolvedRoute{}); got != "" {
		t.Fatalf("ObserverContext=nil 时应返回空 trace,got %q", got)
	}
	// ObserverContext 存在但类型不对(vkeys 把它声明为 any)→ 同样不许猜。
	if got := traceIDForAudit(&vkeys.ResolvedRoute{ObserverContext: "not-a-request-context"}); got != "" {
		t.Fatalf("ObserverContext 类型不匹配时应返回空 trace,got %q", got)
	}

	srv, sink := complianceSink(t)
	hook := &stubHook{resp: &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte("[MASKED]"),
		Event:          []byte(`{"event_id":"evt-no-trace","tenant_id":"","action_taken":"mask"}`),
	}}
	p := &Proxy{filterHook: hook}
	p.SetReporter(teamReporter(t, srv.URL), "inst-1", "v-test", "cfg-1", 0, "")

	p.applyInboundFilter(httptest.NewRecorder(),
		newReq(`{"messages":[{"role":"user","content":"leak 4111111111111111"}]}`),
		"m", "team", "org-9", "vk-7", "seat-3", "sess-42", "", discardLogger())

	evs := waitEvents(t, sink, "无 trace 上报")
	if len(evs) != 1 {
		t.Fatalf("应上报 1 条事件,got %d", len(evs))
	}
	if _, present := evs[0]["trace_id"]; present {
		t.Fatalf("空 trace 不应写入字段(伪造的关联键 join 不到任何行):%#v", evs[0])
	}
}
