// filter_cache_audit_replay_test.go — 缓存命中时团队合规审计事件必须仍然上报的围栏
// (2026-08-08 Q4,用户拍板)。
//
// 背景:内容哈希缓存命中时不再调 detector,而 maskVerdict 原来没存 Response.Event,
// 于是命中轮次的 teamEvents 为空 —— 同一段被判违规的历史只在"首次真扫"那一轮产生审计
// 事件,后续轮次静默。首轮上报失败(网络抖动 / reporter 未配)= 该违规永久无审计记录,
// 且没有任何重试路径。
//
// 定案:缓存 Event 字节、命中时原样重放。重放安全的依据是 detector 铸的 event_id 不变,
// 两条入库路径都按 event_id 幂等(control-master storage.IngestBatch 的
// ON CONFLICT (event_id) DO NOTHING;local user-local ingest 同样)。所以重放是"对失败
// 上报的幂等对账",不是对成功上报的重复计数 —— 也因此不需要新增 replayed/cached wire 字段。
//
// 这里按生产链路(真 events.Reporter → httptest 服务端)断言,不 mock 上报路径。
package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
)

// complianceSink 起一个假的 master 合规入口,把每次 POST 收到的 events 数组推进 channel。
func complianceSink(t *testing.T) (*httptest.Server, <-chan []map[string]any) {
	t.Helper()
	got := make(chan []map[string]any, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env struct {
			Events []map[string]any `json:"events"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Errorf("上报 body 不是合法 JSON envelope: %v (%s)", err, body)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		got <- env.Events
		_ = json.NewEncoder(w).Encode(map[string][]string{"accepted_ids": {}})
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

// teamReporter 造一个真 Reporter,团队路由指向假 master。
func teamReporter(t *testing.T, url string) *events.Reporter {
	t.Helper()
	rep, err := events.NewReporter(&events.ReporterConfig{
		CollectorRoutes:           map[string]string{"team": url},
		CollectorRouteCredentials: map[string]events.Credential{"team": &events.StaticTokenCredential{Token: "team-jwt"}},
		WALDir:                    t.TempDir(), // 隔离:不要写到用户 ~/.aikey
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	t.Cleanup(func() { _ = rep.Close() })
	return rep
}

func waitEvents(t *testing.T, ch <-chan []map[string]any, what string) []map[string]any {
	t.Helper()
	select {
	case evs := <-ch:
		return evs
	case <-time.After(5 * time.Second):
		t.Fatalf("%s:没有收到合规事件上报(审计漏记)", what)
		return nil
	}
}

// TestFilterCache_TeamEventReplayedOnCacheHit 是 Q4 的核心断言:
// 同一段违规内容在第二轮命中缓存(detector 不再被调用)时,团队审计事件仍然上报,
// 且携带 detector 原始 event_id(幂等重放 → 下游按 event_id 去重,不会重复计数),
// 以及 proxy 盖的权威归因字段(tenant/vk/seat/session)。
func TestFilterCache_TeamEventReplayedOnCacheHit(t *testing.T) {
	srv, sink := complianceSink(t)

	hook := &stubHook{resp: &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte("[X]"),
		// detector 铸的事件:event_id 一次生成,重放时原样带出去。
		Event: []byte(`{"event_id":"evt-fixed-1","tenant_id":"","action_taken":"mask","user_id":"detector-uid"}`),
	}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 50)
	p.SetReporter(teamReporter(t, srv.URL), "inst-1", "v-test", "cfg-1", 0, "")

	send := func() {
		r := newReq(`{"messages":[{"role":"user","content":"violating content"}]}`)
		p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org-9", "vk-7", "seat-3",
			"sess-42", "", discardLogger())
	}

	// 第1轮:真扫(miss)→ 上报。
	send()
	first := waitEvents(t, sink, "第1轮(cache miss)")
	if len(first) != 1 {
		t.Fatalf("第1轮应上报 1 条事件,got %d", len(first))
	}
	if hook.called != 1 {
		t.Fatalf("第1轮应真扫一次,got %d", hook.called)
	}

	// 第2轮:同内容 → 命中缓存(detector 不调用),事件仍必须上报。
	send()
	second := waitEvents(t, sink, "第2轮(cache hit)")
	if hook.called != 1 {
		t.Fatalf("前提:第2轮应命中缓存、不再调 detector,got called=%d", hook.called)
	}
	if len(second) != 1 {
		t.Fatalf("缓存命中轮次的审计事件缺失(Q4 漏记):got %d 条", len(second))
	}

	ev := second[0]
	// 幂等依据:重放的是同一个 event_id,下游 ON CONFLICT (event_id) DO NOTHING 吸收重复。
	if ev["event_id"] != "evt-fixed-1" {
		t.Errorf("重放事件的 event_id 变了(%v)—— 下游按 event_id 去重,伪造新 id 会导致同一违规重复计数", ev["event_id"])
	}
	if ev["event_id"] != first[0]["event_id"] {
		t.Errorf("两轮 event_id 不一致:%v vs %v", first[0]["event_id"], ev["event_id"])
	}
	// proxy 盖的权威归因字段在重放路径同样生效(注入发生在 Event 取出之后,与是否命中无关)。
	for k, want := range map[string]string{
		"tenant_id":      "org-9",
		"virtual_key_id": "vk-7",
		"seat_id":        "seat-3",
		"session_id":     "sess-42",
	} {
		if ev[k] != want {
			t.Errorf("重放事件 %s = %v, want %s(归因字段必须与首轮一致)", k, ev[k], want)
		}
	}
	if ev["action_taken"] != "mask" || ev["user_id"] != "detector-uid" {
		t.Errorf("重放事件的 detector 原始字段被改动了:%v", ev)
	}
}

// TestFilterCache_CachedEventNotUploadedOnPersonalRoute:个人路由永不上报团队事件,
// 即使缓存里存着一条(同一会话先后走团队/个人路由的混合场景)。routeClass 守卫必须
// 优先于缓存重放 —— 否则个人用量会把事件发到团队 master。
func TestFilterCache_CachedEventNotUploadedOnPersonalRoute(t *testing.T) {
	srv, sink := complianceSink(t)

	hook := &stubHook{resp: &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte("[X]"),
		Event:          []byte(`{"event_id":"evt-personal-guard","action_taken":"mask"}`),
	}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 50)
	p.SetReporter(teamReporter(t, srv.URL), "inst-1", "v-test", "cfg-1", 0, "")

	body := `{"messages":[{"role":"user","content":"violating content"}]}`
	// 先用团队路由把带事件的判定写进缓存(同一会话 scope)。
	r1 := newReq(body)
	p.applyInboundFilter(httptest.NewRecorder(), r1, "m", "team", "org-9", "vk-7", "seat-3", "sess-mix", "", discardLogger())
	waitEvents(t, sink, "团队路由首轮")

	// 同会话同内容改走个人路由 → 命中缓存(含 event),但绝不能上报。
	r2 := newReq(body)
	p.applyInboundFilter(httptest.NewRecorder(), r2, "m", "personal", "", "", "", "sess-mix", "", discardLogger())
	select {
	case evs := <-sink:
		t.Fatalf("个人路由上报了团队事件(routeClass 守卫失效):%v", evs)
	case <-time.After(300 * time.Millisecond):
		// 期望:静默。
	}
}

// TestFilterCache_BlockEventStillUploadedNotCached:block 不入缓存(2026-08-08 前序修复)
// → 每轮都真扫、每轮都由真扫路径产生事件。这条同时防两个方向的回归:
// ①block 别被缓存(安全);②block 的审计事件别因为 Q4 改动而丢。
func TestFilterCache_BlockEventStillUploadedNotCached(t *testing.T) {
	srv, sink := complianceSink(t)

	hook := &stubHook{resp: &apphook.Response{
		Action: apphook.ActionBlock,
		Reason: "policy",
		Event:  []byte(`{"event_id":"evt-block-1","action_taken":"block"}`),
	}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 50)
	p.SetReporter(teamReporter(t, srv.URL), "inst-1", "v-test", "cfg-1", 0, "")

	body := `{"messages":[{"role":"user","content":"blocked content"}]}`
	for turn := 1; turn <= 2; turn++ {
		r := newReq(body)
		if proceed := p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org-9", "vk-7", "seat-3",
			"sess-blk", "", discardLogger()); proceed {
			t.Fatalf("第%d轮 block 必须拦截", turn)
		}
		evs := waitEvents(t, sink, fmt.Sprintf("block 第%d轮", turn))
		if len(evs) != 1 || evs[0]["action_taken"] != "block" {
			t.Fatalf("第%d轮 block 审计事件缺失/错误:%v", turn, evs)
		}
	}
	if hook.called != 2 {
		t.Errorf("block 不得入缓存:两轮应各真扫一次,got called=%d", hook.called)
	}
}
