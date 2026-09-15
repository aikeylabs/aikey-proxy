// filter_cache_confirmed_test.go — 证据门裁决 `confirmed` 必须走完 proxy 这一跳
// （wire 透传 + 判定缓存回放），且绝不被 `confidence` 顶替。
//
// 需求包: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合 (task 2.13)
// spec: R-compliance-grading-16.S4 高分但上下文未确认的命中不计入累计
//
// 背景（读这段就够）：`confirmed` 是证据门（允许名单 / 值校验 / 熵 / 正负上下文）给出的
// **裁决**，由探测器 internal/compliance/actionpolicy 产出、写进上报事件的 findings[]。
// proxy 不重算它、也不该读懂它 —— proxy 的职责只有两件：
//
//	① 盖章（inject* 家族以 map[string]json.RawMessage 改写）时不吞掉这个键；
//	② 判定缓存命中回放时，该值与首次真扫一致。
//
// 一旦某一跳把它掉队成零值，下游看到的就是「未确认」，而 R-compliance-grading-16 正是
// 用它决定哪些命中能参与累计升级 —— 掉队 = 静默削弱升级判定，且不会有任何报错。
// 「手工搬运的中转层会静默吞字段」: workflow/CI/experience/wire-contract.md
//
// 🔴 这条围栏守的是 **proxy 这一跳**，不是探测器的序列化。探测器侧 `confirmed` 是否真的
// 上了 wire 由 ai-compliance-detector cmd/detector TestConfirmedReachesIntakeWire 守；
// 整链（经真实 intake 入口落库）由 aikey-control-master
// internal/compliance TestIntakeEvents_ConfirmedRoundTrips 守。三条缺一不可。
package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// findingsOf 取出一条上报事件的 findings 原始 JSON（不解码进结构体）——
// 键**在不在**和键的**值是多少**是两个不同的断言：`Confirmed bool` 的零值也是 false，
// 只断言值会让「字段整个掉了」和「字段是 false」看起来一模一样。
func findingsOf(t *testing.T, ev map[string]any) []map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(ev["findings"])
	if err != nil {
		t.Fatalf("findings 不可序列化: %v", err)
	}
	var out []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("findings 不是对象数组: %v (%s)", err, raw)
	}
	return out
}

func TestConfirmedSurvivesWireAndCache(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		// 主场景：高分（confidence 98）但证据门判否。分值高不等于裁决为真。
		{name: "high_confidence_but_unconfirmed", want: false},
		// 边界另一侧：true 也必须原样到达，否则「保守方向」会变成永远不升级。
		{name: "confirmed", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, sink := complianceSink(t)

			event, err := json.Marshal(map[string]any{
				"event_id":     "evt-confirmed-" + tc.name,
				"tenant_id":    "",
				"action_taken": "mask",
				"findings": []map[string]any{{
					"finding_id":   "f-1",
					"category":     "pii",
					"entity_type":  "CN_ID_CARD",
					"severity":     "high",
					"confidence":   98,
					"start_offset": 0,
					"end_offset":   18,
					"confirmed":    tc.want,
				}},
			})
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}

			hook := &stubHook{resp: &apphook.Response{
				Action:         apphook.ActionMask,
				MutatedPayload: []byte("[X]"),
				Event:          event,
			}}
			p := &Proxy{filterHook: hook}
			p.SetFilterCacheEnabled(true, 50)
			p.SetReporter(teamReporter(t, srv.URL), "inst-1", "v-test", "cfg-1", 0, "")

			send := func() {
				r := newReq(`{"messages":[{"role":"user","content":"violating content"}]}`)
				p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org-9", "vk-7",
					"seat-3", "sess-42", "", discardLogger())
			}

			assertRound := func(round string, evs []map[string]any) {
				t.Helper()
				if len(evs) != 1 {
					t.Fatalf("%s: 应上报 1 条事件, got %d", round, len(evs))
				}
				fs := findingsOf(t, evs[0])
				if len(fs) != 1 {
					t.Fatalf("%s: 应有 1 条 finding, got %d", round, len(fs))
				}
				raw, present := fs[0]["confirmed"]
				if !present {
					t.Fatalf("%s: 上报事件的 finding 没有 confirmed 键 —— 证据门裁决在 proxy 这一跳掉队了"+
						"（下游只会看到零值 false，且不会报任何错）", round)
				}
				var got bool
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatalf("%s: confirmed 不是布尔值: %s", round, raw)
				}
				if got != tc.want {
					t.Fatalf("%s: confirmed=%v, want %v", round, got, tc.want)
				}
				// proxy 侧读视图（escalation.go 的 Finding）必须读到同一个裁决，
				// 且不得把高分误当成已确认。
				var view []Finding
				fjson, _ := json.Marshal(evs[0]["findings"])
				if err := json.Unmarshal(fjson, &view); err != nil {
					t.Fatalf("%s: proxy 读视图解码失败: %v", round, err)
				}
				if view[0].Confirmed != tc.want {
					t.Fatalf("%s: proxy 读视图 Confirmed=%v, want %v", round, view[0].Confirmed, tc.want)
				}
			}

			// 第 1 轮：真扫（cache miss）。
			send()
			first := waitEvents(t, sink, "第1轮(cache miss)")
			if hook.called != 1 {
				t.Fatalf("前提:第1轮应真扫一次, got called=%d", hook.called)
			}
			assertRound("第1轮(真扫)", first)

			// 第 2 轮：同内容 → 命中判定缓存，detector 不再被调用。
			send()
			second := waitEvents(t, sink, "第2轮(cache hit)")
			if hook.called != 1 {
				t.Fatalf("前提:第2轮应命中缓存、不再调 detector, got called=%d", hook.called)
			}
			assertRound("第2轮(缓存回放)", second)
		})
	}

	// 缺席也是一个合法的 wire 状态（2026-09-13 契约订正：`*bool` + omitempty +
	// 能力探针门）。老探测器、或探针关闭的新探测器，都不发这个键；proxy 绝不能
	// 替它造一个出来——凭空补 `confirmed:false` 会把「没人说过」伪装成「证据门判否」，
	// 而 master 对这两者的落库值虽然相同，审计追溯时的含义并不相同。
	t.Run("absent_stays_absent", func(t *testing.T) {
		srv, sink := complianceSink(t)
		hook := &stubHook{resp: &apphook.Response{
			Action:         apphook.ActionMask,
			MutatedPayload: []byte("[X]"),
			Event: []byte(`{"event_id":"evt-no-confirmed","tenant_id":"","action_taken":"mask",` +
				`"findings":[{"finding_id":"f-1","category":"pii","entity_type":"CN_ID_CARD",` +
				`"severity":"high","confidence":98,"start_offset":0,"end_offset":18}]}`),
		}}
		p := &Proxy{filterHook: hook}
		p.SetFilterCacheEnabled(true, 50)
		p.SetReporter(teamReporter(t, srv.URL), "inst-1", "v-test", "cfg-1", 0, "")
		for _, round := range []string{"第1轮(真扫)", "第2轮(缓存回放)"} {
			r := newReq(`{"messages":[{"role":"user","content":"violating content"}]}`)
			p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org-9", "vk-7",
				"seat-3", "sess-42", "", discardLogger())
			evs := waitEvents(t, sink, round)
			if _, present := findingsOf(t, evs[0])[0]["confirmed"]; present {
				t.Fatalf("%s: proxy 凭空补出了 confirmed 键 —— 探测器没发过它", round)
			}
		}
		if hook.called != 1 {
			t.Fatalf("前提:第2轮应命中缓存, got called=%d", hook.called)
		}
	})
}
