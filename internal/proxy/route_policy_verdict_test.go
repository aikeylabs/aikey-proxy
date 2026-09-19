package proxy

// route_policy_verdict_test.go — TODO-171 P 段:请求裁决行上的 `route_policy` 与
// `escalation.counted_is_lower_bound`(DEC-compliance-grading-27,用户 2026-09-18 拍板;
// 方案 roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/task-execution/runs/todo-171-design.md)。
//
// spec: R-compliance-grading-8.S1 (分级路由拒绝记入请求裁决行)
// spec: R-compliance-grading-17.S2 (16KB 截断 ⇒ 裁决行标注计数为下限)
// spec: R-compliance-grading-18 (一个请求至多一行裁决行,带证据 id)
//
// 守的六件事:
//
//	P-1 发送形状 —— 黄金报文与 aikey-control-master 同名文件字节相同;严格镜像能解
//	P-2 route_policy 拒绝生成裁决行 —— 团队路由进 master 批次,个人路由只进本机
//	P-3 两者共用一行 —— 同一 trace 恰好一行,同时带两个对象
//	P-4 截断标记 —— 截断时 true,对照组键缺席
//	P-5 结构性探针 —— 没有 grading 文档 ⇒ 零裁决行、零新键(老 master 不会收到新字段)
//	P-6 封顶也记账 —— MAX_ACTION=warn 放行时仍记一行 action_taken=warn
//
// 能红方式:删掉 payload 的 RoutePolicy ⇒ P-1/P-2 红;把裁决行生成放回
// `if esc.Rule != nil` 分支 ⇒ P-2/P-6 红;两处各建一行 ⇒ P-3 红;不传
// countIsLowerBound ⇒ P-4 红;让 route_policy 读默认规则 ⇒ P-5 红。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// ── P-1:发送形状 ───────────────────────────────────────────────────────────

// masterVerdictWireMirror hand-copies aikey-control-master's intakeEventWire
// subset a verdict row may use — INCLUDING the TODO-171 fields — as that repo
// declares them. It deliberately does NOT reuse this package's escalationWire /
// routePolicyWire: a mirror built from the sender's own types goes green on any
// key the sender adds, which is exactly the drift it exists to catch.
type masterVerdictWireMirror struct {
	EventID      string    `json:"event_id"`
	CreatedAt    time.Time `json:"created_at"`
	TenantID     string    `json:"tenant_id"`
	Scenario     string    `json:"scenario"`
	PromptLength int       `json:"prompt_length"`
	ActionTaken  string    `json:"action_taken"`
	VirtualKeyID string    `json:"virtual_key_id,omitempty"`
	SeatID       string    `json:"seat_id,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	TraceID      string    `json:"trace_id,omitempty"`
	Escalation   *struct {
		Rule                string   `json:"rule"`
		Counted             int      `json:"counted"`
		UnitIDs             []string `json:"unit_ids"`
		CountedIsLowerBound bool     `json:"counted_is_lower_bound,omitempty"`
	} `json:"escalation,omitempty"`
	RoutePolicy *struct {
		MinLevel       int      `json:"min_level"`
		TargetProvider string   `json:"target_provider,omitempty"`
		UnitIDs        []string `json:"unit_ids"`
	} `json:"route_policy,omitempty"`
	Findings []struct{} `json:"findings"`
}

func goldenVerdictInput() requestVerdict {
	return requestVerdict{
		TraceID:             requestVerdictGoldenTrace,
		TenantID:            "org-golden",
		VirtualKeyID:        "vk-golden",
		SeatID:              "seat-golden",
		SessionID:           "sess-golden",
		Action:              "block",
		Rule:                "min_level=4,min_count=3",
		Counted:             3,
		UnitIDs:             []string{"au_golden_1", "au_golden_2", "au_golden_3"},
		CountedIsLowerBound: true,
		RoutePolicy:         &routePolicyVerdict{MinLevel: 4, TargetProvider: "example-public-llm", UnitIDs: []string{"au_golden_1"}},
		Now:                 time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// TestRequestVerdictWire_GoldenPayloadEmitted pins the sender's bytes to the
// cross-repo golden file. 🔴 CROSS-REPO TWIN:
// aikey-control-master/service/internal/compliance/testdata/request_verdict_v2.golden.json
// must be byte-identical; master's TestRequestVerdictWire_GoldenPayloadAccepted
// asserts its strict decoder takes these bytes and reads them back.
func TestRequestVerdictWire_GoldenPayloadEmitted(t *testing.T) {
	golden, err := os.ReadFile("testdata/request_verdict_v2.golden.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	raw, err := buildRequestVerdictEvent(goldenVerdictInput())
	if err != nil {
		t.Fatalf("buildRequestVerdictEvent: %v", err)
	}
	if !bytes.Equal(raw, bytes.TrimSpace(golden)) {
		t.Fatalf("发送形状与跨仓黄金报文不一致 —— master 侧的严格解码器是按黄金报文验收的:\n got: %s\nwant: %s",
			raw, bytes.TrimSpace(golden))
	}
	// When the sibling repo is checked out next to this one, the two files must
	// be the same bytes (the twin is only a twin if nobody edits one side).
	sibling := "../../../aikey-control-master/service/internal/compliance/testdata/request_verdict_v2.golden.json"
	if other, err := os.ReadFile(sibling); err == nil && !bytes.Equal(other, golden) {
		t.Fatalf("两仓黄金报文字节不同:%s", sibling)
	}
}

// TestBuildRequestVerdictEvent_NewFieldsPassMasterStrictDecoder:master 的严格
// 解码器(DisallowUnknownFields)能解两个新字段;只带 route_policy 的行没有
// escalation 键(否则会被渲染成「触发了空规则、数了 0 条」)。
func TestBuildRequestVerdictEvent_NewFieldsPassMasterStrictDecoder(t *testing.T) {
	for name, v := range map[string]requestVerdict{
		"both": goldenVerdictInput(),
		"route_only": func() requestVerdict {
			v := goldenVerdictInput()
			v.Rule, v.Counted, v.UnitIDs, v.CountedIsLowerBound = "", 0, nil, false
			return v
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := buildRequestVerdictEvent(v)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			var got masterVerdictWireMirror
			if err := dec.Decode(&got); err != nil {
				t.Fatalf("master 严格解码器会整批 400:%v\n%s", err, raw)
			}
			if got.RoutePolicy == nil || got.RoutePolicy.MinLevel != 4 || got.RoutePolicy.TargetProvider != "example-public-llm" {
				t.Fatalf("route_policy 没上 wire:%s", raw)
			}
			if name == "route_only" && got.Escalation != nil {
				t.Fatalf("只违反路由策略的裁决行不应带 escalation 键:%s", raw)
			}
		})
	}
}

// ── P-2..P-6:filter 层 ─────────────────────────────────────────────────────

const rpIDCard = "110101199003074578"

// rpHook: one piece carrying a confirmed hit at `level`, per-piece verdict warn
// (the ladder lets it through), so any refusal is the request-level one.
func rpHook(t *testing.T, level int) *contentScriptedHook {
	return &contentScriptedHook{answer: func(payload string) *apphook.Response {
		if !strings.Contains(payload, rpIDCard) {
			return &apphook.Response{Action: apphook.ActionAllow}
		}
		return &apphook.Response{Action: apphook.ActionWarn,
			Event: eventJSON(t, "ev-rp", "warn", payload, []gradedHit{{rpIDCard, "pii", level, true}})}
	}}
}

func rpRequest(t *testing.T, target string) *http.Request {
	r := newReq(`{"messages":[{"role":"user","content":` + mustJSON(t, "customer id "+rpIDCard+" please summarize") + `}]}`)
	withRouteTarget(r, ProviderRef{Code: target})
	return r
}

func mustSetGradingDoc(t *testing.T, p *Proxy, doc string) {
	t.Helper()
	if _, rejected, err := p.SetComplianceGrading([]byte(doc)); err != nil || len(rejected) > 0 {
		t.Fatalf("SetComplianceGrading(%s): err=%v rejected=%v", doc, err, rejected)
	}
}

// verdictRows decodes the batch and returns every scenario=request_verdict event
// as a raw key map (so key PRESENCE is observable, not just zero values).
func verdictRows(t *testing.T, body []byte) []map[string]json.RawMessage {
	t.Helper()
	var env struct {
		Events []map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("not a compliance envelope: %v\n%s", err, body)
	}
	var out []map[string]json.RawMessage
	for _, e := range env.Events {
		if string(e["scenario"]) == `"`+scenarioRequestVerdict+`"` {
			out = append(out, e)
		}
	}
	return out
}

type rpDecoded struct {
	MinLevel       int      `json:"min_level"`
	TargetProvider *string  `json:"target_provider"`
	UnitIDs        []string `json:"unit_ids"`
}

func decodeRP(t *testing.T, raw json.RawMessage) rpDecoded {
	t.Helper()
	var rp rpDecoded
	if err := json.Unmarshal(raw, &rp); err != nil {
		t.Fatalf("route_policy: %v (%s)", err, raw)
	}
	return rp
}

const l4RoutePolicyDoc = `{"route_policy":[{"min_level":4,"allowed_providers":["intranet-*"],"otherwise":"block"}]}`

// TestRoutePolicy_DeniedRequestEmitsVerdictRow — P-2 / R-compliance-grading-8.S1。
//
// GIVEN route_policy=[{min_level:4, allowed_providers:["intranet-*"]}]
// WHEN  a confirmed L4 hit targets `anthropic`
// THEN  team route: the master batch holds exactly one rv_ row with
//
//	route_policy{4,"anthropic",[<the content row's event_id>]}, action block, no
//	escalation key;
//	personal route: the row goes to the local self-view only, the team sink
//	receives nothing (R-compliance-grading-24).
func TestRoutePolicy_DeniedRequestEmitsVerdictRow(t *testing.T) {
	t.Run("team", func(t *testing.T) {
		sinks := newRouteSinks(t)
		p := &Proxy{filterHook: rpHook(t, 4), reporter: sinks.rep}
		mustSetGradingDoc(t, p, l4RoutePolicyDoc)
		if p.applyInboundFilter(httptest.NewRecorder(), rpRequest(t, "anthropic"), "m", "team", "org-1", "vk-1", "seat-1", "sess-1", "trace-rp-team", discardLogger()) {
			t.Fatal("L4 to anthropic must be refused")
		}
		body := firstBatch(sinks.team, 3*time.Second)
		if body == nil {
			t.Fatal("master sink received nothing")
		}
		rows := verdictRows(t, body)
		if len(rows) != 1 {
			t.Fatalf("route_policy 拒绝应恰好产生一行请求裁决行,got %d:\n%s", len(rows), body)
		}
		v := rows[0]
		if string(v["event_id"]) != `"`+requestVerdictEventID("trace-rp-team")+`"` || string(v["action_taken"]) != `"block"` {
			t.Fatalf("裁决行 id/action 不对:%s", body)
		}
		if _, has := v["escalation"]; has {
			t.Fatalf("没触发累计的请求不应带 escalation 键:%s", body)
		}
		raw, ok := v["route_policy"]
		if !ok {
			t.Fatalf("裁决行没带 route_policy —— 合规官在审计页上查不到这次拦截:%s", body)
		}
		rp := decodeRP(t, raw)
		contents := contentRows(t, body)
		if len(contents) != 1 {
			t.Fatalf("content rows = %d, want 1", len(contents))
		}
		if rp.MinLevel != 4 || rp.TargetProvider == nil || *rp.TargetProvider != "anthropic" ||
			len(rp.UnitIDs) != 1 || rp.UnitIDs[0] != contents[0].EventID {
			t.Fatalf("route_policy = %s, want {4, anthropic, [%s]}", raw, contents[0].EventID)
		}
	})

	t.Run("personal", func(t *testing.T) {
		sinks := newRouteSinks(t)
		pc := personalPiece{"customer id " + rpIDCard + " please summarize", gradedHit{rpIDCard, "pii", 4, true}, apphook.ActionWarn}
		mint := &projectionMint{}
		p := &Proxy{filterHook: personalHook(t, []personalPiece{pc}, mint, true), reporter: sinks.rep}
		mustSetGradingDoc(t, p, l4RoutePolicyDoc)
		r := personalRequest(t, []personalPiece{pc})
		withRouteTarget(r, ProviderRef{Code: "anthropic"})
		if filterPersonal(p, httptest.NewRecorder(), r, "trace-rp-personal", discardLogger()) {
			t.Fatal("org route_policy follows the member onto the personal key (TODO-87 口径)")
		}
		body := firstBatch(sinks.local, 3*time.Second)
		if body == nil {
			t.Fatal("local self-view received no verdict row")
		}
		rows := verdictRows(t, body)
		if len(rows) != 1 {
			t.Fatalf("local verdict rows = %d, want 1: %s", len(rows), body)
		}
		rp := decodeRP(t, rows[0]["route_policy"])
		if rp.MinLevel != 4 || len(rp.UnitIDs) != 1 || rp.UnitIDs[0] == "" {
			t.Fatalf("personal route_policy = %s", rows[0]["route_policy"])
		}
		if team := batchesWithin(sinks.team, 300*time.Millisecond); len(team) != 0 {
			t.Fatalf("personal-route verdict reached master: %s", team[0])
		}
	})
}

// TestRoutePolicy_AndEscalationShareOneVerdictRow — P-3。一个 trace 只有一行
// (id 由 trace 派生,第二行会被 master ON CONFLICT DO NOTHING 静默吞掉)。
func TestRoutePolicy_AndEscalationShareOneVerdictRow(t *testing.T) {
	sinks := newRouteSinks(t)
	pieces := threeMembers()
	byText := map[string]gradedHit{}
	msgs := make([]string, 0, len(pieces))
	for _, pc := range pieces {
		byText[pc.text] = pc.hit
		msgs = append(msgs, `{"role":"user","content":`+mustJSON(t, pc.text)+`}`)
	}
	hook := &contentScriptedHook{answer: func(payload string) *apphook.Response {
		h, ok := byText[payload]
		if !ok {
			return &apphook.Response{Action: apphook.ActionAllow}
		}
		return &apphook.Response{Action: apphook.ActionWarn,
			Event: eventJSON(t, "ev-"+itoaInt64(int64(len(payload))), "warn", payload, []gradedHit{h})}
	}}
	p := &Proxy{filterHook: hook, reporter: sinks.rep}
	mustSetGradingDoc(t, p, `{"escalation":[{"min_level":4,"min_count":3,"action":"block"}],`+
		`"route_policy":[{"min_level":4,"allowed_providers":["intranet-*"],"otherwise":"block"}]}`)
	r := newReq(`{"messages":[` + strings.Join(msgs, ",") + `]}`)
	withRouteTarget(r, ProviderRef{Code: "anthropic"})
	if p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org-1", "vk-1", "seat-1", "sess-1", "trace-rp-both", discardLogger()) {
		t.Fatal("must be refused")
	}
	body := firstBatch(sinks.team, 3*time.Second)
	rows := verdictRows(t, body)
	if len(rows) != 1 {
		t.Fatalf("累计升级与路由策略同时触发时必须共用一行裁决行,got %d:\n%s", len(rows), body)
	}
	if _, ok := rows[0]["escalation"]; !ok {
		t.Fatalf("共用行缺 escalation:%s", body)
	}
	rp := decodeRP(t, rows[0]["route_policy"])
	if len(rp.UnitIDs) != 3 {
		t.Fatalf("三段都含 confirmed L4 命中,route_policy.unit_ids 应为 3 条:%v", rp.UnitIDs)
	}
	if string(rows[0]["action_taken"]) != `"block"` {
		t.Fatalf("action_taken = %s, want block", rows[0]["action_taken"])
	}
}

// TestEscalation_TruncatedVerdictRowMarksLowerBound — P-4 / R-compliance-grading-17.S2。
// 复用 TODO-72 的 16KB 夹具。
func TestEscalation_TruncatedVerdictRowMarksLowerBound(t *testing.T) {
	cases := []struct {
		name      string
		piece     string
		wantLower bool
	}{
		{"truncated", overCapPiece([]string{truncIDA, truncIDB, truncIDC}, nil), true},
		{"untruncated control", "客户 " + truncIDA + "；" + truncIDB + "；" + truncIDC, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sinks := newRouteSinks(t)
			p := &Proxy{filterHook: idScanningHook(t), reporter: sinks.rep}
			mustSetGrading(t, p, []EscalationRule{{MinLevel: 4, MinCount: 3, Action: "block"}})
			body := `{"messages":[{"role":"user","content":` + mustJSON(t, tc.piece) + `}]}`
			if p.applyInboundFilter(httptest.NewRecorder(), newReq(body), "m", "team", "org-1", "vk-1", "seat-1", "sess-1", "trace-trunc-row", discardLogger()) {
				t.Fatal("must escalate")
			}
			batch := firstBatch(sinks.team, 3*time.Second)
			rows := verdictRows(t, batch)
			if len(rows) != 1 {
				t.Fatalf("verdict rows = %d", len(rows))
			}
			esc := string(rows[0]["escalation"])
			has := strings.Contains(esc, `"counted_is_lower_bound":true`)
			if has != tc.wantLower {
				t.Fatalf("counted_is_lower_bound present=%v want %v: %s", has, tc.wantLower, esc)
			}
			if !tc.wantLower && strings.Contains(esc, "counted_is_lower_bound") {
				t.Fatalf("对照组不应出现 counted_is_lower_bound 键(false 会被读成「计数完整」):%s", esc)
			}
		})
	}
}

// TestRoutePolicy_NoGradingDocumentEmitsNoNewKeys — P-5,结构性探针。
//
// 新字段只可能出现在「master 已下发 grading」的请求上:route_policy / escalation
// 规则只来自 grading 文档,而 grading 文档只在策略响应里有 `grading` 键时才有。
// 所以老 master(无 grading 键)永远收不到新字段 —— 这是版本错配的核心论据,
// 零 wire 字段协商。
func TestRoutePolicy_NoGradingDocumentEmitsNoNewKeys(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, p *Proxy)
	}{
		{"never installed", func(*testing.T, *Proxy) {}},
		// The supervisor hands the proxy gradingPolicyAbsent ("") when the policy
		// response has no `grading` key (an older master). Rules installed by an
		// earlier generation must not survive it.
		{"absent document replaces rules", func(t *testing.T, p *Proxy) {
			mustSetGradingDoc(t, p, `{"escalation":[{"min_level":4,"min_count":1,"action":"block"}],`+
				`"route_policy":[{"min_level":4,"allowed_providers":["intranet-*"],"otherwise":"block"}]}`)
			if _, _, err := p.SetComplianceGrading([]byte("")); err != nil {
				t.Fatalf("SetComplianceGrading(absent): %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) { noGradingNoNewKeys(t, tc.setup) })
	}
}

func noGradingNoNewKeys(t *testing.T, setup func(*testing.T, *Proxy)) {
	sinks := newRouteSinks(t)
	p := &Proxy{filterHook: rpHook(t, 5), reporter: sinks.rep}
	setup(t, p)
	if !p.applyInboundFilter(httptest.NewRecorder(), rpRequest(t, "anthropic"), "m", "team", "org-1", "vk-1", "seat-1", "sess-1", "trace-rp-nogr", discardLogger()) {
		t.Fatal("with no grading document nothing request-level may refuse")
	}
	body := firstBatch(sinks.team, 3*time.Second)
	if body == nil {
		t.Fatal("the content row itself must still upload (anti-vacuous)")
	}
	if rows := verdictRows(t, body); len(rows) != 0 {
		t.Fatalf("没有 grading 文档却产生了裁决行:%s", body)
	}
	for _, k := range []string{"route_policy", "counted_is_lower_bound"} {
		if strings.Contains(string(body), k) {
			t.Fatalf("没有 grading 文档时批次里出现了新键 %q —— 老 master 会整批 400:%s", k, body)
		}
	}
}

// TestRoutePolicy_CappedEmitsWarnVerdictRow — P-6(用户 2026-09-18 拍板 ④):
// MAX_ACTION=warn 把拒绝封顶放行,L4 内容真的发往了允许清单以外的厂商 —— 这正是
// 审计最该留痕的事实,仍记一行 action_taken=warn。
func TestRoutePolicy_CappedEmitsWarnVerdictRow(t *testing.T) {
	sinks := newRouteSinks(t)
	p := &Proxy{filterHook: rpHook(t, 4), reporter: sinks.rep}
	mustSetGradingDoc(t, p, l4RoutePolicyDoc)
	if err := p.SetComplianceMaxAction("warn"); err != nil {
		t.Fatalf("SetComplianceMaxAction: %v", err)
	}
	if !p.applyInboundFilter(httptest.NewRecorder(), rpRequest(t, "anthropic"), "m", "team", "org-1", "vk-1", "seat-1", "sess-1", "trace-rp-cap", discardLogger()) {
		t.Fatal("MAX_ACTION=warn must let the request through")
	}
	body := firstBatch(sinks.team, 3*time.Second)
	rows := verdictRows(t, body)
	if len(rows) != 1 {
		t.Fatalf("封顶放行时也必须记一行裁决行,got %d:\n%s", len(rows), body)
	}
	if string(rows[0]["action_taken"]) != `"warn"` {
		t.Fatalf("action_taken = %s, want warn", rows[0]["action_taken"])
	}
	if rp := decodeRP(t, rows[0]["route_policy"]); rp.MinLevel != 4 || rp.TargetProvider == nil || *rp.TargetProvider != "anthropic" {
		t.Fatalf("route_policy = %s", rows[0]["route_policy"])
	}
}
