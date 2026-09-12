// request_verdict_test.go — 请求级裁决事件的构造围栏
// (R-compliance-grading-18.S1 / 18.S3,DEC-compliance-grading-14)。
//
// # 这里守什么
//
// 累计升级("三个片段各命中一条 L4 → 整条请求拦下")的结论是**请求级**的。它不能
// 写回任何一条内容行:内容行的 event_id 是内容派生的,入库走 ON CONFLICT DO NOTHING,
// 要改写就得把它变成 DO UPDATE —— 而那一改,审计从此可被任何一次重扫覆盖。语义上也
// 是假话:片段 1 没被拦,被拦的是整条请求。
//
// 所以由本文件铸一条**独立**的事件:id 由 trace 派生、scenario 标记为请求裁决、
// 参与计数的内容单元 id 放进定型字段 escalation.unit_ids。
//
// # 两条跨仓契约,任一条断了都是静默故障
//
//	①id 派生    —— proxy 铸、master 存。两边各自自洽却互不一致时,裁决行落在没人查的
//	                id 下,而且每次重试都新铸一行。金标准向量钉死它。
//	②wire 键集  —— master 的 intake 解码是 DisallowUnknownFields。多一个键 = **整批
//	                400**,同批搭车的普通内容事件一起丢。这里用一份 master 结构的镜像
//	                做严格解码,把"多发了一个键"当场变红,而不是等到线上审计断流。
package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// requestVerdictGolden* 与 aikey-control-master 侧
// (service/internal/compliance/storage/request_verdict_test.go)逐字节相同。
//
// 🔴 改这个值就是一次 wire 变更,两个仓必须同批改。
const (
	requestVerdictGoldenTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	requestVerdictGoldenID    = "rv_8d8dba041f2262deb4d671f2193e298e"
)

func TestRequestVerdictEventID_GoldenVector(t *testing.T) {
	if got := requestVerdictEventID(requestVerdictGoldenTrace); got != requestVerdictGoldenID {
		t.Fatalf("trace→event_id 派生变了:got %q want %q。\n"+
			"master 侧按同一个算法查这一行(storage.RequestVerdictEventID),两边必须逐字节一致;"+
			"改了盐/前缀/截断宽度会让两边各自自洽却互相对不上 —— 裁决行落在没人查的 id 下,"+
			"重试还会每次新铸一行。要改就两个仓同批改。", got, requestVerdictGoldenID)
	}
}

// masterIntakeEventWireMirror 是 aikey-control-master
// service/internal/compliance/handler.go 里 intakeEventWire 的**键集镜像**。
//
// 只镜像键名,不镜像语义 —— 它唯一的用途是配合 DisallowUnknownFields 复现 master
// 的解码闸门。跨仓不能共享结构体(那是一个 one-way door 的新公共模块),所以用
// "镜像 + 严格解码"把漂移变成本仓的红灯。
//
// 🔴 master 加字段时**不需要**动这里(少一个键不会 400);proxy 要多发一个键时**必须**
// 先在 master 声明、先发布 master,再回来加这里 —— 顺序反了就是整批 400。
type masterIntakeEventWireMirror struct {
	EventID         string          `json:"event_id"`
	CreatedAt       time.Time       `json:"created_at"`
	UserID          string          `json:"user_id"`
	TenantID        string          `json:"tenant_id"`
	ProxyVersion    string          `json:"proxy_version"`
	TargetModel     string          `json:"target_model"`
	Scenario        string          `json:"scenario"`
	PromptLength    int             `json:"prompt_length"`
	ActionTaken     string          `json:"action_taken"`
	PromptHash      string          `json:"prompt_hash,omitempty"`
	VirtualKeyID    string          `json:"virtual_key_id,omitempty"`
	SeatID          string          `json:"seat_id,omitempty"`
	SessionID       string          `json:"session_id,omitempty"`
	TraceID         string          `json:"trace_id,omitempty"`
	DetectLatencyMs *float64        `json:"detect_latency_ms,omitempty"`
	MaxLevel        *int            `json:"max_level,omitempty"`
	Escalation      *escalationWire `json:"escalation,omitempty"`
	Findings        []struct{}      `json:"findings"`
}

func sampleVerdict() requestVerdict {
	return requestVerdict{
		TraceID:      requestVerdictGoldenTrace,
		TenantID:     "org-9",
		VirtualKeyID: "vk-7",
		SeatID:       "seat-3",
		SessionID:    "sess-42",
		Action:       "block",
		Rule:         "min_level=4,min_count=3",
		Counted:      3,
		UnitIDs:      []string{"au_p1", "au_p2", "au_p3"},
		Now:          time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
	}
}

// TestBuildRequestVerdictEvent_MasterAcceptsWireShape 复现 master 的解码闸门。
//
// 能红方式:给 buildRequestVerdictEvent 的输出多加任意一个键(例如把命中文本塞进去)
// → 这里立刻红,而不是等 master 把整批 400 掉、审计静默断流才发现。
func TestBuildRequestVerdictEvent_MasterAcceptsWireShape(t *testing.T) {
	raw, err := buildRequestVerdictEvent(sampleVerdict())
	if err != nil {
		t.Fatalf("buildRequestVerdictEvent: %v", err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var got masterIntakeEventWireMirror
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("master 的 DisallowUnknownFields 解码器会拒掉这条事件 —— **整批 400**,"+
			"同批搭车的普通内容事件一起丢:%v\npayload=%s", err, raw)
	}

	if got.EventID != requestVerdictGoldenID {
		t.Fatalf("event_id=%q,应由 trace 派生 =%q", got.EventID, requestVerdictGoldenID)
	}
	if got.Scenario != scenarioRequestVerdict {
		t.Fatalf("scenario=%q,应为 %q —— 审计页靠它把裁决行与内容命中行分开计数",
			got.Scenario, scenarioRequestVerdict)
	}
	if got.ActionTaken != "block" {
		t.Fatalf("action_taken=%q,应为升级后动作", got.ActionTaken)
	}
	if got.TraceID != requestVerdictGoldenTrace || got.TenantID != "org-9" {
		t.Fatalf("归因字段没盖上:trace=%q tenant=%q", got.TraceID, got.TenantID)
	}
	if got.VirtualKeyID != "vk-7" || got.SeatID != "seat-3" || got.SessionID != "sess-42" {
		t.Fatalf("vk/seat/session 在手工搬运里被吞了:%+v", got)
	}
	if got.Escalation == nil {
		t.Fatalf("escalation 没上 wire —— 裁决行会落成一条没有证据的记录")
	}
	if got.Escalation.Counted != 3 || len(got.Escalation.UnitIDs) != 3 {
		t.Fatalf("escalation 内容不对:%+v", *got.Escalation)
	}
	for i, want := range []string{"au_p1", "au_p2", "au_p3"} {
		if got.Escalation.UnitIDs[i] != want {
			t.Fatalf("unit_ids[%d]=%q want %q", i, got.Escalation.UnitIDs[i], want)
		}
	}
}

// TestBuildRequestVerdictEvent_NoTraceProducesNoEvent。
//
// 没有 trace 就没有可派生的 id。hash("") 会让全网所有没有 trace 的请求共用同一行,
// 看起来像幂等,实际是审计被静默吞掉 —— 比不发这条事件严重得多。
func TestBuildRequestVerdictEvent_NoTraceProducesNoEvent(t *testing.T) {
	v := sampleVerdict()
	v.TraceID = ""
	raw, err := buildRequestVerdictEvent(v)
	if err != nil {
		t.Fatalf("无 trace 不应报错(这是正常状态,不是故障):%v", err)
	}
	if raw != nil {
		t.Fatalf("无 trace 时不得铸事件,否则所有无 trace 请求共用一行:%s", raw)
	}
	if got := requestVerdictEventID(""); got != "" {
		t.Fatalf("空 trace 的派生 id 应为空串,got %q", got)
	}
}

// TestBuildRequestVerdictEvent_CarriesNoContent 守 DC5 与本能力的
// 「不得有内容派生值进 wire 或落库」。
//
// 裁决事件是本包唯一一条**由 proxy 全新铸造**的合规事件 —— 它不经过 detector,
// 也就不经过 detector 那一侧的任何脱敏。所以"它带了什么"这件事只有这里能守。
func TestBuildRequestVerdictEvent_CarriesNoContent(t *testing.T) {
	v := sampleVerdict()
	raw, err := buildRequestVerdictEvent(v)
	if err != nil {
		t.Fatalf("buildRequestVerdictEvent: %v", err)
	}
	// 键集必须恰好是这几个。多一个键就是给内容派生值开了搭车位
	// (也会被 master 的 DisallowUnknownFields 打成整批 400)。
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	allowed := map[string]bool{
		"event_id": true, "created_at": true, "tenant_id": true, "scenario": true,
		"action_taken": true, "prompt_length": true, "virtual_key_id": true,
		"seat_id": true, "session_id": true, "trace_id": true,
		"escalation": true, "findings": true,
	}
	for k := range keys {
		if !allowed[k] {
			t.Fatalf("裁决事件多带了一个键 %q —— 这条事件由 proxy 全新铸造,不经 detector 脱敏,"+
				"键集必须是白名单。且 master 的 DisallowUnknownFields 会把**整批**打成 400", k)
		}
	}
	// escalation 的子键同样是白名单 —— master 侧多一个子键也是 400。
	var esc map[string]json.RawMessage
	if err := json.Unmarshal(keys["escalation"], &esc); err != nil {
		t.Fatalf("unmarshal escalation: %v", err)
	}
	for k := range esc {
		if k != "rule" && k != "counted" && k != "unit_ids" {
			t.Fatalf("escalation 多带了子键 %q —— DEC-compliance-grading-14 的字段集是固定的", k)
		}
	}
	// prompt_hash / redacted_snippet / context_snippet 这类可能携带内容的键
	// 一个都不能出现在这条事件上。
	for _, forbidden := range []string{"prompt_hash", "context_snippet", "redacted_snippet", "findings\":[{"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("裁决事件带上了 %q:%s", forbidden, raw)
		}
	}
}
