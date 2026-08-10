package proxy

// filter_restore_thinking_test.go — S3 (用户拍板 2026-08-09) 围栏:
// **响应侧不还原推理块**(Anthropic thinking / redacted_thinking、OpenAI Responses
// reasoning item、chat-completions reasoning_content)。
//
// 为什么这是安全修复而不是显示偏好:请求侧**不能**扫 thinking —— 这些块带
// `signature`,客户端回传时上游会校验,改写文本 = 请求被上游直接拒(400)。而响应还原
// 原本是整树字符串替换,于是模型在 thinking 里复述的占位符被还原成**原文**交回客户端,
// 客户端把它存进历史,下一轮又原封不动地在 thinking 里发回来 —— 正好落在"永远不扫"
// 的那块地上。结果:从第 2 轮起敏感原文明文进上游 LLM,全程 HTTP 200,无任何信号。
// 修复 = 推理块里始终保持占位符,泄漏链在响应侧被切断,且不改写任何已签名内容。
//
// 关联:bugfix `workflow/CI/bugfix/20260809-thinking-block-restore-leak.md`;
// 规格 `workflow/CI/requirements/2026-06-04-compliance-filter-direction-and-scope.md`
// 「响应方向唯一例外」+「扫描的消息角色范围」。

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// --- 非流式:整树替换必须跳过推理块 -------------------------------------------

// TestRestoreMaskedResponseBody_ThinkingBlockKeepsPlaceholder 是本修复的核心断言。
//
// 能红设计:同一个响应体里同时放 text 块和 thinking 块,**用同一个占位符**。
//   - text 块必须被还原 —— 这是对照组,证明映射表、占位符拼写、还原链路本身是活的;
//     少了它,"thinking 里还是占位符"可能只是因为占位符根本没配对(恒真断言)。
//   - thinking / redacted_thinking 块必须原样保留占位符。
//
// 去掉 restoreJSONStrings 里的 reasoningBlockTypes 跳过 → 第二组断言必红。
func TestRestoreMaskedResponseBody_ThinkingBlockKeepsPlaceholder(t *testing.T) {
	const addr = "北京市朝阳区建国路8801号"
	ctx := restoreStateCtx(map[string]string{"{{ADDR_1}}": addr})

	body := []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[` +
		`{"type":"thinking","thinking":"用户要寄到{{ADDR_1}}，先确认收件人。","signature":"ErUBCkYIA..."},` +
		`{"type":"redacted_thinking","data":"encrypted-blob-{{ADDR_1}}"},` +
		`{"type":"text","text":"好的，会寄到{{ADDR_1}}。"}` +
		`],"usage":{"input_tokens":10,"output_tokens":20}}`)

	got := restoreMaskedResponseBody(ctx, body, discardLogger())

	blocks := gjson.GetBytes(got, "content").Array()
	if len(blocks) != 3 {
		t.Fatalf("restore must not reshape the body; content=%s", gjson.GetBytes(got, "content").Raw)
	}
	// ① 对照组:正式回复必须还原(否则本用例的绿是假绿)。
	if text := blocks[2].Get("text").String(); !strings.Contains(text, addr) {
		t.Fatalf("对照组失效:text 块没有被还原,说明本用例根本没跑通还原链路;text=%q", text)
	}
	// ② 修复断言:推理块保持占位符,原文一个字都不能出现。
	if think := blocks[0].Get("thinking").String(); !strings.Contains(think, "{{ADDR_1}}") || strings.Contains(think, addr) {
		t.Errorf("thinking 块被还原了 —— 原文会进客户端历史,下一轮以不可扫的 thinking 身份回上游;thinking=%q", think)
	}
	if data := blocks[1].Get("data").String(); !strings.Contains(data, "{{ADDR_1}}") || strings.Contains(data, addr) {
		t.Errorf("redacted_thinking 块被还原了;data=%q", data)
	}
	// signature 必须字节不变(改写已签名内容 = 上游 400)。
	if sig := blocks[0].Get("signature").String(); sig != "ErUBCkYIA..." {
		t.Errorf("signature 被改动:%q", sig)
	}
	// 非字符串字段照旧不受影响。
	if n := gjson.GetBytes(got, "usage.input_tokens").Int(); n != 10 {
		t.Errorf("usage 被破坏:%d", n)
	}
	if !t.Failed() {
		t.Logf("✅ text 还原为原文;thinking / redacted_thinking 保持 {{ADDR_1}}")
	}
}

// TestRestoreMaskedResponseBody_OpenAIReasoningChannelsKeepPlaceholder:
// OpenAI 侧的等价推理通道同样排除。两种形态:
//   - Responses API 的 `{"type":"reasoning", "summary":[{"type":"summary_text",...}]}`
//     item —— 客户端下一轮会连 `encrypted_content` 一起回传做上下文保持,而入站扫描
//     只收 text / input_text / output_text 块,泄漏链与 Anthropic thinking 完全同形;
//   - chat-completions 的 `message.reasoning_content` 兄弟字段(DeepSeek-R1 形态)——
//     它不是"块",所以按字段名排除;流式侧本来就不还原它,非流式跟上才是两条腿一致。
//
// 对照组同样在同一个 body 里:output_text / content 必须被还原。
func TestRestoreMaskedResponseBody_OpenAIReasoningChannelsKeepPlaceholder(t *testing.T) {
	const addr = "上海市浦东新区世纪大道1002号"

	t.Run("responses_reasoning_item", func(t *testing.T) {
		ctx := restoreStateCtx(map[string]string{"{{ADDR_1}}": addr})
		body := []byte(`{"id":"resp_1","object":"response","output":[` +
			`{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"要寄到{{ADDR_1}}"}],"encrypted_content":"gAAAA{{ADDR_1}}"},` +
			`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"好的，寄到{{ADDR_1}}。"}]}` +
			`]}`)
		got := restoreMaskedResponseBody(ctx, body, discardLogger())

		if answer := gjson.GetBytes(got, "output.1.content.0.text").String(); !strings.Contains(answer, addr) {
			t.Fatalf("对照组失效:output_text 没被还原;text=%q", answer)
		}
		if s := gjson.GetBytes(got, "output.0.summary.0.text").String(); !strings.Contains(s, "{{ADDR_1}}") || strings.Contains(s, addr) {
			t.Errorf("reasoning item 的 summary 被还原了;summary=%q", s)
		}
		if e := gjson.GetBytes(got, "output.0.encrypted_content").String(); !strings.Contains(e, "{{ADDR_1}}") || strings.Contains(e, addr) {
			t.Errorf("reasoning item 的 encrypted_content 被改动了;got=%q", e)
		}
	})

	t.Run("chat_completions_reasoning_content", func(t *testing.T) {
		ctx := restoreStateCtx(map[string]string{"{{ADDR_1}}": addr})
		body := []byte(`{"id":"cc_1","object":"chat.completion","choices":[{"index":0,"message":` +
			`{"role":"assistant","reasoning_content":"先把地址记下来：{{ADDR_1}}","content":"好的，寄到{{ADDR_1}}。"}}]}`)
		got := restoreMaskedResponseBody(ctx, body, discardLogger())

		if answer := gjson.GetBytes(got, "choices.0.message.content").String(); !strings.Contains(answer, addr) {
			t.Fatalf("对照组失效:content 没被还原;content=%q", answer)
		}
		if rc := gjson.GetBytes(got, "choices.0.message.reasoning_content").String(); !strings.Contains(rc, "{{ADDR_1}}") || strings.Contains(rc, addr) {
			t.Errorf("reasoning_content 被还原了(且与流式侧行为不一致);reasoning_content=%q", rc)
		}
	})
}

// --- 流式:thinking_delta 退出还原通道 ----------------------------------------

func anthropicThinkingFrame(text string) string {
	enc, _ := jsonMarshalString(text)
	return "event: content_block_delta\ndata: " +
		`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":` + enc + `}}` +
		"\n\n"
}

// concatDeltaField 把输出流里某个 gjson 路径上的所有值拼起来(客户端可见的该通道文本)。
func concatDeltaField(stream, path string) string {
	var sb strings.Builder
	for _, line := range strings.Split(stream, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := line[len("data: "):]
		if payload == "" || payload[0] != '{' {
			continue
		}
		if v := gjson.Get(payload, path); v.Exists() {
			sb.WriteString(v.String())
		}
	}
	return sb.String()
}

// TestSSERestore_ThinkingDeltaKeepsPlaceholder:流式下 thinking_delta 帧里的占位符
// 必须原样透传(含跨帧被切成两半的情况),text_delta 帧照旧还原。
//
// 能红设计同上:text 通道是对照组。把 sseTextFieldPath 的 thinking_delta 分支加回去
// → thinking 通道断言必红。
func TestSSERestore_ThinkingDeltaKeepsPlaceholder(t *testing.T) {
	const addr = "广州市天河区体育西路12号"
	st := sseTestState(map[string]string{"{{ADDR_1}}": addr})

	// thinking 块的占位符被切成两半(跨帧),text 块的也被切成两半。
	in := anthropicThinkingFrame("用户要寄到{{AD") +
		anthropicThinkingFrame("DR_1}}，确认一下。") +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		anthropicTextFrame("好的，寄到{{AD") +
		anthropicTextFrame("DR_1}}。") +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n"

	out := drainAll(t, newSSEPlaceholderRestorer(&chunkReader{data: []byte(in), chunk: 17}, st))

	// ① 对照组:text 通道跨帧还原必须成立。
	if text := concatTextDeltas(t, out); !strings.Contains(text, addr) || strings.Contains(text, "{{ADDR_1}}") {
		t.Fatalf("对照组失效:text 通道没有跨帧还原,本用例并未验证通道选择;text=%q", text)
	}
	// ② 修复断言:thinking 通道保持占位符。
	think := concatDeltaField(out, "delta.thinking")
	if strings.Contains(think, addr) {
		t.Errorf("thinking_delta 被还原了 —— 原文会进客户端历史;thinking=%q", think)
	}
	if !strings.Contains(think, "{{ADDR_1}}") {
		t.Errorf("thinking 通道应原样保留占位符(允许跨帧拼接后可见);thinking=%q", think)
	}
	// 整条流里任何地方都不能出现原文以外的意外:thinking 帧应字节直通。
	if strings.Count(out, addr) != strings.Count(concatTextDeltas(t, out), addr) {
		t.Errorf("原文出现在 text 通道以外的位置;stream=%s", out)
	}
	if !t.Failed() {
		t.Logf("✅ text 通道跨帧还原;thinking 通道保持 {{ADDR_1}}")
	}
}

// --- 端到端:两轮对话,thinking 出去的必须仍是占位符 ---------------------------

// TestRestoreLeak_ThinkingRoundTripStaysMasked 复现完整泄漏链并锁死修复:
//
//	第 1 轮:用户发地址 → 出站 {{ADDR_1}} → 上游在 thinking 和 text 里都复述了占位符
//	        → 响应还原 → 客户端拿到"thinking 里是占位符 / text 里是原文"
//	第 2 轮:客户端把整段历史(含 thinking 块)重发 → 断言出站 body 里没有原文
//
// 能红对照(第二段):把 thinking 块的内容换成原文(= 修复前响应还原写进去的东西),
// 同一条链路必须**真的泄漏**。这证明 thinking 块确实不被扫描 —— 唯一挡住泄漏的就是
// "响应侧不还原",而不是别的什么兜底在起作用。
func TestRestoreLeak_ThinkingRoundTripStaysMasked(t *testing.T) {
	const addr = "杭州市西湖区文三路9003号"

	// ── 第 1 轮:请求侧打码 + 响应侧还原 ──
	p := &Proxy{filterHook: &stubRestorableHook{addrs: []string{addr}}}
	r1 := newReq(`{"model":"m","messages":[{"role":"user","content":"寄到` + addr + `"}]}`)
	r1.Header.Set("X-Claude-Code-Session-Id", "s3-thinking-roundtrip")
	if !p.applyInboundFilter(httptest.NewRecorder(), r1, "m", "personal", "", "", "",
		resolveSessionID(r1, "anthropic", "anthropic"), "", discardLogger()) {
		t.Fatal("第 1 轮被 block,用例前提不成立")
	}
	if fwd := readReqBody(t, r1); strings.Contains(fwd, addr) {
		t.Fatalf("第 1 轮就泄漏了,用例前提不成立;body=%s", fwd)
	}

	upstream := []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[` +
		`{"type":"thinking","thinking":"用户要寄到{{ADDR_1}}，先确认。","signature":"ErUBCkYIA..."},` +
		`{"type":"text","text":"好的，会寄到{{ADDR_1}}。"}]}`)
	clientVisible := restoreMaskedResponseBody(r1.Context(), upstream, discardLogger())
	if !strings.Contains(string(clientVisible), addr) {
		t.Fatalf("前提不成立:正式回复没被还原,后面的第 2 轮就不具代表性;body=%s", clientVisible)
	}

	// ── 第 2 轮:客户端把收到的 content 数组原样塞回历史重发 ──
	history := gjson.GetBytes(clientVisible, "content").Raw
	round2 := func(assistantContent string) string {
		p2 := &Proxy{filterHook: &stubRestorableHook{addrs: []string{addr}}}
		r2 := newReq(`{"model":"m","messages":[` +
			`{"role":"user","content":"寄到` + addr + `"},` +
			`{"role":"assistant","content":` + assistantContent + `},` +
			`{"role":"user","content":"再帮我确认一下收件人"}` +
			`]}`)
		r2.Header.Set("X-Claude-Code-Session-Id", "s3-thinking-roundtrip-2")
		if !p2.applyInboundFilter(httptest.NewRecorder(), r2, "m", "personal", "", "", "",
			resolveSessionID(r2, "anthropic", "anthropic"), "", discardLogger()) {
			t.Fatal("第 2 轮被 block,用例前提不成立")
		}
		return readReqBody(t, r2)
	}

	fwd2 := round2(history)
	if strings.Contains(fwd2, addr) {
		t.Errorf("还原泄漏未修:第 2 轮原文明文出站\n出站 body=%s", fwd2)
	}
	if !strings.Contains(fwd2, "{{ADDR_1}}") {
		t.Errorf("thinking 块里的占位符应原样出站(它就是切断泄漏链的东西)\n出站 body=%s", fwd2)
	}

	// 能红对照:如果响应侧把 thinking 还原成了原文(修复前的行为),同一条链路必须泄漏。
	leaked, _ := json.Marshal([]any{
		map[string]any{"type": "thinking", "thinking": "用户要寄到" + addr + "，先确认。", "signature": "ErUBCkYIA..."},
		map[string]any{"type": "text", "text": "好的，会寄到" + addr + "。"},
	})
	if fwdLeak := round2(string(leaked)); !strings.Contains(fwdLeak, addr) {
		t.Fatalf("能红对照失效:thinking 块里放原文竟然也没泄漏 —— 说明上面的绿不是靠本修复拿到的\n出站 body=%s", fwdLeak)
	}
	t.Logf("✅ 能红成立:thinking 保持占位符 → 第 2 轮无原文;thinking 放原文 → 第 2 轮泄漏(%q)", addr)
}
