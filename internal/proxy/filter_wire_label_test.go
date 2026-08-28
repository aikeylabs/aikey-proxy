// filter_wire_label_test.go — 围栏:方案 L「结果回填」(update doc
// 20260810-合规事件携带命中片段原文 §16.3,2026-08-11 用户拍板)。
//
// # 这组围栏在守什么
//
// 落库的脱敏片段一直显示 detector 的**无编号** token `{{PHONE}}`,而真正发给模型的
// 是代理在转发那一刻分配的**有编号**标签 `{{PHONE_1}}`。成员在自视图看到的字符串
// 从来没有被发出去过,并且同类型的多个命中彼此无法区分。
//
// 方案 L 的做法:**不搬编号规则**(它今天就只有一份,在 renumberRestorables),只把
// 已经算好的**结果**回填到事件上 —— 与代理已经在做的 6 个 inject*(org / seat /
// session / trace / 封顶后的真实动作 …)完全同型。
//
// 因此这组围栏钉死的**不是**"字段有值",而是四条会被后人"顺手"改坏的性质:
//
//	① 编号出口只有一个 —— 全仓只有 renumberRestorables 会拼 prefix+N+suffix,
//	   回填路径**不许**自己算号(否则就成了第二份规则,方案 L 的前提当场瓦解)。
//	② 等值 join 必须真的对上 —— 每条命中拿到的标签,必须等于它在**实际出站文本**
//	   里的那个标签,不是"有值就行"。多命中场景下这两者很容易错位一位。
//	③ 只记账(audit)档必须**没有**编号 —— 这条是承重的。audit 档的原文是**照发**
//	   的,给它标一个占位符名字 = 告诉合规看板"这个值被打码了",而事实相反。这正是
//	   injectActionTaken 隔壁一格在防的虚假安全信号。将来一定会有人觉得"有的有有的
//	   没有很难看"而顺手补全 —— 这条测试就是拦他的。
//	③' 被动作封顶的分片同理:根本没打码,自然不该有编号。
//	④ 三条还原降级路径下必须**没有**编号 —— 降级时掩码保留、编号跳过,回填必须跟着
//	   一起没有,不能凭空造一个。
//
// 全链路走生产代码:真 applyInboundFilter → 真 events.Reporter → httptest 假 master。
package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// --- ① 编号出口唯一 ---------------------------------------------------------

// TestFilterRestore_SingleNumberingSource 钉死"生成一个编号"这件事全仓只有一个出口。
//
// 围栏按**概念有几个出口**写,不按"我改了哪几行"写:被扫的是 st.nextN(那个请求作用域
// 计数器)的引用点,以及回填函数体内不得出现任何整数格式化。加一个新的编号器、或者在
// injectWireLabels 里"顺手"拼一个 fallback 标签,都会让这条红。
//
// 能红验证:在 injectWireLabels 里写一行 `label := prefix + strconv.Itoa(n) + suffix`
// ⇒ 红(nextN 引用点数变了 / 回填函数出现 strconv)。
func TestFilterRestore_SingleNumberingSource(t *testing.T) {
	restoreSrc := readProxySource(t, "filter_restore.go")
	dispatchSrc := readProxySource(t, "filter_dispatch.go")

	// nextN 是编号的唯一状态。它只应出现在 filter_restore.go 里 4 次:结构体字段
	// 声明、newMaskRestore 里初始化为 1、renumberRestorables 里读一次、自增一次。
	// 多出来的引用点意味着有人开了第二条编号路径。
	if n := strings.Count(restoreSrc, "nextN"); n != 4 {
		t.Errorf("filter_restore.go 里 nextN 的引用点 = %d,期望 4(声明/初始化/读/自增)。"+
			"编号计数器多一个引用点就可能是多了一条编号路径 —— 方案 L 的前提是"+
			"『编号规则只有一份』,请确认新增的引用点没有在别处生成标签", n)
	}
	if strings.Contains(dispatchSrc, "nextN") {
		t.Error("filter_dispatch.go 引用了 nextN:编号只允许在 filter_restore.go " +
			"renumberRestorables 里分配,回填侧只能消费已经算好的结果(方案 L §16.3)")
	}

	// 回填函数体内不得出现任何数字格式化 —— 它只允许**查表**。
	body := funcBody(t, dispatchSrc, "func injectWireLabels(")
	for _, forbidden := range []string{"strconv.", "Itoa", "Sprintf", "Sprint("} {
		if strings.Contains(body, forbidden) {
			t.Errorf("injectWireLabels 里出现 %q:回填只能等值 join 查表,"+
				"一旦它开始拼字符串就等于出现了第二份编号规则", forbidden)
		}
	}
}

// --- ② 等值 join 的正确性 ---------------------------------------------------

// TestInjectWireLabels_JoinMatchesTheTextActuallySent 是这组围栏里最核心的一条:
// 每条命中回填到的标签,必须等于它在**出站文本**里真实出现的那个标签。
//
// 做法刻意不信任任何中间结果:先跑真的 renumberRestorables 拿到出站文本,再从出站
// 文本里按出现顺序抽出标签序列,然后按命中的 start_offset 排序去比对。所以"回填成
// 功但错位一位"(多命中场景最容易出的 bug)会红,而不是被"字段非空"糊弄过去。
func TestInjectWireLabels_JoinMatchesTheTextActuallySent(t *testing.T) {
	a1, a2, a3 := "北京市朝阳区建国路88号", "上海市浦东新区世纪大道100号", "广州市天河区体育西路5号"
	head := "收货：" + a1 + "；备用：" + a2 + "；第三：" + a3
	masked := maskAddrs(head, a1, a2, a3)

	st := newMaskRestore()
	sent, spanLabels := renumberRestorables(head, masked, []apphook.RestorableMask{
		addrRestorable(head, a1, a2, a3),
	}, st, discardLogger())

	// 出站文本里按左→右实际出现的标签序列 —— 这是"真的发出去了什么"的唯一真相。
	labelsInSent := regexp.MustCompile(`\{\{ADDR_\d+\}\}`).FindAllString(sent, -1)
	if len(labelsInSent) != 3 {
		t.Fatalf("出站文本里的标签数 = %d,期望 3;文本=%q", len(labelsInSent), sent)
	}

	// 事件侧:三条命中,偏移量与 detector 会写的一致(raw 帧,同一坐标系)。
	ev := findingsEvent(t, spansOf(head, a1, a2, a3))
	out := injectWireLabels(ev, spanLabels)

	got := wireLabelsByOffset(t, out)
	for i, span := range spansOf(head, a1, a2, a3) {
		want := labelsInSent[i] // 第 i 个地址在文本里就是第 i 个标签(左→右)
		if got[span] != want {
			t.Errorf("命中 #%d (span %v) 回填的标签 = %q,但它在实际出站文本里是 %q。"+
				"等值 join 错位 = 用户在自视图看到的名字对应的是别人的值", i, span, got[span], want)
		}
	}
}

// TestInjectWireLabels_FailSafeAndNoop 钉死回填与其它六个 inject* 同样的 fail-safe
// 语义:空映射 / 坏 JSON / 没有 findings 一律原样返回。回填只是一个注解,任何闪失都
// 不能把审计记录本身赔进去。
func TestInjectWireLabels_FailSafeAndNoop(t *testing.T) {
	const ev = `{"event_id":"e1","findings":[{"finding_id":"f1","start_offset":0,"end_offset":3}]}`

	if got := string(injectWireLabels([]byte(ev), nil)); got != ev {
		t.Errorf("空映射改动了事件:%s", got)
	}
	if got := string(injectWireLabels([]byte(ev), map[[2]int]string{{9, 9}: "{{X_1}}"})); got != ev {
		t.Errorf("无命中的映射改动了事件(必须原样返回,而不是写空字段):%s", got)
	}
	const bad = `{not json`
	if got := string(injectWireLabels([]byte(bad), map[[2]int]string{{0, 3}: "{{X_1}}"})); got != bad {
		t.Errorf("坏 JSON 被改动了:%s", got)
	}
	const noFindings = `{"event_id":"e1","action_taken":"mask"}`
	if got := string(injectWireLabels([]byte(noFindings), map[[2]int]string{{0, 3}: "{{X_1}}"})); got != noFindings {
		t.Errorf("没有 findings 的事件被改动了:%s", got)
	}
}

// --- ③ 只记账(audit)档必须没有编号 -----------------------------------------

// TestInjectWireLabels_AuditFindingStaysUnlabelled 是**承重**的一条。
//
// 场景照抄生产:一个窗口里两条命中 —— 一条 mask 档(真的被替换成占位符发出去了),
// 一条 audit 档(例如 CN_ADDRESS,出厂默认就是 audit:记一笔,字节**原样转发**)。
// audit 档那条根本不在 detector 的掩码计划里,所以它没有 span,回填自然填不上。
//
// 🔴 这个"填不上"是**特性不是缺陷**。给一条其实原文照发的命中标上 `{{ADDR_1}}`,
// 等于对着合规看板宣称这个值被打码了 —— 本项目在这一带反复踩的虚假安全信号。
//
// 能红验证:把回填改成"对事件里的全部 findings 都标号",本用例立刻红。
func TestInjectWireLabels_AuditFindingStaysUnlabelled(t *testing.T) {
	a1 := "北京市朝阳区建国路88号"
	audited := "13800138000" // audit 档:记账但不打码,原文照发
	head := "地址：" + a1 + "；电话：" + audited
	masked := maskAddrs(head, a1)

	st := newMaskRestore()
	_, spanLabels := renumberRestorables(head, masked, []apphook.RestorableMask{
		addrRestorable(head, a1), // 只有 mask 档进掩码计划
	}, st, discardLogger())

	maskedSpan := spansOf(head, a1)[0]
	auditSpan := spansOf(head, audited)[0]

	out := injectWireLabels(findingsEvent(t, [][2]int{maskedSpan, auditSpan}), spanLabels)
	got := wireLabelsByOffset(t, out)

	if got[maskedSpan] != "{{ADDR_1}}" {
		t.Errorf("被打码的命中没有拿到编号:%q", got[maskedSpan])
	}
	if lbl, present := got[auditSpan]; present {
		t.Errorf("只记账(audit)档的命中被标上了 wire_label=%q。"+
			"这条命中的原文是**照发**的,给它一个占位符名字就是在制造虚假安全信号"+
			"(与 injectActionTaken 防的是同一件事)。空 = 『只被记账,原文照发』,"+
			"这是有用的语义,不要『顺手补全』", lbl)
	}
}

// --- ④ 三条降级路径下必须没有编号 -------------------------------------------

// TestRenumberRestorables_DegradePathsYieldNoLabels 钉死三条既有降级路径在方案 L
// 之后仍然**零改动**地成立,并且回填跟着一起没有。
//
// 三条降级的共同性质是:掩码保留(敏感文本仍然被遮住),只丢还原。方案 L 不碰它们,
// 所以此时也必须**没有**编号可回填 —— 编号本来就没分配出去。
func TestRenumberRestorables_DegradePathsYieldNoLabels(t *testing.T) {
	a1 := "北京市朝阳区建国路88号"

	t.Run("次数不符(用户自己写了 token)", func(t *testing.T) {
		head := "地址：" + a1 + "，模板里写了 " + tAddrToken
		// 用户手写的 token 让 masked 里出现 2 个 occurrence,但 spans 只有 1 个。
		masked := strings.Replace(head, a1, tAddrToken, 1)
		st := newMaskRestore()
		out, spanLabels := renumberRestorables(head, masked, []apphook.RestorableMask{
			addrRestorable(head, a1),
		}, st, discardLogger())
		assertNoLabels(t, out, masked, spanLabels)
	})

	t.Run("两族共用同一个 token", func(t *testing.T) {
		head := "地址：" + a1
		masked := maskAddrs(head, a1)
		dup := addrRestorable(head, a1) // 同一个 Token 出现两条 Restorable
		st := newMaskRestore()
		out, spanLabels := renumberRestorables(head, masked, []apphook.RestorableMask{dup, dup},
			st, discardLogger())
		assertNoLabels(t, out, masked, spanLabels)
	})

	t.Run("span 非法", func(t *testing.T) {
		head := "地址：" + a1
		masked := maskAddrs(head, a1)
		bad := apphook.RestorableMask{
			Token: tAddrToken, NumberedPrefix: tAddrPrefix, NumberedSuffix: tAddrSuffix,
			Spans: [][2]int{{5, 1_000_000}}, // 越界
		}
		st := newMaskRestore()
		out, spanLabels := renumberRestorables(head, masked, []apphook.RestorableMask{bad},
			st, discardLogger())
		assertNoLabels(t, out, masked, spanLabels)
	})
}

func assertNoLabels(t *testing.T, out, masked string, spanLabels map[[2]int]string) {
	t.Helper()
	if out != masked {
		t.Errorf("降级路径下出站文本被改写了:%q,期望保持无编号掩码 %q", out, masked)
	}
	if len(spanLabels) != 0 {
		t.Errorf("降级路径下返回了 %d 个标签:%v。降级 = 掩码保留、编号跳过,"+
			"此时不存在『实际发出的编号形态』,回填必须一起没有", len(spanLabels), spanLabels)
	}
	// 回填在这种情况下必须是彻底的 no-op。
	ev := findingsEvent(t, [][2]int{{0, 3}})
	if got := injectWireLabels(ev, spanLabels); string(got) != string(ev) {
		t.Errorf("降级路径下事件仍被改动:%s", got)
	}
}

// --- 端到端:真 applyInboundFilter → 真 Reporter → 假 master ------------------

// TestWireLabel_EndToEnd_TeamEventCarriesTheLabelActuallySent 走完整生产链路,断言
// 上报给 master 的事件里,finding 的 wire_label 与**转发出去的请求体**里那个标签
// 逐字一致。这是"落库的标签 == 上游实际收到的文本里的标签"在单测层的对照。
//
// 能红验证:去掉 filter_dispatch.go 里的 injectWireLabels 调用 ⇒ 红。
func TestWireLabel_EndToEnd_TeamEventCarriesTheLabelActuallySent(t *testing.T) {
	a1 := "北京市朝阳区建国路88号"
	head := "收货地址是" + a1 + "谢谢"
	span := spansOf(head, a1)[0]

	srv, sink := complianceSink(t)
	hook := &stubHook{resp: &apphook.Response{
		Action:         apphook.ActionMask,
		MutatedPayload: []byte(maskAddrs(head, a1)),
		Restorables:    []apphook.RestorableMask{addrRestorable(head, a1)},
		Event: []byte(`{"event_id":"evt-1","tenant_id":"","action_taken":"mask","findings":[` +
			findingJSON("f1", span) + `]}`),
	}}
	p := &Proxy{filterHook: hook}
	p.SetReporter(teamReporter(t, srv.URL), "inst-1", "v-test", "cfg-1", 0, "")

	r := newReq(`{"messages":[{"role":"user","content":` + mustJSON(t, head) + `}]}`)
	p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org-9", "vk-7", "seat-3",
		"sess-42", "trace-1", discardLogger())

	// 真正转发上游的请求体 —— "上游实际收到的文本"。
	forwarded := readReqBody(t, r)
	labels := regexp.MustCompile(`\{\{ADDR_\d+\}\}`).FindAllString(forwarded, -1)
	if len(labels) != 1 {
		t.Fatalf("转发出去的请求体里标签数 = %d,期望 1;body=%s", len(labels), forwarded)
	}
	if strings.Contains(forwarded, a1) {
		t.Fatalf("原文泄漏到转发请求体:%s", forwarded)
	}

	evs := waitEvents(t, sink, "团队合规事件")
	if len(evs) != 1 {
		t.Fatalf("上报事件数 = %d,期望 1", len(evs))
	}
	findings, _ := evs[0]["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings 数 = %d,期望 1", len(findings))
	}
	f, _ := findings[0].(map[string]any)
	if got := f["wire_label"]; got != labels[0] {
		t.Errorf("上报的 wire_label = %v,但上游实际收到的标签是 %q。"+
			"这两者不一致 = 用户在自视图看到的形态仍然不是真的发出去的那个", got, labels[0])
	}
}

// TestWireLabel_CeilingCappedPieceCarriesNoLabel 钉死"被动作封顶的分片没有编号"。
//
// 封顶(方案② tool_use/tool_result)把 mask 判定降级成 allow:**什么都没打码**,
// 字节原样转发。所以 ActionMask 分支根本不执行,一个编号都没分配 —— 事件里必须没有
// wire_label。与 ③ 同源:没打码就不能声称打码了。
func TestWireLabel_CeilingCappedPieceCarriesNoLabel(t *testing.T) {
	secret := "北京市朝阳区建国路88号"
	head := "ls " + secret

	srv, sink := complianceSink(t)
	hook := &stubHook{resp: &apphook.Response{
		Action:         apphook.ActionMask, // detector 说要打码……
		MutatedPayload: []byte(maskAddrs(head, secret)),
		Restorables:    []apphook.RestorableMask{addrRestorable(head, secret)},
		Event: []byte(`{"event_id":"evt-capped","tenant_id":"","action_taken":"mask","findings":[` +
			findingJSON("f1", spansOf(head, secret)[0]) + `]}`),
	}}
	p := &Proxy{filterHook: hook}
	p.SetReporter(teamReporter(t, srv.URL), "inst-1", "v-test", "cfg-1", 0, "")

	// tool_result 分片 → ceilingAudit → clamp 到 allow(……代理不打码)。
	body := `{"messages":[{"role":"user","content":[{"type":"tool_result","content":` +
		mustJSON(t, head) + `}]}]}`
	r := newReq(body)
	p.applyInboundFilter(httptest.NewRecorder(), r, "m", "team", "org-9", "vk-7", "seat-3",
		"sess-42", "trace-1", discardLogger())

	forwarded := readReqBody(t, r)
	if !strings.Contains(forwarded, secret) {
		t.Fatalf("前提不成立:封顶分片应当原文转发,实际被改写了:%s", forwarded)
	}

	evs := waitEvents(t, sink, "封顶分片的合规事件")
	findings, _ := evs[0]["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings 数 = %d,期望 1(封顶只降级动作,不取消记账)", len(findings))
	}
	f, _ := findings[0].(map[string]any)
	if lbl, present := f["wire_label"]; present {
		t.Errorf("被封顶的分片带上了 wire_label=%v。这条命中的原文是**照发**的"+
			"(action_taken 也被改写成 audit),标一个占位符名字就是虚假安全信号", lbl)
	}
}

// --- 测试小工具 -------------------------------------------------------------

func spansOf(head string, subs ...string) [][2]int {
	out := make([][2]int, 0, len(subs))
	off := 0
	for _, s := range subs {
		i := strings.Index(head[off:], s)
		if i < 0 {
			panic("test substring not in head: " + s)
		}
		start := off + i
		out = append(out, [2]int{start, start + len(s)})
		off = start + len(s)
	}
	return out
}

func findingJSON(id string, span [2]int) string {
	b, _ := json.Marshal(map[string]any{
		"finding_id": id, "category": "pii", "entity_type": "CN_ADDRESS",
		"severity": "high", "confidence": 90,
		"start_offset": span[0], "end_offset": span[1],
	})
	return string(b)
}

func findingsEvent(t *testing.T, spans [][2]int) []byte {
	t.Helper()
	parts := make([]string, 0, len(spans))
	for i, sp := range spans {
		parts = append(parts, findingJSON(string(rune('a'+i)), sp))
	}
	return []byte(`{"event_id":"e1","action_taken":"mask","findings":[` + strings.Join(parts, ",") + `]}`)
}

// wireLabelsByOffset 把事件解回 span → wire_label。只收录**存在**该键的条目,
// 这样调用方能区分"空字符串"和"根本没有这个字段"。
func wireLabelsByOffset(t *testing.T, eventJSON []byte) map[[2]int]string {
	t.Helper()
	var m struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(eventJSON, &m); err != nil {
		t.Fatalf("解析回填后的事件失败: %v (%s)", err, eventJSON)
	}
	out := make(map[[2]int]string, len(m.Findings))
	for _, f := range m.Findings {
		lbl, ok := f["wire_label"]
		if !ok {
			continue
		}
		s, _ := f["start_offset"].(float64)
		e, _ := f["end_offset"].(float64)
		out[[2]int{int(s), int(e)}] = lbl.(string)
	}
	return out
}

// readProxySource reads a source file from this package for the static fences
// (same convention as chain_fences_test.go / chain_edition_matrix_test.go).
func readProxySource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// funcBody returns the text of the function whose declaration starts with decl,
// up to the closing brace at column 0. Good enough for a "does this function
// contain X" scan and deliberately dumb — a parser here would be more machinery
// than the assertion is worth.
func funcBody(t *testing.T, src, decl string) string {
	t.Helper()
	i := strings.Index(src, decl)
	if i < 0 {
		t.Fatalf("函数 %q 不存在了。这条围栏钉的是它的性质,如果它被改名/合并,"+
			"请把围栏迁到新的出口上,而不是删掉", decl)
	}
	rest := src[i:]
	if j := strings.Index(rest, "\n}\n"); j >= 0 {
		return rest[:j]
	}
	return rest
}
