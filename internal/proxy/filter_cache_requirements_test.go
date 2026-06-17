package proxy

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// contentAwareHook masks any piece whose payload contains maskFor, else allows.
// Lets a test assert end-to-end that SPECIFIC content gets masked (vs the
// all-or-nothing stubHook).
type contentAwareHook struct {
	maskFor string
	called  int
}

func (h *contentAwareHook) Name() string { return "content-aware" }
func (h *contentAwareHook) Detect(_ context.Context, req *apphook.Request) *apphook.Response {
	h.called++
	if strings.Contains(string(req.Payload), h.maskFor) {
		return &apphook.Response{Action: apphook.ActionMask, MutatedPayload: []byte("[MASKED]")}
	}
	return &apphook.Response{Action: apphook.ActionAllow}
}
func (h *contentAwareHook) Status() *apphook.Status { return &apphook.Status{Healthy: true} }

// ─────────────────────────────────────────────────────────────────────────────
// 这三个测试直接对应用户在设计讨论中明确强调的需求,各注明对应需求。
// ─────────────────────────────────────────────────────────────────────────────

// 需求①(核心):多轮对话里,用户先前说过的敏感词在历史里**仍被 mask、不原文透传**。
// 即"他是谁"那种场景的根因修复 —— 缓存命中也要复用打码,而不是放行。
func TestReq_HistorySensitiveStaysMaskedAcrossTurns(t *testing.T) {
	hook := &contentAwareHook{maskFor: "secret"}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	// 第1轮:用户发敏感词
	r1 := newReq(`{"messages":[{"role":"user","content":"secret"}]}`)
	p.applyInboundFilter(httptest.NewRecorder(), r1, "m", "personal", "", "", discardLogger())

	// 第2轮:敏感词进历史,最新 turn 是普通追问
	r2 := newReq(`{"messages":[{"role":"user","content":"secret"},{"role":"assistant","content":"ok"},{"role":"user","content":"more"}]}`)
	p.applyInboundFilter(httptest.NewRecorder(), r2, "m", "personal", "", "", discardLogger())

	body2 := readReqBody(t, r2)
	if strings.Contains(body2, "secret") {
		t.Error("需求①失败:历史里的敏感词原文透传了(根因漏点未堵)")
	}
	if !strings.Contains(body2, "[MASKED]") {
		t.Error("需求①失败:历史敏感词应从缓存复用打码")
	}
	if hook.called != 2 { // secret 命中缓存复用;assistant"ok"不扫(返回内容);只扫 more
		t.Errorf("需求①(性能侧):Detect 累计 %d, want 2(secret 命中缓存、assistant 不扫、只扫 more)", hook.called)
	}
}

// 需求②:不能串 —— 一个 OpenClaw/gateway 多用户多会话,不同会话即使发**相同内容**,
// 也不能复用彼此的判定(缓存按 scope 隔离)。
func TestReq_NoCrossSessionReuse(t *testing.T) {
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionMask, MutatedPayload: []byte("[M]")}}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	send := func(sess string) {
		r := newReq(`{"messages":[{"role":"user","content":"same-content"}]}`)
		r.Header.Set("X-Claude-Code-Session-Id", sess) // scope = h:<sess>
		p.applyInboundFilter(httptest.NewRecorder(), r, "m", "personal", "", "", discardLogger())
	}

	send("sessA") // 首次 → 扫,called=1
	send("sessA") // 同会话同内容 → 命中,called 仍 1
	if hook.called != 1 {
		t.Fatalf("同会话同内容应复用:called %d, want 1", hook.called)
	}
	send("sessB") // 不同会话同内容 → 不能串 → 必须重扫
	if hook.called != 2 {
		t.Errorf("需求②失败:跨会话串了!sessB 复用了 sessA 的判定:called %d, want 2", hook.called)
	}
}

// 需求③:compaction 安全 —— 历史被压成 summary(新文本)后,summary 是新内容,
// 必须被重扫(不能因为"同一会话"就跳过),且 summary 里的敏感词不漏。
func TestReq_CompactionRescansSummary(t *testing.T) {
	hook := &contentAwareHook{maskFor: "敏感"}
	p := &Proxy{filterHook: hook}
	p.SetFilterCacheEnabled(true, 5)

	// 第1轮:原始敏感消息
	r1 := newReq(`{"messages":[{"role":"user","content":"敏感原文X"}]}`)
	p.applyInboundFilter(httptest.NewRecorder(), r1, "m", "personal", "", "", discardLogger())
	if hook.called != 1 {
		t.Fatalf("turn1 called %d, want 1", hook.called)
	}

	// 第2轮(compaction):历史被压成 summary(全新文本),原消息消失
	r2 := newReq(`{"messages":[{"role":"user","content":"总结:用户提过敏感的事"}]}`)
	p.applyInboundFilter(httptest.NewRecorder(), r2, "m", "personal", "", "", discardLogger())

	if hook.called != 2 {
		t.Errorf("需求③失败:compaction summary 没被重扫:called %d, want 2(summary 是新 hash 必 miss)", hook.called)
	}
	if body2 := readReqBody(t, r2); strings.Contains(body2, "敏感") {
		t.Error("需求③失败:compaction summary 里的敏感词漏了(未 mask)")
	}
}
