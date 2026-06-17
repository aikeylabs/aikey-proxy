package proxy

import (
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// openClawShape mimics how OpenClaw / Claude Code / Codex / Cursor resend the
// FULL conversation each turn: a big static system prompt + prior history +
// the new user message last. Only the last user message is new.
func openClawShape(latestUser string) string {
	bigSystem := strings.Repeat("你是数字员工助手，遵循以下守则：", 400) // ~多KB 静态 system
	return `{"model":"claude-sonnet-4-5","stream":true,` +
		`"system":"` + bigSystem + `",` +
		`"messages":[` +
		`{"role":"user","content":"第一轮历史问题"},` +
		`{"role":"assistant","content":"第一轮历史回答"},` +
		`{"role":"user","content":"` + latestUser + `"}]}`
}

// TestExtractLatestUserContent_HappyPath: incremental extraction returns ONLY
// the latest user turn — not system, not history.
func TestExtractLatestUserContent_HappyPath(t *testing.T) {
	pieces, parsed, ok := extractLatestUserContent([]byte(openClawShape("请登记身份证 110101199003078515")))
	if !ok {
		t.Fatal("expected ok for a normal user-terminated request")
	}
	if len(pieces) != 1 {
		t.Fatalf("expected exactly 1 piece (latest user turn), got %d", len(pieces))
	}
	if pieces[0].text != "请登记身份证 110101199003078515" {
		t.Errorf("extracted wrong text: %q", pieces[0].text)
	}
	if parsed == nil {
		t.Error("parsed map must be returned for mask write-back")
	}
}

// TestExtractLatestUserContent_SafetyFallbacks: every shape it can't confidently
// reduce MUST return ok=false so the caller falls back to a full scan.
func TestExtractLatestUserContent_SafetyFallbacks(t *testing.T) {
	cases := []struct{ name, body string }{
		{"non_json", `not json at all`},
		{"no_messages", `{"model":"m","system":"hi"}`},
		{"empty_messages", `{"model":"m","messages":[]}`},
		{"last_is_assistant", `{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"yo"}]}`},
		{"last_user_no_text", `{"messages":[{"role":"user","content":[{"type":"tool_result","content":"x"}]}]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, ok := extractLatestUserContent([]byte(c.body))
			if ok {
				t.Errorf("%s: expected ok=false (force full-scan fallback), got ok=true", c.name)
			}
		})
	}
}

// TestApplyInboundFilter_DeprecatedIncrementalNowFullScans: the old
// "incremental" (latest-user-turn-only) mode is DEPRECATED (2026-06-16 history-leak
// fix). Even with filterIncremental=true (the env is still set on form-② lobster
// installs), applyInboundFilter now FULL-SCANS every piece — so a sensitive word the
// user sent in HISTORY is re-scanned every turn instead of being skipped (→ no leak).
func TestApplyInboundFilter_DeprecatedIncrementalNowFullScans(t *testing.T) {
	body := openClawShape("他是谁") // 历史里有"第一轮历史问题";最新 turn 普通追问

	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}
	// filterIncremental=true:旧 env 仍开,但已被忽略 → 仍走全量扫。
	p := &Proxy{filterHook: hook, filterIncremental: true}
	if proceed := p.applyInboundFilter(nil, newReq(body), "m", "personal", "", "", discardLogger()); !proceed {
		t.Fatal("expected proceed")
	}
	// 全量扫:system + 3 条消息都扫 → >1 次。增量(旧漏因)只会 1 次(只扫最新 turn)。
	if hook.called <= 1 {
		t.Errorf("历史漏扫修复后必须全量扫(system+history+latest);got %d(=1 说明还在只扫最新 turn、没修)", hook.called)
	}
}

// TestApplyInboundFilter_IncrementalFallsBackOnAgentLoop: an agent-loop request
// ending in a non-user message MUST fall back to a full scan (incremental
// returns ok=false), so we never silently skip filtering.
func TestApplyInboundFilter_IncrementalFallsBackOnAgentLoop(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"前文"},{"role":"assistant","content":"工具调用"}]}`
	hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow}}
	p := &Proxy{filterHook: hook, filterIncremental: true}
	if proceed := p.applyInboundFilter(nil, newReq(body), "m", "personal", "", "", discardLogger()); !proceed {
		t.Fatal("expected proceed")
	}
	// Full-scan fallback ran (the user piece got scanned), not a silent skip.
	if hook.called == 0 {
		t.Error("agent-loop request was silently skipped — must fall back to full scan")
	}
}
