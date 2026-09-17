package proxy

// filter_scan_incomplete_live_test.go — fences F8/F9 of TODO-121 (需求包
// roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// task-execution/runs/design-todo-121.md §5).
//
// The REAL detector binary, over the REAL v4 pipe, through the REAL dispatcher.
// Everything else in this change is fenced against a stub; this is the leg that
// proves the two processes agree.
//
// 🔴 TRIGGERED DETERMINISTICALLY, BY CONFIGURATION — not by making the machine
// slow. The bypass this task closes used to be reachable only when a lane
// overran a 100ms wall clock, so the equivalent TODO-120 fence had to retry five
// times and still flaked. Because the safety judgement now hangs off a HIT
// BUDGET, and the budget is readable from the child's environment, this fence
// sets AIKEY_COMPLIANCE_LANE_HIT_BUDGET=3 on the spawned detector and the
// truncation happens on every run, on any machine.
//
// Both names start with TestApplyInboundFilter_LiveDetector on purpose:
// `make -f workflow/CI/Makefile p4-filter-live` selects by that prefix and routes
// the run through the compliance result gate, where a SKIP is red.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// liveScanIncompleteBody builds a chat request carrying one content piece.
func liveScanIncompleteBody(t *testing.T, content string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"model":    "claude-3-5-sonnet",
		"messages": []map[string]string{{"role": "user", "content": content}},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return string(b)
}

// spawnLiveDetector starts the real detector with the given extra environment
// and returns a Proxy wired to it.
func spawnLiveDetector(t *testing.T, what string, extraEnv []string) (*Proxy, *apphook.ChildHook) {
	t.Helper()
	bin, sealed := liveDetectorBinary(t, what)
	hook := apphook.NewChildHook(&apphook.ChildHookConfig{
		Name:       "ai-compliance-detector",
		BinaryPath: bin,
		// Generous: this fence is about COMPLETENESS of the scan, not about the
		// per-Detect deadline. A tight timeout would let the proxy's own fail-open
		// path answer first and confound the two causes.
		Timeout:      10 * time.Second,
		ReadyTimeout: 15 * time.Second,
		ExtraEnv:     extraEnv,
	})
	if err := hook.Start(context.Background()); err != nil {
		t.Fatalf("spawn detector: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = hook.Shutdown(ctx)
		cancel()
	})
	sealed.AssertHeld(t, hook)
	return &Proxy{filterHook: hook}, hook
}

// TestApplyInboundFilter_LiveDetector_HitExplosionNeverForwardedUnscanned — F8.
//
// GIVEN the real detector with its per-lane hit budget forced to 3, and a piece
// that repeats a built-in PII value far more than 3 times
// WHEN the request goes through applyInboundFilter
// THEN the raw values never appear in the forwarded body — the request is either
// refused (403 COMPLIANCE_BLOCKED) or masked — and the child stays healthy and is
// not restarted.
//
// BUT NOT: before TODO-121 a scan that did not finish produced zero findings,
// which the detector read as 「no findings → allow」, and the prompt was forwarded
// with its values intact.
func TestApplyInboundFilter_LiveDetector_HitExplosionNeverForwardedUnscanned(t *testing.T) {
	p, hook := spawnLiveDetector(t, "the TODO-121 incomplete-scan live fence",
		[]string{"AIKEY_COMPLIANCE_LANE_HIT_BUDGET=3"})

	// The same synthetic values the sibling live fences prove the shipped
	// detector masks (valid GB 11643 check digit; a phone outside the
	// obvious-non-live veto list).
	const (
		idCard = "110101199003077424"
		phone  = "13857492631"
	)
	unit := "客户手机号 " + phone + "，身份证号 " + idCard + "；"
	big := strings.Repeat(unit, (pipeInputCap-512)/len(unit))
	if len(big) >= pipeInputCap {
		t.Fatalf("fixture %d bytes reaches the pipe input cap %d; the tail would be forwarded "+
			"unscanned for an unrelated reason", len(big), pipeInputCap)
	}

	before := hook.Status()
	r := newReq(liveScanIncompleteBody(t, big))
	w := httptest.NewRecorder()
	proceed := p.applyInboundFilter(w, r, "claude-3-5-sonnet", "team", "org-fixture", "vk-fixture",
		"", "", "", discardLogger())

	if proceed {
		forwarded := readReqBody(t, r)
		if strings.Contains(forwarded, phone) || strings.Contains(forwarded, idCard) {
			t.Fatalf("a piece whose scan was TRUNCATED at the hit budget was forwarded with its raw "+
				"values intact — this is the TODO-121 bypass (healthy=%v reason=%q)",
				hook.Status().Healthy, hook.Status().DegradedReason)
		}
		if !strings.Contains(forwarded, "{{") {
			t.Fatalf("the piece was forwarded with neither a refusal nor a placeholder — it was " +
				"neither masked nor blocked, i.e. it went upstream uninspected")
		}
	} else if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "COMPLIANCE_BLOCKED") {
		t.Fatalf("refused, but not as 403 COMPLIANCE_BLOCKED: status=%d body=%q", w.Code, w.Body.String())
	}

	// The child did its job and must survive it: a truncated scan is a verdict,
	// not a crash.
	s := hook.Status()
	if !s.Healthy {
		t.Errorf("child unhealthy after a truncated scan: reason=%q", s.DegradedReason)
	}
	if s.RestartCount != before.RestartCount {
		t.Errorf("RestartCount %d → %d: a truncated scan must not cost the child its pipe",
			before.RestartCount, s.RestartCount)
	}

	// And the next ordinary request on the SAME child is still inspected — the
	// budget is per request, not a latch.
	small := "请帮我核对客户手机号 " + phone + "，身份证号 " + idCard + " 是否正确"
	r2 := newReq(liveScanIncompleteBody(t, small))
	w2 := httptest.NewRecorder()
	if p.applyInboundFilter(w2, r2, "claude-3-5-sonnet", "team", "org-fixture", "vk-fixture",
		"", "", "", discardLogger()) {
		if f := readReqBody(t, r2); strings.Contains(f, phone) || strings.Contains(f, idCard) {
			t.Errorf("a small PII request after the truncated one was forwarded unmasked — the hook " +
				"failed it open")
		}
	}
}

// TestApplyInboundFilter_LiveDetector_NormalLargeTextStillPasses — F9, the UX
// regression fence.
//
// 🔴 THIS IS THE ONE THAT SAYS THE FIX IS SHIPPABLE. Every other fence here
// pushes toward refusing; without a control that ordinary traffic is untouched,
// a build that simply refused everything would pass all of them. It runs at the
// SHIPPED budget (no env override) because the number that has to be safe is the
// default, and 16KB of ordinary Chinese prose is the realistic large-prompt
// shape — measured at 1-70 findings against a budget of 585 (report §1.5).
func TestApplyInboundFilter_LiveDetector_NormalLargeTextStillPasses(t *testing.T) {
	p, _ := spawnLiveDetector(t, "the TODO-121 ordinary-traffic control", nil)

	const filler = "今天下午的评审会我们过了一遍新版本的发布计划，测试环境的回归结果整体符合预期，" +
		"剩余两个问题排到下个迭代处理，注意接口的兼容性和数据的正确性。"
	var sb strings.Builder
	for sb.Len() < pipeInputCap-1024 {
		sb.WriteString(filler)
	}
	prose := sb.String()

	r := newReq(liveScanIncompleteBody(t, prose))
	w := httptest.NewRecorder()
	if !p.applyInboundFilter(w, r, "claude-3-5-sonnet", "team", "org-fixture", "vk-fixture",
		"", "", "", discardLogger()) {
		t.Fatalf("16KB of ORDINARY prose was refused (status=%d, body=%q). The hit budget must sit far "+
			"above what legitimate traffic produces — a fail-closed rule that fires on normal text is "+
			"an outage, not a fix.", w.Code, w.Body.String())
	}
	if got := readReqBody(t, r); !strings.Contains(got, "评审会") {
		t.Errorf("ordinary prose was mutated on the way upstream")
	}
}
