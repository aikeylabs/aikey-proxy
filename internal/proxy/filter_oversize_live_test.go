package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
)

// TestApplyInboundFilter_LiveDetector_OversizeVerdictNeverForwardedUnscanned —
// fence F1 of TODO-120 (P0: repeating a sensitive value a few hundred times made
// the content bypass compliance inspection).
//
// GIVEN the real ai-compliance-detector on a TEAM route, and one user message
// that repeats built-in PII values up to just under the proxy's 16 KiB pipe input
// cap (so no tail is forwarded unscanned for an unrelated reason)
// WHEN the detector's verdict frame for that piece exceeds the pipe's single-frame
// limit (pipewire.MaxPayloadBytes)
// THEN the raw values never reach the forwarded body (refused with 403
// COMPLIANCE_BLOCKED, or — once the detector budgets its frame, TODO-120-A —
// masked), the child stays healthy and is not restarted, and both a later and a
// concurrent small PII request on the same hook are still masked.
//
// BUT NOT: before TODO-120-D the proxy marked the child degraded on the frame
// header, failed this request and every in-flight request OPEN after the
// deadline, and failed later requests open instantly until a respawn.
//
// The name starts with TestApplyInboundFilter_LiveDetector on purpose:
// `make -f workflow/CI/Makefile p4-filter-live` selects by that prefix and routes
// the run through the compliance result gate, so a skip is RED there.
//
// Related: TODO-120 (需求包 roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// task-execution/TODO.md) · R-compliance-canned-answer-6 (an unreadable verdict
// fails closed; TODO-120 extends its reach to an oversize frame).
func TestApplyInboundFilter_LiveDetector_OversizeVerdictNeverForwardedUnscanned(t *testing.T) {
	bin, sealed := liveDetectorBinary(t, "the TODO-120 oversize-verdict live fence")

	hook := apphook.NewChildHook(&apphook.ChildHookConfig{
		Name:       "ai-compliance-detector",
		BinaryPath: bin,
		// Generous on purpose: this fence is about the FRAME limit, not the
		// detection deadline (that bypass is TODO-121). A tight deadline would let
		// a timeout fail the request open and confound the two causes.
		Timeout:      10 * time.Second,
		ReadyTimeout: 15 * time.Second,
	})
	if err := hook.Start(context.Background()); err != nil {
		t.Fatalf("spawn detector: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = hook.Shutdown(ctx)
		cancel()
	}()
	sealed.AssertHeld(t, hook)

	// Same synthetic values TestApplyInboundFilter_LiveDetector proves the shipped
	// detector masks (see that test for why these exact literals: valid GB 11643
	// check digit, and a phone outside the obvious-non-live veto list).
	const (
		idCard = "110101199003077424"
		phone  = "13857492631"
	)
	unit := "客户手机号 " + phone + "，身份证号 " + idCard + "；"
	bigText := strings.Repeat(unit, (pipeInputCap-512)/len(unit))
	if len(bigText) >= pipeInputCap {
		t.Fatalf("fixture %d bytes reaches the pipe input cap %d; the tail would be forwarded unscanned for a different reason", len(bigText), pipeInputCap)
	}
	smallText := "请帮我核对客户手机号 " + phone + "，身份证号 " + idCard + " 是否正确"

	chatBody := func(content string) string {
		b, err := json.Marshal(map[string]any{
			"model":    "claude-3-5-sonnet",
			"messages": []map[string]string{{"role": "user", "content": content}},
		})
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		return string(b)
	}

	p := &Proxy{filterHook: hook}
	before := hook.Status()
	statusLine := func() string {
		s := hook.Status()
		return "healthy=" + boolStr(s.Healthy) + " degraded_reason=" + s.DegradedReason
	}

	type outcome struct {
		proceed   bool
		code      int
		respBody  string
		forwarded string
	}
	run := func(content string) outcome {
		r := newReq(chatBody(content))
		w := httptest.NewRecorder()
		proceed := p.applyInboundFilter(w, r, "claude-3-5-sonnet", "team", "org-fixture", "vk-fixture", "", "", "", discardLogger())
		o := outcome{proceed: proceed, code: w.Code, respBody: w.Body.String()}
		if proceed {
			o.forwarded = readReqBody(t, r)
		}
		return o
	}
	// ① the large piece is never forwarded with its raw values.
	assertBigNotLeaked := func(t *testing.T, o outcome) {
		t.Helper()
		if !o.proceed {
			if o.code != http.StatusForbidden || !strings.Contains(o.respBody, "COMPLIANCE_BLOCKED") {
				t.Errorf("refused, but not as 403 COMPLIANCE_BLOCKED: status=%d body=%q", o.code, o.respBody)
			}
			return
		}
		if strings.Contains(o.forwarded, phone) || strings.Contains(o.forwarded, idCard) {
			t.Errorf("large repeated-PII piece was FORWARDED with raw values (unscanned bypass). %s", statusLine())
		}
	}
	assertSmallMasked := func(t *testing.T, o outcome) {
		t.Helper()
		if !o.proceed {
			t.Errorf("small PII request was refused (status=%d), want masked and forwarded. %s", o.code, statusLine())
			return
		}
		if strings.Contains(o.forwarded, phone) || strings.Contains(o.forwarded, idCard) {
			t.Errorf("small PII request forwarded with raw values — the hook failed it open. %s", statusLine())
		}
	}
	assertHookIntact := func(t *testing.T) {
		t.Helper()
		s := hook.Status()
		// ② healthy
		if !s.Healthy {
			t.Errorf("hook unhealthy after an oversize verdict: %s", statusLine())
		}
		// ③ not restarted
		if s.RestartCount != before.RestartCount {
			t.Errorf("RestartCount %d → %d: an oversize verdict must not cost the child its pipe", before.RestartCount, s.RestartCount)
		}
	}

	t.Run("large_piece_alone", func(t *testing.T) {
		o := run(bigText)
		t.Logf("large piece (%d bytes): proceed=%v status=%d; %s", len(bigText), o.proceed, o.code, statusLine())
		assertBigNotLeaked(t, o)
		assertHookIntact(t)
		// NO oversize-counter assertion here, on purpose (2026-09-15, user ruling).
		// TODO-120 has two halves and this leg exercises the END STATE of both:
		// the detector's frame budget (A) compacts the reply BEFORE it is written
		// (observed on this very run: findings_before=1736 kept=3,
		// frame_bytes_before=425822 after=848), so a CURRENT detector never hands
		// the proxy an oversize frame and D's unreadable-verdict branch is
		// unreachable from here. Asserting the counter would therefore pin a path
		// that only an OLD detector can reach — the fence would be red for the
		// right system and green for the wrong one.
		//
		// D's branch and its counter stay fenced where they are reachable
		// deterministically: TestApplyInboundFilter_OversizeVerdictFailsClosedAndIsCounted
		// (filter_oversize_test.go, real dispatcher + a stub child that writes an
		// oversize frame) and TestChildHook_OversizeFrameFailsClosedAndStreamStaysInSync.
		// What this leg owns is the property the bypass was about: a hit-explosion
		// piece is never forwarded unscanned, and the child survives it.
		if o.proceed && !strings.Contains(o.forwarded, "{{") {
			t.Errorf("large repeated-PII piece was forwarded with no placeholder at all — "+
				"neither refused nor masked. %s", statusLine())
		}
	})

	// ④ the next small request on the SAME hook is inspected, not failed open.
	t.Run("next_small_request_masked", func(t *testing.T) {
		res := hook.Detect(context.Background(), &apphook.Request{
			Direction:  apphook.DirectionInbound,
			Payload:    []byte(smallText),
			RouteClass: apphook.RouteClassTeam,
		})
		if res.Degraded {
			t.Errorf("small Detect after the oversize verdict came back Degraded (reason %q)", res.Reason)
		}
		if res.Action != apphook.ActionMask {
			t.Errorf("small Detect action = %s, want mask", res.Action)
		}
		assertSmallMasked(t, run(smallText))
		assertHookIntact(t)
	})

	// ⑤ requests in flight alongside the large one are all inspected.
	t.Run("concurrent_small_requests_masked", func(t *testing.T) {
		const n = 8
		var wg sync.WaitGroup
		bigOut := make(chan outcome, 1)
		wg.Add(1)
		go func() { defer wg.Done(); bigOut <- run(bigText) }()
		// Let the large request reach the pipe first so the small ones are queued
		// behind its oversize reply rather than ahead of it.
		time.Sleep(20 * time.Millisecond)
		smallOut := make(chan outcome, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); smallOut <- run(smallText) }()
		}
		wg.Wait()
		close(smallOut)
		assertBigNotLeaked(t, <-bigOut)
		for o := range smallOut {
			assertSmallMasked(t, o)
		}
		assertHookIntact(t)
	})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
