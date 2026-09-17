package proxy

// filter_scan_incomplete_test.go — fences F5/F6/F7 of TODO-121 (需求包
// roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// task-execution/runs/design-todo-121.md §5).
//
// The dispatcher half: a verdict the detector produced from a scan that did NOT
// finish must be REFUSED, must never be cached, and must not drag the ordinary
// timeout path (which stays fail-open) with it.

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// TestApplyInboundFilter_IncompleteVerdictFailsClosed — F5.
//
// GIVEN a hook whose response says the scan did not look at everything
// WHEN applyInboundFilter dispatches it, on a personal AND a team route
// THEN the request is refused (403 COMPLIANCE_BLOCKED, constant message), the
// hook's Reason is never echoed to the caller, the WARN
// proxy.filter.scan_incomplete is emitted content-free, and
// /v1/diagnostics/pipeline counts it.
//
// BUT NOT: fail-open. The Degraded path next door is unchanged — see
// TestApplyInboundFilter_DegradedFailsOpen, the control this change must not
// break (F6).
//
// 🔴 THE ACTION BYTE IS DELIBERATELY `Allow` IN EVERY ROW. If the dispatcher
// leaned on the action instead of on ScanIncomplete, this fence would pass while
// a real incomplete-but-allowed verdict sailed through — which is the exact bug.
func TestApplyInboundFilter_IncompleteVerdictFailsClosed(t *testing.T) {
	const reasonMarker = "reason-from-an-unfinished-scan"
	const contentMarker = "synthetic incomplete-scan fixture"

	for _, route := range []string{"personal", "team"} {
		t.Run(route, func(t *testing.T) {
			hook := &stubHook{resp: &apphook.Response{
				Action:         apphook.ActionAllow,
				ScanIncomplete: true,
				Reason:         reasonMarker,
			}}
			p := &Proxy{filterHook: hook}
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
			r := newReq(`{"model":"m","messages":[{"role":"user","content":"` + contentMarker + `"}]}`)
			w := httptest.NewRecorder()

			if p.applyInboundFilter(w, r, "m", route, "org-fixture", "vk-fixture", "", "", "", logger) {
				t.Fatalf("an INCOMPLETE scan must fail CLOSED; proceed=true forwards content that was " +
					"never fully inspected (TODO-121, the P0)")
			}
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "COMPLIANCE_BLOCKED") {
				t.Errorf("status=%d body=%q, want 403 COMPLIANCE_BLOCKED", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "request blocked by compliance policy") {
				t.Errorf("client must get the constant refusal message, got %q", w.Body.String())
			}
			if strings.Contains(w.Body.String(), reasonMarker) {
				t.Errorf("the unfinished scan's Reason leaked to the caller: %q", w.Body.String())
			}
			out := logs.String()
			if !strings.Contains(out, observability.EventProxyFilterScanIncomplete) {
				t.Errorf("missing WARN %s; logs:\n%s", observability.EventProxyFilterScanIncomplete, out)
			}
			if strings.Contains(out, contentMarker) || strings.Contains(out, reasonMarker) {
				t.Errorf("the WARN must be content-free; logs:\n%s", out)
			}
			if diag := readPipelineDiagnostics(t, p); !strings.Contains(diag, `"scan_incomplete_verdicts":1`) {
				t.Errorf("/v1/diagnostics/pipeline does not count the refusal:\n%s", diag)
			}
		})
	}
}

// TestApplyInboundFilter_IncompleteAndDegradedPointOppositeWays — F6 as an
// EXPLICIT pair rather than a promise.
//
// The two shapes differ by one field and must end in opposite outcomes:
//
//	Degraded       — the child could not ANSWER          → fail OPEN  (§6 #11)
//	ScanIncomplete — it answered, and did not finish     → fail CLOSED (TODO-121)
//
// Asserting them side by side is what makes "only the second one was reversed"
// a checked fact. TestApplyInboundFilter_DegradedFailsOpen still stands on its
// own next door; this row exists so the DIFFERENCE cannot quietly collapse.
func TestApplyInboundFilter_IncompleteAndDegradedPointOppositeWays(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"same content both ways"}]}`

	for _, tc := range []struct {
		name        string
		resp        *apphook.Response
		wantProceed bool
		why         string
	}{
		{
			name:        "degraded_fails_open",
			resp:        &apphook.Response{Action: apphook.ActionAllow, Degraded: true, Reason: "child unreachable"},
			wantProceed: true,
			why: "a filter that cannot run must NOT fail the user's request (§6 #11) — reversing this " +
				"would turn every detector restart into an outage",
		},
		{
			name:        "incomplete_fails_closed",
			resp:        &apphook.Response{Action: apphook.ActionAllow, ScanIncomplete: true},
			wantProceed: false,
			why:         "the child answered and said it did not finish — forwarding on that is the TODO-121 bypass",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := &stubHook{resp: tc.resp}
			p := &Proxy{filterHook: hook}
			r := newReq(body)
			w := httptest.NewRecorder()
			got := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", discardLogger())
			if got != tc.wantProceed {
				t.Fatalf("proceed = %v, want %v. %s", got, tc.wantProceed, tc.why)
			}
		})
	}
}

// TestFilterCache_IncompleteVerdictIsNeverCached — F7.
//
// A verdict produced from an unfinished scan must not be replayed. The cache
// holds entries for an hour with a SLIDING expiry, so one cached bad verdict is
// not a one-off: it is the same wrong answer for every repeat of that content
// for as long as the conversation stays alive. That is what turned an occasional
// miss into a durable one and is why TODO-121 calls the cache leg the highest
// value / lowest cost part of the fix.
//
// Observed through the hook's call count rather than by reaching into the cache:
// the question that matters is "was the detector asked again?", and asserting on
// internal cache state would pass even if the dispatcher stopped consulting it.
func TestFilterCache_IncompleteVerdictIsNeverCached(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"identical content on both turns"}]}`

	t.Run("incomplete_is_rescanned", func(t *testing.T) {
		hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow, ScanIncomplete: true}}
		p := &Proxy{filterHook: hook, filterCache: newSessionMaskCache(4, 8, time.Hour)}
		for turn := 1; turn <= 2; turn++ {
			r := newReq(body)
			w := httptest.NewRecorder()
			if p.applyInboundFilter(w, r, "m", "team", "org", "vk", "", "sess-1", "", discardLogger()) {
				t.Fatalf("turn %d: incomplete verdict must be refused", turn)
			}
		}
		if hook.called != 2 {
			t.Fatalf("detector called %d times over two identical turns, want 2 — a verdict from an "+
				"UNFINISHED scan was cached and replayed, so the same content would keep being judged "+
				"by a scan that never completed (sliding 1h TTL)", hook.called)
		}
	})

	// Control: the cache still works. Without this the assertion above would also
	// pass on a build where caching was broken outright.
	t.Run("control_complete_verdict_is_cached", func(t *testing.T) {
		hook := &stubHook{resp: &apphook.Response{
			Action:         apphook.ActionMask,
			MutatedPayload: []byte("identical content on both turns"),
		}}
		p := &Proxy{filterHook: hook, filterCache: newSessionMaskCache(4, 8, time.Hour)}
		for turn := 1; turn <= 2; turn++ {
			r := newReq(body)
			w := httptest.NewRecorder()
			if !p.applyInboundFilter(w, r, "m", "team", "org", "vk", "", "sess-2", "", discardLogger()) {
				t.Fatalf("turn %d: an ordinary mask verdict must proceed", turn)
			}
		}
		if hook.called != 1 {
			t.Fatalf("detector called %d times over two identical turns, want 1 — the ordinary verdict "+
				"cache is not working, so the assertion above proves nothing", hook.called)
		}
	})
}
