package proxy

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// TestApplyInboundFilter_OversizeVerdictFailsClosedAndIsCounted — dispatcher half
// of TODO-120 (no detector binary; the live half is
// TestApplyInboundFilter_LiveDetector_OversizeVerdictNeverForwardedUnscanned and
// the pipe half is internal/apphook TestChildHook_OversizeFrameFailsClosedAndStreamStaysInSync).
//
// GIVEN a hook reporting a verdict it could not read (VerdictUnreadable: the
// child's frame exceeded the pipe limit), on a personal AND a team route
// WHEN applyInboundFilter dispatches
// THEN the request is refused with 403 COMPLIANCE_BLOCKED and the constant
// message, the hook's Reason is never echoed, the WARN
// proxy.filter.verdict_unreadable_oversize names the frame size without content,
// and /v1/diagnostics/pipeline counts it.
// BUT NOT: fail-open. The Degraded path next door stays fail-open
// (TestApplyInboundFilter_DegradedFailsOpen).
func TestApplyInboundFilter_OversizeVerdictFailsClosedAndIsCounted(t *testing.T) {
	const reasonMarker = "reason-from-an-unread-frame"
	hook := &stubHook{resp: &apphook.Response{
		// ChildHook's shape. Action is already Block; the dispatcher must refuse on
		// VerdictUnreadable itself, so the Allow row below proves it does not lean
		// on the action byte.
		Action:               apphook.ActionBlock,
		VerdictUnreadable:    true,
		UnreadableFrameBytes: 425822,
		Reason:               reasonMarker,
	}}

	for _, tc := range []struct {
		name, route string
		action      apphook.Action
	}{
		{"personal_block", "personal", apphook.ActionBlock},
		{"team_block", "team", apphook.ActionBlock},
		{"team_action_byte_allow", "team", apphook.ActionAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook.resp.Action = tc.action
			hook.resp.Reason = reasonMarker
			p := &Proxy{filterHook: hook}
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
			r := newReq(`{"model":"m","messages":[{"role":"user","content":"synthetic oversize fixture"}]}`)
			w := httptest.NewRecorder()

			if p.applyInboundFilter(w, r, "m", tc.route, "org-fixture", "vk-fixture", "", "", "", logger) {
				t.Fatalf("unreadable (oversize) verdict must fail CLOSED; proceed=true forwards the content unscanned")
			}
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "COMPLIANCE_BLOCKED") {
				t.Errorf("status=%d body=%q, want 403 COMPLIANCE_BLOCKED", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "request blocked by compliance policy") {
				t.Errorf("client must get the constant refusal message, got %q", w.Body.String())
			}
			if strings.Contains(w.Body.String(), reasonMarker) {
				t.Errorf("the unread verdict's Reason leaked into the client response: %q", w.Body.String())
			}
			out := logs.String()
			if !strings.Contains(out, observability.EventProxyFilterVerdictUnreadableOversize) ||
				!strings.Contains(out, "frame_bytes=425822") || !strings.Contains(out, "max_bytes=65536") {
				t.Errorf("missing WARN %s with frame_bytes/max_bytes, got logs:\n%s",
					observability.EventProxyFilterVerdictUnreadableOversize, out)
			}
			if strings.Contains(out, "synthetic oversize fixture") || strings.Contains(out, reasonMarker) {
				t.Errorf("WARN must be content-free, got logs:\n%s", out)
			}
			if !strings.Contains(readPipelineDiagnostics(t, p), `"scan_unreadable_oversize_verdicts":1`) {
				t.Errorf("/v1/diagnostics/pipeline does not count the refusal:\n%s", readPipelineDiagnostics(t, p))
			}
		})
	}
}
