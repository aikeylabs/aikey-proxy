package supervisor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

// TestGradingDownlink_SingleRejectEmitsOneWarn guards the「一条 WARN」clause of
// R-compliance-grading-14.S2 (运行时遇到非法策略保留上一份有效值): ONE unusable
// policy download (oversize, or bad JSON) produces EXACTLY ONE WARN-level log
// line carrying a recognizable event.name and the reason code for THAT failure,
// while the runtime keeps enforcing the last valid policy.
//
// Why a separate fence: TestGradingDownlink_RejectStreakEscalatesPastWarn only
// asserts the ONE ERROR after a sustained run; nothing asserted the per-poll
// WARN the escalation is documented to rise above. Zero WARNs hides the first
// rejection from anyone reading logs; two WARNs for one poll double-count it.
//
// Driven through syncComplianceMasterPolicy — the real poller entry — so every
// log line the production path emits for one poll is in scope, not just the
// ones a single helper happens to write.
//
// Scope (user decision 2026-09-15, TODO-103 14.S2 row): unusable documents only.
// Network errors and non-200 answers are deliberately NOT covered here.
//
// spec: R-compliance-grading-14.S2
// (roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/openspec/specs/compliance-grading/spec.md)
func TestGradingDownlink_SingleRejectEmitsOneWarn(t *testing.T) {
	for _, c := range []struct{ name, body, wantEvent, wantCode string }{
		{"oversize grading document", gradingOversizePolicyBody(),
			observability.EventComplianceGradingInvalid, observability.ErrCodeComplianceGradingUnusable},
		{"malformed JSON", `{"enabled":true,"grading":{"ladder":}}`,
			observability.EventCompliancePolicyUndecodable, observability.ErrCodeCompliancePolicyUndecodable},
		{"grading not an object", `{"enabled":true,"grading":"nope"}`,
			observability.EventComplianceGradingInvalid, observability.ErrCodeComplianceGradingUnusable},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, seeded := seedGradingSupervisor(t)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			t.Setenv("AIKEY_HUB_CONTROL_URL", srv.URL)
			t.Setenv("AIKEY_HUB_ORG_ID", "org-synthetic-103b")

			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			defer slog.SetDefault(prev)

			s.syncComplianceMasterPolicy(t.Context())

			// Precondition: the poll really reached the handling code (a missing
			// URL/org early-returns silently and would make "0 WARN" meaningless).
			if rejects, attempted := s.ComplianceMasterPolicyHealth(); !attempted || rejects != 1 {
				t.Fatalf("precondition: one poll must be recorded as one rejection; rejects=%d attempted=%v",
					rejects, attempted)
			}
			// Runtime keeps the last valid policy (L5 = block), never {}.
			if got := s.gradingEnvValue(); got != seeded {
				t.Fatalf("AIKEY_COMPLIANCE_GRADING = %q, want the last valid %q", got, seeded)
			}

			warns := warnRecords(t, buf.Bytes())
			if len(warns) != 1 {
				t.Fatalf("one rejected policy download logged %d WARN lines, want exactly 1.\nlogs:\n%s",
					len(warns), buf.String())
			}
			if name, _ := warns[0]["event.name"].(string); name != c.wantEvent {
				t.Fatalf("the WARN has event.name %q, want %q.\nlogs:\n%s", name, c.wantEvent, buf.String())
			}
			if code, _ := warns[0]["error.code"].(string); code != c.wantCode {
				t.Fatalf("the WARN has error.code %q, want reason code %q.\nlogs:\n%s", code, c.wantCode, buf.String())
			}
		})
	}
}

// warnRecords returns every WARN-level record in a slog JSON handler stream.
func warnRecords(t *testing.T, logs []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(logs))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("unparseable log line %q: %v", sc.Text(), err)
		}
		if rec["level"] == slog.LevelWarn.String() {
			out = append(out, rec)
		}
	}
	return out
}
