package proxy

// escalation_truncation_observability_test.go — fences for TODO-72 (alpha.9
// scope, user decision 2026-09-18: observable + declared; chunked scanning is
// the next release).
//
// THE BLIND SPOT THESE FENCES MAKE VISIBLE (they do NOT close it): a content
// piece longer than pipeInputCap (16 KiB) is scanned only up to the cap, so a
// hit in its tail never reaches the request-level cumulative counter. A request
// that should escalate at 3 distinct L4 hits can be counted at 2 and forwarded
// (measured: runs/todo-72-verify.md §1.1, third_id_in_tail).
//
// What is pinned here:
//  1. the escalation counters are readable on GET /v1/diagnostics/pipeline, and
//     a truncated request moves BOTH `evaluated` and
//     `evaluated_on_truncated_input` — so an operator can see how many
//     request-level verdicts were reached on incomplete input;
//  2. the `proxy.filter.escalated` line says when its count is only a lower
//     bound.
//
// 🔴 Nothing here asserts that the truncated request is FORWARDED. That is the
// known gap (DEC-compliance-grading-26), not a contract; pinning it would turn
// the next release's chunked scan into a "regression".
//
// rules (proposal-layer, hence `rule:` not `spec:`):
//
//	R-compliance-grading-17.S2  已知限制：16KB 截断使累计计数为下限
//	R-compliance-grading-15.S2  判定路径已执行（计数器可断言）
//
// TODO: TODO-72 (需求包 博时基金合规能力融合 task-execution/TODO.md)

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
)

const (
	truncIDA = "110101199003071234"
	truncIDB = "310101198807153695"
	truncIDC = "440305197502289517"
)

// idScanningHook plays a detector that finds every known ID in WHATEVER it was
// handed — which, for a piece over the cap, is only the head. Each hit is a
// confirmed L4 pii finding and every piece's own verdict is mask, so any
// refusal has to come from the cumulative rule.
func idScanningHook(t *testing.T) *contentScriptedHook {
	return &contentScriptedHook{answer: func(payload string) *apphook.Response {
		var hits []gradedHit
		masked := payload
		for _, id := range []string{truncIDA, truncIDB, truncIDC} {
			if strings.Contains(payload, id) {
				hits = append(hits, gradedHit{id, "pii", 4, true})
				masked = strings.ReplaceAll(masked, id, "{{IDCARD}}")
			}
		}
		if len(hits) == 0 {
			return &apphook.Response{Action: apphook.ActionAllow}
		}
		return &apphook.Response{
			Action:         apphook.ActionMask,
			MutatedPayload: []byte(masked),
			Event:          eventJSON(t, "ev-trunc-"+itoaInt64(int64(len(payload))), "mask", payload, hits),
		}
	}}
}

// overCapPiece returns one piece > pipeInputCap with `head` IDs before the cap
// and `tail` IDs after it.
func overCapPiece(head, tail []string) string {
	var b strings.Builder
	b.WriteString("客户名单：")
	for _, id := range head {
		b.WriteString(id + "；")
	}
	for b.Len() < pipeInputCap+64 {
		b.WriteString("x")
	}
	for _, id := range tail {
		b.WriteString("；" + id)
	}
	return b.String()
}

func readEscalationHealth(t *testing.T, p *Proxy) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	p.handleDiagnosticsPipeline(w, httptest.NewRequest(http.MethodGet, "/v1/diagnostics/pipeline", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("diagnostics status = %d", w.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode diagnostics: %v", err)
	}
	esc, ok := out["escalation"].(map[string]any)
	if !ok {
		t.Fatalf("GET /v1/diagnostics/pipeline has no `escalation` block — the request-level "+
			"verdict counters are not externally readable (TODO-72). body=%s", w.Body.String())
	}
	return esc
}

func escNum(t *testing.T, esc map[string]any, key string) int64 {
	t.Helper()
	v, ok := esc[key].(float64)
	if !ok {
		t.Fatalf("escalation.%s missing or not a number: %v", key, esc)
	}
	return int64(v)
}

// TestEscalationHealth_TruncatedRequestMovesBothCounters — GIVEN the cumulative
// rule «≥L4 ×3 → block» WHEN one request carries a >16KB piece with two IDs in
// the head and a third in the unscanned tail THEN the endpoint shows the verdict
// ran (evaluated +1) AND that it ran on truncated input
// (evaluated_on_truncated_input +1), with status lower_bound. An untruncated
// control request moves only `evaluated`.
func TestEscalationHealth_TruncatedRequestMovesBothCounters(t *testing.T) {
	p := &Proxy{filterHook: idScanningHook(t)}
	mustSetGrading(t, p, []EscalationRule{{MinLevel: 4, MinCount: 3, Action: "block"}})

	before := readEscalationHealth(t, p)
	if escNum(t, before, "evaluated") != 0 || escNum(t, before, "evaluated_on_truncated_input") != 0 {
		t.Fatalf("fresh generation must start at zero: %v", before)
	}
	if before["status"] != string(EscalationHealthOK) {
		t.Fatalf("rules configured, nothing evaluated: status = %v, want ok", before["status"])
	}

	// Control: short piece, not truncated.
	body := `{"messages":[{"role":"user","content":` + mustJSON(t, "客户 "+truncIDA) + `}]}`
	p.applyInboundFilter(httptest.NewRecorder(), newReq(body), "m", "team", "org-1", "vk-1", "seat-1", "sess-1", "trace-ctl", discardLogger())
	mid := readEscalationHealth(t, p)
	if got := escNum(t, mid, "evaluated"); got != 1 {
		t.Fatalf("control: evaluated = %d, want 1", got)
	}
	if got := escNum(t, mid, "evaluated_on_truncated_input"); got != 0 {
		t.Fatalf("control: an untruncated request moved evaluated_on_truncated_input to %d", got)
	}

	piece := overCapPiece([]string{truncIDA, truncIDB}, []string{truncIDC})
	body = `{"messages":[{"role":"user","content":` + mustJSON(t, piece) + `}]}`
	p.applyInboundFilter(httptest.NewRecorder(), newReq(body), "m", "team", "org-1", "vk-1", "seat-1", "sess-1", "trace-trunc", discardLogger())

	after := readEscalationHealth(t, p)
	if got := escNum(t, after, "evaluated"); got != 2 {
		t.Errorf("evaluated = %d, want 2", got)
	}
	if got := escNum(t, after, "evaluated_on_truncated_input"); got != 1 {
		t.Errorf("evaluated_on_truncated_input = %d, want 1 — a verdict reached on a truncated "+
			"request must be counted so the operator can see the blind spot", got)
	}
	if got := escNum(t, after, "last_counted"); got != 2 {
		t.Errorf("last_counted = %d, want 2 (the tail ID was never scanned)", got)
	}
	for _, k := range []string{"triggered", "unresolved_hits", "rules"} {
		escNum(t, after, k) // present and numeric
	}
	if after["status"] != string(EscalationHealthLowerBound) {
		t.Errorf("status = %v, want %s", after["status"], EscalationHealthLowerBound)
	}
	if r, _ := after["reason"].(string); !strings.Contains(r, "lower bound") {
		t.Errorf("reason must say the counts are a lower bound, got %q", r)
	}
}

// TestEscalationHealth_StatusPrecedence pins the pure verdict: no rules →
// inactive (whatever the counters say); a desync → degraded before lower_bound.
func TestEscalationHealth_StatusPrecedence(t *testing.T) {
	cases := []struct {
		name                          string
		rules, unresolved, truncEvals int
		want                          EscalationHealthStatus
	}{
		{"no rules", 0, 0, 5, EscalationHealthInactive},
		{"clean", 1, 0, 0, EscalationHealthOK},
		{"truncated input", 1, 0, 1, EscalationHealthLowerBound},
		{"desync wins", 1, 2, 1, EscalationHealthDegraded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{}
			if tc.rules > 0 {
				mustSetGrading(t, p, []EscalationRule{{MinLevel: 4, MinCount: 3, Action: "block"}})
			}
			p.escalationMetrics.unresolvedHits.Store(int64(tc.unresolved))
			p.escalationMetrics.evaluatedOnTruncated.Store(int64(tc.truncEvals))
			h := p.escalationHealth()
			if h.Status != tc.want {
				t.Fatalf("status = %s, want %s", h.Status, tc.want)
			}
			if h.Reason == "" {
				t.Fatal("reason must never be empty")
			}
		})
	}
}

// TestEscalation_EscalatedLogMarksTruncatedInputAsLowerBound — GIVEN «≥L4 ×3 →
// block» WHEN a >16KB piece carries all three IDs in its head (so the rule
// fires) THEN proxy.filter.escalated carries pieces_truncated=1 and
// counted_is_lower_bound=true. Control: the same IDs in a short piece log
// pieces_truncated=0, counted_is_lower_bound=false.
func TestEscalation_EscalatedLogMarksTruncatedInputAsLowerBound(t *testing.T) {
	cases := []struct {
		name      string
		piece     string
		wantTrunc int64
		wantLower bool
	}{
		{"truncated", overCapPiece([]string{truncIDA, truncIDB, truncIDC}, nil), 1, true},
		{"untruncated control", "客户 " + truncIDA + "；" + truncIDB + "；" + truncIDC, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{filterHook: idScanningHook(t)}
			mustSetGrading(t, p, []EscalationRule{{MinLevel: 4, MinCount: 3, Action: "block"}})
			capt := newLogCapture()
			body := `{"messages":[{"role":"user","content":` + mustJSON(t, tc.piece) + `}]}`
			proceed := p.applyInboundFilter(httptest.NewRecorder(), newReq(body), "m", "team", "org-1", "vk-1", "seat-1", "sess-1", "trace-log", correlatedLogger(capt))
			if proceed {
				t.Fatal("three distinct confirmed L4 hits in the scanned head must escalate")
			}
			recs := capt.withEvent(observability.EventProxyFilterEscalated)
			if len(recs) != 1 {
				t.Fatalf("want exactly one %s line, got %d", observability.EventProxyFilterEscalated, len(recs))
			}
			rec := recs[0]
			v, ok := rec.attrs["counted_is_lower_bound"]
			if !ok {
				t.Fatalf("%s has no counted_is_lower_bound field: %v", observability.EventProxyFilterEscalated, rec.attrs)
			}
			if v.Bool() != tc.wantLower {
				t.Errorf("counted_is_lower_bound = %v, want %v", v.Bool(), tc.wantLower)
			}
			if _, ok := rec.attrs["pieces_truncated"]; !ok {
				t.Fatalf("%s has no pieces_truncated field", observability.EventProxyFilterEscalated)
			}
			if got := rec.num("pieces_truncated"); got != tc.wantTrunc {
				t.Errorf("pieces_truncated = %d, want %d", got, tc.wantTrunc)
			}
		})
	}
}
