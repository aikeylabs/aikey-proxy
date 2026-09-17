package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
)

// TestApplyInboundFilter_DowngradedActionKeepsFindingInEvent guards the proxy
// half of R-compliance-rule-triple-9.S1 (Finding 与动作解耦不因反例反转):
// THEN「事件 findings 含该命中（动作可降级，Finding 不删）」.
//
// The detector half — a rule with counter-examples / negative keywords keeps
// its Finding while its action is lowered — is TestNegativeKeywords_KeepFindingLowerAction
// (ai-compliance-detector/cmd/detector/negative_keywords_test.go). This fence
// takes that detector OUTPUT (a warn verdict whose event still carries the
// finding) through the real applyInboundFilter team path and asserts the proxy
// neither drops the finding nor rewrites the downgraded action on the way to
// master. TestApplyInboundFilter_Warn cannot see this: its stub carries no event.
//
// spec: R-compliance-rule-triple-9.S1
// (roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/openspec/specs/compliance-rule-triple/spec.md)
// bugfix: workflow/CI/bugfix/2026-08-06-compliance-action-policy-false-positive.md
func TestApplyInboundFilter_DowngradedActionKeepsFindingInEvent(t *testing.T) {
	const (
		ruleID      = "synthetic.rule-103b.counter-example"
		startOffset = 21
		endOffset   = 40
		marker      = "downgrade-marker-103b"
	)
	// Detector event shape (intake.Event / intake.Finding wire names). Synthetic
	// values only; the "hit" is an obviously fake placeholder.
	finding := `{"finding_id":"f-103b-1","rule_id":"` + ruleID + `","category":"pii",` +
		`"entity_type":"SYNTHETIC_TEST_ENTITY","severity":"high","confidence":90,` +
		`"start_offset":21,"end_offset":40,"detector":"synthetic","confirmed":false}`
	eventWith := func(findings string) []byte {
		return []byte(`{"event_id":"e-103b","scenario":"` + marker + `","action_taken":"warn",` +
			`"prompt_length":48,"findings":[` + findings + `]}`)
	}
	const body = `{"model":"m","messages":[{"role":"user","content":"synthetic text FAKE-0000-0000-0000 end"}]}`

	// run drives one request through applyInboundFilter on the team route and
	// returns the single uploaded event carrying the marker.
	run := func(t *testing.T, event []byte) map[string]json.RawMessage {
		t.Helper()
		got := make(chan []byte, 4)
		sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			got <- b
			_, _ = w.Write([]byte(`{"accepted_ids":["e-103b"]}`))
		}))
		defer sink.Close()
		rep, err := events.NewReporter(&events.ReporterConfig{
			CollectorRoutes:           map[string]string{"team": sink.URL},
			CollectorRouteCredentials: map[string]events.Credential{"team": &events.StaticTokenCredential{Token: "synthetic-jwt"}},
		})
		if err != nil {
			t.Fatalf("NewReporter: %v", err)
		}
		hook := &stubHook{resp: &apphook.Response{Action: apphook.ActionWarn, Reason: "downgraded", Event: event}}
		p := &Proxy{filterHook: hook, reporter: rep}
		r := newReq(body)
		w := httptest.NewRecorder()

		if !p.applyInboundFilter(w, r, "m", "team", "org", "vk", "seat", "", "", discardLogger()) {
			t.Fatal("a downgraded (warn) verdict must let the request through")
		}
		if w.Code != http.StatusOK {
			t.Fatalf("a warn verdict must not write an error status, got %d", w.Code)
		}
		if gotBody := readReqBody(t, r); gotBody != body {
			t.Fatalf("a warn verdict must not mutate the body: %s", gotBody)
		}

		var envelope []byte
		select {
		case envelope = <-got:
		case <-time.After(3 * time.Second):
			t.Fatal("the team sink never received the compliance event")
		}
		var batch struct {
			Events []map[string]json.RawMessage `json:"events"`
		}
		if err := json.Unmarshal(envelope, &batch); err != nil {
			t.Fatalf("uploaded envelope is not {events:[...]}: %v\n%s", err, envelope)
		}
		var found []map[string]json.RawMessage
		for _, ev := range batch.Events {
			var sc string
			_ = json.Unmarshal(ev["scenario"], &sc)
			if sc == marker {
				found = append(found, ev)
			}
		}
		if len(found) != 1 {
			t.Fatalf("want exactly 1 uploaded event with the marker, got %d\n%s", len(found), envelope)
		}
		return found[0]
	}

	// hitsFor returns the uploaded findings whose rule_id is ruleID.
	hitsFor := func(t *testing.T, ev map[string]json.RawMessage) []struct {
		RuleID      string `json:"rule_id"`
		StartOffset int    `json:"start_offset"`
		EndOffset   int    `json:"end_offset"`
	} {
		t.Helper()
		var fs []struct {
			RuleID      string `json:"rule_id"`
			StartOffset int    `json:"start_offset"`
			EndOffset   int    `json:"end_offset"`
		}
		if raw, ok := ev["findings"]; ok && string(raw) != "null" {
			if err := json.Unmarshal(raw, &fs); err != nil {
				t.Fatalf("uploaded findings unreadable: %v\n%s", err, raw)
			}
		}
		out := fs[:0]
		for _, f := range fs {
			if f.RuleID == ruleID {
				out = append(out, f)
			}
		}
		return out
	}

	t.Run("downgraded verdict keeps the finding and the downgraded action", func(t *testing.T) {
		ev := run(t, eventWith(finding))
		hits := hitsFor(t, ev)
		if len(hits) != 1 {
			t.Fatalf("uploaded event carries %d findings with rule_id %q, want 1 — the action was "+
				"downgraded, the Finding must not be deleted.\nevent findings: %s", len(hits), ruleID, ev["findings"])
		}
		if hits[0].StartOffset != startOffset || hits[0].EndOffset != endOffset {
			t.Fatalf("finding offsets = [%d,%d), want [%d,%d) verbatim",
				hits[0].StartOffset, hits[0].EndOffset, startOffset, endOffset)
		}
		var action string
		_ = json.Unmarshal(ev["action_taken"], &action)
		if action != apphook.ActionWarn.String() {
			t.Fatalf("uploaded action_taken = %q, want the downgraded %q", action, apphook.ActionWarn.String())
		}
	})

	t.Run("negative control: same stub without the finding has no such finding", func(t *testing.T) {
		ev := run(t, eventWith(""))
		if hits := hitsFor(t, ev); len(hits) != 0 {
			t.Fatalf("an event the detector sent with no findings was uploaded with %d findings for %q",
				len(hits), ruleID)
		}
	})
}
