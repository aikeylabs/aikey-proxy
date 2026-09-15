package proxy

// === Fence for task 3.12 — the 代答 text must not travel to master ===
//
// 需求包: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// spec (PROPOSAL layer, openspec/changes/add-compliance-grading-fusion/specs/
// compliance-canned-answer/spec.md):
//
//	R-compliance-canned-answer-1.S1  代答不产生任何上游请求 (验收 3.A14 后半)
//	R-compliance-canned-answer-7     answer_source 随审计事件上报
//
// # The confusion this exists to catch
//
// Two different things in this pipeline are called "findings":
//
//	pipewire.Response.Findings  — a per-op payload slot on the parent↔child pipe.
//	                              ActionMask → the masked payload; ListPacks → a
//	                              JSON report; ActionAnswer (task 3.12) → the
//	                              administrator's canned answer text. It is
//	                              consumed inside the proxy and NEVER uploaded.
//	event.findings[]            — an array INSIDE the compliance event JSON, which
//	                              IS uploaded to master.
//
// 同名异物. Task 3.12 puts administrator-authored CONTENT into the first one; a
// reader who believes the (now corrected) comment in escalation.go — 「the
// dispatcher forwards findings to master」 — would conclude that the text is
// already leaving the machine and design the next feature accordingly. This
// fence pins the truth as behaviour rather than as prose.
//
// The SOURCE label (`answer_source`) does go up, deliberately: an administrator
// reading the audit page must be able to tell which tier the sentence came from
// (R-compliance-canned-answer-7). Asserting the label is present while the text
// is absent is also this fence's anti-vacuity guard — an event that never got
// uploaded at all would fail the label assertion.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
)

func TestCannedAnswerTextNeverLeavesInUploadedEvent(t *testing.T) {
	sink := func(ch chan<- []byte) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			ch <- b
			_, _ = w.Write([]byte(`{"accepted_ids":["e-answer-1"]}`))
		}))
	}
	teamCh, localCh := make(chan []byte, 1), make(chan []byte, 1)
	teamSink, localSink := sink(teamCh), sink(localCh)
	defer teamSink.Close()
	defer localSink.Close()

	rep, err := events.NewReporter(&events.ReporterConfig{
		CollectorRoutes: map[string]string{"team": teamSink.URL, "personal": localSink.URL},
		CollectorRouteCredentials: map[string]events.Credential{
			"team":     &events.StaticTokenCredential{Token: "member-jwt"},
			"personal": &events.StaticTokenCredential{Token: "local-token"},
		},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	hook := &stubHook{resp: &apphook.Response{
		Action:       apphook.ActionAnswer,
		AnswerText:   cannedAnswerSample,
		AnswerSource: "level",
		Event:        []byte(`{"event_id":"e-answer-1","scenario":"answer-marker","action_taken":"answer","prompt_length":10,"findings":[]}`),
	}}
	p := &Proxy{filterHook: hook, reporter: rep}
	r := newReq(`{"model":"m","messages":[{"role":"user","content":"my synthetic token AAAA-BBBB"}]}`)
	w := httptest.NewRecorder()

	proceed := p.applyInboundFilter(w, r, "m", "team", "org", "vk", "seat", "", "", discardLogger())

	// Anti-vacuity #1: the answer really was SERVED. A run in which the answer
	// silently degraded to a 403 would trivially satisfy "the text did not leave".
	if proceed {
		t.Fatal("a canned answer must short-circuit (proceed=false)")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the answer degraded, so this run proves nothing "+
			"about where the text goes", w.Code)
	}
	if !strings.Contains(w.Body.String(), "抱歉，这条内容命中了公司合规策略") {
		t.Fatalf("the client did not receive the administrator's text; body=%q", w.Body.String())
	}

	// Both upload legs: master AND the local self-view mirror. The mirror is a
	// second, independent hop (events.Reporter.MirrorComplianceEventsLocally) —
	// checking only the master leg would leave half the chain unwatched, which is
	// how 「手工搬运的中转层会静默吞字段」 keeps recurring in the other direction.
	for _, leg := range []struct {
		name string
		ch   <-chan []byte
	}{{"master", teamCh}, {"local mirror", localCh}} {
		select {
		case b := <-leg.ch:
			body := string(b)
			if !strings.Contains(body, "answer-marker") {
				t.Fatalf("%s: envelope carries no event at all: %s", leg.name, body)
			}
			// 🔴 THE ASSERTION. Neither the text nor a key that could hold it.
			if strings.Contains(body, "抱歉，这条内容命中了公司合规策略") {
				t.Errorf("%s: THE CANNED ANSWER TEXT LEFT THE MACHINE. It is administrator-authored "+
					"content with no reason to be in an audit row, and Response.Findings (where it "+
					"arrives) is not the event's findings[] (which is uploaded) — 同名异物. Envelope: %s",
					leg.name, body)
			}
			if strings.Contains(body, "answer_text") {
				t.Errorf("%s: the `answer_text` KEY reached the upload envelope. Not by value and not "+
					"by key — a future reader must not even be able to tell an empty one from an "+
					"absent one. Envelope: %s", leg.name, body)
			}
			// Anti-vacuity #2 + R-compliance-canned-answer-7: the SOURCE label does travel.
			if !strings.Contains(body, `"answer_source":"level"`) {
				t.Errorf("%s: answer_source is missing — an administrator cannot tell which tier the "+
					"sentence came from, and this fence would pass on an empty event. Envelope: %s",
					leg.name, body)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: never received the compliance event", leg.name)
		}
	}
}
