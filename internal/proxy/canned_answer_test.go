package proxy

// === Fences for task 3.6 — the canned answer (代答) six-shape synthesizer ===
//
// 需求包: roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// spec (PROPOSAL layer, openspec/changes/add-compliance-grading-fusion/specs/
// compliance-canned-answer/spec.md):
//
//	R-compliance-canned-answer-1.S1  代答不产生任何上游请求
//	R-compliance-canned-answer-4.S1  非流式 chat completions 代答形状
//	R-compliance-canned-answer-4.S2  流式代答产生完整且可被 SDK 消费的事件序列
//	R-compliance-canned-answer-3.S1  代答文案原样输出，不得插值命中片段
//	R-compliance-canned-answer-2.S2  三级皆空 → 降级为阻断，绝不空正文放行
//
// ⚠️ Deliberately NOT written as `spec:` anchors — the rules still live in
// openspec/changes/…, not openspec/specs/. Same convention as
// compliance_guardrail_response_fence_test.go; both upgrade in the change that
// writes the rules back to the steady-state layer.
//
// 🔴 NO REAL HIT SAMPLES ANYWHERE IN THIS FILE. Every "sensitive" value below is
// an obviously-synthetic token with no run of 7+ digits. A fence for 「原文不出
// 信任边界」 that carries a real card number in its own source would be the
// defect it exists to catch.

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/apphook"
	"github.com/AiKeyLabs/aikey-proxy/internal/events"
)

// cannedAnswerSample is an administrator-authored refusal in the shape a real
// one takes: non-ASCII, multi-line, and — the part that matters — carrying a
// literal placeholder token. Nothing in the pipeline may treat it as a template.
const cannedAnswerSample = "抱歉，这条内容命中了公司合规策略，无法发送给模型。\n" +
	"如需帮助请联系合规部门。占位语法示例：{{IDCARD_1}} 原样保留。"

// -----------------------------------------------------------------------------
// R-compliance-canned-answer-1.S1 — the canned answer issues NO upstream request.
// -----------------------------------------------------------------------------

// TestCannedAnswer_NoUpstreamRequestIssued pins the whole point of 代答: the
// refusal is served WITHOUT the prompt ever leaving the machine.
//
// A Mock upstream counts every inbound request. The assertion is that the
// counter is still 0 after a request that hits an Answer verdict, and that the
// filter short-circuited (proceed=false) rather than handing the request on.
//
// ⚠️ LAYER BOUNDARY, stated out loud: applyInboundFilter is not itself the thing
// that forwards. proceed=false IS the "upstream receives 0 requests" mechanism
// at this layer — its sole caller returns immediately on false, before any
// forwarding step (forward_and_resolve.go, read 2026-09-13; the same boundary
// TestApplyInboundFilter_UnknownAction_FailsClosedBlocked documents). The Mock
// upstream is here so that any future code that DOES dial from inside the filter
// turns this fence red instead of passing quietly.
func TestCannedAnswer_NoUpstreamRequestIssued(t *testing.T) {
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	hook := &stubHook{resp: &apphook.Response{
		Action:       apphook.ActionAnswer,
		AnswerText:   cannedAnswerSample,
		AnswerSource: "level",
	}}
	p := &Proxy{filterHook: hook}
	r := newReq(`{"model":"m","messages":[{"role":"user","content":"my synthetic token AAAA-BBBB"}]}`)
	w := httptest.NewRecorder()
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", logger)

	if proceed {
		t.Fatal("a canned answer must SHORT-CIRCUIT (proceed=false). proceed=true forwards the " +
			"very content the answer exists to withhold — R-compliance-canned-answer-1.S1")
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Errorf("Mock upstream received %d request(s), want 0 — 代答的全部意义就是原文不出上游", got)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 — 代答是一条正常回复的形状，不是 403", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "抱歉，这条内容命中了公司合规策略") {
		t.Errorf("response body does not carry the administrator's text; got %q", body)
	}
}

// -----------------------------------------------------------------------------
// R-compliance-canned-answer-4.S1 — non-streaming chat completions shape.
// -----------------------------------------------------------------------------

func TestCannedAnswer_ShapeOpenAIChatNonStream(t *testing.T) {
	w := httptest.NewRecorder()
	if err := writeCannedAnswer(w, ProtocolOpenAIChat, false, "gpt-4o-mini", cannedAnswerSample); err != nil {
		t.Fatalf("writeCannedAnswer: %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var got struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		Model   string `json:"model"`
		Choices []struct {
			Index   int `json:"index"`
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON (%v); body:\n%s", err, w.Body.String())
	}

	if got.Object != "chat.completion" {
		t.Errorf("object = %q, want %q", got.Object, "chat.completion")
	}
	if !strings.HasPrefix(got.ID, "chatcmpl-") {
		t.Errorf("id = %q, want a chatcmpl- id (clients key logs and retries on its shape)", got.ID)
	}
	if got.Created == 0 {
		t.Error("created = 0; SDKs surface it as a timestamp")
	}
	if got.Model != "gpt-4o-mini" {
		t.Errorf("model = %q, want the requested model echoed back", got.Model)
	}
	if len(got.Choices) != 1 {
		t.Fatalf("len(choices) = %d, want 1", len(got.Choices))
	}
	c := got.Choices[0]
	if c.Message.Role != "assistant" {
		t.Errorf("choices[0].message.role = %q, want assistant", c.Message.Role)
	}
	if c.Message.Content != cannedAnswerSample {
		t.Errorf("choices[0].message.content is not the administrator's text verbatim:\n got %q\nwant %q",
			c.Message.Content, cannedAnswerSample)
	}
	if c.FinishReason != "content_filter" {
		t.Errorf(`choices[0].finish_reason = %q, want "content_filter" — the protocol-native `+
			`filter signal is how a downstream tool tells this apart from a normal answer`, c.FinishReason)
	}
	// usage must be ZERO: no tokens were spent, and a non-zero count here would
	// be invented billing data on a request that never reached a provider.
	if got.Usage.PromptTokens != 0 || got.Usage.CompletionTokens != 0 || got.Usage.TotalTokens != 0 {
		t.Errorf("usage = %+v, want all zero — nothing was sent upstream, so nothing was billed", got.Usage)
	}
}

// -----------------------------------------------------------------------------
// R-compliance-canned-answer-4.S2 — streaming sequences close cleanly.
// -----------------------------------------------------------------------------

// TestCannedAnswer_StreamSequenceClosesCleanly asserts that each streamed shape
// is a COMPLETE, terminated event sequence — the thing an SDK's stream reader
// needs in order to finish instead of hanging or raising.
//
// Anthropic: message_start → content_block_start → content_block_delta →
// content_block_stop → message_delta → message_stop.
// chat completions: role chunk → content chunk → finish chunk → [DONE].
// Responses: response.created … response.output_text.delta … response.incomplete.
func TestCannedAnswer_StreamSequenceClosesCleanly(t *testing.T) {
	t.Run("anthropic", func(t *testing.T) {
		w := httptest.NewRecorder()
		if err := writeCannedAnswer(w, ProtocolAnthropicMessages, true, "claude-sonnet-4-6", cannedAnswerSample); err != nil {
			t.Fatalf("writeCannedAnswer: %v", err)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
			t.Errorf("Content-Type = %q, want text/event-stream", ct)
		}
		frames := parseSSE(t, w.Body.String())
		wantTypes := []string{
			"message_start", "content_block_start", "content_block_delta",
			"content_block_stop", "message_delta", "message_stop",
		}
		gotTypes := make([]string, 0, len(frames))
		for _, f := range frames {
			gotTypes = append(gotTypes, f.jsonString(t, "type"))
			// Anthropic SDKs dispatch on the `event:` line; it must agree with
			// the payload's own `type` or the reader silently drops the frame.
			if f.event != "" && f.event != f.jsonString(t, "type") {
				t.Errorf("frame event line %q disagrees with payload type %q", f.event, f.jsonString(t, "type"))
			}
		}
		if strings.Join(gotTypes, ",") != strings.Join(wantTypes, ",") {
			t.Fatalf("anthropic event sequence =\n  %v\nwant\n  %v", gotTypes, wantTypes)
		}
		if txt := frames[2].jsonString(t, "delta.text"); txt != cannedAnswerSample {
			t.Errorf("content_block_delta text is not verbatim:\n got %q\nwant %q", txt, cannedAnswerSample)
		}
		if sr := frames[4].jsonString(t, "delta.stop_reason"); sr != "refusal" {
			t.Errorf(`message_delta stop_reason = %q, want "refusal" (Anthropic's native filter signal)`, sr)
		}
	})

	t.Run("openai_chat", func(t *testing.T) {
		w := httptest.NewRecorder()
		if err := writeCannedAnswer(w, ProtocolOpenAIChat, true, "gpt-4o-mini", cannedAnswerSample); err != nil {
			t.Fatalf("writeCannedAnswer: %v", err)
		}
		raw := w.Body.String()
		if !strings.HasSuffix(strings.TrimRight(raw, "\n"), "data: [DONE]") {
			t.Fatalf("chat completions stream must terminate with `data: [DONE]`; tail was:\n%q",
				raw[max(0, len(raw)-80):])
		}
		frames := parseSSE(t, raw)
		if len(frames) != 4 {
			t.Fatalf("chat completions stream = %d frames, want 4 (role, content, finish, [DONE])", len(frames))
		}
		if frames[0].jsonString(t, "choices.0.delta.role") != "assistant" {
			t.Error("first chunk must open the message with delta.role=assistant")
		}
		if c := frames[1].jsonString(t, "choices.0.delta.content"); c != cannedAnswerSample {
			t.Errorf("content chunk is not verbatim:\n got %q\nwant %q", c, cannedAnswerSample)
		}
		if fr := frames[2].jsonString(t, "choices.0.finish_reason"); fr != "content_filter" {
			t.Errorf(`finish chunk finish_reason = %q, want "content_filter"`, fr)
		}
		if frames[3].data != "[DONE]" {
			t.Errorf("last frame = %q, want [DONE]", frames[3].data)
		}
	})

	t.Run("openai_responses", func(t *testing.T) {
		w := httptest.NewRecorder()
		if err := writeCannedAnswer(w, ProtocolOpenAIResponses, true, "gpt-5-codex", cannedAnswerSample); err != nil {
			t.Fatalf("writeCannedAnswer: %v", err)
		}
		frames := parseSSE(t, w.Body.String())
		var types []string
		for _, f := range frames {
			types = append(types, f.jsonString(t, "type"))
		}
		joined := strings.Join(types, ",")
		for _, must := range []string{
			"response.created", "response.output_item.added", "response.content_part.added",
			"response.output_text.delta", "response.output_text.done", "response.content_part.done",
			"response.output_item.done", "response.incomplete",
		} {
			if !strings.Contains(joined, must) {
				t.Errorf("Responses stream is missing %q; got %v", must, types)
			}
		}
		if types[len(types)-1] != "response.incomplete" {
			t.Errorf("Responses stream must terminate on a terminal response event, got %q", types[len(types)-1])
		}
		// The text channel is the TOP-LEVEL `delta` string on
		// response.output_text.delta — not choices[], not delta.text
		// (sse_restore.go learned this the hard way, 2026-09-03).
		var deltaSeen bool
		for _, f := range frames {
			if f.jsonString(t, "type") == "response.output_text.delta" {
				deltaSeen = true
				if d := f.jsonString(t, "delta"); d != cannedAnswerSample {
					t.Errorf("output_text.delta is not verbatim:\n got %q\nwant %q", d, cannedAnswerSample)
				}
			}
		}
		if !deltaSeen {
			t.Fatal("no response.output_text.delta frame — the client would render an empty reply")
		}
		// sequence_number must be strictly increasing; SDK readers use it to
		// detect dropped frames.
		last := int64(-1)
		for _, f := range frames {
			n := f.jsonInt(t, "sequence_number")
			if n <= last {
				t.Errorf("sequence_number went %d → %d (must strictly increase)", last, n)
			}
			last = n
		}
	})
}

// -----------------------------------------------------------------------------
// R-compliance-canned-answer-3.S1 — the text is NEVER interpolated. 🔴 RED LINE.
// -----------------------------------------------------------------------------

// TestCannedAnswer_TextIsNeverInterpolated is the behavioral half of design §6
// invariant 12 (the source-scan half is
// TestFence_GuardrailShortCircuitBodyIsNeverInterpolated).
//
// The administrator's text contains `{{IDCARD_1}}` as a LITERAL. Every one of the
// six shapes must reproduce it byte for byte, and no shape may contain any
// fragment of the content that was just scanned.
//
// Why this matters more than it looks: if the writer ever rendered the text as a
// template, the guardrail would answer the user with the very ID-card number the
// block was for — 「原文不出客户信任边界」 breached from the other side.
func TestCannedAnswer_TextIsNeverInterpolated(t *testing.T) {
	// A synthetic "finding" the detector might have produced from the prompt.
	// Obviously fake, no run of 7+ digits — see the file header.
	const findingFragment = "AAAA-BBBB-CCCC"

	for _, tc := range []struct {
		name      string
		proto     ProtocolKind
		streaming bool
		// jsonPath of the field that must equal the text verbatim.
		textPaths []string
	}{
		{"openai_chat/non-stream", ProtocolOpenAIChat, false, []string{"choices.0.message.content"}},
		{"openai_chat/stream", ProtocolOpenAIChat, true, []string{"choices.0.delta.content"}},
		{"anthropic/non-stream", ProtocolAnthropicMessages, false, []string{"content.0.text"}},
		{"anthropic/stream", ProtocolAnthropicMessages, true, []string{"delta.text"}},
		{"responses/non-stream", ProtocolOpenAIResponses, false, []string{"output.0.content.0.text"}},
		{"responses/stream", ProtocolOpenAIResponses, true, []string{"delta", "text"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if err := writeCannedAnswer(w, tc.proto, tc.streaming, "m", cannedAnswerSample); err != nil {
				t.Fatalf("writeCannedAnswer: %v", err)
			}
			body := w.Body.String()

			// 1. No fragment of the scanned content may appear anywhere.
			if strings.Contains(body, findingFragment) {
				t.Fatalf("the response body contains a scanned-content fragment %q — the canned "+
					"answer has become an echo channel (R-compliance-canned-answer-3)", findingFragment)
			}

			// 2. The placeholder syntax survives as a LITERAL. If any templating
			// ran, `{{IDCARD_1}}` would have been substituted or stripped.
			if !strings.Contains(body, `{{IDCARD_1}}`) {
				t.Fatalf("`{{IDCARD_1}}` is missing from the wire bytes — something rendered the "+
					"administrator's text as a template. Body:\n%s", body)
			}

			// 3. The decoded text field equals the administrator's text BYTE FOR
			// BYTE. JSON escaping on the wire is encoding, not interpolation: what
			// the client's decoder yields must be the original bytes.
			var found bool
			for _, frame := range decodeAllJSONFrames(t, body, tc.streaming) {
				for _, p := range tc.textPaths {
					if v, ok := lookupJSONString(frame, p); ok && v != "" {
						found = true
						if v != cannedAnswerSample {
							t.Errorf("%s: decoded text is not byte-identical to the stored text:\n got %q\nwant %q",
								p, v, cannedAnswerSample)
						}
					}
				}
			}
			if !found {
				t.Fatalf("no text field found at %v — this assertion is looking at nothing. Body:\n%s",
					tc.textPaths, body)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// R-compliance-canned-answer-2.S2 — three empty tiers degrade to BLOCK.
// -----------------------------------------------------------------------------

// TestCannedAnswer_EmptyTextFallsBackToBlock pins the direction the fallback
// leans when no tier carried a text: towards refusal, never towards forwarding
// and never towards an empty 200.
//
// 🔴 THIS FENCE IS LULL-PROOF ON PURPOSE. master stopped rejecting an
// out-of-domain answer_source on 2026-09-12 (1.20 收口: 200 + NULL column +
// WARN, no longer 400), so nothing downstream will report this if the proxy gets
// it wrong. The only thing standing here is this test.
func TestCannedAnswer_EmptyTextFallsBackToBlock(t *testing.T) {
	for _, tc := range []struct{ name, text, source string }{
		{"no tier had a text", "", "none"},
		{"whitespace only", "   \n\t ", "org"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := &stubHook{resp: &apphook.Response{
				Action:       apphook.ActionAnswer,
				AnswerText:   tc.text,
				AnswerSource: tc.source,
			}}
			p := &Proxy{filterHook: hook}
			r := newReq(`{"model":"m","messages":[{"role":"user","content":"hello world"}]}`)
			w := httptest.NewRecorder()
			var logBuf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

			proceed := p.applyInboundFilter(w, r, "m", "personal", "", "", "", "", "", logger)

			if proceed {
				t.Fatal("an answer with no text must degrade to BLOCK (proceed=false), never forward — " +
					"配代答的意图就是不让原文出去，缺文案不能变成「那就发出去吧」")
			}
			if w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403 (the plain block path)", w.Code)
			}
			if body := w.Body.String(); !strings.Contains(body, "COMPLIANCE_BLOCKED") {
				t.Errorf("body must be the ordinary block refusal, got %q", body)
			}
			if strings.TrimSpace(w.Body.String()) == "" {
				t.Error("an empty body would read to the user as 「模型什么也没说」, not as a refusal")
			}
			if logs := logBuf.String(); !strings.Contains(logs, "proxy.filter.canned_answer_degraded") {
				t.Errorf("the degrade must be LOUD — an administrator who configured a canned answer "+
					"and got a hard block has no other way to learn why. Logs:\n%s", logs)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// The verdict cache must not replay a canned answer.
// -----------------------------------------------------------------------------

// TestCannedAnswer_VerdictIsNeverCached pins that an Answer verdict is excluded
// from the piece-verdict cache, exactly as Block is.
//
// 🔴 THE CONCRETE BUG IT PREVENTS. maskVerdict has no slot for the answer text
// (maskedHead / reason / restorables / event). Cache the verdict and the replay
// arrives with an empty text, which planCannedAnswer correctly degrades to a
// 403 — so the SAME prompt would be answered with a friendly 200 the first time
// and refused hard the second time, inside the TTL, with nothing changed. That
// is the "hand-copied relay drops fields" family this repository has hit four
// times, in its cache-shaped variant.
//
// 🔴 AND THE RULE IT KEEPS TRUE. design.md: 「代答与阻断同强度」. clamp() already
// treats Answer as block-strength; if the cache did not, 「同强度」 would be false
// in exactly one place — and an administrator who edits the sentence in the
// console would keep seeing the old one served in the operator's name.
//
// Asserted on the SHARED predicate rather than by driving two requests, because
// the predicate is what both the read guard and the write guard consult; a
// behavioral test would prove one of the two sites and say nothing about the
// other. Anti-vacuity: the mask/warn/allow rungs are asserted cacheable in the
// same loop, so a predicate that simply returned false everywhere fails here.
func TestCannedAnswer_VerdictIsNeverCached(t *testing.T) {
	for a, wantCacheable := range map[apphook.Action]bool{
		apphook.ActionAllow:  true,
		apphook.ActionMask:   true,
		apphook.ActionWarn:   true,
		apphook.ActionBlock:  false,
		apphook.ActionAnswer: false,
	} {
		if got := cacheableVerdict(a); got != wantCacheable {
			t.Errorf("cacheableVerdict(%s) = %v, want %v", a, got, wantCacheable)
		}
	}
}

// -----------------------------------------------------------------------------
// Boundaries — the administrator's text is arbitrary, and one of the shapes
// frames it inside a line-oriented protocol.
// -----------------------------------------------------------------------------

// TestCannedAnswer_TextBoundaries covers the three edges the text can actually
// have, plus the adversarial one that only exists because SSE is line-oriented.
//
// 🔴 THE INTERESTING CASE IS "sse_breaker". An SSE frame is terminated by a
// blank line, so a text containing "\n\ndata: [DONE]\n\n" would — if it were
// ever written raw into a data line — end the stream early and inject a frame of
// the administrator's choosing. It cannot happen here because the payload is
// json.Marshal'd (newlines become the two characters \ and n, so a frame is
// always exactly one line), and asserting it is how that property stays true if
// someone later "optimizes" the framing. Note this is NOT a text-interpolation
// bug — nothing substitutes anything — it is a FRAMING bug, which is why it
// needs its own assertion rather than relying on the interpolation fence.
//
// The administrator is trusted, so this is not a threat model so much as a
// robustness one: a pasted refusal that happens to contain a blank line must not
// silently truncate the reply.
func TestCannedAnswer_TextBoundaries(t *testing.T) {
	long := strings.Repeat("合规提示。Compliance notice. ", 1200) // ~40 KB of UTF-8
	for _, tc := range []struct{ name, text string }{
		{"non_ascii_and_emoji", "合规策略拒绝了这条请求 🚫 — “引号” и кириллица\tタブ"},
		{"oversized", long},
		{"sse_breaker", "before\n\ndata: [DONE]\n\nevent: message_stop\ndata: {}\n\nafter"},
		{"json_metacharacters", `quote " backslash \ brace } bracket ] null \u0000-ish`},
	} {
		for _, proto := range []ProtocolKind{ProtocolOpenAIChat, ProtocolAnthropicMessages, ProtocolOpenAIResponses} {
			for _, streaming := range []bool{false, true} {
				name := tc.name + "/" + proto.String()
				if streaming {
					name += "/stream"
				}
				t.Run(name, func(t *testing.T) {
					w := httptest.NewRecorder()
					if err := writeCannedAnswer(w, proto, streaming, "m", tc.text); err != nil {
						t.Fatalf("writeCannedAnswer: %v", err)
					}
					if w.Code != http.StatusOK {
						t.Fatalf("status = %d, want 200", w.Code)
					}
					// Whatever the text, the wire must still decode and still
					// carry the text byte for byte.
					var seen bool
					for _, frame := range decodeAllJSONFrames(t, w.Body.String(), streaming) {
						for _, path := range []string{
							"choices.0.message.content", "choices.0.delta.content",
							"content.0.text", "delta.text",
							"output.0.content.0.text", "delta", "text",
						} {
							if v, ok := lookupJSONString(frame, path); ok && v != "" {
								seen = true
								if v != tc.text {
									t.Fatalf("%s: text is not byte-identical\n got %q\nwant %q",
										path, truncate(v), truncate(tc.text))
								}
							}
						}
					}
					if !seen {
						t.Fatal("no text field decoded — assertion is looking at nothing")
					}
					if streaming {
						// Framing integrity: exactly the frame count the shape
						// promises, no more. An extra frame means the text broke
						// out of its data line.
						want := map[ProtocolKind]int{
							ProtocolOpenAIChat: 4, ProtocolAnthropicMessages: 6, ProtocolOpenAIResponses: 9,
						}[proto]
						if got := len(parseSSE(t, w.Body.String())); got != want {
							t.Fatalf("%s stream produced %d frames, want %d — the text escaped its "+
								"data line and injected frames of its own", proto, got, want)
						}
					}
				})
			}
		}
	}
}

func truncate(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// -----------------------------------------------------------------------------
// helpers — SSE parsing and JSON path lookup, test-local.
// -----------------------------------------------------------------------------

type sseFrameT struct {
	event string
	data  string
}

func (f sseFrameT) jsonString(t *testing.T, path string) string {
	t.Helper()
	var m any
	if err := json.Unmarshal([]byte(f.data), &m); err != nil {
		t.Fatalf("frame data is not JSON (%v): %s", err, f.data)
	}
	v, _ := lookupJSONString(m, path)
	return v
}

func (f sseFrameT) jsonInt(t *testing.T, path string) int64 {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(f.data), &m); err != nil {
		t.Fatalf("frame data is not JSON (%v): %s", err, f.data)
	}
	n, _ := m[path].(float64)
	return int64(n)
}

// parseSSE splits an SSE body into frames, asserting the framing itself is
// well-formed (blank-line separated, `data:` present). A malformed frame is the
// failure mode that makes an SDK hang rather than error, so it fails here.
func parseSSE(t *testing.T, body string) []sseFrameT {
	t.Helper()
	blocks := strings.Split(strings.TrimRight(body, "\n"), "\n\n")
	out := make([]sseFrameT, 0, len(blocks))
	for _, block := range blocks {
		if strings.TrimSpace(block) == "" {
			continue
		}
		var f sseFrameT
		var dataLines []string
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "event: "):
				f.event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
			default:
				t.Fatalf("unrecognized SSE line %q — an SDK reader would stall on this", line)
			}
		}
		if len(dataLines) == 0 {
			t.Fatalf("SSE block has no data line:\n%s", block)
		}
		f.data = strings.Join(dataLines, "\n")
		out = append(out, f)
	}
	if len(out) == 0 {
		t.Fatal("no SSE frames parsed — this assertion is looking at nothing")
	}
	return out
}

// decodeAllJSONFrames yields every JSON document in a body: the single object of
// a non-streaming reply, or every frame of an SSE stream.
//
// 🔴 IT IS TOLD WHICH, NEVER SNIFFS. The first version decided by looking for
// "data: " in the body and TestCannedAnswer_TextBoundaries/sse_breaker caught it
// immediately: an administrator's text containing the literal "data: " made a
// plain JSON body look like a stream. Sniffing a format from content that
// includes attacker-shaped (here: merely awkward) text is the same mistake in
// miniature that the whole feature is about.
func decodeAllJSONFrames(t *testing.T, body string, streaming bool) []any {
	t.Helper()
	if !streaming {
		var m any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("body is not JSON (%v):\n%s", err, body)
		}
		return []any{m}
	}
	frames := parseSSE(t, body)
	out := make([]any, 0, len(frames))
	for _, f := range frames {
		if f.data == "[DONE]" {
			continue
		}
		var m any
		if err := json.Unmarshal([]byte(f.data), &m); err != nil {
			t.Fatalf("frame is not JSON (%v): %s", err, f.data)
		}
		out = append(out, m)
	}
	return out
}

// lookupJSONString walks a dotted path (numeric segments index arrays) and
// returns the string at the end. Deliberately tiny and test-local: production
// code must never need to reach into the synthesized body.
func lookupJSONString(v any, path string) (string, bool) {
	cur := v
	for _, seg := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			nxt, ok := node[seg]
			if !ok {
				return "", false
			}
			cur = nxt
		case []any:
			idx := 0
			for _, c := range seg {
				if c < '0' || c > '9' {
					return "", false
				}
				idx = idx*10 + int(c-'0')
			}
			if idx >= len(node) {
				return "", false
			}
			cur = node[idx]
		default:
			return "", false
		}
	}
	s, ok := cur.(string)
	return s, ok
}

// -----------------------------------------------------------------------------
// R-compliance-canned-answer-8.S1 — [回归] 未配代答时四条既有路径逐字节等价 (task 3.7)
// -----------------------------------------------------------------------------

// baselinePathOutcome is one observation of ONE existing path on ONE round.
//
// Every field here is something a customer or an auditor can actually see:
// whether the request went on (proceed), what the caller's HTTP client got
// (status + respBody), what the UPSTREAM would have received (fwdBody — the
// mask path rewrites it, the other three must not), and what landed in the
// compliance record (eventEnvelope, byte for byte including the derived
// audit-unit id). detectorCalls is here because "did this round re-ask the
// detector or replay the cache" is the difference between the two rounds, and
// a cache round that silently stopped being a cache round would make the
// second half of this fence a duplicate of the first.
type baselinePathOutcome struct {
	proceed       bool
	status        int
	respBody      string
	fwdBody       string
	eventEnvelope string
	detectorCalls int
}

// cannedAnswerBaseline holds what the four existing paths produced on the LAST
// commit before 代答 existed — 7da287bfed60f4046efe0cb7064e2cc8c1ec4f2c, the
// parent of the commit that introduced apphook.ActionAnswer.
//
// 🔴 THESE LITERALS WERE MEASURED, NOT REASONED. They were captured on
// 2026-09-13 by checking that commit out into a detached worktree (inside a
// directory of symlinks to the sibling repos, because go.mod's replaces are
// relative) and running a throwaway harness whose scenario table is the same
// one below, verbatim:
//
//	git worktree add --detach <ws>/aikey-proxy 7da287b
//	cd <ws>/aikey-proxy && GOWORK=off go test ./internal/proxy \
//	    -run '^TestZZBaselineCapture$' -count=1 -v
//
// WHY IT HAD TO BE MEASURED, and this is the whole point of task 3.7: the
// tempting argument is "an organization that configured no canned answer never
// reaches the new code, so nothing can have changed". That argument assumes we
// already know every entry point, and 3.6 did not only add a branch — it also
// rewrote the verdict-cache guard that block / mask / warn / allow ALL pass
// through (`v.action != apphook.ActionBlock` → `cacheableVerdict(v.action)`,
// both on the read side and on the write side). A guard on the shared path is
// exactly where "it can't affect us" stops being true. Reasoning cannot show
// the bytes are the same; only comparing them can.
var cannedAnswerBaseline = map[string][2]baselinePathOutcome{
	// round 1 = fresh detect, round 2 = same content again (cache round).
	"allow": {
		{true, 200, "", `{"model":"m","messages":[{"role":"user","content":"hello world"}]}`, baselineEnvelope("allow"), 1},
		{true, 200, "", `{"model":"m","messages":[{"role":"user","content":"hello world"}]}`, baselineEnvelope("allow"), 1},
	},
	"warn": {
		{true, 200, "", `{"model":"m","messages":[{"role":"user","content":"hello world"}]}`, baselineEnvelope("warn"), 1},
		{true, 200, "", `{"model":"m","messages":[{"role":"user","content":"hello world"}]}`, baselineEnvelope("warn"), 1},
	},
	"mask": {
		{true, 200, "", `{"messages":[{"content":"hello {{PHONE}}","role":"user"}],"model":"m"}`, baselineEnvelope("mask"), 1},
		{true, 200, "", `{"messages":[{"content":"hello {{PHONE}}","role":"user"}],"model":"m"}`, baselineEnvelope("mask"), 1},
	},
	"block": {
		// detectorCalls climbs to 2 on round 2 and that is the POINT: a block
		// verdict is deliberately not cached (bugfix 2026-08-08), so the same
		// content is re-judged against the latest policy. If 3.6's rewrite of
		// that guard had gone wrong in the other direction, this 2 would read 1.
		{false, 403, baselineBlockBody, `{"model":"m","messages":[{"role":"user","content":"hello world"}]}`, baselineEnvelope("block"), 1},
		{false, 403, baselineBlockBody, `{"model":"m","messages":[{"role":"user","content":"hello world"}]}`, baselineEnvelope("block"), 2},
	},
}

// baselineBlockBody is the 403 the ordinary block path writes, captured at
// 7da287b. Spelled out in full rather than substring-matched: 「逐字节一致」 is
// the requirement, and a substring check would not notice a changed error code
// or a new field appearing beside it.
const baselineBlockBody = `{"error":{"code":"COMPLIANCE_BLOCKED","message":"AiKey: high-risk content blocked","type":"invalid_request_error"},"origin":"local-proxy.COMPLIANCE_BLOCKED"}`

// baselineEnvelope is the compliance upload body for one path, captured at
// 7da287b. `au_3384b256…` is the content-derived audit-unit id (auditUnitID,
// bugfix 2026-09-08) — pinned literally, because a change to WHAT the id is
// derived from would be invisible to any assertion that only checked the field
// exists. Keys are alphabetical because the inject* family round-trips the
// event through a map[string]json.RawMessage.
func baselineEnvelope(action string) string {
	return `{"events":[{"action_taken":"` + action + `","event_id":"au_3384b2562d4bd22100613a90ebc7fd23",` +
		`"findings":[],"prompt_length":11,"scenario":"regr","seat_id":"seat-3","session_id":"sess-r",` +
		`"tenant_id":"org-9","trace_id":"trace-r","virtual_key_id":"vk-7"}]}`
}

// baselineProbeBody is the one request all five sub-cases send. Ordinary
// content on purpose: this fence is about the paths a customer who never
// configured 代答 walks every day.
const baselineProbeBody = `{"model":"m","messages":[{"role":"user","content":"hello world"}]}`

// baselineHookFor returns the detector verdict that drives one path. Copied
// verbatim from the capture harness — if these diverge, the goldens above stop
// describing this test's inputs and the comparison becomes meaningless.
func baselineHookFor(path string) *stubHook {
	ev := func(a string) []byte {
		return []byte(`{"event_id":"det-1","scenario":"regr","action_taken":"` + a + `","prompt_length":11,"findings":[]}`)
	}
	switch path {
	case "allow":
		return &stubHook{resp: &apphook.Response{Action: apphook.ActionAllow, Event: ev("allow")}}
	case "warn":
		return &stubHook{resp: &apphook.Response{
			Action: apphook.ActionWarn, Reason: "warned content", Event: ev("warn")}}
	case "mask":
		return &stubHook{resp: &apphook.Response{
			Action: apphook.ActionMask, Reason: "masked content",
			MutatedPayload: []byte("hello {{PHONE}}"), Event: ev("mask")}}
	case "block":
		return &stubHook{resp: &apphook.Response{
			Action: apphook.ActionBlock, Reason: "high-risk content blocked", Event: ev("block")}}
	}
	panic("baselineHookFor: unknown path " + path)
}

// TestCannedAnswer_UnconfiguredPathsByteIdentical is the regression half of the
// canned answer: it proves that adding 代答 changed NOTHING for an organization
// that has not configured one.
//
// 🔴 IT ASSERTS TWO THINGS AND NEEDS BOTH. Byte-equality alone is worthless on
// a build where the feature is switched off — it would pass by describing an
// empty room. So the first thing this test does is prove the new logic IS live
// in this binary (SupportsCannedAnswer() == true, and the `case ActionAnswer`
// branch is compiled AND reachable, shown by actually being served one), and
// only then compares the four old paths against the pre-代答 goldens. Take
// either half away and the remaining half proves nothing.
//
// 🔴 WHY THE SECOND ROUND EXISTS. 3.6 rewrote the verdict-cache guard that all
// four paths share, on both the read side and the write side. A first-round-only
// comparison would never execute the replay branch — the one place the rewrite
// actually sits. Round 2 sends the same content again: allow / warn / mask must
// replay (detector calls stay at 1) and block must re-scan (climbs to 2).
//
// spec: R-compliance-canned-answer-8.S1 (PROPOSAL layer — see this file's header
// for why these are referenced by id rather than written as `spec:` anchors).
func TestCannedAnswer_UnconfiguredPathsByteIdentical(t *testing.T) {
	// ---- Anti-vacuity gate: the new logic is LIVE in this binary. ------------
	//
	// Without this, a build that had never enabled 代答 at all would sail
	// through every comparison below and report "nothing changed" — true, and
	// evidence of nothing. This is the failure shape this requirement package
	// keeps producing: a correct assertion pointed at an empty subject.
	if !apphook.SupportsCannedAnswer() {
		t.Fatal("SupportsCannedAnswer() = false — the equivalence asserted below would be VACUOUS: " +
			"it would only be showing that a disabled feature changes nothing. R-compliance-canned-answer-8.S1 " +
			"requires the equivalence to hold with 代答 live in the binary")
	}
	t.Run("precondition: the ActionAnswer branch is compiled in and reachable", func(t *testing.T) {
		// Behavioral, not reflective: a `case apphook.ActionAnswer:` that had
		// been dropped or made unreachable cannot produce a 200 carrying the
		// administrator's sentence. This is the strongest in-process evidence
		// that the branch exists in THIS binary — the same binary the four
		// comparisons below run against.
		hook := &stubHook{resp: &apphook.Response{
			Action: apphook.ActionAnswer, AnswerText: cannedAnswerSample, AnswerSource: "org"}}
		p := &Proxy{filterHook: hook}
		w := httptest.NewRecorder()
		if proceed := p.applyInboundFilter(w, newReq(baselineProbeBody), "m", "personal",
			"", "", "", "", "", discardLogger()); proceed {
			t.Fatal("an Answer verdict must short-circuit; proceed=true means the branch is not doing its job")
		}
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "抱歉，这条内容命中了公司合规策略") {
			t.Fatalf("the ActionAnswer branch did not serve the administrator's text (status=%d body=%q) — "+
				"everything asserted below would then be describing a build WITHOUT 代答, which is not what "+
				"R-compliance-canned-answer-8.S1 asks about", w.Code, w.Body.String())
		}
	})

	// ---- The four existing paths, against the pre-代答 goldens. --------------
	for _, path := range []string{"allow", "warn", "mask", "block"} {
		t.Run(path, func(t *testing.T) {
			evCh := make(chan string, 8)
			sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				evCh <- string(b)
				_, _ = w.Write([]byte(`{"accepted_ids":[]}`))
			}))
			defer sink.Close()
			rep, err := events.NewReporter(&events.ReporterConfig{
				CollectorRoutes:           map[string]string{"team": sink.URL},
				CollectorRouteCredentials: map[string]events.Credential{"team": &events.StaticTokenCredential{Token: "tk"}},
			})
			if err != nil {
				t.Fatalf("NewReporter: %v", err)
			}
			hook := baselineHookFor(path)
			p := &Proxy{filterHook: hook, reporter: rep}
			p.SetFilterCacheEnabled(true, 5)

			for round := 0; round < 2; round++ {
				want := cannedAnswerBaseline[path][round]
				r := newReq(baselineProbeBody)
				w := httptest.NewRecorder()
				proceed := p.applyInboundFilter(w, r, "m", "team", "org-9", "vk-7", "seat-3",
					"sess-r", "trace-r", discardLogger())
				fwd, _ := io.ReadAll(r.Body)

				got := baselinePathOutcome{
					proceed:       proceed,
					status:        w.Code,
					respBody:      w.Body.String(),
					fwdBody:       string(fwd),
					eventEnvelope: waitForEnvelope(t, evCh),
					detectorCalls: hook.called,
				}
				if got != want {
					t.Errorf("round %d of the %s path is NOT byte-identical to the pre-代答 baseline (7da287b).\n"+
						" got: %#v\nwant: %#v\n"+
						"代答 was specified to be additive: an organization that configured none must see the "+
						"exact same bytes it saw before (R-compliance-canned-answer-8.S1). A difference here is "+
						"a change shipped to every customer who never asked for the feature.", round+1, path, got, want)
				}
			}
		})
	}
}

// waitForEnvelope reads the one compliance upload this round produced. The
// upload is async (observability.GoSafe), so a missing envelope is reported as
// the literal "<none>" rather than hanging the suite — and "<none>" then fails
// the comparison loudly, which is the correct outcome: an audit row that stopped
// being sent is exactly the kind of silent loss this fence exists to catch.
func waitForEnvelope(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(5 * time.Second):
		return "<none>"
	}
}
