package proxy

import (
	"os"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

// chat_completions_bridge_destream_test.go — fences for the non-streaming
// client path.
//
// Why these matter more than their size suggests: the bridge exists to serve
// Chat Completions clients, and the most common call in that ecosystem is the
// non-streaming one. Before de-streaming, that exact call was the one shape the
// bridge could not serve — measured cells S03/S06/S07 answer 400 "Stream must
// be set to true" — so a deployment could pass every other test here and still
// fail for most of its traffic.

const responsesRelayHost = "resp-relay.corp.example"
const responsesRelayBase = "https://resp-relay.corp.example/v1"

// responsesRelayRules declares a NON-Codex host that speaks Responses. It is
// what separates "Codex requires streaming" from "the Responses API requires
// streaming" — only the first is true.
func responsesRelayRules() []BridgeUpstreamRule {
	return []BridgeUpstreamRule{{Host: responsesRelayHost, Dialect: "responses"}}
}

const nonStreamChatBody = `{"model":"gpt-5.4","messages":[{"role":"user","content":"hi"}]}`

func armedState(t *testing.T, r *http.Request) *bridgeState {
	t.Helper()
	st := bridgeFromContext(r.Context())
	if st == nil {
		t.Fatal("bridge did not arm the response leg")
	}
	return st
}

// ── request leg ─────────────────────────────────────────────────────────────

// TestDeStream_NonStreamChatClientIsSentUpstreamAsAStream is the fence for the
// defect itself. `stream` is `omitempty`, so a non-streaming client used to
// produce a body with NO stream field — cell S07, a hard 400.
func TestDeStream_NonStreamChatClientIsSentUpstreamAsAStream(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, nil) // codex is always permitted

	r := bridgeRequest(t, "/v1/chat/completions", nonStreamChatBody)
	out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", "", quietLogger())
	if refusal != nil {
		t.Fatalf("non-streaming chat request was refused: %s", refusal.Message)
	}

	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := gjson.GetBytes(body, "stream"); !got.Exists() || !got.Bool() {
		t.Fatalf("upstream body must say stream:true (Codex serves nothing else); got %s", body)
	}
	if !armedState(t, out).deStream {
		t.Error("de-streaming was not armed, so the client would receive raw SSE for a non-streaming request")
	}

	// The pre-dial shape gate must now pass. If it still refuses, the client
	// gets 422 and none of the above matters.
	if reason := oauthUpstreamRejectsShape("openai", out); reason != "" {
		t.Errorf("shape gate still refuses a de-streamed request: %s", reason)
	}
}

// TestDeStream_StreamingClientIsUntouched — de-streaming must not reach the
// clients that were already working.
func TestDeStream_StreamingClientIsUntouched(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, nil)

	r := bridgeRequest(t, "/v1/chat/completions",
		`{"model":"gpt-5.4","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", "", quietLogger())
	if refusal != nil {
		t.Fatalf("refused: %s", refusal.Message)
	}
	if armedState(t, out).deStream {
		t.Error("a client that asked to stream was de-streamed; it would get one blob instead of frames")
	}
}

// TestDeStream_IsKeyedOnCodexNotOnTheResponsesDialect — the constraint belongs
// to one BACKEND, not to the Responses API. api.openai.com and any relay an
// operator declares serve /responses non-streaming perfectly well, and
// rewriting their requests would change a working wire form for nothing.
func TestDeStream_IsKeyedOnCodexNotOnTheResponsesDialect(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, responsesRelayRules())

	r := bridgeRequest(t, "/v1/chat/completions", nonStreamChatBody)
	out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", responsesRelayBase, quietLogger())
	if refusal != nil {
		t.Fatalf("refused: %s", refusal.Message)
	}
	if armedState(t, out).deStream {
		t.Fatal("a declared Responses relay was treated as Codex; its requests were rewritten to stream for no reason")
	}
	body, _ := io.ReadAll(out.Body)
	if gjson.GetBytes(body, "stream").Bool() {
		t.Errorf("non-Codex upstream was forced to stream: %s", body)
	}
}

// ── response leg ────────────────────────────────────────────────────────────

func deStreamedBody(t *testing.T, sse string) (http.Header, []byte) {
	t.Helper()
	r := armBridgeDeStreamed(
		bridgeRequest(t, "/v1/chat/completions", nonStreamChatBody),
		translator.FormatOpenAI, translator.FormatOpenAIResponses)
	resp := &http.Response{Header: http.Header{}, StatusCode: 200}
	resp.Header.Set("Content-Type", sseContentType)
	resp.Header.Set("Content-Length", "999") // the upstream's count for a body we replace
	body := newBridgedStreamingBody(r.Context(), resp, io.NopCloser(strings.NewReader(sse)), quietLogger())
	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("reading the de-streamed body: %v", err)
	}
	return resp.Header, out
}

const completedSSE = "event: response.created\n" +
	`data: {"type":"response.created","response":{"id":"resp_1","status":"in_progress"}}` + "\n\n" +
	"event: response.output_text.delta\n" +
	`data: {"type":"response.output_text.delta","delta":"ok"}` + "\n\n" +
	"event: response.completed\n" +
	`data: {"type":"response.completed","response":{"id":"resp_1","status":"completed","model":"gpt-5.4",` +
	`"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],` +
	`"usage":{"input_tokens":9,"output_tokens":2,"total_tokens":11}}}` + "\n\n" +
	"data: [DONE]\n\n"

func TestDeStream_StreamBecomesOneChatCompletionsBody(t *testing.T) {
	hdr, out := deStreamedBody(t, completedSSE)

	if got := hdr.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type = %q; a non-streaming client must not be told this is an event stream", got)
	}
	// A stale Content-Length is not cosmetic: ReverseProxy copies the header
	// map verbatim, so it would advertise the upstream's byte count for a body
	// we just replaced.
	if got := hdr.Get("Content-Length"); got != "" {
		t.Errorf("stale Content-Length %q survived the rewrite", got)
	}
	if got := gjson.GetBytes(out, "object").String(); got != "chat.completion" {
		t.Fatalf("not a Chat Completions body (object=%q): %s", got, out)
	}
	if got := gjson.GetBytes(out, "choices.0.message.content").String(); got != "ok" {
		t.Errorf("answer text lost: %s", out)
	}
	// Taken from the completed event rather than recounted from deltas — the
	// backend already assembled it.
	if got := gjson.GetBytes(out, "usage.total_tokens").Int(); got != 11 {
		t.Errorf("usage.total_tokens = %d, want 11: %s", got, out)
	}
	if strings.Contains(string(out), "event:") || strings.Contains(string(out), "[DONE]") {
		t.Errorf("SSE framing leaked into the client body: %s", out)
	}
}

// TestDeStream_MultiLineDataPayloadIsNotTruncated — SSE lets one payload span
// several `data:` lines, and a long completion is exactly when it does. A
// line-wise reader would silently truncate the largest answers.
func TestDeStream_MultiLineDataPayloadIsNotTruncated(t *testing.T) {
	split := "event: response.completed\n" +
		`data: {"type":"response.completed","response":{"id":"r","status":"completed",` + "\n" +
		`data: "output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],` + "\n" +
		`data: "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}` + "\n\n"

	_, out := deStreamedBody(t, split)
	if got := gjson.GetBytes(out, "choices.0.message.content").String(); got != "ok" {
		t.Fatalf("multi-line payload was truncated: %s", out)
	}
}

// TestDeStream_InterruptedStreamIsVisibleNotEmpty — the client already has
// HTTP 200 by the time we discover the stream never completed, so the failure
// has to be stated in the body. Zero bytes would read as "the model said
// nothing" while the request was billed.
func TestDeStream_InterruptedStreamIsVisibleNotEmpty(t *testing.T) {
	_, out := deStreamedBody(t,
		"event: response.created\n"+
			`data: {"type":"response.created","response":{"id":"r"}}`+"\n\n")

	if len(out) == 0 {
		t.Fatal("interrupted stream produced an empty body")
	}
	if got := gjson.GetBytes(out, "error.code").String(); got != "BRIDGE_DESTREAM_INCOMPLETE" {
		t.Fatalf("interrupted stream did not name its failure (code=%q): %s", got, out)
	}
	if !strings.Contains(gjson.GetBytes(out, "error.message").String(), "billed") {
		t.Errorf("failure message does not tell the caller the request was still billed: %s", out)
	}
}

// TestDeStream_NonSSEUpstreamIsForwardedVerbatim — an upstream ERROR body is
// JSON, not frames. Collapsing it would hand the client zero bytes and lose the
// reason it failed, which is the same defect the streaming wrapper documents.
func TestDeStream_NonSSEUpstreamIsForwardedVerbatim(t *testing.T) {
	errEnvelope := `{"error":{"message":"upstream said no","type":"invalid_request_error"}}`
	r := armBridgeDeStreamed(
		bridgeRequest(t, "/v1/chat/completions", nonStreamChatBody),
		translator.FormatOpenAI, translator.FormatOpenAIResponses)
	resp := &http.Response{Header: http.Header{}, StatusCode: 400}
	resp.Header.Set("Content-Type", "application/json")

	body := newBridgedStreamingBody(r.Context(), resp, io.NopCloser(strings.NewReader(errEnvelope)), quietLogger())
	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != errEnvelope {
		t.Fatalf("upstream error body was not forwarded verbatim:\ngot  %s\nwant %s", out, errEnvelope)
	}
}

// TestDeStream_UnarmedRequestIsUntouched — invariant 4: nothing the bridge did
// not engage for may be rewritten.
func TestDeStream_UnarmedRequestIsUntouched(t *testing.T) {
	raw := "event: x\ndata: {\"a\":1}\n\n"
	r := bridgeRequest(t, "/v1/chat/completions", nonStreamChatBody)
	resp := &http.Response{Header: http.Header{}, StatusCode: 200}
	resp.Header.Set("Content-Type", sseContentType)

	out, err := io.ReadAll(newBridgedStreamingBody(r.Context(), resp, io.NopCloser(strings.NewReader(raw)), quietLogger()))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != raw {
		t.Fatalf("unarmed body was rewritten:\ngot  %q\nwant %q", out, raw)
	}
	if got := resp.Header.Get("Content-Type"); got != sseContentType {
		t.Errorf("unarmed response had its content-type changed to %q", got)
	}
}

// TestDeStream_TextComesFromDeltasWhenTheEnvelopeHasNone is the fence for the
// defect the E2E found and every unit test here missed.
//
// The resident codex fixture ends its stream with a completed event carrying
// usage and NO output. Read the envelope alone and the client gets a
// well-formed, correctly-billed chat.completion whose content is the empty
// string — the model answered, the answer was billed, and it was dropped
// between the drainer and the client.
func TestDeStream_TextComesFromDeltasWhenTheEnvelopeHasNone(t *testing.T) {
	thin := "event: response.output_text.delta\n" +
		`data: {"type":"response.output_text.delta","delta":"partial "}` + "\n\n" +
		"event: response.output_text.delta\n" +
		`data: {"type":"response.output_text.delta","delta":"answer"}` + "\n\n" +
		"event: response.completed\n" +
		`data: {"type":"response.completed","response":{"id":"r","status":"completed",` +
		`"usage":{"input_tokens":11,"output_tokens":4,"total_tokens":15}}}` + "\n\n"

	_, out := deStreamedBody(t, thin)
	if got := gjson.GetBytes(out, "choices.0.message.content").String(); got != "partial answer" {
		t.Fatalf("content = %q, want the concatenated deltas — a streaming client would have "+
			"rendered exactly that text:\n%s", got, out)
	}
	if got := gjson.GetBytes(out, "usage.total_tokens").Int(); got != 15 {
		t.Errorf("usage lost while recovering the text: %s", out)
	}
}

// TestDeStream_FatEnvelopeIsNotOverwrittenByDeltas — when the upstream DID send
// a finished output array, it is authoritative. Flattening it to the delta
// string would discard structure a flat string cannot carry: tool calls,
// refusals, multi-part content.
func TestDeStream_FatEnvelopeIsNotOverwrittenByDeltas(t *testing.T) {
	// The deltas deliberately disagree with the envelope, so whichever wins is
	// visible in the result.
	fat := "event: response.output_text.delta\n" +
		`data: {"type":"response.output_text.delta","delta":"DELTAS"}` + "\n\n" +
		"event: response.completed\n" +
		`data: {"type":"response.completed","response":{"id":"r","status":"completed","model":"m",` +
		`"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ENVELOPE"}]}],` +
		`"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}` + "\n\n"

	_, out := deStreamedBody(t, fat)
	if got := gjson.GetBytes(out, "choices.0.message.content").String(); got != "ENVELOPE" {
		t.Fatalf("content = %q; the upstream's own assembled output must win over the deltas", got)
	}
}

// ── native /responses clients (no dialect translation involved) ─────────────

const nativeResponsesBody = `{"model":"gpt-5-codex","instructions":"be brief","input":"hi"}`

// TestDeStream_NativeResponsesClientIsServedNonStreaming — a client speaking
// exactly the dialect the upstream speaks, refused anyway because it wanted one
// whole body. Nothing here needs translating; only the streaming has to be
// reconciled.
func TestDeStream_NativeResponsesClientIsServedNonStreaming(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, nil)

	r := bridgeRequest(t, "/v1/responses", nativeResponsesBody)
	out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", "", quietLogger())
	if refusal != nil {
		t.Fatalf("native non-streaming Responses request was refused: %s", refusal.Message)
	}
	if out.URL.Path != "/v1/responses" {
		t.Errorf("path was rewritten to %q; the dialects agree, so the route must not move", out.URL.Path)
	}
	body, _ := io.ReadAll(out.Body)
	if !gjson.GetBytes(body, "stream").Bool() {
		t.Fatalf("upstream body must say stream:true (Codex serves nothing else): %s", body)
	}
	st := armedState(t, out)
	if !st.deStream {
		t.Error("de-streaming was not armed; the client would receive raw SSE for a non-streaming request")
	}
	if st.from != st.to {
		t.Errorf("from=%s to=%s; a same-dialect request must not be marked for translation", st.from, st.to)
	}
	if reason := oauthUpstreamRejectsShape("openai", out); reason != "" {
		t.Errorf("pre-dial shape gate still refuses it: %s", reason)
	}
}

// TestDeStream_NativeResponsesUntouchedWithTheSwitchOff is invariant 1 for this
// path: a deployment that never opted in keeps the old refusal, and the request
// reaches the gate byte-for-byte as it was sent.
func TestDeStream_NativeResponsesUntouchedWithTheSwitchOff(t *testing.T) {
	p := &Proxy{} // zero value = the shipped default

	r := bridgeRequest(t, "/v1/responses", nativeResponsesBody)
	out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", "", quietLogger())
	if refusal != nil {
		t.Fatalf("the bridge itself refused; the pre-dial gate owns this refusal: %+v", refusal)
	}
	if bridgeFromContext(out.Context()) != nil {
		t.Error("bridge armed with the switch off")
	}
	body, _ := io.ReadAll(out.Body)
	if string(body) != nativeResponsesBody {
		t.Errorf("body rewritten with the switch off:\n got: %s\nwant: %s", body, nativeResponsesBody)
	}
	// And the refusal that used to be the whole story still happens.
	out.Body = io.NopCloser(strings.NewReader(string(body)))
	if reason := oauthUpstreamRejectsShape("openai", out); reason == "" {
		t.Error("with the switch off the non-streaming request must still be refused pre-dial")
	}
}

// TestDeStream_SameDialectCollapseReturnsResponsesNotChatCompletions — the
// collapsing is shared with the translated path, so the risk is that it also
// translates. A native client must get its own dialect back.
func TestDeStream_SameDialectCollapseReturnsResponsesNotChatCompletions(t *testing.T) {
	r := armBridgeDeStreamed(
		bridgeRequest(t, "/v1/responses", nativeResponsesBody),
		translator.FormatOpenAIResponses, translator.FormatOpenAIResponses)
	resp := &http.Response{Header: http.Header{}, StatusCode: 200}
	resp.Header.Set("Content-Type", sseContentType)

	body := newBridgedStreamingBody(r.Context(), resp, io.NopCloser(strings.NewReader(completedSSE)), quietLogger())
	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type = %q, want application/json", got)
	}
	if got := gjson.GetBytes(out, "object").String(); got == "chat.completion" {
		t.Fatalf("a native Responses client was handed a Chat Completions body: %s", out)
	}
	if got := gjson.GetBytes(out, "status").String(); got != "completed" {
		t.Fatalf("not a Responses response object (status=%q): %s", got, out)
	}
	if got := gjson.GetBytes(out, "output.0.content.0.text").String(); got != "ok" {
		t.Errorf("answer text lost: %s", out)
	}
	if got := gjson.GetBytes(out, "usage.input_tokens").Int(); got != 9 {
		t.Errorf("Responses-native usage was renamed or lost: %s", out)
	}
}

// TestDeStream_NativeResponsesToADeclaredRelayIsUntouched — the same-dialect
// path must be keyed on the DESTINATION too, not merely on "the client did not
// ask to stream".
//
// A relay an operator declared as Responses-speaking serves a non-streaming
// request perfectly well, exactly as api.openai.com does. Rewriting it to
// stream and collapsing the answer back would change a working wire form,
// spend the round trip differently, and gain nothing.
func TestDeStream_NativeResponsesToADeclaredRelayIsUntouched(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, responsesRelayRules())

	r := bridgeRequest(t, "/v1/responses", nativeResponsesBody)
	out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", responsesRelayBase, quietLogger())
	if refusal != nil {
		t.Fatalf("refused: %s", refusal.Message)
	}
	if bridgeFromContext(out.Context()) != nil {
		t.Fatal("a declared Responses relay was treated as Codex; its request was rewritten to stream for no reason")
	}
	body, _ := io.ReadAll(out.Body)
	if string(body) != nativeResponsesBody {
		t.Errorf("body rewritten for an upstream that serves it as sent:\n got: %s\nwant: %s", body, nativeResponsesBody)
	}
}

// ── upstream event streams that arrive WITHOUT a Content-Type ───────────────
//
// The real ChatGPT Codex backend, behind the cluster worker's group lane, sends
// its event stream with no Content-Type header (master2 staging, 2026-09-11).
// Every mock above sets text/event-stream, which is exactly why none of them saw
// the bridge forward those responses untranslated.

func responseWithoutContentType() *http.Response {
	return &http.Response{Header: http.Header{}, StatusCode: http.StatusOK}
}

func TestDeStream_CodexStreamWithoutContentTypeIsStillCollapsed(t *testing.T) {
	r := armBridgeDeStreamed(
		bridgeRequest(t, "/v1/chat/completions", nonStreamChatBody),
		translator.FormatOpenAI, translator.FormatOpenAIResponses)
	resp := responseWithoutContentType()

	out, err := io.ReadAll(newBridgedStreamingBody(r.Context(), resp, io.NopCloser(strings.NewReader(completedSSE)), quietLogger()))
	if err != nil {
		t.Fatal(err)
	}
	if got := gjson.GetBytes(out, "object").String(); got != "chat.completion" {
		t.Fatalf("a non-streaming client got the raw upstream stream instead of one body:\n%s", out)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type = %q, want application/json", got)
	}
}

func TestBridge_StreamingClientGetsFramesWhenUpstreamOmitsContentType(t *testing.T) {
	upstream := strings.Join([]string{
		"event: response.created",
		`data: {"type":"response.created","response":{"id":"resp_n","model":"gpt-5.5"}}`,
		"",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","delta":"ok"}`,
		"",
		"event: response.completed",
		`data: {"type":"response.completed","response":{"id":"resp_n","status":"completed","usage":{"input_tokens":3,"output_tokens":1}}}`,
		"", "",
	}, "\n")
	r := armBridge(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		translator.FormatOpenAI, translator.FormatOpenAIResponses)
	resp := responseWithoutContentType()

	out, err := io.ReadAll(newBridgedStreamingBody(r.Context(), resp, io.NopCloser(strings.NewReader(upstream)), quietLogger()))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if strings.Contains(text, "event: response.") || !strings.Contains(text, `"chat.completion.chunk"`) {
		t.Fatalf("a streaming Chat Completions client got untranslated Responses frames:\n%s", text)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("client content-type = %q; the client must be told it is receiving an event stream", got)
	}
}

func TestBridge_ContentTypeLessJSONErrorIsForwardedVerbatim(t *testing.T) {
	const errBody = `{"error":{"code":"OAUTH_MODEL_UNSUPPORTED","message":"not entitled"}}`
	r := armBridgeDeStreamed(
		bridgeRequest(t, "/v1/chat/completions", nonStreamChatBody),
		translator.FormatOpenAI, translator.FormatOpenAIResponses)
	resp := responseWithoutContentType()

	out, err := io.ReadAll(newBridgedStreamingBody(r.Context(), resp, io.NopCloser(strings.NewReader(errBody)), quietLogger()))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != errBody {
		t.Fatalf("an error body without Content-Type was altered or swallowed:\n got: %q\nwant: %q", out, errBody)
	}
	if got := resp.Header.Get("Content-Type"); got != "" {
		t.Errorf("content-type invented for a non-stream body: %q", got)
	}
}

func TestBridge_ExplicitJSONContentTypeIsAuthoritative(t *testing.T) {
	r := armBridgeDeStreamed(
		bridgeRequest(t, "/v1/chat/completions", nonStreamChatBody),
		translator.FormatOpenAI, translator.FormatOpenAIResponses)
	resp := responseWithoutContentType()
	resp.Header.Set("Content-Type", "application/json")

	out, err := io.ReadAll(newBridgedStreamingBody(r.Context(), resp, io.NopCloser(strings.NewReader(completedSSE)), quietLogger()))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != completedSSE {
		t.Fatalf("an explicit Content-Type was overridden by sniffing; body changed:\n%s", out)
	}
}

func TestBridge_UnarmedResponseWithoutContentTypeIsUntouched(t *testing.T) {
	r := bridgeRequest(t, "/v1/responses", nativeResponsesBody) // bridge never armed
	resp := responseWithoutContentType()

	out, err := io.ReadAll(newBridgedStreamingBody(r.Context(), resp, io.NopCloser(strings.NewReader(completedSSE)), quietLogger()))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != completedSSE {
		t.Fatalf("an unarmed response was modified:\n%s", out)
	}
	if got := resp.Header.Get("Content-Type"); got != "" {
		t.Errorf("an unarmed response gained a content-type: %q (switch-off must stay byte-identical)", got)
	}
}

func TestBridge_SniffDoesNotHoldBackAStreamThatPausesAfterItsFirstBytes(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() { _, _ = pw.Write([]byte(": keep-alive\n\n")) }() // then the upstream goes quiet

	done := make(chan bool, 1)
	go func() {
		isSSE, _ := sniffEventStream(pr)
		done <- isSSE
	}()
	select {
	case isSSE := <-done:
		if !isSSE {
			t.Fatal("a stream opening with an SSE comment was not recognized as an event stream")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sniffing waited for more bytes than the upstream's first write; a slow stream would stall before the client sees anything")
	}
}

// The bytes the real ChatGPT Codex backend sent through the cluster worker's group
// lane on master2 staging (2026-09-11, gpt-5.5, native /responses stream:true),
// ids sanitized. They differ from every hand-written fixture in this file in three
// ways, and each one hid a defect that only staging found: no Content-Type header,
// a response.completed envelope whose "output" is [] (the text arrives only as
// deltas), and an explicit "error": null among ~30 other keys.
// Bugfix: workflow/CI/bugfix/2026-09-11-bridge-error-null-treated-as-error-envelope.md
func TestDeStream_RealCodexStreamServesAllThreeClientShapes(t *testing.T) {
	raw, err := os.ReadFile("testdata/codex_real_stream_2026-09-11.sse")
	if err != nil {
		t.Fatalf("fixture missing: %v", err)
	}

	t.Run("non-streaming Chat Completions client", func(t *testing.T) {
		r := armBridgeDeStreamed(bridgeRequest(t, "/v1/chat/completions", nonStreamChatBody),
			translator.FormatOpenAI, translator.FormatOpenAIResponses)
		resp := responseWithoutContentType()
		out, err := io.ReadAll(newBridgedStreamingBody(r.Context(), resp, io.NopCloser(bytes.NewReader(raw)), quietLogger()))
		if err != nil {
			t.Fatal(err)
		}
		if got := gjson.GetBytes(out, "object").String(); got != "chat.completion" {
			t.Fatalf("object = %q, want chat.completion. The real envelope came back untranslated:\n%.400s", got, out)
		}
		if got := gjson.GetBytes(out, "choices.0.message.content").String(); got != "ok" {
			t.Errorf("content = %q, want ok", got)
		}
		if gjson.GetBytes(out, "usage.prompt_tokens").Int() <= 0 {
			t.Errorf("usage lost:\n%.400s", out)
		}
		if got := resp.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content-type = %q, want application/json", got)
		}
	})

	t.Run("streaming Chat Completions client", func(t *testing.T) {
		r := armBridge(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
			translator.FormatOpenAI, translator.FormatOpenAIResponses)
		resp := responseWithoutContentType()
		out, err := io.ReadAll(newBridgedStreamingBody(r.Context(), resp, io.NopCloser(bytes.NewReader(raw)), quietLogger()))
		if err != nil {
			t.Fatal(err)
		}
		text := string(out)
		if strings.Contains(text, "event: response.") || !strings.Contains(text, "chat.completion.chunk") || !strings.Contains(text, "[DONE]") {
			t.Fatalf("streaming client did not get translated frames:\n%.600s", text)
		}
	})

	t.Run("native non-streaming Responses client", func(t *testing.T) {
		r := armBridgeDeStreamed(bridgeRequest(t, "/v1/responses", nativeResponsesBody),
			translator.FormatOpenAIResponses, translator.FormatOpenAIResponses)
		resp := responseWithoutContentType()
		out, err := io.ReadAll(newBridgedStreamingBody(r.Context(), resp, io.NopCloser(bytes.NewReader(raw)), quietLogger()))
		if err != nil {
			t.Fatal(err)
		}
		if gjson.GetBytes(out, "status").String() != "completed" || strings.Contains(string(out), "chat.completion") {
			t.Fatalf("native client did not get one Responses object:\n%.400s", out)
		}
		if got := gjson.GetBytes(out, "output.#(type==\"message\").content.0.text").String(); got != "ok" {
			t.Errorf("answer not rebuilt from deltas: %q", got)
		}
	})
}
