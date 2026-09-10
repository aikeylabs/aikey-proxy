package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AiKeyLabs/aikey-proxy/internal/observability"
	translator "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator"
	"github.com/tidwall/gjson"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func bridgeRequest(t *testing.T, path, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.ContentLength = int64(len(body))
	return r
}

const sseContentType = "text/event-stream"

const (
	simpleChatBody      = `{"model":"gpt-5.4","messages":[{"role":"user","content":"hi"}]}`
	simpleResponsesBody = `{"model":"gpt-5.4","instructions":"be brief","input":"hi"}`
	relayHost           = "relay.corp.example"
	relayBase           = "https://relay.corp.example/v1"
)

// relayRules declares a Chat Completions relay — the "both upstream kinds
// exist" deployment shape.
func relayRules() []BridgeUpstreamRule {
	return []BridgeUpstreamRule{{Host: relayHost, Dialect: "chat_completions"}}
}

// ── invariant 1: off is the old behaviour, byte for byte ────────────────────

// TestBridge_OffKeepsTheOriginalRefusal is the most important fence here. The
// switch defaulting to off is what makes shipping this safe: a deployment that
// never opted in must behave exactly as it did before, including the wording of
// the refusal, which names the remedy users act on.
func TestBridge_OffKeepsTheOriginalRefusal(t *testing.T) {
	p := &Proxy{} // zero value: disabled, empty allowlist — the shipped default

	r := bridgeRequest(t, "/v1/chat/completions", simpleChatBody)
	out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", "", quietLogger())

	if refusal == nil {
		t.Fatal("a /chat/completions request was accepted with the bridge off")
	}
	// Asserted against the CONSTANT, not a literal: the pre-dial gate this sits
	// in front of owns the status (422 since 2026-09-10, so a relay retries it
	// while a direct SDK still sees it). A literal here would quietly diverge
	// from the gate the moment that decision is revisited.
	if refusal.Code != observability.ErrCodeOAuthResponsesOnly || refusal.Status != oauthResponsesOnlyStatus {
		t.Errorf("refusal = %d/%s, want %d/%s",
			refusal.Status, refusal.Code, oauthResponsesOnlyStatus, observability.ErrCodeOAuthResponsesOnly)
	}
	if want := oauthUpstreamRejectsPath("openai", "/v1/chat/completions"); refusal.Message != want {
		t.Errorf("refusal wording drifted.\n got: %s\nwant: %s", refusal.Message, want)
	}
	if out.URL.Path != "/v1/chat/completions" {
		t.Errorf("path was rewritten with the bridge off: %s", out.URL.Path)
	}
	if bridgeFromContext(out.Context()) != nil {
		t.Error("bridge state armed with the switch off")
	}
}

// ── invariant 4: agreeing dialects are never touched ────────────────────────

// TestBridge_AgreeingDialectsArePassedThrough covers BOTH passthrough
// quadrants, in both switch states. These are the combinations that already
// worked, and nothing this file added may disturb them.
func TestBridge_AgreeingDialectsArePassedThrough(t *testing.T) {
	for _, tc := range []struct {
		name, path, body, base string
		rules                  []BridgeUpstreamRule
	}{
		{"responses client → codex", "/v1/responses", simpleResponsesBody, "", nil},
		{"chat client → relay", "/v1/chat/completions", simpleChatBody, relayBase, relayRules()},
	} {
		for _, enabled := range []bool{false, true} {
			t.Run(tc.name, func(t *testing.T) {
				p := &Proxy{}
				p.SetChatCompletionsBridge(enabled, tc.rules)

				r := bridgeRequest(t, tc.path, tc.body)
				out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", tc.base, quietLogger())
				if refusal != nil {
					t.Fatalf("enabled=%v: refused: %+v", enabled, refusal)
				}
				if out.URL.Path != tc.path {
					t.Errorf("enabled=%v: path rewritten to %q", enabled, out.URL.Path)
				}
				if bridgeFromContext(out.Context()) != nil {
					t.Errorf("enabled=%v: bridge armed where the dialects already agree", enabled)
				}
				got, _ := io.ReadAll(out.Body)
				if string(got) != tc.body {
					t.Errorf("enabled=%v: body rewritten:\n got: %s\nwant: %s", enabled, got, tc.body)
				}
			})
		}
	}
}

// ── the two translating quadrants ───────────────────────────────────────────

// TestBridge_ChatClientToResponsesUpstream — the codex case.
func TestBridge_ChatClientToResponsesUpstream(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, nil)

	r := bridgeRequest(t, "/v1/chat/completions", simpleChatBody)
	out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", "", quietLogger())
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if out.URL.Path != "/v1/responses" {
		t.Fatalf("path = %q, want /v1/responses", out.URL.Path)
	}
	st := bridgeFromContext(out.Context())
	if st == nil {
		t.Fatal("bridge state not armed; the response leg would not translate back")
	}
	if st.from != translator.FormatOpenAI || st.to != translator.FormatOpenAIResponses {
		t.Errorf("armed direction = %s→%s", st.from, st.to)
	}
	body, _ := io.ReadAll(out.Body)
	if gjson.GetBytes(body, "messages").Exists() {
		t.Error("forwarded body still carries messages[]")
	}
	if gjson.GetBytes(body, "input.0.content.0.text").String() != "hi" {
		t.Errorf("prompt lost: %s", body)
	}
}

// TestBridge_ResponsesClientToChatUpstream is the quadrant that only exists
// once a credential can point at a Chat Completions relay — a codex CLI served
// by a self-hosted gateway.
func TestBridge_ResponsesClientToChatUpstream(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, relayRules())

	r := bridgeRequest(t, "/v1/responses", simpleResponsesBody)
	out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", relayBase, quietLogger())
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if out.URL.Path != "/v1/chat/completions" {
		t.Fatalf("path = %q, want /v1/chat/completions", out.URL.Path)
	}
	st := bridgeFromContext(out.Context())
	if st == nil || st.from != translator.FormatOpenAIResponses || st.to != translator.FormatOpenAI {
		t.Fatalf("armed direction wrong: %+v", st)
	}
	body, _ := io.ReadAll(out.Body)
	if gjson.GetBytes(body, "input").Exists() {
		t.Error("forwarded body still carries input[]")
	}
	msgs := gjson.GetBytes(body, "messages").Array()
	if len(msgs) != 2 || msgs[0].Get("role").String() != "system" || msgs[1].Get("content").String() != "hi" {
		t.Errorf("instructions+input did not become messages[]: %s", body)
	}
}

// TestBridge_ResponsesClientToChatUpstreamRefusedWhenOff — the mirror refusal
// must name what the upstream actually serves, and must NOT reuse the
// Responses-only wording, whose remedy ("use a Responses client") would be
// exactly backwards here.
func TestBridge_ResponsesClientToChatUpstreamRefusedWhenOff(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(false, relayRules())

	r := bridgeRequest(t, "/v1/responses", simpleResponsesBody)
	_, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", relayBase, quietLogger())
	if refusal == nil {
		t.Fatal("a Responses request to a Chat Completions upstream was accepted with the bridge off")
	}
	if !strings.Contains(refusal.Message, "Chat Completions") {
		t.Errorf("refusal does not say what the upstream serves: %s", refusal.Message)
	}
	if strings.Contains(refusal.Message, "such as codex") {
		t.Error("refusal reuses the Responses-only remedy, which points the caller the wrong way")
	}
}

// ── the OAuth destination allowlist (security) ──────────────────────────────

// TestBridge_UnlistedUpstreamIsIgnoredNotUsed is the security fence. An OAuth
// access token is the subscription itself; a host that receives one holds the
// account. A base_url nobody enumerated must not become a destination.
func TestBridge_UnlistedUpstreamIsIgnoredNotUsed(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, nil) // enabled, but NOTHING allowlisted

	got := p.oauthUpstreamBase("openai", "openai_compatible", "https://attacker.example/v1", quietLogger())
	if got != codexUpstreamBaseURL() {
		t.Fatalf("OAuth traffic resolved to %q; an un-enumerated host must never receive the token", got)
	}
}

func TestBridge_ListedUpstreamIsUsed(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, relayRules())

	got := p.oauthUpstreamBase("openai", "openai_compatible", relayBase, quietLogger())
	if got != relayBase {
		t.Fatalf("allowlisted upstream = %q, want %q", got, relayBase)
	}
}

// TestBridge_PlaintextUpstreamIsRefusedEvenWhenListed — an operator can
// enumerate a host but still must not push the subscription across a hop
// anyone on the path can read. Loopback is the exception, because those bytes
// never leave the machine.
func TestBridge_PlaintextUpstreamIsRefusedEvenWhenListed(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, []BridgeUpstreamRule{
		{Host: "plain.corp.example", Dialect: "chat_completions"},
		{Host: "127.0.0.1", Dialect: "chat_completions"},
	})

	if got := p.oauthUpstreamBase("openai", "", "http://plain.corp.example/v1", quietLogger()); got != codexUpstreamBaseURL() {
		t.Errorf("plaintext upstream was used: %q", got)
	}
	loop := "http://127.0.0.1:9111/v1"
	if got := p.oauthUpstreamBase("openai", "", loop, quietLogger()); got != loop {
		t.Errorf("loopback upstream = %q, want it permitted for local testing", got)
	}
}

// TestBridge_AllowlistDoesNotLeakToOtherProviders — every other provider's
// OAuth upstream equals its API-key upstream, and those already accept any
// base_url. The allowlist must not start constraining them.
func TestBridge_AllowlistDoesNotLeakToOtherProviders(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, nil)
	custom := "https://anthropic-gw.corp.example"
	if got := p.oauthUpstreamBase("anthropic", "anthropic", custom, quietLogger()); got != custom {
		t.Fatalf("anthropic upstream = %q, want %q — the allowlist is openai-only", got, custom)
	}
}

// TestBridge_UndeclaredDialectFailsClosed — reaching an upstream whose dialect
// nobody declared means nothing knows what shape to send, and guessing is how a
// request comes back answered in the wrong dialect with no way to tell.
func TestBridge_UndeclaredDialectFailsClosed(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, nil)
	// Force an upstream that resolves but has no declared dialect by rewriting
	// the runtime's map directly — a state config validation prevents, which is
	// exactly why the request path must still refuse rather than assume.
	p.bridge.Store(&bridgeRuntime{enabled: true, byHost: map[string]translator.Format{relayHost: ""}})

	r := bridgeRequest(t, "/v1/chat/completions", simpleChatBody)
	_, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", relayBase, quietLogger())
	if refusal == nil {
		t.Fatal("an upstream with no declared dialect was used anyway")
	}
	if refusal.Status != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", refusal.Status)
	}
}

// ── scope ───────────────────────────────────────────────────────────────────

func TestBridge_OnlyOpenAIOAuthIsBridged(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, nil)
	for _, code := range []string{"anthropic", "kimi", "google"} {
		r := bridgeRequest(t, "/v1/chat/completions", simpleChatBody)
		out, refusal := p.bridgeOrRejectDialect(r, code, "", "", quietLogger())
		if refusal != nil {
			t.Errorf("%s: refused: %+v", code, refusal)
			continue
		}
		if out.URL.Path != "/v1/chat/completions" || bridgeFromContext(out.Context()) != nil {
			t.Errorf("%s: bridge engaged for a provider that needs no reconciliation", code)
		}
	}
}

// TestBridge_NonChatSurfacesAreUntouched — /v1/models and friends carry no
// dialect and must flow exactly as before.
func TestBridge_NonChatSurfacesAreUntouched(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, nil)
	r := bridgeRequest(t, "/v1/models", "")
	out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", "", quietLogger())
	if refusal != nil {
		t.Fatalf("/v1/models refused: %+v", refusal)
	}
	if out.URL.Path != "/v1/models" || bridgeFromContext(out.Context()) != nil {
		t.Error("a non-chat surface was bridged")
	}
}

func TestBridge_RefusedParamsSurfaceAsClientErrors(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, nil)
	body := `{"model":"m","messages":[{"role":"user","content":"x"}],"stop":["END"]}`
	r := bridgeRequest(t, "/v1/chat/completions", body)
	_, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", "", quietLogger())
	if refusal == nil {
		t.Fatal("`stop` was accepted; the model would run past the caller's stop sequence")
	}
	if !strings.Contains(refusal.Message, "stop") {
		t.Errorf("refusal does not name the parameter: %s", refusal.Message)
	}
	if refusal.Code == observability.ErrCodeOAuthResponsesOnly {
		t.Error("a parameter problem was reported as a dialect problem")
	}
}

func TestBridge_GetBodyReplaysTranslatedBytes(t *testing.T) {
	p := &Proxy{}
	p.SetChatCompletionsBridge(true, nil)
	r := bridgeRequest(t, "/v1/chat/completions", simpleChatBody)
	out, refusal := p.bridgeOrRejectDialect(r, "openai", "openai_compatible", "", quietLogger())
	if refusal != nil {
		t.Fatal(refusal)
	}
	if out.GetBody == nil {
		t.Fatal("GetBody is nil; an h2 stream reset would make this request unretryable")
	}
	replay, err := out.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	replayed, _ := io.ReadAll(replay)
	if gjson.GetBytes(replayed, "messages").Exists() || !gjson.GetBytes(replayed, "input").Exists() {
		t.Fatalf("GetBody replays the PRE-translation body: %s", replayed)
	}
}

// ── response leg ────────────────────────────────────────────────────────────

func TestBridge_NonStreamResponseTranslatesInBothDirections(t *testing.T) {
	responsesBody := []byte(`{"id":"resp_z","status":"completed","model":"m",
		"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],
		"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
	chatBody := []byte(`{"id":"chatcmpl-z","object":"chat.completion","created":1,"model":"m",
		"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],
		"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)

	// Not armed → byte-identical passthrough.
	if out, tErr := translateBridgedResponse(context.Background(), responsesBody, quietLogger()); tErr != nil {
		t.Fatal(tErr)
	} else if !bytes.Equal(out, responsesBody) {
		t.Errorf("unarmed response was rewritten:\n%s", out)
	}

	base := httptest.NewRequest(http.MethodPost, "/v1/x", nil)

	// chat client ← responses upstream
	ctxA := armBridge(base, translator.FormatOpenAI, translator.FormatOpenAIResponses).Context()
	outA, tErr := translateBridgedResponse(ctxA, responsesBody, quietLogger())
	if tErr != nil {
		t.Fatal(tErr)
	}
	if gjson.GetBytes(outA, "object").String() != "chat.completion" {
		t.Fatalf("not translated to Chat Completions: %s", outA)
	}

	// responses client ← chat upstream
	ctxB := armBridge(base, translator.FormatOpenAIResponses, translator.FormatOpenAI).Context()
	outB, tErr := translateBridgedResponse(ctxB, chatBody, quietLogger())
	if tErr != nil {
		t.Fatal(tErr)
	}
	if gjson.GetBytes(outB, "object").String() != "response" {
		t.Fatalf("not translated to Responses: %s", outB)
	}
	if gjson.GetBytes(outB, "output_text").String() != "ok" {
		t.Errorf("output_text missing: %s", outB)
	}
}

// ── SSE ─────────────────────────────────────────────────────────────────────

func TestBridge_SSEChatClientReceivesChatCompletionsFrames(t *testing.T) {
	upstream := strings.Join([]string{
		"event: response.created",
		`data: {"type":"response.created","response":{"id":"resp_w","model":"gpt-5.4"}}`,
		"",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","delta":"Hi"}`,
		"",
		"event: response.completed",
		`data: {"type":"response.completed","response":{"id":"resp_w","status":"completed","usage":{"input_tokens":3,"output_tokens":1}}}`,
		"", "data: [DONE]", "", "",
	}, "\n")

	ctx := armBridge(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		translator.FormatOpenAI, translator.FormatOpenAIResponses).Context()
	got, err := io.ReadAll(newSSEChatCompletionsBridge(ctx, io.NopCloser(strings.NewReader(upstream)), sseContentType, quietLogger()))
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if strings.Contains(text, "event:") {
		t.Errorf("Chat Completions streams unnamed frames; an event line leaked:\n%s", text)
	}
	if !strings.Contains(text, `"chat.completion.chunk"`) || !strings.Contains(text, `"content":"Hi"`) {
		t.Errorf("stream not translated:\n%s", text)
	}
	if n := strings.Count(text, "data: [DONE]"); n != 1 {
		t.Errorf("%d terminators, want 1:\n%s", n, text)
	}
}

// TestBridge_SSEResponsesClientReceivesNamedEvents is the reverse leg AND the
// fence for the `event:` line. A Responses client registering per-event
// listeners receives nothing at all from an unnamed stream, and the failure
// looks like "the model returned nothing" rather than a protocol error.
func TestBridge_SSEResponsesClientReceivesNamedEvents(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"id":"chatcmpl-r","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`,
		"",
		`data: {"id":"chatcmpl-r","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"Yo"},"finish_reason":null}]}`,
		"",
		`data: {"id":"chatcmpl-r","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`,
		"", "data: [DONE]", "", "",
	}, "\n")

	ctx := armBridge(httptest.NewRequest(http.MethodPost, "/v1/responses", nil),
		translator.FormatOpenAIResponses, translator.FormatOpenAI).Context()
	got, err := io.ReadAll(newSSEChatCompletionsBridge(ctx, io.NopCloser(strings.NewReader(upstream)), sseContentType, quietLogger()))
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)

	for _, want := range []string{
		"event: response.created",
		"event: response.output_text.delta",
		"event: response.completed",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q — a per-event listener would receive nothing:\n%s", want, text)
		}
	}
	if strings.Contains(text, "chat.completion.chunk") {
		t.Errorf("a Chat Completions frame reached a Responses client:\n%s", text)
	}
	if strings.Contains(text, "data: [DONE]") {
		t.Errorf("the Chat Completions terminator leaked into a Responses stream:\n%s", text)
	}
	if !strings.Contains(text, `"delta":"Yo"`) {
		t.Errorf("the model's text did not survive:\n%s", text)
	}
}

func TestBridge_SSEPassthroughWhenUnarmed(t *testing.T) {
	raw := "event: message_start\ndata: {\"type\":\"message_start\"}\n\n"
	got, _ := io.ReadAll(newSSEChatCompletionsBridge(context.Background(),
		io.NopCloser(strings.NewReader(raw)), sseContentType, quietLogger()))
	if string(got) != raw {
		t.Errorf("unarmed stream rewritten:\n got: %q\nwant: %q", got, raw)
	}
}

func TestBridge_SSEDropsMalformedFramesWithoutKillingTheStream(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_m","model":"m"}}`, "",
		"data: {malformed", "",
		`data: {"type":"response.output_text.delta","delta":"after"}`, "", "",
	}, "\n")
	ctx := armBridge(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		translator.FormatOpenAI, translator.FormatOpenAIResponses).Context()
	got, err := io.ReadAll(newSSEChatCompletionsBridge(ctx, io.NopCloser(strings.NewReader(upstream)), sseContentType, quietLogger()))
	if err != nil {
		t.Fatalf("a malformed frame killed the stream: %v", err)
	}
	if !strings.Contains(string(got), `"content":"after"`) {
		t.Errorf("content after the malformed frame was lost:\n%s", got)
	}
	if strings.Contains(string(got), "malformed") {
		t.Errorf("the malformed frame was forwarded verbatim:\n%s", got)
	}
}

// TestBridge_VersionSegmentFollowsDeclarationNotAddress pins the fix for a
// coupling the reverse-direction E2E exposed.
//
// The codex endpoint serves /responses directly off its base with no version
// segment, so the client's /v1 must be stripped (bugfix 2026-07-19, a live
// codex 404). Keying that strip on the ADDRESS made it fire for anything that
// happened to sit where the codex default points — which is what the hermetic
// E2Es arrange, and would equally be true of a relay deployed at a redirected
// address. A declared host is the operator's, and follows the generic
// version-dedup rule instead.
func TestBridge_VersionSegmentFollowsDeclarationNotAddress(t *testing.T) {
	codexHost := hostOf(codexUpstreamBaseURL())

	t.Run("undeclared codex address keeps the codex strip", func(t *testing.T) {
		p := &Proxy{}
		p.SetChatCompletionsBridge(true, nil)
		r := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"m"}`))
		base, out := p.resolveOAuthUpstream("openai", "openai_compatible", "", r, quietLogger())
		if base != codexUpstreamBaseURL() {
			t.Fatalf("base = %q", base)
		}
		if out.URL.Path != "/responses" {
			t.Errorf("path = %q, want /responses — the codex upstream has no version segment", out.URL.Path)
		}
	})

	t.Run("declared host at the same address keeps its version segment", func(t *testing.T) {
		p := &Proxy{}
		p.SetChatCompletionsBridge(true, []BridgeUpstreamRule{{Host: codexHost, Dialect: "chat_completions"}})
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m"}`))
		_, out := p.resolveOAuthUpstream("openai", "openai_compatible", "", r, quietLogger())
		if out.URL.Path != "/v1/chat/completions" {
			t.Errorf("path = %q, want /v1/chat/completions — a declared host is the operator's and "+
				"must not inherit the codex URL convention", out.URL.Path)
		}
	})

	t.Run("declared host whose base carries /v1 dedups", func(t *testing.T) {
		p := &Proxy{}
		p.SetChatCompletionsBridge(true, relayRules())
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m"}`))
		base, out := p.resolveOAuthUpstream("openai", "openai_compatible", relayBase, r, quietLogger())
		if base != relayBase {
			t.Fatalf("base = %q, want %q", base, relayBase)
		}
		if out.URL.Path != "/chat/completions" {
			t.Errorf("path = %q; base already ends in /v1 so the client's copy must be deduped", out.URL.Path)
		}
	})
}

// ── sync/async mismatches ───────────────────────────────────────────────────

// TestBridge_NonSSEBodyIsForwardedNotEaten is the fence for the worst failure
// this file can produce.
//
// Whether the response leg streams is decided from the REQUEST, so a request
// that asked to stream takes the streaming path no matter what came back — and
// two very ordinary things come back NOT as SSE: an upstream error (4xx/5xx
// bodies are JSON, and nothing above returns early for them) and a relay that
// ignores `stream:true` and answers with one whole JSON body.
//
// A frame reader finds no `data:` lines in either. Before this guard the whole
// body was dropped and the client received ZERO bytes — the answer, or the
// reason it failed, silently gone while the usage was still billed, because the
// drainer read it upstream of this wrapper.
func TestBridge_NonSSEBodyIsForwardedNotEaten(t *testing.T) {
	for _, tc := range []struct{ name, ct, body string }{
		{"upstream error on a streaming request", "application/json",
			`{"error":{"type":"rate_limit_error","message":"slow down"}}`},
		{"relay ignored stream:true", "application/json",
			`{"id":"resp_x","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"whole answer"}]}]}`},
		{"no content type at all", "",
			`{"error":{"message":"boom"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := armBridge(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
				translator.FormatOpenAI, translator.FormatOpenAIResponses).Context()
			got, err := io.ReadAll(newSSEChatCompletionsBridge(ctx,
				io.NopCloser(strings.NewReader(tc.body)), tc.ct, quietLogger()))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.body {
				t.Fatalf("body was not forwarded verbatim.\n got: %q\nwant: %q", got, tc.body)
			}
		})
	}
}

// TestBridge_InterruptedStreamIsStillTerminated — an upstream can be cut off,
// time out, or simply stop. Both dialects have a MANDATORY terminator, and a
// client that never receives one waits on a connection that already closed.
func TestBridge_InterruptedStreamIsStillTerminated(t *testing.T) {
	t.Run("chat client, upstream stops before response.completed", func(t *testing.T) {
		upstream := `data: {"type":"response.created","response":{"id":"resp_x","model":"m"}}` + "\n\n" +
			`data: {"type":"response.output_text.delta","delta":"Hi"}` + "\n\n"
		ctx := armBridge(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
			translator.FormatOpenAI, translator.FormatOpenAIResponses).Context()
		got, _ := io.ReadAll(newSSEChatCompletionsBridge(ctx,
			io.NopCloser(strings.NewReader(upstream)), sseContentType, quietLogger()))
		text := string(got)
		if !strings.Contains(text, `"content":"Hi"`) {
			t.Fatalf("the bytes that DID arrive were lost:\n%s", text)
		}
		if !strings.Contains(text, `"finish_reason":"stop"`) {
			t.Errorf("no closing finish_reason:\n%s", text)
		}
		if n := strings.Count(text, "data: [DONE]"); n != 1 {
			t.Errorf("%d terminators, want exactly 1:\n%s", n, text)
		}
	})

	t.Run("responses client, upstream stops before finish_reason", func(t *testing.T) {
		upstream := `data: {"id":"chatcmpl-x","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}` + "\n\n" +
			`data: {"id":"chatcmpl-x","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}` + "\n\n"
		ctx := armBridge(httptest.NewRequest(http.MethodPost, "/v1/responses", nil),
			translator.FormatOpenAIResponses, translator.FormatOpenAI).Context()
		got, _ := io.ReadAll(newSSEChatCompletionsBridge(ctx,
			io.NopCloser(strings.NewReader(upstream)), sseContentType, quietLogger()))
		text := string(got)
		if !strings.Contains(text, `"delta":"Hi"`) {
			t.Fatalf("the bytes that DID arrive were lost:\n%s", text)
		}
		if n := strings.Count(text, "event: response.completed"); n != 1 {
			t.Fatalf("%d response.completed events, want exactly 1 — a Responses client has no "+
				"bare sentinel to fall back on:\n%s", n, text)
		}
		if !strings.Contains(text, `"output_text":"Hi"`) {
			t.Errorf("the terminal frame does not carry what arrived:\n%s", text)
		}
	})
}

// TestBridge_ProperlyTerminatedStreamGetsExactlyOneTerminator — the flush must
// be idempotent with the pair's own terminal path.
func TestBridge_ProperlyTerminatedStreamGetsExactlyOneTerminator(t *testing.T) {
	upstream := `data: {"type":"response.created","response":{"id":"resp_x","model":"m"}}` + "\n\n" +
		`data: {"type":"response.output_text.delta","delta":"Hi"}` + "\n\n" +
		`data: {"type":"response.completed","response":{"id":"resp_x","status":"completed"}}` + "\n\n" +
		"data: [DONE]\n\n"
	ctx := armBridge(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		translator.FormatOpenAI, translator.FormatOpenAIResponses).Context()
	got, _ := io.ReadAll(newSSEChatCompletionsBridge(ctx,
		io.NopCloser(strings.NewReader(upstream)), sseContentType, quietLogger()))
	if n := strings.Count(string(got), "data: [DONE]"); n != 1 {
		t.Fatalf("%d terminators after a clean stream, want 1:\n%s", n, got)
	}
}
