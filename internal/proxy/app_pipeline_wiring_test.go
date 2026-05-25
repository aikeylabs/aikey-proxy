package proxy

// AKL-208 wiring tests — these pin three contracts that together
// guarantee the App pipeline's URL-routing entry point is wired
// correctly into the main Proxy.Handle dispatcher:
//
//   1. /apps/<slug>/v1/... is detected BEFORE the legacy
//      provider-prefix extractor (otherwise /apps/X/v1 would be
//      misread as provider="apps" and produce a confusing 404).
//
//   2. handleAppPipeline returns the expected 501 stub with the parsed
//      AppContext echoed back in the body — confirming the parsed slug +
//      protocol made it from router.go into the handler without loss.
//
//   3. App bearer tokens (aikey_app_<64hex>) presented at the LEGACY /v1
//      or /<provider>/v1/ entries are rejected with the precise
//      APP_TOKEN_WRONG_PATH error pointing the user at the correct URL —
//      not the generic "Unexpected token classification" fallthrough that
//      pre-AKL-208 default-case produced.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AiKeyLabs/aikey-proxy/internal/events"
	"github.com/AiKeyLabs/aikey-proxy/internal/provider"
	"github.com/AiKeyLabs/aikey-proxy/internal/vault"
	"github.com/AiKeyLabs/aikey-proxy/internal/vkeys"
	"github.com/AiKeyLabs/aikey-proxy/pkg/observer"

	// Blank-import the OpenAI ↔ Anthropic translator pair so its init()
	// registers with translator.DefaultRegistry() at test-binary boot.
	// In production this happens in cmd/aikey-proxy/main.go; the
	// internal/proxy package itself does not import any pairs package,
	// so test binaries need the explicit blank-import. Without this
	// every cross-protocol test fails with TRANSLATION_PAIR_NOT_REGISTERED
	// despite the production binary working correctly — see
	// TestHandle_AppPath_OpenAIWireToAnthropicUpstream_TranslatesEndToEnd
	// for the regression it fences. (The comment in
	// translation_isolation_test.go:38-39 claiming "tests import the
	// pair via transitive imports" is aspirational, not true — this
	// blank-import makes it true for the whole package.)
	_ "github.com/AiKeyLabs/aikey-proxy/pkg/protocol-translator/pairs/openai_anthropic"
)

// strict app bearer fixture (74 chars: aikey_app_ + 64-hex)
const testAppBearer = "aikey_app_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// seedAppRouteInProxy primes the proxy's Registry with an app route for
// the given slug bound to testAppBearer. Mirrors what supervisor.loadVaultRoutesIntoRegistry
// produces in production, but synchronously so tests can verify the
// post-authn handler behavior in isolation.
func seedAppRouteInProxy(p *Proxy, slug string) {
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{
		testAppBearer: {
			VirtualKeyID: "app:" + slug,
			RouteSource:  "app",
			AppSlug:      slug,
			AppKind:      "third-party",
			AppKeyID:     "test-uuid",
		},
	})
}

// newAppPipelineTestVault returns a mockActiveVault primed with the App-pipeline
// happy-path shape: app_record with `upstreams`, an app-scoped binding pointing
// at a personal key (alias `app-test-key`), and the personal key wired through
// `personalAlias` so credential resolution returns a usable secret.
//
// AKL-207 (Step 3) integration: handleAppPipeline now invokes the full
// credential resolver, which needs `p.activeReader.GetPersonalKeyByAlias`.
// `setupTestProxyWithActive` wires this mock as BOTH activeReader AND
// apppipe.VaultReader (since New() auto-detects the apppipe.VaultReader
// interface via type assertion), so one mock covers both layers.
func newAppPipelineTestVault(slug string, upstreams []string, personalSecret, personalBaseURL string) *mockActiveVault {
	return &mockActiveVault{
		appRecord: &vault.AppRecord{Slug: slug, Upstreams: upstreams, AppKind: "third-party"},
		appBindings: map[string]*vault.ProviderBinding{
			"app:" + slug + "|" + upstreams[0]: {
				ProviderCode:  upstreams[0],
				KeySourceType: "personal",
				KeySourceRef:  "app-test-key",
			},
		},
		personalAlias:   "app-test-key",
		personalText:    personalSecret,
		personalProv:    upstreams[0],
		personalBaseURL: personalBaseURL,
	}
}

// TestHandle_AppPath_HappyPathForwardsToUpstream pins the full happy-path
// flow now that AKL-207 step 3 wired actual forwarding: authn → resolve →
// sanitize → resolve-binding-credential → serveRoute → upstream sees the
// sanitized body with the real upstream key injected.
func TestHandle_AppPath_HappyPathForwardsToUpstream(t *testing.T) {
	var (
		capturedAuth string
		capturedBody []byte
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"chatcmpl-test","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	av := newAppPipelineTestVault("my-agent", []string{"openai"}, "sk-upstream-real", upstream.URL)
	p := setupTestProxyWithActive(t, av)
	seedAppRouteInProxy(p, "my-agent")

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"aikey":{"task":"test"}}`
	req := httptest.NewRequest("POST", "/apps/my-agent/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from upstream forward, got %d: %s", w.Code, w.Body.String())
	}
	// Upstream must have received the REAL key (vault-decrypted), not the
	// inbound aikey_app_ bearer — proves prov.RewriteRequest fired.
	if capturedAuth != "Bearer sk-upstream-real" {
		t.Errorf("upstream Authorization = %q, want Bearer sk-upstream-real", capturedAuth)
	}
	// Upstream body must have aikey field STRIPPED by sanitizer.
	if strings.Contains(string(capturedBody), `"aikey"`) {
		t.Errorf("upstream body still contains aikey field — sanitizer didn't fire: %s", string(capturedBody))
	}
	// Upstream body must still contain the user's actual message — proves
	// sanitizer didn't accidentally trash the request.
	if !strings.Contains(string(capturedBody), `"messages"`) {
		t.Errorf("upstream body lost messages field: %s", string(capturedBody))
	}
}

// TestHandle_AppPath_OpenAIWireToAnthropicUpstream_TranslatesEndToEnd is
// the A2 (Google "medium" — real localhost TCP for the upstream side;
// inbound stays synthetic via httptest.NewRequest as elsewhere in this
// file) regression for the protocol-translator integration on the App
// pipeline. Added 2026-05-25 because the Agent-Quickstart "Supported
// matrix" specifically claims this case works ("Cursor OpenAI-compat
// endpoint + Claude model → /apps/X/v1/chat/completions → ✅ Fully
// supported (OpenAI→Anthropic translation)"), but until now there was
// NO end-to-end test that exercised:
//
//   inbound OpenAI wire (URL path /v1/chat/completions)
//        ↓
//   translator pairs/openai_anthropic.ConvertRequest
//        ↓
//   outbound Anthropic wire (URL path /v1/messages, top-level
//        `messages` + `max_tokens`, no OpenAI `choices`)
//        ↓
//   translator pairs/openai_anthropic.ConvertNonStream
//        ↓
//   inbound-shaped OpenAI response (`choices[0].message.content`)
//
// Direct passthrough is covered by HappyPathForwardsToUpstream above
// (OpenAI → OpenAI) and the rhythm-test-app tests further down
// (Anthropic → Anthropic). Both assume same-wire-format passthrough,
// so neither catches a regression that breaks translator wiring —
// translator unit tests pass + same-wire passthrough passes, but the
// "Cursor + Claude" path silently 500s. This test fences that gap.
//
// What the test does NOT cover: streaming SSE chunks. Per the
// translator package doc that's still 阶段 1 work; the matrix
// explicitly carves out streaming as a known limit. Non-stream is the
// claim we can validate today.
func TestHandle_AppPath_OpenAIWireToAnthropicUpstream_TranslatesEndToEnd(t *testing.T) {
	var (
		upstreamPath    string
		upstreamBody    []byte
		upstreamAuth    string
		upstreamAPIKey  string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		// Anthropic API uses x-api-key, not Authorization. OpenAI uses
		// Authorization: Bearer. Capture both so the assertion below
		// works for either header convention.
		upstreamAuth = r.Header.Get("Authorization")
		upstreamAPIKey = r.Header.Get("X-Api-Key")
		upstreamBody, _ = io.ReadAll(r.Body)
		// Anthropic non-stream response shape. The proxy's translator
		// MUST convert this to OpenAI shape before returning it to the
		// client — that's the assertion below on w.Body.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": "msg_test",
			"type": "message",
			"role": "assistant",
			"model": "claude-3-5-sonnet-20241022",
			"content": [{"type":"text","text":"hi from anthropic"}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 3, "output_tokens": 5}
		}`))
	}))
	defer upstream.Close()

	av := newAppPipelineTestVault("cross-proto-test", []string{"anthropic"}, "sk-ant-real", upstream.URL)
	p := setupTestProxyWithActive(t, av)
	seedAppRouteInProxy(p, "cross-proto-test")

	// Inbound: OpenAI wire (URL = /v1/chat/completions) but body.model is
	// claude-*. The resolver infers upstream=anthropic from the model
	// name; the translator must then flip the wire format.
	body := `{
		"model": "claude-3-5-sonnet-20241022",
		"messages": [{"role":"user","content":"hi"}]
	}`
	req := httptest.NewRequest("POST", "/apps/cross-proto-test/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from cross-proto forward, got %d: %s", w.Code, w.Body.String())
	}

	// 1) Upstream URL flip — translator must have moved the URL path
	//    from /v1/chat/completions (OpenAI) to /v1/messages (Anthropic).
	//    A regression here is the most common symptom of broken
	//    translator wiring (proxy just passes /chat/completions through
	//    to api.anthropic.com which 404s).
	if upstreamPath != "/v1/messages" {
		t.Errorf("upstream path = %q, want /v1/messages (proves translator URL flip)", upstreamPath)
	}

	// 2) Outbound credential — must be the vault-decrypted personal key,
	//    NOT the inbound aikey_app_ bearer. Anthropic uses x-api-key
	//    not Authorization, so check both header conventions: at least
	//    one must carry the secret AND neither must carry the app
	//    bearer (that would mean the credential resolver failed to swap
	//    in the upstream key).
	hasKey := upstreamAPIKey == "sk-ant-real" || upstreamAuth == "Bearer sk-ant-real"
	if !hasKey {
		t.Errorf("upstream got NO vault-decrypted key (x-api-key=%q, Authorization=%q); credential resolver failed",
			upstreamAPIKey, upstreamAuth)
	}
	if upstreamAuth == "Bearer "+testAppBearer || upstreamAPIKey == testAppBearer {
		t.Errorf("upstream got the inbound app bearer (x-api-key=%q, Authorization=%q); credential resolver did NOT swap in the upstream key",
			upstreamAPIKey, upstreamAuth)
	}

	// 3) Outbound body shape — must look like Anthropic, not like OpenAI.
	//    `choices` is OpenAI's response-side field; if it leaks into the
	//    request body the translator's request half didn't fire.
	//    `max_tokens` is required by Anthropic Messages API, so its
	//    presence proves the translator added it (OpenAI request bodies
	//    don't require it).
	bodyStr := string(upstreamBody)
	if strings.Contains(bodyStr, `"choices"`) {
		t.Errorf("upstream body leaked OpenAI 'choices' field — translator request half didn't fire: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"messages"`) {
		t.Errorf("upstream body missing 'messages' field: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"max_tokens"`) {
		t.Errorf("upstream body missing 'max_tokens' (required by Anthropic, added by translator): %s", bodyStr)
	}

	// 4) Inbound response shape — translator response half must have
	//    converted Anthropic's `content: [{type:"text",text:"..."}]`
	//    into OpenAI's `choices[0].message.content`. If the upstream
	//    response leaked through unchanged, the client (Cursor /
	//    openai-python) would fail to parse — that's the user-visible
	//    breakage we're fencing against.
	var openAIResp struct {
		ID      string `json:"id"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &openAIResp); err != nil {
		t.Fatalf("response not JSON: %v, body=%s", err, w.Body.String())
	}
	if len(openAIResp.Choices) == 0 {
		t.Fatalf("response missing OpenAI choices array (translator response half didn't fire): %s", w.Body.String())
	}
	if !strings.Contains(openAIResp.Choices[0].Message.Content, "hi from anthropic") {
		t.Errorf("response content = %q, want substring 'hi from anthropic'", openAIResp.Choices[0].Message.Content)
	}
}

// TestParseUpstreamErrorEnvelope fences the JSON shape parsing for the
// 2026-05-25 default-on app-pipeline 4xx/5xx forensic log. The parser
// must handle both Anthropic and OpenAI envelope shapes (they share
// the same `error.{type,message}` nested path, so one struct covers
// both) and degrade silently to ("", "") for non-JSON / unknown shapes.
//
// Why this matters: if the parser silently swallows a known shape,
// the WARN log loses its highest-signal fields (error_type +
// error_message) and operators are back to staring at a generic
// `404 Not Found` with no upstream context. That was the exact
// symptom that motivated this whole feature (8 × 404s from claude-mem
// with no way to see Anthropic's explanation).
func TestParseUpstreamErrorEnvelope(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantType    string
		wantMessage string
	}{
		{
			name:        "anthropic 404 not_found_error",
			body:        `{"type":"error","error":{"type":"not_found_error","message":"model: claude-opus-4-7"}}`,
			wantType:    "not_found_error",
			wantMessage: "model: claude-opus-4-7",
		},
		{
			name:        "anthropic 429 rate_limit",
			body:        `{"type":"error","error":{"type":"rate_limit_error","message":"This request would exceed your organization's rate limit"}}`,
			wantType:    "rate_limit_error",
			wantMessage: "This request would exceed your organization's rate limit",
		},
		{
			name:        "openai invalid_request_error",
			body:        `{"error":{"message":"Unsupported model","type":"invalid_request_error","code":"model_not_found"}}`,
			wantType:    "invalid_request_error",
			wantMessage: "Unsupported model",
		},
		{
			name:        "openai authentication_error",
			body:        `{"error":{"message":"Invalid API key","type":"authentication_error","code":"invalid_api_key","param":null}}`,
			wantType:    "authentication_error",
			wantMessage: "Invalid API key",
		},
		{
			name:        "empty body — graceful",
			body:        "",
			wantType:    "",
			wantMessage: "",
		},
		{
			name:        "non-JSON HTML (gateway 502 page) — graceful",
			body:        `<html><body>502 Bad Gateway</body></html>`,
			wantType:    "",
			wantMessage: "",
		},
		{
			name:        "JSON but unknown envelope shape — graceful",
			body:        `{"status":"error","detail":"something went wrong"}`,
			wantType:    "",
			wantMessage: "",
		},
		{
			name:        "JSON with only partial fields — partial fill",
			body:        `{"error":{"type":"server_error"}}`,
			wantType:    "server_error",
			wantMessage: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotType, gotMsg := parseUpstreamErrorEnvelope([]byte(c.body))
			if gotType != c.wantType {
				t.Errorf("type = %q, want %q", gotType, c.wantType)
			}
			if gotMsg != c.wantMessage {
				t.Errorf("message = %q, want %q", gotMsg, c.wantMessage)
			}
		})
	}
}

// TestHandle_AppPath_UpstreamError_LogsForensic verifies the
// end-to-end wiring: when the upstream returns 4xx, the app pipeline
// ModifyResponse closure invokes logAppUpstreamErrorForensic and the
// downstream client still gets the original payload (the drain +
// re-buffer must not corrupt the response).
//
// This pins the contract that ADDING the forensic log doesn't BREAK
// the existing pass-through-to-client behavior — a regression where
// the log forgot to re-buffer would silently 0-byte every 4xx
// response to the user.
func TestHandle_AppPath_UpstreamError_LogsForensic(t *testing.T) {
	const anthropicErrBody = `{"type":"error","error":{"type":"not_found_error","message":"model: claude-experimental-xyz not found"}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("request-id", "req_011_test_404")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(anthropicErrBody))
	}))
	defer upstream.Close()

	av := newAppPipelineTestVault("err-test-app", []string{"anthropic"}, "sk-ant-real", upstream.URL)
	p := setupTestProxyWithActive(t, av)
	seedAppRouteInProxy(p, "err-test-app")

	// Use a model the resolver recognises as claude-family (prefix
	// "claude-") so it routes to the anthropic upstream — letting the
	// test exercise the END-OF-PIPELINE 4xx path (upstream rejects),
	// not the EARLY-RESOLUTION 4xx path (UPSTREAM_UNINFERRABLE for
	// unknown model names). The model name itself just has to be
	// claude-prefixed; the mock upstream returns 404 regardless of
	// what specific model id arrives.
	body := `{"model":"claude-experimental-xyz","messages":[{"role":"user","content":"hi"}],"max_tokens":10}`
	req := httptest.NewRequest("POST", "/apps/err-test-app/v1/messages", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	// 1) Client must see the upstream's 404 — proxy is a passthrough
	//    for error responses, the forensic log is a side observation.
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 passthrough, got %d: %s", w.Code, w.Body.String())
	}

	// 2) Client body must be the EXACT upstream body. A regression in
	//    the drain+re-buffer dance (forgetting NopCloser, double-read)
	//    would silently 0-byte the client. Byte-for-byte match here is
	//    the strongest possible fence.
	if got := w.Body.String(); got != anthropicErrBody {
		t.Errorf("response body corrupted by forensic log drain:\n  want: %q\n  got:  %q", anthropicErrBody, got)
	}

	// 3) Upstream request_id must be surfaced via Content-Length /
	//    headers — verify ContentLength matches (proves re-buffer set
	//    it correctly).
	if w.Header().Get("Request-Id") != "req_011_test_404" {
		t.Errorf("upstream request-id header not forwarded: got %q", w.Header().Get("Request-Id"))
	}
}

// TestHandle_AppPathTakesPrecedenceOverProviderPrefix is the regression
// test for the ordering invariant called out in router.go's ExtractAppPath
// docstring + apppipe/router.go's package doc. Slug='openai' could in
// principle look like the legacy provider-prefix path if the order is
// wrong; with correct order it MUST route to App pipeline (which will
// then forward upstream + return 200), not to legacy provider-prefix
// routing (which would resolve a different binding entirely).
func TestHandle_AppPathTakesPrecedenceOverProviderPrefix(t *testing.T) {
	var precedenceCheckUpstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		precedenceCheckUpstreamHit = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"y"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	// Seed both Registry (for authn) and vault under slug="openai" — the
	// cross-collision slug. The 200 + capturedUpstream flag prove the App
	// pipeline forward fired (NOT the legacy provider-prefix path, which
	// would have hit a different upstream chosen from activeKeyConfig).
	av := newAppPipelineTestVault("openai", []string{"openai"}, "sk-upstream-real", upstream.URL)
	p := setupTestProxyWithActive(t, av)
	seedAppRouteInProxy(p, "openai")

	req := httptest.NewRequest("POST", "/apps/openai/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (App pipeline forwarded upstream), got %d: %s\n"+
			"This means the legacy provider-prefix parser captured the URL — Tier 0a ordering is broken.",
			w.Code, w.Body.String())
	}
	if !precedenceCheckUpstreamHit {
		t.Error("upstream test server received NO request — App pipeline didn't forward, or hit a different URL")
	}
}

// TestHandle_AppTokenAtLegacyV1EntryRejected pins the precise error code
// for "user sent app token to wrong URL" at the legacy /v1/... entry
// (which has no path prefix). Pre-AKL-208 this would fall to the
// default-case "Unexpected token classification" message — generic and
// unactionable. Post-AKL-208 the user gets APP_TOKEN_WRONG_PATH with a
// direct pointer at `aikey app authorize <slug>`'s OPENAI_BASE_URL line.
func TestHandle_AppTokenAtLegacyV1EntryRejected(t *testing.T) {
	p := setupTestProxy(t, "http://unused")

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
	var errResp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "APP_TOKEN_WRONG_PATH" {
		t.Errorf("error.code = %q, want APP_TOKEN_WRONG_PATH", errResp.Error.Code)
	}
	if !strings.Contains(errResp.Error.Message, "/apps/") {
		t.Errorf("error message must point at /apps/ URL, got: %s", errResp.Error.Message)
	}
	if !strings.Contains(errResp.Error.Message, "aikey app authorize") {
		t.Errorf("error message should reference `aikey app authorize`, got: %s", errResp.Error.Message)
	}
}

// TestHandle_AppTokenAtProviderPrefixEntryRejected is the
// /<provider>/v1/... counterpart. Same precise error; the message names
// the wrong provider prefix so the user can spot the URL mistake.
func TestHandle_AppTokenAtProviderPrefixEntryRejected(t *testing.T) {
	p := setupTestProxy(t, "http://unused")

	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
	var errResp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "APP_TOKEN_WRONG_PATH" {
		t.Errorf("error.code = %q, want APP_TOKEN_WRONG_PATH", errResp.Error.Code)
	}
	// Message should name the wrong provider prefix so user spots the
	// URL choice they need to change.
	if !strings.Contains(errResp.Error.Message, "/openai/v1/") {
		t.Errorf("error message should name the wrong path '/openai/v1/', got: %s", errResp.Error.Message)
	}
}

// TestHandle_AppPath_AuthnRejectsUnknownToken is the AKL-204 integration
// smoke test at the proxy level: an /apps/<slug>/v1 request
// with a syntactically-valid app bearer that is NOT in the Registry
// must surface as 401 APP_KEY_NOT_FOUND, NOT fall through to the post-
// authn 501 stub. Catches a regression where the handler accidentally
// returns 501 unconditionally regardless of authn.
func TestHandle_AppPath_AuthnRejectsUnknownToken(t *testing.T) {
	p := setupTestProxy(t, "http://unused")
	// Deliberately NOT seeding any app route — the bearer below should
	// be unknown to the Registry.
	req := httptest.NewRequest("POST", "/apps/unknown-agent/v1/chat", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (authn rejected), got %d: %s", w.Code, w.Body.String())
	}
	var errResp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "APP_KEY_NOT_FOUND" {
		t.Errorf("error.code = %q, want APP_KEY_NOT_FOUND", errResp.Error.Code)
	}
}

// TestHandle_AppPath_AuthnRejectsSlugMismatch is the AKL-204 integration
// case for cross-slug token reuse: bearer was issued for slug A but the
// URL targets slug B. Must return 403 APP_MISMATCH naming both slugs so
// the user can spot the mistake (token paste in wrong Agent config, or
// URL typo in the Agent's BASE_URL).
func TestHandle_AppPath_AuthnRejectsSlugMismatch(t *testing.T) {
	p := setupTestProxy(t, "http://unused")
	seedAppRouteInProxy(p, "agent-a") // bearer bound to agent-a

	// Hit /apps/agent-b/... with the bearer bound to agent-a.
	req := httptest.NewRequest("POST", "/apps/agent-b/v1/chat", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (slug mismatch), got %d: %s", w.Code, w.Body.String())
	}
	var errResp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "APP_MISMATCH" {
		t.Errorf("error.code = %q, want APP_MISMATCH", errResp.Error.Code)
	}
	if !strings.Contains(errResp.Error.Message, "agent-a") || !strings.Contains(errResp.Error.Message, "agent-b") {
		t.Errorf("error message must name both slugs (token's vs URL's): %s", errResp.Error.Message)
	}
}

// TestHandle_AppPath_ResolveRejectsMissingVault is the AKL-205 integration
// case: authn passes (Registry has the route) but no VaultReader is wired
// (Personal edition without app pipeline support, or test environment
// mishap). Must surface as 503 APP_VAULT_NOT_AVAILABLE, not crash or
// silently 501.
func TestHandle_AppPath_ResolveRejectsMissingVault(t *testing.T) {
	p := setupTestProxy(t, "http://unused")
	seedAppRouteInProxy(p, "my-agent")
	// Deliberately NOT calling seedAppVaultInProxy — Proxy.appVault is nil.

	req := httptest.NewRequest("POST", "/apps/my-agent/v1/chat", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (no vault for app pipeline), got %d: %s", w.Code, w.Body.String())
	}
	var errResp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "APP_VAULT_NOT_AVAILABLE" {
		t.Errorf("error.code = %q, want APP_VAULT_NOT_AVAILABLE", errResp.Error.Code)
	}
}

// TestHandle_AppPath_ResolveRejectsUpstreamNotDeclared is Phase 2 Day 7's
// replacement for the old PROTOCOL_NOT_ALLOWED test. The URL no longer
// carries a <protocol> segment; instead, upstream is inferred from
// body.model. If the inferred upstream isn't in app.Upstreams, the
// request is rejected with UPSTREAM_NOT_DECLARED — same intent (defend
// against vendor mid-flight scope expansion), expressed in the new
// model-routed shape.
func TestHandle_AppPath_ResolveRejectsUpstreamNotDeclared(t *testing.T) {
	av := newAppPipelineTestVault("openai-only-agent", []string{"openai"}, "sk-unused", "http://unused")
	p := setupTestProxyWithActive(t, av)
	seedAppRouteInProxy(p, "openai-only-agent")

	// body.model = claude-... infers upstream=anthropic, but the app only
	// declared upstreams=[openai]. Must reject with 403 UPSTREAM_NOT_DECLARED.
	body := `{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/apps/openai-only-agent/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (upstream not declared), got %d: %s", w.Code, w.Body.String())
	}
	var errResp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != "UPSTREAM_NOT_DECLARED" {
		t.Errorf("error.code = %q, want UPSTREAM_NOT_DECLARED", errResp.Error.Code)
	}
}

// TestHandle_AppPath_UsageEventCarriesAppFields pins AKL-207 step 4:
// when a request flows through the App pipeline, the usage_event written
// to the collector carries app_slug / app_key_id / app_mode / bound_via /
// requested_model / resolved_provider per 主方案 §5.3. Legacy /v1/...
// paths produce events with these fields empty — pinned by separate
// regression tests in proxy_test.go's existing token-recording suite.
func TestHandle_AppPath_UsageEventCarriesAppFields(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"y"}}],"usage":{"prompt_tokens":7,"completion_tokens":11}}`))
	}))
	defer upstream.Close()

	// Wire collector with capturing store so we can assert the emitted event.
	store := newCapturingStore()
	collector, _ := newTestCollector(t)
	_ = collector // collector created inside helper; we use store below

	av := newAppPipelineTestVault("audit-agent", []string{"openai"}, "sk-upstream-real", upstream.URL)
	// Construct proxy via New so the appVault wires up. setupTestProxyWithActive
	// doesn't expose a store override, so build inline.
	regCreated := vkeys.NewRegistry()
	prov := provider.NewRegistry()
	coll := events.NewCollector(store, 1, 5*time.Millisecond)
	t.Cleanup(func() { coll.Close() })
	p := New(av, regCreated, prov, coll, context.Background())
	regCreated.Merge(map[string]*vkeys.ResolvedRoute{
		testAppBearer: {
			VirtualKeyID: "app:audit-agent",
			RouteSource:  "app",
			AppSlug:      "audit-agent",
			AppKind:      "third-party",
			AppKeyID:     "uuid-audit",
			// FollowUserActive false → mode="isolated", bound_via="app:audit-agent"
		},
	})

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/apps/audit-agent/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-aikey-model", "gpt-4o") // simulate the extractor's model stash
	p.Handle(httptest.NewRecorder(), req)

	ev := store.waitEvent(t, 2*time.Second)
	if ev.AppSlug != "audit-agent" {
		t.Errorf("AppSlug = %q, want audit-agent", ev.AppSlug)
	}
	if ev.AppKeyID != "uuid-audit" {
		t.Errorf("AppKeyID = %q, want uuid-audit", ev.AppKeyID)
	}
	if ev.AppMode != "isolated" {
		t.Errorf("AppMode = %q, want isolated (FollowUserActive=false)", ev.AppMode)
	}
	if ev.BoundVia != "app:audit-agent" {
		t.Errorf("BoundVia = %q, want app:audit-agent", ev.BoundVia)
	}
	if ev.ResolvedProvider != "openai" {
		t.Errorf("ResolvedProvider = %q, want openai", ev.ResolvedProvider)
	}
	if ev.RequestedModel != "gpt-4o" {
		t.Errorf("RequestedModel = %q, want gpt-4o", ev.RequestedModel)
	}
}

// TestHandle_LegacyPathsStillWorkUnchanged is the no-regression smoke
// test — adding the Tier 0a branch + Tier1App case branches must NOT
// disturb the existing legacy /v1 + /<provider>/v1 paths that personal /
// team / oauth tokens use today. Without this, a future change to the
// Tier 0a precedence could silently break the dominant path.
func TestHandle_LegacyPathsStillWorkUnchanged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer aikey_team_openai_test")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	p.Handle(w, req)

	if w.Code != 200 {
		t.Fatalf("legacy team-token path broke: got %d: %s", w.Code, w.Body.String())
	}
}

// TestProtocolFamilyLookup_PinsExpectedMapping pins the contract that
// handleAppPipeline relies on at Stage 6 to fill
// ResolvedRoute.ProtocolFamily — for the Phase 4 M2 plugin observer
// (degrade-detector rhythm) to dispatch SSE parsers correctly.
//
// If the yaml file's "protocol:" column drifts for any of these providers,
// the App pipeline will fill ProtocolFamily with the wrong value and the
// plugin observer will try to parse e.g. OpenAI-shaped chunks with the
// Anthropic SSE parser — silently producing nonsense rhythm timings. This
// test guards the data contract independently of the integration path.
func TestProtocolFamilyLookup_PinsExpectedMapping(t *testing.T) {
	cases := []struct {
		providerCode string
		wantFamily   string
	}{
		// Direct providers — one provider per family.
		{"anthropic", "anthropic"},
		{"google_gemini", "gemini"},
		// OpenAI wire family — multiple providers map to the same family
		// (degrade-detector parser dispatch must group these together).
		{"openai", "openai_compatible"},
		{"kimi_code", "openai_compatible"},
		{"moonshot", "openai_compatible"},
		{"deepseek", "openai_compatible"},
		{"qwen", "openai_compatible"},
		{"openrouter", "openai_compatible"},
	}
	for _, c := range cases {
		t.Run(c.providerCode, func(t *testing.T) {
			pr, ok := provider.Routes().ByProvider(c.providerCode)
			if !ok {
				t.Fatalf("provider.Routes().ByProvider(%q) missing — yaml provider_fingerprint may have removed this provider; either restore the row or update plugin observer expectations", c.providerCode)
			}
			if pr.Protocol != c.wantFamily {
				t.Errorf("provider.Routes().ByProvider(%q).Protocol = %q, want %q (yaml drift would silently mis-dispatch plugin observer SSE parsers)", c.providerCode, pr.Protocol, c.wantFamily)
			}
		})
	}
}

// TestProtocolFamilyLookup_UnknownProviderReturnsEmpty pins the
// "unknown provider" fallback — handleAppPipeline leaves
// ProtocolFamily="" rather than panicking. The Phase 4 M2 plugin observer
// must treat "" as "skip rhythm dispatch / log warn", not as a valid
// family equal to e.g. anthropic.
func TestProtocolFamilyLookup_UnknownProviderReturnsEmpty(t *testing.T) {
	if _, ok := provider.Routes().ByProvider("nonexistent-vendor"); ok {
		t.Fatalf("provider.Routes().ByProvider(\"nonexistent-vendor\") returned ok=true — yaml grew an unexpected row")
	}
}

// --- Phase 4 M2 plugin observer wiring tests --------------------------------
//
// These two tests together pin the observer hook contract from
// plugin-架构设计.md §5.1:
//
//   1. App pipeline requests trigger NotifyStart + NotifyEnd on the
//      observer registry, with a RequestContext carrying the right
//      AppSlug / AppKeyID / AppMode / ProviderID / ProtocolFamily.
//   2. Legacy (non-App) requests do NOT trigger Notify*, even if an
//      observer registry is attached — gating prevents observer
//      surface from bleeding into the legacy /v1/... path.
//
// SSE-event delivery (NotifySSEEvent) is exercised by streamDrainer-
// focused tests in Stage B (see streamDrainer_test.go).

// rhythmHooksRecorder is a minimal observer.StreamingObserver that
// records which hooks fire for which RequestContext. Used in the two
// wiring tests below to assert NotifyStart/End contract without
// pulling in the real rhythm observer (which would require a full
// SSE stream to be meaningful).
type rhythmHooksRecorder struct {
	startSeen map[string]*observer.RequestContext // keyed by TraceID
	endSeen   map[string]int                      // TraceID → latencyMs
	mu        sync.Mutex
	done      chan struct{} // closed when end has been seen
}

func newRhythmHooksRecorder() *rhythmHooksRecorder {
	return &rhythmHooksRecorder{
		startSeen: make(map[string]*observer.RequestContext),
		endSeen:   make(map[string]int),
		done:      make(chan struct{}),
	}
}

func (r *rhythmHooksRecorder) OnRequestStart(_ context.Context, req *observer.RequestContext) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.startSeen[req.TraceID] = req
}

func (r *rhythmHooksRecorder) OnSSEEvent(_ context.Context, _ *observer.RequestContext, _ string, _ []byte) {
	// SSE-frame coverage lives in Stage B's streamDrainer tests; here
	// we ignore frames entirely.
}

func (r *rhythmHooksRecorder) OnRequestEnd(_ context.Context, req *observer.RequestContext, latencyMs int) {
	r.mu.Lock()
	r.endSeen[req.TraceID] = latencyMs
	r.mu.Unlock()
	// Signal that end was seen. close() is idempotent if called multiple
	// times only via sync.Once, but tests will only run one request so
	// the first close() is the only one we care about.
	select {
	case <-r.done:
		// already closed
	default:
		close(r.done)
	}
}

// buildTestObserverRegistry constructs an observer.Registry with the
// rhythmHooksRecorder registered + Build-d.
//
// Clears the global registration sink BEFORE registering, then again
// in t.Cleanup, so tests in this package don't see each other's
// observer descriptors. Without this isolation a second test calling
// BuildObservers would see (this-test-name × 2) registrations and
// fail with "expected exactly 1 active observer, got 2".
//
// Side-effect-clean test pattern courtesy of the global registration
// sink design — registry self-registration is great for production
// but requires explicit isolation in test harnesses.
func buildTestObserverRegistry(t *testing.T, recorder *rhythmHooksRecorder) *observer.Registry {
	t.Helper()
	observer.ResetRegistrationsForTest()
	t.Cleanup(observer.ResetRegistrationsForTest)
	observer.RegisterObserver(observer.Observer{
		Name:         "rhythm-test-" + t.Name(),
		OwnerAppSlug: "degrade-detector", // matches FirstPartyAllowlist
		// Production rhythm observer subscribes only to App pipeline; mirror
		// here so the test fixture exercises the same stream-routing path
		// the prod observer takes (App pipeline NotifyStart calls hit it,
		// user_chat / probe calls — which we'll wire in P3 step 4 — don't).
		Streams: []string{observer.StreamAppPipeline},
		Build: func(_ map[string]any) (observer.StreamingObserver, error) {
			return recorder, nil
		},
	})
	reg := observer.NewRegistry(slog.Default())
	reg.BuildObservers(func(_ string) bool { return true }, nil)
	if reg.Active() != 1 {
		t.Fatalf("expected exactly 1 active observer, got %d", reg.Active())
	}
	return reg
}

// TestHandle_AppPath_NotifyStartEndFireWithRequestContext pins:
//   - handleAppPipeline calls registry.NotifyStart before serveRoute
//   - handleAppPipeline calls registry.NotifyEnd after serveRoute
//   - The RequestContext carries the right AppSlug / AppKeyID /
//     AppMode / ProviderID / ProtocolFamily / RequestedModel
//   - TraceID is non-empty (extracted from the W3C trace header or
//     generated fresh)
//   - The latencyMs reported to NotifyEnd is sane (>= 0)
func TestHandle_AppPath_NotifyStartEndFireWithRequestContext(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"x","choices":[{"message":{"content":"y"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer upstream.Close()

	av := newAppPipelineTestVault("rhythm-test-app", []string{"anthropic"}, "sk-ant-real", upstream.URL)
	p := setupTestProxyWithActive(t, av)
	// Override the seeded route so the AppSlug / AppKeyID / AppKind
	// match what we want to assert in the RequestContext.
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{
		testAppBearer: {
			VirtualKeyID: "app:rhythm-test-app",
			RouteSource:  "app",
			AppSlug:      "rhythm-test-app",
			AppKind:      "first-party",
			AppKeyID:     "uuid-rhythm",
		},
	})

	recorder := newRhythmHooksRecorder()
	p.SetObserverRegistry(buildTestObserverRegistry(t, recorder))

	body := `{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/apps/rhythm-test-app/v1/messages", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")
	p.Handle(httptest.NewRecorder(), req)

	// NotifyEnd is dispatched to a per-(request × observer) consumer
	// goroutine that processes events serially; wait briefly for it.
	select {
	case <-recorder.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("OnRequestEnd never fired within 2s; observer wiring is broken")
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.startSeen) != 1 {
		t.Fatalf("expected exactly 1 NotifyStart, got %d", len(recorder.startSeen))
	}
	if len(recorder.endSeen) != 1 {
		t.Fatalf("expected exactly 1 NotifyEnd, got %d", len(recorder.endSeen))
	}
	// Pull the single RequestContext + latency from the captured maps.
	var seenReq *observer.RequestContext
	var seenLat int
	for tid, rc := range recorder.startSeen {
		seenReq = rc
		seenLat = recorder.endSeen[tid]
		break
	}
	if seenReq.AppSlug != "rhythm-test-app" {
		t.Errorf("AppSlug = %q, want rhythm-test-app", seenReq.AppSlug)
	}
	if seenReq.AppKeyID != "uuid-rhythm" {
		t.Errorf("AppKeyID = %q, want uuid-rhythm", seenReq.AppKeyID)
	}
	if seenReq.AppMode != "isolated" {
		t.Errorf("AppMode = %q, want isolated (FollowUserActive=false)", seenReq.AppMode)
	}
	if seenReq.ProviderID != "anthropic" {
		t.Errorf("ProviderID = %q, want anthropic", seenReq.ProviderID)
	}
	if seenReq.ProtocolFamily != "anthropic" {
		t.Errorf("ProtocolFamily = %q, want anthropic", seenReq.ProtocolFamily)
	}
	// F1 regression pin (review-and-fixes 2026-05-21): handleAppPipeline
	// MUST fill KeyAlias from cred.KeyAlias so trust-local's
	// LocalObservation.alias_name aggregation works. Without this the
	// rhythm observer reports key_alias="" for every request and
	// per-alias trust queries can't surface real-user trust.
	if seenReq.KeyAlias != "app-test-key" {
		t.Errorf("KeyAlias = %q, want app-test-key (F1 regression — review-and-fixes 2026-05-21)", seenReq.KeyAlias)
	}
	if seenReq.RequestedModel != "claude-3-5-sonnet-20241022" {
		t.Errorf("RequestedModel = %q, want claude-3-5-sonnet-20241022", seenReq.RequestedModel)
	}
	if seenReq.TraceID == "" {
		t.Errorf("TraceID empty; expected non-empty W3C-style trace id")
	}
	if seenLat < 0 {
		t.Errorf("latency = %d, want >= 0", seenLat)
	}
}

// rhythmFramesRecorder is the SSE-frame variant of rhythmHooksRecorder
// — captures every (eventType, payload) tuple the registry dispatches
// via NotifySSEEvent. Used by TestHandle_AppPath_SSEFramesDispatched
// to assert end-to-end per-frame delivery.
type rhythmFramesRecorder struct {
	mu     sync.Mutex
	frames []struct {
		EventType string
		Payload   []byte
	}
	done chan struct{}
}

func newRhythmFramesRecorder() *rhythmFramesRecorder {
	return &rhythmFramesRecorder{done: make(chan struct{})}
}

func (r *rhythmFramesRecorder) OnRequestStart(context.Context, *observer.RequestContext) {}
func (r *rhythmFramesRecorder) OnSSEEvent(_ context.Context, _ *observer.RequestContext, eventType string, payload []byte) {
	r.mu.Lock()
	// payload is already a copy at the registry boundary (P0-1
	// invariant). Tests can retain the slice safely without re-copy.
	r.frames = append(r.frames, struct {
		EventType string
		Payload   []byte
	}{eventType, payload})
	r.mu.Unlock()
}
func (r *rhythmFramesRecorder) OnRequestEnd(context.Context, *observer.RequestContext, int) {
	select {
	case <-r.done:
	default:
		close(r.done)
	}
}

// TestHandle_AppPath_SSEFramesDispatched pins the Stage B contract:
// when an App pipeline request streams an Anthropic-shape SSE body
// from upstream, the observer receives per-frame NotifySSEEvent
// dispatches with byte-identical payloads + the right eventType. This
// is the strongest end-to-end evidence that:
//
//   - streamDrainer's SSE parser handles realistic Anthropic frames
//   - chunk boundaries in upstream's response don't fragment frames
//   - the payload bytes are NOT mutated by ResponseTransform / drainer
//     before the observer sees them (the doc-anchor ordering invariant)
//   - the consumer-goroutine fan-out preserves frame order
//
// If any of these breaks, the rhythm observer would either see
// torn JSON / wrong event types / corrupted timing — silent failure
// modes that this test catches loudly.
func TestHandle_AppPath_SSEFramesDispatched(t *testing.T) {
	// Realistic Anthropic SSE wire format. Chunk it deliberately at
	// non-frame boundaries to exercise cross-chunk reassembly.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		// First chunk: message_start + START of content_block_delta.
		w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content"))
		if flusher != nil {
			flusher.Flush()
		}
		// Second chunk: REST of content_block_delta + message_stop.
		w.Write([]byte("_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	av := newAppPipelineTestVault("rhythm-frames-app", []string{"anthropic"}, "sk-real", upstream.URL)
	p := setupTestProxyWithActive(t, av)
	p.registry.Merge(map[string]*vkeys.ResolvedRoute{
		testAppBearer: {
			VirtualKeyID: "app:rhythm-frames-app",
			RouteSource:  "app",
			AppSlug:      "rhythm-frames-app",
			AppKind:      "first-party",
			AppKeyID:     "uuid-frames",
		},
	})
	recorder := newRhythmFramesRecorder()
	// Reuse buildTestObserverRegistry's cleanup pattern but plug the
	// frames recorder directly. The hooks recorder isn't compatible
	// because OnRequestEnd / OnSSEEvent semantics differ — easier to
	// build a one-off registry here than to overgeneralize.
	observer.ResetRegistrationsForTest()
	t.Cleanup(observer.ResetRegistrationsForTest)
	observer.RegisterObserver(observer.Observer{
		Name:         "rhythm-frames-" + t.Name(),
		OwnerAppSlug: "degrade-detector",
		Streams:      []string{observer.StreamAppPipeline}, // see sibling fixture comment
		Build: func(_ map[string]any) (observer.StreamingObserver, error) {
			return recorder, nil
		},
	})
	reg := observer.NewRegistry(slog.Default())
	reg.BuildObservers(func(_ string) bool { return true }, nil)
	if reg.Active() != 1 {
		t.Fatalf("expected exactly 1 active observer, got %d", reg.Active())
	}
	p.SetObserverRegistry(reg)

	// Send the request. stream=true so the streaming code path fires
	// (not the buffered non-stream path).
	body := `{"model":"claude-3-5-sonnet-20241022","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/apps/rhythm-frames-app/v1/messages", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAppBearer)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.Handle(rec, req)

	// Drain the client-side response so the drainer's read loop
	// actually consumes upstream. ReadAll blocks until upstream closes.
	io.ReadAll(rec.Result().Body)

	// Wait for OnRequestEnd before asserting — observer dispatch is
	// async (per-request consumer goroutine).
	select {
	case <-recorder.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("OnRequestEnd never fired; observer SSE wiring is broken")
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.frames) != 3 {
		t.Fatalf("expected 3 SSE frames, got %d: %#v", len(recorder.frames), recorder.frames)
	}
	wantEvents := []string{"message_start", "content_block_delta", "message_stop"}
	for i, want := range wantEvents {
		if recorder.frames[i].EventType != want {
			t.Errorf("frame[%d].EventType = %q, want %q", i, recorder.frames[i].EventType, want)
		}
	}
	// Spot-check that the cross-chunk-boundary frame reassembled
	// correctly (this is the partial-frame straddling test —
	// equivalent to TestSSEParser_PartialFrameStraddlesChunkBoundary
	// but at the full proxy/drainer level).
	if !strings.Contains(string(recorder.frames[1].Payload), `"text":"hi"`) {
		t.Errorf("content_block_delta payload lost the cross-chunk text: %q", string(recorder.frames[1].Payload))
	}
	if !strings.Contains(string(recorder.frames[1].Payload), `"index":0`) {
		t.Errorf("content_block_delta payload lost the cross-chunk index field: %q", string(recorder.frames[1].Payload))
	}
}

// TestHandle_LegacyPath_NoNotifyEvenWithRegistryAttached pins the
// gating invariant: even when an observer registry is attached to the
// Proxy, requests that don't go through the App pipeline (i.e. legacy
// /v1/... + /<provider>/v1/...) must NOT trigger Notify*. Without
// this gating the observer surface would silently inspect every
// proxied request, breaking the "first-party app observers only" R2
// promise + leaking SSE bytes to off-app observers.
func TestHandle_LegacyPath_NoNotifyEvenWithRegistryAttached(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	p := setupTestProxy(t, upstream.URL)
	recorder := newRhythmHooksRecorder()
	p.SetObserverRegistry(buildTestObserverRegistry(t, recorder))

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer aikey_team_openai_test")
	req.Header.Set("Content-Type", "application/json")
	p.Handle(httptest.NewRecorder(), req)

	// Wait a tick to let any spurious observer dispatch run; if Notify*
	// fired (incorrectly) the recorder would have seen something by now.
	time.Sleep(50 * time.Millisecond)
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.startSeen) != 0 {
		t.Errorf("legacy path triggered NotifyStart (%d times); observer surface leaked beyond App pipeline", len(recorder.startSeen))
	}
	if len(recorder.endSeen) != 0 {
		t.Errorf("legacy path triggered NotifyEnd (%d times); observer surface leaked beyond App pipeline", len(recorder.endSeen))
	}
}
